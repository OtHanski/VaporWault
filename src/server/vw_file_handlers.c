#include "vw_file_handlers.h"
#include "vw_cluster.h"
#include "vw_invite.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_oplog.h"
#include "vw_server_core.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>

/* Defeat dead-store elimination on buffers holding session tokens. */
static void *(* volatile g_memset_fn)(void *, int, size_t) = memset;
#define secure_zero(p, n) ((void)g_memset_fn((p), 0, (n)))

/* Debug/warning logs (no tokens, no chunk data per SEC.07).
 * ##__VA_ARGS__ is a GNU extension; suppress the pedantic warning on Clang. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif
#define LOG_DEBUG(fmt, ...) \
    fprintf(stderr, "[DBG] vw_file_handlers: " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) \
    fprintf(stderr, "[WRN] vw_file_handlers: " fmt "\n", ##__VA_ARGS__)
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/*
 * Send VW_MSG_ERROR with a numeric error code and no human-readable message.
 * Returns the result of vw_proto_send (VW_OK on successful send).
 */
static vw_err_t send_error(vw_conn_t *conn, vw_err_t code)
{
    uint8_t buf[8];
    uint32_t len;
    vw_err_t err = vw_proto_encode_error((uint32_t)code, NULL, 0,
                                          buf, sizeof(buf), &len);
    if (err != VW_OK) return err;
    return vw_proto_send(conn, VW_MSG_ERROR, buf, len);
}

vw_err_t vw_path_validate(const char *path, uint32_t len)
{
    if (!path || len == 0 || len > VW_MAX_PATH_BYTES) return VW_ERR_PATH_INVALID;
    if (path[0] != '/') return VW_ERR_PATH_INVALID;

    for (uint32_t i = 0; i < len; i++) {
        if (path[i] == '\0') return VW_ERR_PATH_INVALID;
        if (path[i] == '\\') return VW_ERR_PATH_INVALID;
    }

    /* No empty components ('//') and no '..' components. */
    const char *p = path;
    while (*p) {
        if (*p == '/') {
            p++;
            if (*p == '/') return VW_ERR_PATH_INVALID; /* empty component */
            /* Check for '..' */
            if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
                return VW_ERR_PATH_INVALID;
        } else {
            p++;
        }
    }
    return VW_OK;
}

/*
 * Extract session_token from the first VW_TOKEN_BYTES of payload and validate.
 * On failure sends VW_MSG_ERROR(VW_ERR_AUTH_REQUIRED) and returns non-OK.
 * On success sets *out_user_id and zeroes the local session copy.
 *
 * SEC.07-A-2: token validated before any other payload field is parsed.
 */
static vw_err_t validate_session(vw_store_t    *store,
                                  vw_conn_t     *conn,
                                  const uint8_t *payload,
                                  uint32_t       plen,
                                  uint64_t      *out_user_id)
{
    if (plen < VW_TOKEN_BYTES) {
        (void)send_error(conn, VW_ERR_PROTO_TRUNCATED);
        return VW_ERR_PROTO_TRUNCATED;
    }

    vw_session_record_t sess;
    vw_err_t err = vw_store_session_get(store, payload, &sess);
    if (err != VW_OK) {
        secure_zero(&sess, sizeof(sess));
        (void)send_error(conn, VW_ERR_AUTH_REQUIRED);
        return VW_ERR_AUTH_REQUIRED;
    }
    *out_user_id = sess.user_id;
    secure_zero(&sess, sizeof(sess));  /* contains token — wipe after reading user_id */
    return VW_OK;
}

/* ── FILE_LIST ───────────────────────────────────────────────────────────── */

static vw_err_t handle_file_list(vw_store_t      *store,
                                  vw_file_store_t *fs,
                                  vw_conn_t       *conn,
                                  const uint8_t   *payload,
                                  uint32_t         plen)
{
    /* SEC.07-A-2: session first */
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* Decode fixed fields after token */
    if (plen < VW_TOKEN_BYTES + 2u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint8_t recursive       = payload[VW_TOKEN_BYTES];
    /* include_deleted at offset VW_TOKEN_BYTES+1 — Phase 2: always shallow */
    (void)payload[VW_TOKEN_BYTES + 1]; /* include_deleted: not used in Phase 2 */

    /* Read the path string */
    const uint8_t *var = payload + VW_TOKEN_BYTES + 2u;
    uint32_t var_len   = plen - VW_TOKEN_BYTES - 2u;
    uint32_t off       = 0;
    const char *path   = NULL;
    uint16_t path_len  = 0;
    err = vw_proto_read_str(var, var_len, &off, &path, &path_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    /* Resolve path → parent directory file_id.
     * Empty path or "/" means root (parent_dir_id = 0). */
    uint64_t root_dir_id = 0;
    if (path_len > 0 && !(path_len == 1 && path[0] == '/')) {
        char path_buf[VW_MAX_PATH_BYTES + 1];
        if (path_len > VW_MAX_PATH_BYTES)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
        memcpy(path_buf, path, path_len);
        path_buf[path_len] = '\0';
        err = vw_path_validate(path_buf, (uint32_t)path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
        vw_file_record_t dir_rec;
        err = vw_store_file_get_by_path(fs, user_id, path_buf, &dir_rec);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
        if (dir_rec.owner_id != user_id) /* SEC.07-B-1 */
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
        root_dir_id = dir_rec.file_id;
    }

    /* BFS to collect all entries (recursive=1 walks subdirs) */
    vw_file_record_t *all      = NULL;
    uint32_t          all_len  = 0;
    uint32_t          all_cap  = 0;

    uint64_t *dir_queue = NULL;
    uint32_t  q_head = 0, q_tail = 0, q_cap = 0;

    /* Push starting directory */
    dir_queue = malloc(sizeof(uint64_t) * 16);
    if (!dir_queue) return (send_error(conn, VW_ERR_OOM), VW_OK);
    q_cap = 16;
    dir_queue[q_tail++] = root_dir_id;

    while (q_head < q_tail && all_len < 65535u) {
        uint64_t dir_id = dir_queue[q_head++];

        vw_file_record_t *entries = NULL;
        uint32_t count = 0;
        err = vw_store_file_list(fs, user_id, dir_id, &entries, &count);
        if (err != VW_OK) { free(entries); break; }

        for (uint32_t i = 0; i < count && all_len < 65535u; i++) {
            /* Grow all[] */
            if (all_len >= all_cap) {
                uint32_t new_cap = all_cap ? all_cap * 2u : 64u;
                vw_file_record_t *na = realloc(all, sizeof(*na) * new_cap);
                if (!na) { free(entries); goto done; }
                all = na; all_cap = new_cap;
            }
            all[all_len++] = entries[i];

            if (recursive && entries[i].entry_type == VW_ENTRY_DIR) {
                /* Enqueue subdirectory */
                if (q_tail >= q_cap) {
                    uint32_t new_cap = q_cap * 2u;
                    uint64_t *nq = realloc(dir_queue, sizeof(uint64_t) * new_cap);
                    if (!nq) { free(entries); goto done; }
                    dir_queue = nq; q_cap = new_cap;
                }
                dir_queue[q_tail++] = entries[i].file_id;
            }
        }
        free(entries);
    }

done:
    free(dir_queue);

    if (all_len == 65535u)
        LOG_DEBUG("FILE_LIST uid=%llu truncated at 65535 entries",
                  (unsigned long long)user_id);

    /* Encode FILE_LIST_RESP.
     * Per-entry layout: string(name) + u64 file_id + u64 size_bytes +
     *                   i64 mtime_unix + u8 entry_type + u8 perm. */
    uint32_t resp_cap = 4u + (uint32_t)all_len * (2u + 64u + 8u + 8u + 8u + 2u);
    uint8_t *resp = malloc(resp_cap);
    if (!resp) { free(all); return (send_error(conn, VW_ERR_OOM), VW_OK); }

    uint32_t roff = 0;
    vw_write_u32le(resp + roff, all_len); roff += 4;

    for (uint32_t i = 0; i < all_len; i++) {
        const vw_file_record_t *r = &all[i];
        uint16_t nlen = (uint16_t)strnlen(r->name, sizeof(r->name));
        err = vw_proto_write_str(resp, resp_cap, &roff, r->name, nlen);
        if (err != VW_OK) break;
        vw_write_u64le(resp + roff, r->file_id);    roff += 8;
        vw_write_u64le(resp + roff, r->size_bytes);  roff += 8;
        vw_write_u64le(resp + roff, (uint64_t)r->mtime_unix); roff += 8;
        resp[roff++] = r->entry_type;
        resp[roff++] = (uint8_t)VW_PERM_OWNER;
    }

    free(all);
    err = vw_proto_send(conn, VW_MSG_FILE_LIST_RESP, resp, roff);
    free(resp);

    LOG_DEBUG("FILE_LIST uid=%llu dir=%llu count=%u rc=%d",
              (unsigned long long)user_id, (unsigned long long)root_dir_id,
              all_len, (int)err);
    return err;
}

/* ── FILE_STAT ───────────────────────────────────────────────────────────── */

static vw_err_t handle_file_stat(vw_store_t      *store,
                                  vw_file_store_t *fs,
                                  vw_conn_t       *conn,
                                  const uint8_t   *payload,
                                  uint32_t         plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][file_id u64][path string if file_id==0] */
    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t file_id = vw_read_u64le(payload + VW_TOKEN_BYTES);
    vw_file_record_t rec;

    if (file_id == 0) {
        const uint8_t *var = payload + VW_TOKEN_BYTES + 8u;
        uint32_t var_len   = plen - VW_TOKEN_BYTES - 8u;
        uint32_t off = 0;
        const char *path; uint16_t path_len;
        err = vw_proto_read_str(var, var_len, &off, &path, &path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

        char path_buf[VW_MAX_PATH_BYTES + 1];
        if (path_len > VW_MAX_PATH_BYTES)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
        memcpy(path_buf, path, path_len);
        path_buf[path_len] = '\0';
        err = vw_path_validate(path_buf, (uint32_t)path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);

        err = vw_store_file_get_by_path(fs, user_id, path_buf, &rec);
    } else {
        err = vw_store_file_get_by_id(fs, file_id, &rec);
    }

    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    if (rec.owner_id != user_id) /* SEC.07-B-1 */
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    /* Encode FILE_STAT_RESP:
     * u8 entry_type + u64 file_id + u64 size_bytes + i64 mtime_unix +
     * u64 version_id + u64 owner_id + u8 perm + string path(name) */
    uint8_t resp[2 + 64 + 1 + 8 + 8 + 8 + 8 + 8 + 1];
    uint32_t roff = 0;
    resp[roff++] = rec.entry_type;
    vw_write_u64le(resp + roff, rec.file_id);             roff += 8;
    vw_write_u64le(resp + roff, rec.size_bytes);           roff += 8;
    vw_write_u64le(resp + roff, (uint64_t)rec.mtime_unix); roff += 8;
    vw_write_u64le(resp + roff, rec.current_version_id);   roff += 8;
    vw_write_u64le(resp + roff, rec.owner_id);             roff += 8;
    resp[roff++] = (uint8_t)VW_PERM_OWNER;

    uint16_t nlen = (uint16_t)strnlen(rec.name, sizeof(rec.name));
    err = vw_proto_write_str(resp, sizeof(resp), &roff, rec.name, nlen);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_OOM), VW_OK);

    err = vw_proto_send(conn, VW_MSG_FILE_STAT_RESP, resp, roff);
    LOG_DEBUG("FILE_STAT uid=%llu fid=%llu rc=%d",
              (unsigned long long)user_id, (unsigned long long)rec.file_id,
              (int)err);
    return err;
}

/* ── CHUNK_QUERY ─────────────────────────────────────────────────────────── */

static vw_err_t handle_chunk_query(vw_store_t    *store,
                                    vw_storage_t  *cs,
                                    vw_conn_t     *conn,
                                    const uint8_t *payload,
                                    uint32_t       plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][count u16][count * 32 bytes] */
    if (plen < VW_TOKEN_BYTES + 2u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint16_t count = vw_read_u16le(payload + VW_TOKEN_BYTES);
    if (count > 1024u)
        return (send_error(conn, VW_ERR_PROTO_INVALID), VW_ERR_PROTO_INVALID);

    uint32_t expected = VW_TOKEN_BYTES + 2u + (uint32_t)count * VW_HASH_BYTES;
    if (plen < expected)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    const uint8_t (*hashes)[VW_HASH_BYTES] =
        (const uint8_t (*)[VW_HASH_BYTES])(payload + VW_TOKEN_BYTES + 2u);

    uint32_t bitmask_bytes = count == 0u ? 0u : (count + 7u) / 8u;
    /* Response: [count u16][bitmask bitmask_bytes] */
    uint8_t resp[2 + 128]; /* 1024 bits = 128 bytes max */
    vw_write_u16le(resp, count);
    uint32_t roff = 2;
    if (count > 0) {
        memset(resp + roff, 0, bitmask_bytes);
        err = vw_storage_chunk_query(cs, hashes, count, resp + roff);
        if (err != VW_OK)
            return (send_error(conn, err), VW_OK);
        roff += bitmask_bytes;
    }

    err = vw_proto_send(conn, VW_MSG_CHUNK_QUERY_RESP, resp, roff);
    LOG_DEBUG("CHUNK_QUERY uid=%llu count=%u rc=%d",
              (unsigned long long)user_id, (unsigned)count, (int)err);
    return err;
}

/* ── CHUNK_UPLOAD ────────────────────────────────────────────────────────── */

static vw_err_t handle_chunk_upload(vw_store_t    *store,
                                     vw_storage_t  *cs,
                                     vw_conn_t     *conn,
                                     const uint8_t *payload,
                                     uint32_t       plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][chunk_hash 32][chunk_len u32][chunk_data chunk_len] */
    if (plen < VW_TOKEN_BYTES + VW_HASH_BYTES + 4u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    const uint8_t *hash     = payload + VW_TOKEN_BYTES;
    uint32_t       data_len = vw_read_u32le(payload + VW_TOKEN_BYTES + VW_HASH_BYTES);

    if (data_len > VW_CHUNK_SIZE_DEFAULT)
        return (send_error(conn, VW_ERR_PROTO_INVALID), VW_ERR_PROTO_INVALID);

    uint32_t expected = VW_TOKEN_BYTES + VW_HASH_BYTES + 4u + data_len;
    if (plen < expected)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    const uint8_t *data = payload + VW_TOKEN_BYTES + VW_HASH_BYTES + 4u;

    /* Quota enforcement is done atomically inside vw_storage_chunk_put under the
     * write lock, preventing TOCTOU double-charging on concurrent uploads. */
    err = vw_storage_chunk_put(cs, hash, data, data_len, user_id);
    if (err == VW_ERR_QUOTA_EXCEEDED) {
        send_error(conn, VW_ERR_QUOTA_EXCEEDED);
        return VW_OK;
    }

    /* CHUNK_UPLOAD_ACK: [chunk_hash 32][error_code u32] */
    uint8_t ack[VW_HASH_BYTES + 4u];
    memcpy(ack, hash, VW_HASH_BYTES);
    vw_write_u32le(ack + VW_HASH_BYTES, (uint32_t)(err == VW_OK ? 0 : err));
    vw_err_t send_err = vw_proto_send(conn, VW_MSG_CHUNK_UPLOAD_ACK,
                                       ack, sizeof(ack));

    LOG_DEBUG("CHUNK_UPLOAD uid=%llu len=%u rc=%d",
              (unsigned long long)user_id, (unsigned)data_len, (int)err);
    return send_err;
}

/* ── CHUNK_DOWNLOAD ──────────────────────────────────────────────────────── */

/*
 * BFS ownership check: returns VW_OK if user owns any current-version file
 * that references hash.
 *
 * SEC.07-A-1: both "chunk absent" and "chunk not owned" map to VW_ERR_NOT_FOUND
 * so the caller cannot distinguish ownership from existence.
 */
static vw_err_t check_chunk_ownership(vw_file_store_t *fs,
                                       uint64_t         user_id,
                                       const uint8_t    hash[VW_HASH_BYTES])
{
    /* BFS over the user's virtual file tree via parent_dir_id expansion. */
    uint64_t *dir_q = malloc(sizeof(uint64_t) * 64u);
    if (!dir_q) return VW_ERR_OOM;
    uint32_t q_head = 0, q_tail = 0, q_cap = 64u;
    dir_q[q_tail++] = 0; /* root */

    vw_err_t result = VW_ERR_NOT_FOUND;

    while (q_head < q_tail && result != VW_OK) {
        uint64_t dir_id = dir_q[q_head++];

        vw_file_record_t *entries = NULL;
        uint32_t count = 0;
        if (vw_store_file_list(fs, user_id, dir_id, &entries, &count) != VW_OK)
            continue;

        for (uint32_t i = 0; i < count && result != VW_OK; i++) {
            if (entries[i].entry_type == VW_ENTRY_DIR) {
                /* Enqueue subdirectory for BFS expansion. */
                if (q_tail >= q_cap) {
                    uint32_t nc = q_cap * 2u;
                    uint64_t *nq = realloc(dir_q, sizeof(uint64_t) * nc);
                    if (!nq) { free(entries); goto done; }
                    dir_q = nq; q_cap = nc;
                }
                dir_q[q_tail++] = entries[i].file_id;
            } else {
                if (entries[i].current_version_id == 0) continue;
                vw_version_record_t ver;
                if (vw_store_version_get(fs, entries[i].current_version_id,
                                         &ver) != VW_OK) continue;
                uint8_t *hashes = NULL;
                if (vw_store_version_get_chunks(fs, &ver, &hashes) != VW_OK)
                    continue;
                for (uint32_t c = 0; c < ver.chunk_count; c++) {
                    if (memcmp(hashes + (size_t)c * VW_HASH_BYTES,
                               hash, VW_HASH_BYTES) == 0) {
                        result = VW_OK;
                        break;
                    }
                }
                free(hashes);
            }
        }
        free(entries);
    }

done:
    free(dir_q);
    return result;
    /* TODO(Phase 4): replace BFS with a chunk→version reverse index. */
}

static vw_err_t handle_chunk_download(vw_store_t      *store,
                                       vw_file_store_t *fs,
                                       vw_storage_t    *cs,
                                       vw_conn_t       *conn,
                                       const uint8_t   *payload,
                                       uint32_t         plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][chunk_hash 32] */
    if (plen < VW_TOKEN_BYTES + VW_HASH_BYTES)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    const uint8_t *hash = payload + VW_TOKEN_BYTES;

    /* SEC.07-A-1: authorization check before chunk retrieval.
     * Returns VW_ERR_NOT_FOUND for both absent and non-owned chunks. */
    err = check_chunk_ownership(fs, user_id, hash);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    uint8_t *data = NULL;
    uint32_t data_len = 0;
    err = vw_storage_chunk_get(cs, hash, &data, &data_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    /* CHUNK_DATA: [chunk_hash 32][chunk_len u32][data chunk_len] */
    uint32_t resp_size = VW_HASH_BYTES + 4u + data_len;
    uint8_t *resp = malloc(resp_size);
    if (!resp) {
        free(data);
        return (send_error(conn, VW_ERR_OOM), VW_OK);
    }
    memcpy(resp, hash, VW_HASH_BYTES);
    vw_write_u32le(resp + VW_HASH_BYTES, data_len);
    memcpy(resp + VW_HASH_BYTES + 4u, data, data_len);
    free(data);

    err = vw_proto_send(conn, VW_MSG_CHUNK_DATA, resp, resp_size);
    free(resp);

    LOG_DEBUG("CHUNK_DOWNLOAD uid=%llu len=%u rc=%d",
              (unsigned long long)user_id, (unsigned)data_len, (int)err);
    return err;
}

/* ── FILE_COMMIT ─────────────────────────────────────────────────────────── */

static vw_err_t handle_file_commit(vw_store_t      *store,
                                    vw_file_store_t *fs,
                                    vw_storage_t    *cs,
                                    vw_conn_t       *conn,
                                    const uint8_t   *payload,
                                    uint32_t         plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][file_id u64][logical_size u64][chunk_count u32]
     * [path string][chunk_count * 32 bytes] */
    uint32_t fixed = VW_TOKEN_BYTES + 8u + 8u + 4u;
    if (plen < fixed)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t file_id      = vw_read_u64le(payload + VW_TOKEN_BYTES);
    uint64_t logical_size = vw_read_u64le(payload + VW_TOKEN_BYTES + 8u);
    uint32_t chunk_count  = vw_read_u32le(payload + VW_TOKEN_BYTES + 16u);

    if (chunk_count > 65535u)
        return (send_error(conn, VW_ERR_PROTO_INVALID), VW_ERR_PROTO_INVALID);

    const uint8_t *var = payload + fixed;
    uint32_t var_len   = plen - fixed;
    uint32_t off = 0;
    const char *path; uint16_t path_len;
    err = vw_proto_read_str(var, var_len, &off, &path, &path_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    char path_buf[VW_MAX_PATH_BYTES + 1];
    if (path_len > VW_MAX_PATH_BYTES)
        return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
    memcpy(path_buf, path, path_len);
    path_buf[path_len] = '\0';

    /* Allow empty/root path only when file_id != 0 (update by id). */
    if (path_len > 0) {
        err = vw_path_validate(path_buf, (uint32_t)path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);
    }

    /* Chunk hashes follow the path string */
    uint32_t hash_bytes = chunk_count * VW_HASH_BYTES;
    if (var_len - off < hash_bytes)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    const uint8_t *chunk_hashes = var + off;

    /* Verify all chunks exist in chunk store. */
    if (chunk_count > 0) {
        uint32_t bitmask_bytes = (chunk_count + 7u) / 8u;
        uint8_t *mask = calloc(1, bitmask_bytes);
        if (!mask) return (send_error(conn, VW_ERR_OOM), VW_OK);
        err = vw_storage_chunk_query(cs,
            (const uint8_t (*)[VW_HASH_BYTES])chunk_hashes,
            (uint16_t)chunk_count, mask);
        int all_present = (err == VW_OK);
        if (all_present) {
            /* Check every bit is set. */
            for (uint32_t b = 0; b < chunk_count && all_present; b++) {
                uint8_t byte = mask[b / 8u];
                uint8_t bit  = (uint8_t)(1u << (7u - (b % 8u))); /* big-endian bit */
                if (!(byte & bit)) all_present = 0;
            }
        }
        free(mask);
        if (!all_present)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    }

    /* Resolve or create the file record. */
    vw_file_record_t file_rec;
    int is_new = 0;

    if (file_id != 0) {
        err = vw_store_file_get_by_id(fs, file_id, &file_rec);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
        if (file_rec.owner_id != user_id) /* SEC.07-B-1 */
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    } else if (path_len > 0) {
        err = vw_store_file_get_by_path(fs, user_id, path_buf, &file_rec);
        if (err == VW_OK && file_rec.owner_id == user_id) {
            file_id = file_rec.file_id;
        } else {
            /* Compute parent directory and leaf name. */
            uint64_t parent_dir_id = 0;
            const char *slash = strrchr(path_buf, '/');
            const char *leaf  = slash ? slash + 1 : path_buf;

            if (slash && slash != path_buf) {
                /* Resolve the parent directory path. */
                char parent_buf[VW_MAX_PATH_BYTES + 1];
                size_t parent_len = (size_t)(slash - path_buf);
                memcpy(parent_buf, path_buf, parent_len);
                parent_buf[parent_len] = '\0';

                vw_file_record_t parent_rec;
                err = vw_store_file_get_by_path(fs, user_id, parent_buf,
                                                 &parent_rec);
                if (err != VW_OK || parent_rec.owner_id != user_id)
                    return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
                parent_dir_id = parent_rec.file_id;
            }

            memset(&file_rec, 0, sizeof(file_rec));
            file_rec.owner_id      = user_id;
            file_rec.parent_dir_id = parent_dir_id;
            file_rec.entry_type    = VW_ENTRY_FILE;
            strncpy(file_rec.name, leaf, sizeof(file_rec.name) - 1u);
            is_new = 1;
        }
    } else {
        return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);
    }

    /* Increment ref-count for every chunk (new version now references them).
     * chunk_query above confirmed all are present; addref cannot return NOT_FOUND
     * unless a concurrent GC ran between query and here (extremely unlikely). */
    for (uint32_t c = 0; c < chunk_count; c++) {
        const uint8_t *h = chunk_hashes + (size_t)c * VW_HASH_BYTES;
        err = vw_storage_chunk_addref(cs, h);
        if (err != VW_OK) {
            /* Undo: decref the chunks we already incremented. */
            for (uint32_t r = 0; r < c; r++)
                (void)vw_storage_chunk_decref(cs, chunk_hashes + (size_t)r * VW_HASH_BYTES);
            return (send_error(conn, err), VW_OK);
        }
    }

    /* Create the version record. */
    vw_version_record_t ver_rec;
    memset(&ver_rec, 0, sizeof(ver_rec));
    ver_rec.file_id     = is_new ? 0 : file_id; /* filled in after file_create */
    ver_rec.created_at  = (uint64_t)time(NULL);
    ver_rec.size_bytes  = logical_size;
    ver_rec.chunk_count = chunk_count;

    uint64_t new_version_id = 0;
    uint64_t new_file_id    = file_id;

    if (is_new) {
        /* Create file first so we have a file_id for the version. */
        err = vw_store_file_create(fs, &file_rec, &new_file_id);
        if (err != VW_OK) {
            for (uint32_t c = 0; c < chunk_count; c++)
                (void)vw_storage_chunk_decref(cs, chunk_hashes + (size_t)c * VW_HASH_BYTES);
            return (send_error(conn, err), VW_OK);
        }
        ver_rec.file_id = new_file_id;
    }

    err = vw_store_version_create(fs, &ver_rec, chunk_hashes, &new_version_id);
    if (err != VW_OK) {
        for (uint32_t c = 0; c < chunk_count; c++)
            (void)vw_storage_chunk_decref(cs, chunk_hashes + (size_t)c * VW_HASH_BYTES);
        return (send_error(conn, err), VW_OK);
    }

    /* Update file record: current_version_id, size, mtime. */
    vw_file_record_t updated;
    if (is_new) {
        err = vw_store_file_get_by_id(fs, new_file_id, &updated);
        if (err != VW_OK) return (send_error(conn, err), VW_OK);
    } else {
        updated = file_rec;
    }
    updated.current_version_id = new_version_id;
    updated.size_bytes          = logical_size;
    updated.mtime_unix          = (int64_t)ver_rec.created_at;
    if (vw_store_file_update(fs, new_file_id, &updated) != VW_OK) {
        /* The new version was committed but the file record meta-update failed.
         * Log a warning and let GC clean up; do not surface this to the client
         * because the version data is durable. Atomic compound journalling is a
         * Phase 5 concern (TASK-024). */
        LOG_WARN("FILE_COMMIT: vw_store_file_update failed for fid=%llu; "
                 "version is durable, file record will be stale until GC",
                 (unsigned long long)new_file_id);
    }

    /* FILE_COMMIT_ACK: [file_id u64][version_id u64][error_code u32] */
    uint8_t ack[8 + 8 + 4];
    vw_write_u64le(ack,      new_file_id);
    vw_write_u64le(ack + 8,  new_version_id);
    vw_write_u32le(ack + 16, 0u);
    err = vw_proto_send(conn, VW_MSG_FILE_COMMIT_ACK, ack, sizeof(ack));

    LOG_DEBUG("FILE_COMMIT uid=%llu path=%s fid=%llu vid=%llu rc=%d",
              (unsigned long long)user_id, path_len > 0 ? path_buf : "(by id)",
              (unsigned long long)new_file_id, (unsigned long long)new_version_id,
              (int)err);
    return err;
}

/* ── FILE_DELETE ─────────────────────────────────────────────────────────── */

static vw_err_t handle_file_delete(vw_store_t      *store,
                                    vw_file_store_t *fs,
                                    vw_conn_t       *conn,
                                    const uint8_t   *payload,
                                    uint32_t         plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][file_id u64][path string if file_id==0] */
    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t file_id = vw_read_u64le(payload + VW_TOKEN_BYTES);
    vw_file_record_t rec;

    if (file_id == 0) {
        const uint8_t *var = payload + VW_TOKEN_BYTES + 8u;
        uint32_t var_len   = plen - VW_TOKEN_BYTES - 8u;
        uint32_t off = 0;
        const char *path; uint16_t path_len;
        err = vw_proto_read_str(var, var_len, &off, &path, &path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

        char path_buf[VW_MAX_PATH_BYTES + 1];
        if (path_len > VW_MAX_PATH_BYTES)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
        memcpy(path_buf, path, path_len);
        path_buf[path_len] = '\0';
        err = vw_path_validate(path_buf, (uint32_t)path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);
        err = vw_store_file_get_by_path(fs, user_id, path_buf, &rec);
    } else {
        err = vw_store_file_get_by_id(fs, file_id, &rec);
    }

    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    if (rec.owner_id != user_id) /* SEC.07-B-1 */
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    /* For directories, reject if children exist. */
    if (rec.entry_type == VW_ENTRY_DIR) {
        vw_file_record_t *children = NULL;
        uint32_t child_count = 0;
        err = vw_store_file_list(fs, user_id, rec.file_id,
                                  &children, &child_count);
        free(children);
        if (err == VW_OK && child_count > 0u)
            return (send_error(conn, VW_ERR_DIR_NOT_EMPTY), VW_OK);
    }

    err = vw_store_file_soft_delete(fs, rec.file_id);

    /* FILE_DELETE_ACK: [error_code u32] */
    uint8_t ack[4];
    vw_write_u32le(ack, (uint32_t)(err == VW_OK ? 0u : (uint32_t)err));
    vw_err_t send_err = vw_proto_send(conn, VW_MSG_FILE_DELETE_ACK,
                                       ack, sizeof(ack));

    LOG_DEBUG("FILE_DELETE uid=%llu fid=%llu rc=%d",
              (unsigned long long)user_id, (unsigned long long)rec.file_id,
              (int)err);
    return send_err;
}

/* ── VERSION_LIST ────────────────────────────────────────────────────────── */

static vw_err_t handle_version_list(vw_store_t      *store,
                                     vw_file_store_t *fs,
                                     vw_conn_t       *conn,
                                     const uint8_t   *payload,
                                     uint32_t         plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][file_id u64][offset u32][limit u32] */
    if (plen < VW_TOKEN_BYTES + 8u + 4u + 4u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t file_id = vw_read_u64le(payload + VW_TOKEN_BYTES);
    uint32_t offset  = vw_read_u32le(payload + VW_TOKEN_BYTES + 8u);
    uint32_t limit   = vw_read_u32le(payload + VW_TOKEN_BYTES + 12u);
    if (limit == 0u) limit = 50u;

    vw_file_record_t file_rec;
    err = vw_store_file_get_by_id(fs, file_id, &file_rec);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    if (file_rec.owner_id != user_id) /* SEC.07-B-1 */
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    vw_version_record_t *versions = NULL;
    uint32_t total = 0;
    err = vw_store_version_list(fs, file_id, &versions, &total);
    if (err != VW_OK)
        return (send_error(conn, err), VW_OK);

    /* Apply pagination. */
    uint32_t start = offset < total ? offset : total;
    uint32_t count = total - start;
    if (count > limit) count = limit;

    /* VERSION_LIST_RESP: [count u32][total u32][count * entry]
     * Per-entry: {version_id u64, created_at i64, size_bytes u64, creator_user_id u64} */
    uint32_t resp_size = 4u + 4u + count * (8u + 8u + 8u + 8u);
    uint8_t *resp = malloc(resp_size);
    if (!resp) { free(versions); return (send_error(conn, VW_ERR_OOM), VW_OK); }

    uint32_t roff = 0;
    vw_write_u32le(resp + roff, count); roff += 4;
    vw_write_u32le(resp + roff, total); roff += 4;
    for (uint32_t i = 0; i < count; i++) {
        const vw_version_record_t *v = &versions[start + i];
        vw_write_u64le(resp + roff, v->version_id);  roff += 8;
        vw_write_u64le(resp + roff, v->created_at);  roff += 8;
        vw_write_u64le(resp + roff, v->size_bytes);  roff += 8;
        vw_write_u64le(resp + roff, user_id);        roff += 8; /* creator=owner Phase 2 */
    }
    free(versions);

    err = vw_proto_send(conn, VW_MSG_VERSION_LIST_RESP, resp, roff);
    free(resp);
    LOG_DEBUG("VERSION_LIST uid=%llu fid=%llu count=%u rc=%d",
              (unsigned long long)user_id, (unsigned long long)file_id,
              count, (int)err);
    return err;
}

/* ── VERSION_RESTORE ─────────────────────────────────────────────────────── */

static vw_err_t handle_version_restore(vw_store_t      *store,
                                        vw_file_store_t *fs,
                                        vw_storage_t    *cs,
                                        vw_conn_t       *conn,
                                        const uint8_t   *payload,
                                        uint32_t         plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][version_id u64][path string] */
    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t version_id = vw_read_u64le(payload + VW_TOKEN_BYTES);

    const uint8_t *var = payload + VW_TOKEN_BYTES + 8u;
    uint32_t var_len   = plen - VW_TOKEN_BYTES - 8u;
    uint32_t off = 0;
    const char *path; uint16_t path_len;
    err = vw_proto_read_str(var, var_len, &off, &path, &path_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    char path_buf[VW_MAX_PATH_BYTES + 1];
    if (path_len > VW_MAX_PATH_BYTES)
        return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
    memcpy(path_buf, path, path_len);
    path_buf[path_len] = '\0';
    err = vw_path_validate(path_buf, (uint32_t)path_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);

    /* Look up the target version. */
    vw_version_record_t src_ver;
    err = vw_store_version_get(fs, version_id, &src_ver);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);

    /* Verify the owning file belongs to this user. */
    vw_file_record_t file_rec;
    err = vw_store_file_get_by_id(fs, src_ver.file_id, &file_rec);
    if (err != VW_OK || file_rec.owner_id != user_id) /* SEC.07-B-1 */
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);

    /* Retrieve the chunk hash list from the source version. */
    uint8_t *src_hashes = NULL;
    err = vw_store_version_get_chunks(fs, &src_ver, &src_hashes);
    if (err != VW_OK)
        return (send_error(conn, err), VW_OK);

    /* Bump ref_count for all chunks (new version references them). */
    for (uint32_t c = 0; c < src_ver.chunk_count; c++) {
        err = vw_storage_chunk_addref(cs,
                                       src_hashes + (size_t)c * VW_HASH_BYTES);
        if (err != VW_OK) {
            for (uint32_t r = 0; r < c; r++)
                (void)vw_storage_chunk_decref(cs,
                    src_hashes + (size_t)r * VW_HASH_BYTES);
            free(src_hashes);
            return (send_error(conn, err), VW_OK);
        }
    }

    /* Create a new version record copying src_ver's chunk list. */
    vw_version_record_t new_ver;
    memset(&new_ver, 0, sizeof(new_ver));
    new_ver.file_id     = src_ver.file_id;
    new_ver.created_at  = (uint64_t)time(NULL);
    new_ver.size_bytes  = src_ver.size_bytes;
    new_ver.chunk_count = src_ver.chunk_count;

    uint64_t new_version_id = 0;
    err = vw_store_version_create(fs, &new_ver, src_hashes, &new_version_id);
    if (err != VW_OK) {
        /* Undo ref_count bumps before releasing src_hashes. */
        for (uint32_t c = 0; c < new_ver.chunk_count; c++)
            (void)vw_storage_chunk_decref(cs, src_hashes + (size_t)c * VW_HASH_BYTES);
        free(src_hashes);
        return (send_error(conn, err), VW_OK);
    }
    free(src_hashes);

    /* Update file record to point at new version. */
    file_rec.current_version_id = new_version_id;
    file_rec.size_bytes         = new_ver.size_bytes;
    file_rec.mtime_unix         = (int64_t)new_ver.created_at;
    (void)vw_store_file_update(fs, file_rec.file_id, &file_rec);

    /* VERSION_RESTORE_ACK: [version_id u64][error_code u32] */
    uint8_t ack[8 + 4];
    vw_write_u64le(ack,     new_version_id);
    vw_write_u32le(ack + 8, 0u);
    err = vw_proto_send(conn, VW_MSG_VERSION_RESTORE_ACK, ack, sizeof(ack));

    LOG_DEBUG("VERSION_RESTORE uid=%llu src_vid=%llu new_vid=%llu rc=%d",
              (unsigned long long)user_id, (unsigned long long)version_id,
              (unsigned long long)new_version_id, (int)err);
    return err;
}

/* ── VERSION_CHUNKS ──────────────────────────────────────────────────────── */

static vw_err_t handle_version_chunks(vw_store_t      *store,
                                       vw_file_store_t *fs,
                                       vw_conn_t       *conn,
                                       const uint8_t   *payload,
                                       uint32_t         plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* [token 32][version_id u64] */
    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t version_id = vw_read_u64le(payload + VW_TOKEN_BYTES);

    vw_version_record_t ver;
    err = vw_store_version_get(fs, version_id, &ver);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);

    /* Verify the owning file belongs to this user. SEC.07-B-2. */
    vw_file_record_t file_rec;
    err = vw_store_file_get_by_id(fs, ver.file_id, &file_rec);
    if (err != VW_OK || file_rec.owner_id != user_id)
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);

    uint8_t *hashes = NULL;
    err = vw_store_version_get_chunks(fs, &ver, &hashes);
    if (err != VW_OK)
        return (send_error(conn, err), VW_OK);

    /* VERSION_CHUNKS_RESP: [chunk_count u32][hashes chunk_count*32] */
    uint32_t resp_size = 4u + ver.chunk_count * VW_HASH_BYTES;
    uint8_t *resp = malloc(resp_size);
    if (!resp) { free(hashes); return (send_error(conn, VW_ERR_OOM), VW_OK); }
    vw_write_u32le(resp, ver.chunk_count);
    memcpy(resp + 4u, hashes, (size_t)ver.chunk_count * VW_HASH_BYTES);
    free(hashes);

    err = vw_proto_send(conn, VW_MSG_VERSION_CHUNKS_RESP, resp, resp_size);
    free(resp);

    LOG_DEBUG("VERSION_CHUNKS uid=%llu vid=%llu count=%u rc=%d",
              (unsigned long long)user_id, (unsigned long long)version_id,
              ver.chunk_count, (int)err);
    return err;
}

/* ── USER_QUOTA (admin only) ─────────────────────────────────────────────── */

/*
 * Payload: session_token[32] + target_user_id(u64 LE) + quota_bytes(u64 LE)
 * Validates admin session, then calls vw_store_quota_set.
 * Response: u32 LE error_code (0 = VW_OK).
 */
static vw_err_t handle_user_quota_set(vw_store_t *store,
                                       vw_conn_t  *conn,
                                       const uint8_t *payload,
                                       uint32_t       plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* Minimum payload: token[32] + target_user_id(8) + quota_bytes(8) = 48 */
    if (plen < VW_TOKEN_BYTES + 8u + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    /* Verify admin status. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, user_id, &urec);
    if (err != VW_OK || !urec.is_admin) {
        send_error(conn, VW_ERR_AUTH_REQUIRED);
        return VW_OK;
    }

    uint64_t target_uid  = vw_read_u64le(payload + VW_TOKEN_BYTES);
    uint64_t quota_bytes = vw_read_u64le(payload + VW_TOKEN_BYTES + 8u);

    err = vw_store_quota_set(store, target_uid, quota_bytes);

    uint8_t resp[4];
    vw_write_u32le(resp, (uint32_t)(err == VW_OK ? 0 : err));
    return vw_proto_send(conn, VW_MSG_QUOTA_ADJUST_ACK, resp, sizeof(resp));
}

/* ── USER_LIST (admin only) ─────────────────────────────────────────────── */

/*
 * Entry wire format (all LE): 220 bytes per user.
 *   user_id(8) + is_admin(1) + is_active(1) + pad(2)
 *   + username(64) + email(128) + quota_bytes(8) + used_bytes(8)
 *
 * Request:  session_token(32) + offset(u32) + limit(u32)
 * Response (USER_LIST_RESP): count(u32) + entries...
 */

#define ULIST_ENTRY_WIRE 220u

typedef struct {
    uint8_t  *buf;
    uint32_t  buf_cap;
    uint32_t  buf_len;
    uint32_t  count;
    uint32_t  offset;
    uint32_t  limit;
    uint32_t  scanned;
    vw_store_t *store;
} ulist_tls_ctx_t;

static int ulist_tls_cb(const vw_user_record_t *rec, void *ud)
{
    ulist_tls_ctx_t *c = (ulist_tls_ctx_t *)ud;

    if (rec->user_id == 0) return 0;

    /* Apply offset/limit pagination. */
    if (c->scanned < c->offset) { c->scanned++; return 0; }
    c->scanned++;
    if (c->limit && c->count >= c->limit) return 1;  /* stop */

    vw_quota_record_t qrec;
    uint64_t quota_bytes = 0, used_bytes = 0;
    if (vw_store_quota_get(c->store, rec->user_id, &qrec) == VW_OK) {
        quota_bytes = qrec.quota_bytes;
        used_bytes  = qrec.used_bytes;
    }

    /* Grow buffer if needed. */
    if (c->buf_len + ULIST_ENTRY_WIRE > c->buf_cap) {
        uint32_t new_cap = c->buf_cap ? c->buf_cap * 2 : ULIST_ENTRY_WIRE * 32;
        uint8_t *p = (uint8_t *)realloc(c->buf, new_cap);
        if (!p) return 1;
        c->buf = p; c->buf_cap = new_cap;
    }

    uint8_t *dst = c->buf + c->buf_len;
    memset(dst, 0, ULIST_ENTRY_WIRE);
    vw_write_u64le(dst + 0,   rec->user_id);
    dst[8]  = rec->is_admin;
    dst[9]  = rec->is_active;
    /* dst[10..11] = pad (zeroed) */
    memcpy(dst + 12,  rec->username, 64);
    memcpy(dst + 76,  rec->email,    128);
    vw_write_u64le(dst + 204, quota_bytes);
    vw_write_u64le(dst + 212, used_bytes);

    c->buf_len += ULIST_ENTRY_WIRE;
    c->count++;
    return 0;
}

static vw_err_t handle_user_list(vw_store_t *store, vw_conn_t *conn,
                                   const uint8_t *payload, uint32_t plen)
{
    uint64_t caller_uid;
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid);
    if (err != VW_OK) return err;

    /* Admin check. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin)
        return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);

    /* Minimum payload: token(32) + offset(4) + limit(4) = 40 */
    uint32_t offset = 0, limit = 50;
    if (plen >= VW_TOKEN_BYTES + 8u) {
        offset = vw_read_u32le(payload + VW_TOKEN_BYTES);
        limit  = vw_read_u32le(payload + VW_TOKEN_BYTES + 4u);
        if (limit == 0 || limit > 200) limit = 50;
    }

    ulist_tls_ctx_t uc;
    memset(&uc, 0, sizeof(uc));
    uc.store  = store;
    uc.offset = offset;
    uc.limit  = limit;

    (void)vw_store_user_scan(store, ulist_tls_cb, &uc);

    uint32_t resp_len = 4u + uc.buf_len;
    uint8_t *resp = (uint8_t *)malloc(resp_len);
    if (!resp) { free(uc.buf); return (send_error(conn, VW_ERR_OOM), VW_OK); }
    vw_write_u32le(resp, uc.count);
    if (uc.buf_len) memcpy(resp + 4, uc.buf, uc.buf_len);
    free(uc.buf);

    err = vw_proto_send(conn, VW_MSG_USER_LIST_RESP, resp, resp_len);
    free(resp);
    return err;
}

/* ── USER_SUSPEND (admin only) ───────────────────────────────────────────── */

/*
 * Request:  session_token(32) + target_user_id(u64) + is_active(u8)
 * Response: error_code(u32)
 *
 * is_active=0 suspends the user; is_active=1 unsuspends.
 * Cannot suspend your own account.
 */
static vw_err_t handle_user_suspend(vw_store_t *store, vw_conn_t *conn,
                                     const uint8_t *payload, uint32_t plen)
{
    uint64_t caller_uid;
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid);
    if (err != VW_OK) return err;

    /* Minimum: token(32) + target_user_id(8) + is_active(1) = 41 */
    if (plen < VW_TOKEN_BYTES + 9u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin)
        return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);

    uint64_t target_uid = vw_read_u64le(payload + VW_TOKEN_BYTES);
    uint8_t  is_active  = payload[VW_TOKEN_BYTES + 8u];

    /* Cannot suspend own account. */
    if (target_uid == caller_uid) {
        uint8_t resp[4]; vw_write_u32le(resp, (uint32_t)VW_ERR_INVALID_ARG);
        return vw_proto_send(conn, VW_MSG_USER_SUSPEND_ACK, resp, 4);
    }

    uint8_t val = is_active ? 1 : 0;
    err = vw_store_user_update_field(store, target_uid,
                                     (uint32_t)offsetof(vw_user_record_t, is_active),
                                     &val, 1);

    uint8_t resp[4];
    vw_write_u32le(resp, (uint32_t)(err == VW_OK ? 0 : err));
    return vw_proto_send(conn, VW_MSG_USER_SUSPEND_ACK, resp, 4);
}

/* ── AUDIT_QUERY (admin only) ────────────────────────────────────────────── */

/*
 * Returns recent confirmed oplog entries for the admin audit log view.
 *
 * Request:  session_token(32) + max_entries(u32)
 * Response (AUDIT_RESP): count(u32) + raw_oplog_bytes[...]
 *   Each entry in raw_oplog_bytes is the on-disk format from vw_oplog:
 *     crc32(4) + payload_len(4) + entry_id(8) + confirmed(1) + op_type(1) + op_payload[...]
 *   Total entry size = 17 + payload_len bytes.
 *
 * Returns the last min(max_entries, 256) confirmed entries from the oplog.
 * If oplog is NULL or empty, returns count=0.
 */
static vw_err_t handle_audit_query(vw_store_t *store, vw_oplog_t *oplog,
                                    vw_conn_t *conn,
                                    const uint8_t *payload, uint32_t plen)
{
    uint64_t caller_uid;
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid);
    if (err != VW_OK) return err;

    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin)
        return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);

    /* Minimum: token(32) + max_entries(4) = 36 */
    uint32_t max_entries = 100;
    if (plen >= VW_TOKEN_BYTES + 4u)
        max_entries = vw_read_u32le(payload + VW_TOKEN_BYTES);
    if (max_entries == 0 || max_entries > 256) max_entries = 100;

    if (!oplog) {
        /* Oplog not attached — return empty result. */
        uint8_t resp[4]; vw_write_u32le(resp, 0);
        return vw_proto_send(conn, VW_MSG_AUDIT_RESP, resp, 4);
    }

    /* Read the last max_entries from the oplog. */
    uint64_t last_eid = vw_oplog_last_entry_id(oplog);
    uint64_t from_eid = (last_eid >= max_entries) ? last_eid - max_entries : 0;

    uint8_t  *entries_buf       = NULL;
    uint32_t  entries_count     = 0;
    uint64_t  entries_last_eid  = 0;

    err = vw_oplog_read_range(oplog, from_eid, max_entries,
                               &entries_buf, &entries_count, &entries_last_eid);
    if (err != VW_OK) {
        free(entries_buf);
        return (send_error(conn, err), VW_OK);
    }

    /* Compute byte length of entries_buf; guard against uint32_t overflow. */
    uint32_t entries_bytes = 0;
    if (entries_buf && entries_count > 0) {
        const uint8_t *p = entries_buf;
        for (uint32_t i = 0; i < entries_count; i++) {
            uint32_t eplen = vw_read_u32le(p + 4);
            if (eplen > VW_MAX_MSG_BYTES || entries_bytes > VW_MAX_MSG_BYTES - (17u + eplen))
                break;  /* truncate — should not happen with server-generated data */
            entries_bytes += 17u + eplen;
            p             += 17u + eplen;
        }
    }

    uint32_t resp_len = 4u + entries_bytes;
    uint8_t *resp = (uint8_t *)malloc(resp_len);
    if (!resp) {
        free(entries_buf);
        return (send_error(conn, VW_ERR_OOM), VW_OK);
    }
    vw_write_u32le(resp, entries_count);
    if (entries_bytes) memcpy(resp + 4, entries_buf, entries_bytes);
    free(entries_buf);

    err = vw_proto_send(conn, VW_MSG_AUDIT_RESP, resp, resp_len);
    free(resp);
    return err;
}

/* ── CLUSTER_STATUS (admin only) ─────────────────────────────────────────── */

/*
 * Request:  session_token(32)
 * Response: role(u8) + node_count(u32 LE) +
 *           per-node: node_id(u64) + is_active(u8) + sync_watermark(u64) +
 *                     lag_entries(u64) + hostname(128 bytes, NUL-padded)
 * Per-node wire size: 8+1+8+8+128 = 153 bytes.
 *
 * SECURITY: auth_token is NEVER included in the response.
 * If cluster is NULL (single-node mode), returns role=1, node_count=0.
 */

#define CLUSTER_NODE_ENTRY_SIZE 154u  /* node_id(8)+is_active(1)+role(1)+swm(8)+lag(8)+host(128) */

static vw_err_t handle_cluster_status(vw_store_t    *store,
                                       vw_cluster_t  *cluster,
                                       vw_oplog_t    *oplog,
                                       vw_conn_t     *conn,
                                       const uint8_t *payload,
                                       uint32_t       plen)
{
    /* Validate session token (SEC.07-A-2: token first). */
    uint64_t caller_uid;
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid);
    if (err != VW_OK) return err;

    /* Admin check. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);
    }
    secure_zero(&urec, sizeof(urec));

    /* Single-node: return role=1 (primary), node_count=0. */
    if (!cluster) {
        uint8_t resp[5] = {1, 0, 0, 0, 0};  /* role=1, count=0 */
        return vw_proto_send(conn, VW_MSG_CLUSTER_STATUS_RESP, resp, sizeof(resp));
    }

    vw_node_record_t *nodes = NULL;
    uint32_t          count = 0;
    err = vw_cluster_node_list(cluster, &nodes, &count);
    if (err != VW_OK) return send_error(conn, err);

    uint64_t primary_eid = oplog ? vw_oplog_last_entry_id(oplog) : 0;

    /* Determine our role: scan for the self-record (role == 1). */
    uint8_t our_role = 0;
    uint32_t i;
    for (i = 0; i < count; i++) {
        if (nodes[i].role == 1) { our_role = 1; break; }
    }

    /* Serialize: 1 (role) + 4 (count) + count * CLUSTER_NODE_ENTRY_SIZE */
    uint32_t resp_len = 5u + count * CLUSTER_NODE_ENTRY_SIZE;
    uint8_t *resp = (uint8_t *)malloc(resp_len);
    if (!resp) { free(nodes); return send_error(conn, VW_ERR_OOM); }

    resp[0] = our_role;
    vw_write_u32le(resp + 1, count);

    uint8_t *p = resp + 5;
    for (i = 0; i < count; i++) {
        const vw_node_record_t *n = &nodes[i];
        uint64_t lag = 0;
        if (n->role == 0 && primary_eid > n->sync_watermark)
            lag = primary_eid - n->sync_watermark;

        vw_write_u64le(p,      n->node_id);  /* auth_token intentionally omitted */
        p[8]  = n->is_active;
        p[9]  = n->role;
        vw_write_u64le(p + 10, n->sync_watermark);
        vw_write_u64le(p + 18, lag);
        memcpy(p + 26, n->hostname, 128);
        p += CLUSTER_NODE_ENTRY_SIZE;
    }

    free(nodes);
    err = vw_proto_send(conn, VW_MSG_CLUSTER_STATUS_RESP, resp, resp_len);
    free(resp);
    return err;
}

/* ── INVITE_CREATE (admin only) ──────────────────────────────────────────── */

/*
 * Payload: session_token[32] + quota_bytes(u64 LE) + ttl_secs(u32 LE)
 * Validates admin session, generates an invite code, responds with
 * INVITE_CREATE_ACK: code[32].
 */
static vw_err_t handle_invite_create(vw_store_t *store,
                                      vw_invite_store_t *invite_store,
                                      vw_conn_t  *conn,
                                      const uint8_t *payload,
                                      uint32_t       plen)
{
    /* Minimum: token[32] + quota_bytes(8) + ttl_secs(4) = 44 */
    if (plen < VW_TOKEN_BYTES + 8u + 4u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id);
    if (err != VW_OK) return err;

    /* Verify admin status. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, user_id, &urec);
    if (err != VW_OK || !urec.is_admin) {
        send_error(conn, VW_ERR_AUTH_REQUIRED);
        return VW_OK;
    }

    if (!invite_store) {
        send_error(conn, VW_ERR_NOT_IMPL);
        return VW_ERR_NOT_IMPL;
    }

    uint64_t quota_bytes = vw_read_u64le(payload + VW_TOKEN_BYTES);
    uint32_t ttl_secs    = vw_read_u32le(payload + VW_TOKEN_BYTES + 8u);

    uint8_t code[32];
    err = vw_invite_create(invite_store, user_id, quota_bytes, ttl_secs, code);
    if (err != VW_OK) {
        send_error(conn, VW_ERR_IO);
        return err;
    }

    return vw_proto_send(conn, VW_MSG_INVITE_CREATE_ACK, code, sizeof(code));
}

/* ── Dispatcher ──────────────────────────────────────────────────────────── */

vw_err_t vw_server_dispatch_file_op(vw_server_ctx_t *ctx,
                                     vw_conn_t       *conn,
                                     vw_msg_type_t    type,
                                     const uint8_t   *payload,
                                     uint32_t         plen)
{
    if (!ctx || !conn || !payload) return VW_ERR_INVALID_ARG;

    vw_store_t        *store   = vw_server_ctx_store(ctx);
    vw_file_store_t   *fs      = vw_server_ctx_file_store(ctx);
    vw_storage_t      *cs      = vw_server_ctx_chunk_store(ctx);
    vw_invite_store_t *invs    = vw_server_ctx_invite_store(ctx);
    vw_oplog_t        *oplog   = vw_server_ctx_oplog(ctx);
    vw_cluster_t      *cluster = vw_server_ctx_cluster(ctx);

    /* Admin-only messages that do not require file/chunk stores. */
    switch (type) {
    case VW_MSG_INVITE_CREATE:
        return handle_invite_create(store, invs, conn, payload, plen);
    case VW_MSG_USER_LIST:
        return handle_user_list(store, conn, payload, plen);
    case VW_MSG_USER_SUSPEND:
        return handle_user_suspend(store, conn, payload, plen);
    case VW_MSG_QUOTA_ADJUST:
        return handle_user_quota_set(store, conn, payload, plen);
    case VW_MSG_AUDIT_QUERY:
        return handle_audit_query(store, oplog, conn, payload, plen);
    case VW_MSG_CLUSTER_STATUS:
        return handle_cluster_status(store, cluster, oplog, conn, payload, plen);
    default:
        break;
    }

    /* File stores must be initialised before Phase 2 ops are dispatched. */
    if (!fs || !cs) {
        (void)send_error(conn, VW_ERR_NOT_IMPL);
        return VW_ERR_NOT_IMPL;
    }

    switch (type) {
    case VW_MSG_FILE_LIST:
        return handle_file_list(store, fs, conn, payload, plen);
    case VW_MSG_FILE_STAT:
        return handle_file_stat(store, fs, conn, payload, plen);
    case VW_MSG_CHUNK_QUERY:
        return handle_chunk_query(store, cs, conn, payload, plen);
    case VW_MSG_CHUNK_UPLOAD:
        return handle_chunk_upload(store, cs, conn, payload, plen);
    case VW_MSG_CHUNK_DOWNLOAD_REQ:
        return handle_chunk_download(store, fs, cs, conn, payload, plen);
    case VW_MSG_FILE_COMMIT:
        return handle_file_commit(store, fs, cs, conn, payload, plen);
    case VW_MSG_FILE_DELETE:
        return handle_file_delete(store, fs, conn, payload, plen);
    case VW_MSG_VERSION_LIST:
        return handle_version_list(store, fs, conn, payload, plen);
    case VW_MSG_VERSION_RESTORE:
        return handle_version_restore(store, fs, cs, conn, payload, plen);
    case VW_MSG_VERSION_CHUNKS:
        return handle_version_chunks(store, fs, conn, payload, plen);
    default:
        return VW_ERR_NOT_IMPL;
    }
}
