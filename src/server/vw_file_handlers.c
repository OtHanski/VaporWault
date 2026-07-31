#include "vw_file_handlers.h"
#include "vw_cluster.h"
#include "vw_invite.h"
#include "vw_share.h"
#include "vw_vault.h"
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
    const char *end = path + len;
    while (p < end) {
        if (*p == '/') {
            p++;
            if (p >= end) break; /* trailing slash — done */
            if (*p == '/') return VW_ERR_PATH_INVALID; /* empty component */
            /* Check for '..' component bounded by '/' or end of path */
            size_t remain = (size_t)(end - p);
            if (remain >= 2 && p[0] == '.' && p[1] == '.'
                    && (remain == 2 || p[2] == '/'))
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
 * On success sets *out_user_id and *out_scope_share_id and zeroes the local
 * session copy.
 *
 * TASK-094: *out_scope_share_id is 0 for a normal session, or the share_id
 * a scoped (anonymous, LINK_ACCESS-issued) session is bound to — callers
 * that don't care about scoped sessions may pass NULL.
 *
 * SEC.07-A-2: token validated before any other payload field is parsed.
 */
static vw_err_t validate_session(vw_store_t    *store,
                                  vw_conn_t     *conn,
                                  const uint8_t *payload,
                                  uint32_t       plen,
                                  uint64_t      *out_user_id,
                                  uint64_t      *out_scope_share_id)
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
    if (out_scope_share_id) *out_scope_share_id = sess.scope_share_id;
    secure_zero(&sess, sizeof(sess));  /* contains token — wipe after reading user_id */
    return VW_OK;
}

/*
 * TASK-094: resolve the caller's effective vw_perm_t on file_rec.
 * Owner check first (unchanged §7.8.1 behavior); falls through to
 * vw_share_resolve_permission for grants (real user_id) or scoped-session
 * access (scope_share_id != 0) — see docs/PROTOCOL.md §7.5's ordered rule.
 * ss may be NULL (sharing disabled) — then only the owner check applies.
 */
static vw_perm_t effective_permission(vw_share_store_t *ss, vw_file_store_t *fs,
                                       const vw_file_record_t *file_rec,
                                       uint64_t user_id, uint64_t scope_share_id)
{
    if (user_id != 0 && file_rec->owner_id == user_id) return VW_PERM_OWNER;
    if (!ss) return VW_PERM_NONE;
    return vw_share_resolve_permission(ss, fs, file_rec->file_id, user_id, scope_share_id);
}

/*
 * Enforce `needed` against `effective`, sending the appropriate error and
 * returning 0 on failure (1 on success — caller proceeds).
 *
 * VW_ERR_NOT_FOUND when the caller has NO access at all (hides the file's
 * existence — matches this codebase's existing SEC.07-B-1 convention for
 * "not yours"). VW_ERR_PERMISSION when the caller has SOME access (e.g.
 * VIEW via a grant) but not enough for this operation — existence is
 * already visible to them via FILE_LIST/STAT, so there's nothing left to
 * hide, and PERMISSION is the honest answer.
 */
static int require_permission(vw_conn_t *conn, vw_perm_t effective, vw_perm_t needed)
{
    if (effective >= needed) return 1;
    if (effective == VW_PERM_NONE) (void)send_error(conn, VW_ERR_NOT_FOUND);
    else                           (void)send_error(conn, VW_ERR_PERMISSION);
    return 0;
}

/* ── FILE_LIST ───────────────────────────────────────────────────────────── */

static vw_err_t handle_file_list(vw_store_t       *store,
                                  vw_file_store_t  *fs,
                                  vw_share_store_t *ss,
                                  vw_conn_t        *conn,
                                  const uint8_t    *payload,
                                  uint32_t          plen)
{
    /* SEC.07-A-2: session first */
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
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

    /* TASK-106: optional trailing dir_file_id(u64) — lets an authenticated
     * grant-holder list a SHARED folder's children by file_id, which no
     * existing FILE_LIST path could reach (path lookups are namespaced by
     * the caller's own owner_id; only a scoped/anonymous session could
     * navigate a shared subtree before this, via its own fixed scope
     * target, never a caller-supplied id). Absent or 0 = today's
     * behavior unchanged; old clients never send this field. */
    uint64_t dir_file_id = 0;
    if (off + 8u <= var_len) dir_file_id = vw_read_u64le(var + off);

    int path_is_root = (path_len == 0) || (path_len == 1 && path[0] == '/');

    /* Resolve path → parent directory file_id.
     * Empty path or "/" means root (parent_dir_id = 0).
     * TASK-094: list_owner_id is the owner_id vw_store_file_list must filter
     * by — this codebase's path/listing namespaces are per-owner, so it is
     * NOT always user_id: a scoped session's root resolves to someone
     * else's item, and every descendant in that subtree is owned by that
     * same someone-else (ownership is per-owner-tree, unaffected by
     * sharing), never by the acting session. */
    uint64_t  root_dir_id   = 0;
    uint64_t  list_owner_id = user_id;
    uint8_t   entry_perm    = (uint8_t)VW_PERM_OWNER;
    vw_file_record_t single_item; /* used only when the scope target is a file, not a dir */
    memset(&single_item, 0, sizeof(single_item)); /* MSVC /W4: silence C4701 */
    int       single_item_only = 0;

    if (scope_share_id != 0) {
        /* TASK-094 (CQR.08 finding): a scoped session has no access to the
         * global root. parent_dir_id == 0 (empty/root path) resolves to the
         * scope's own target instead — never the server's actual root.
         * dir_file_id is rejected for a scoped session: it already has its
         * own fixed navigation root and no legitimate reason to name a
         * different file_id (TASK-106 added dir_file_id for authenticated
         * grant-holders specifically because they have no scope target to
         * fall back on — a scoped session doesn't have that gap). A
         * non-root path from a scoped session isn't supported by this
         * wire message either (recursive=1 from the scope root already
         * returns the whole subtree in one call without needing one) —
         * both rejected explicitly rather than silently misbehaving. */
        if (!path_is_root || dir_file_id != 0)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);

        vw_share_record_t share;
        int64_t now = (int64_t)time(NULL);
        if (vw_share_get_by_id(ss, scope_share_id, &share) != VW_OK ||
            share.revoked || (share.expires_at != 0 && share.expires_at <= now))
            return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);

        vw_file_record_t scope_rec;
        if (vw_store_file_get_by_id(fs, share.file_id, &scope_rec) != VW_OK)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

        entry_perm = share.permission;
        if (scope_rec.entry_type == VW_ENTRY_FILE) {
            single_item      = scope_rec;
            single_item_only = 1;
        } else {
            root_dir_id   = scope_rec.file_id;
            list_owner_id = scope_rec.owner_id;
        }
    } else if (dir_file_id != 0) {
        /* TASK-106: list a folder the caller doesn't own but has a grant
         * on, by file_id — the sync engine's shared-folder support needs
         * this since path-based FILE_LIST can never resolve into someone
         * else's tree. Same permission-resolution helper FILE_COMMIT's
         * directory-target branch uses, and — as that branch does — the
         * permission check runs BEFORE the entry_type check (SEC.07
         * finding during TASK-106 review: checking entry_type first let
         * any authenticated caller learn whether an arbitrary/guessed
         * file_id exists and is a file, via VW_ERR_INVALID_ARG vs.
         * VW_ERR_NOT_FOUND, with zero permission on it — file_id is a
         * single global sequential counter, not scoped per user, so this
         * was a real enumeration oracle). Ordering matters: a caller with
         * no access at all must get the same VW_ERR_NOT_FOUND regardless
         * of whether dir_file_id names a file, a directory, or nothing. */
        vw_file_record_t dir_rec;
        if (vw_store_file_get_by_id(fs, dir_file_id, &dir_rec) != VW_OK)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
        vw_perm_t perm = effective_permission(ss, fs, &dir_rec, user_id, scope_share_id);
        if (!require_permission(conn, perm, VW_PERM_VIEW)) return VW_OK;
        if (dir_rec.entry_type != VW_ENTRY_DIR)
            return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);
        entry_perm    = (uint8_t)perm;
        root_dir_id   = dir_rec.file_id;
        list_owner_id = dir_rec.owner_id;
    } else if (!path_is_root) {
        char path_buf[VW_MAX_PATH_BYTES + 1];
        if (path_len > VW_MAX_PATH_BYTES)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
        memcpy(path_buf, path, path_len);
        path_buf[path_len] = '\0';
        err = vw_path_validate(path_buf, (uint32_t)path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_ERR_PATH_INVALID);
        /* Path lookups are namespaced by owner_id == user_id — this can
         * only ever resolve within the caller's own tree (shared items are
         * reached by file_id, via SHARE_LIST/LINK_LIST, not by path; see
         * TASK-095 for how the client maps those into its local virtual
         * path tree). No permission check needed beyond this: a non-owned
         * directory is structurally unreachable here. */
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
    uint64_t         *dir_queue = NULL;
    uint32_t          q_head = 0, q_tail = 0, q_cap = 0;

    if (single_item_only) {
        all = malloc(sizeof(*all));
        if (!all) return (send_error(conn, VW_ERR_OOM), VW_OK);
        all[0]  = single_item;
        all_len = 1;
        goto done;
    }

    /* Push starting directory */
    dir_queue = malloc(sizeof(uint64_t) * 16);
    if (!dir_queue) return (send_error(conn, VW_ERR_OOM), VW_OK);
    q_cap = 16;
    dir_queue[q_tail++] = root_dir_id;

    while (q_head < q_tail && all_len < 65535u) {
        uint64_t dir_id = dir_queue[q_head++];

        vw_file_record_t *entries = NULL;
        uint32_t count = 0;
        err = vw_store_file_list(fs, list_owner_id, dir_id, &entries, &count);
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
     *                   i64 mtime_unix + u8 entry_type + u8 perm.
     * TASK-109: followed by a trailing, parallel array of all_len * u64
     * version_id (0 for a directory) — current_version_id, the exact same
     * field FILE_STAT_RESP already reports (see handle_file_stat), so a
     * value learned from either message is now directly comparable. This
     * is purely additive the same way every other extension in this
     * protocol is: an old client's decode loop reads exactly all_len
     * fixed-size entries via its own hardcoded byte counts and then simply
     * stops, never touching the trailing block; a new client checks for
     * enough remaining bytes before reading it. No entry-length wrapper or
     * protocol version bump needed, unlike the per-entry-wrapping approach
     * TODO/TASK-109.md originally sketched — a trailing parallel array
     * sidesteps that entirely because it doesn't interleave new data
     * inside each entry's own byte range. */
    uint32_t resp_cap = 4u + (uint32_t)all_len * (2u + 64u + 8u + 8u + 8u + 2u + 8u);
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
        resp[roff++] = entry_perm;
    }

    if (err == VW_OK) {
        for (uint32_t i = 0; i < all_len; i++) {
            uint64_t vid = (all[i].entry_type == VW_ENTRY_DIR) ? 0u : all[i].current_version_id;
            vw_write_u64le(resp + roff, vid); roff += 8;
        }
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

static vw_err_t handle_file_stat(vw_store_t       *store,
                                  vw_file_store_t  *fs,
                                  vw_share_store_t *ss,
                                  vw_conn_t        *conn,
                                  const uint8_t    *payload,
                                  uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
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
    vw_perm_t perm = effective_permission(ss, fs, &rec, user_id, scope_share_id);
    if (!require_permission(conn, perm, VW_PERM_VIEW)) return VW_OK;

    /* TASK-100 (GUI encrypted-indicator support): look up the file's
     * current version's vault_id so the client can show a lock icon
     * without a separate VERSION_CHUNKS round-trip per listed file.
     * A directory (no current_version_id) or a version lookup failure
     * (shouldn't happen for a real file, but fail open to "unencrypted"
     * rather than erroring the whole FILE_STAT) both report vault_id 0. */
    uint64_t vault_id = 0;
    if (rec.entry_type != VW_ENTRY_DIR && rec.current_version_id != 0) {
        vw_version_record_t ver;
        if (vw_store_version_get(fs, rec.current_version_id, &ver) == VW_OK)
            vault_id = ver.vault_id;
    }

    /* Encode FILE_STAT_RESP:
     * u8 entry_type + u64 file_id + u64 size_bytes + i64 mtime_unix +
     * u64 version_id + u64 owner_id + u8 perm + string path(name)
     * + u64 vault_id (TASK-100; always present, 0 = unencrypted — unlike
     * FILE_COMMIT/VERSION_CHUNKS_RESP's absent-when-zero convention, this
     * response has no other optional fields after it, so there's no
     * ambiguity to resolve by omitting it; appending it unconditionally
     * keeps this encoder simpler with no behavioral difference an old
     * client would notice either way, since old clients stop reading
     * after the name string regardless). */
    uint8_t resp[2 + 64 + 1 + 8 + 8 + 8 + 8 + 8 + 1 + 8];
    uint32_t roff = 0;
    resp[roff++] = rec.entry_type;
    vw_write_u64le(resp + roff, rec.file_id);             roff += 8;
    vw_write_u64le(resp + roff, rec.size_bytes);           roff += 8;
    vw_write_u64le(resp + roff, (uint64_t)rec.mtime_unix); roff += 8;
    vw_write_u64le(resp + roff, rec.current_version_id);   roff += 8;
    vw_write_u64le(resp + roff, rec.owner_id);             roff += 8;
    resp[roff++] = (uint8_t)perm;

    uint16_t nlen = (uint16_t)strnlen(rec.name, sizeof(rec.name));
    err = vw_proto_write_str(resp, sizeof(resp), &roff, rec.name, nlen);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_OOM), VW_OK);

    vw_write_u64le(resp + roff, vault_id); roff += 8;

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
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, NULL);
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

static vw_err_t handle_chunk_upload(vw_store_t       *store,
                                     vw_storage_t     *cs,
                                     vw_share_store_t *ss,
                                     vw_conn_t        *conn,
                                     const uint8_t    *payload,
                                     uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;

    /* TASK-094 (SEC.07 finding): per-scoped-session write-count rate limit,
     * independent of the byte-quota check below. Checked before parsing
     * any further payload fields — a rejected scoped session shouldn't
     * even get partial parsing feedback. */
    if (scope_share_id != 0 && ss &&
        vw_share_scoped_write_ratelimit_check(ss, payload) != VW_OK)
        return (send_error(conn, VW_ERR_RATE_LIMITED), VW_OK);

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

    /* TASK-094: quota resolution. A scoped session's own user_id is always
     * 0 (anonymous) — charging chunk_put's quota check against 0 would
     * silently create an unlimited-by-default quota record and let an
     * anonymous public-edit-link holder upload without limit. Resolve the
     * scope's real target owner instead: for a scoped session this is
     * always known up front (the scope's own file/folder), unlike an
     * authenticated grantee's upload, whose eventual file/folder target
     * isn't known until FILE_COMMIT — that case is instead corrected after
     * the fact via vw_storage_chunk_reattribute in handle_file_commit. */
    uint64_t quota_owner_id = user_id;
    if (scope_share_id != 0 && ss) {
        vw_share_record_t share;
        if (vw_share_get_by_id(ss, scope_share_id, &share) == VW_OK)
            quota_owner_id = share.owner_id;
    }

    /* Quota enforcement is done atomically inside vw_storage_chunk_put under the
     * write lock, preventing TOCTOU double-charging on concurrent uploads. */
    err = vw_storage_chunk_put(cs, hash, data, data_len, quota_owner_id);
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
 * BFS over the tree owned by owner_id, starting at start_dir_id (0 = that
 * owner's root): returns VW_OK if any current-version file in that subtree
 * references hash.
 *
 * SEC.07-A-1: both "chunk absent" and "chunk not owned" map to VW_ERR_NOT_FOUND
 * so the caller cannot distinguish ownership from existence.
 */
static vw_err_t bfs_subtree_has_chunk(vw_file_store_t *fs,
                                       uint64_t         owner_id,
                                       uint64_t         start_dir_id,
                                       const uint8_t    hash[VW_HASH_BYTES])
{
    uint64_t *dir_q = malloc(sizeof(uint64_t) * 64u);
    if (!dir_q) return VW_ERR_OOM;
    uint32_t q_head = 0, q_tail = 0, q_cap = 64u;
    dir_q[q_tail++] = start_dir_id;

    vw_err_t result = VW_ERR_NOT_FOUND;

    while (q_head < q_tail && result != VW_OK) {
        uint64_t dir_id = dir_q[q_head++];

        vw_file_record_t *entries = NULL;
        uint32_t count = 0;
        if (vw_store_file_list(fs, owner_id, dir_id, &entries, &count) != VW_OK)
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

/*
 * TASK-094: extends the above to also cover shared access — a grantee's
 * granted subtrees, or a scoped session's single subtree — not just the
 * caller's own tree. Same O(n)-per-subtree tradeoff already acknowledged
 * above; a grant-holder with many active grants pays one BFS per grant.
 */
static vw_err_t check_chunk_access(vw_file_store_t *fs, vw_share_store_t *ss,
                                    uint64_t user_id, uint64_t scope_share_id,
                                    const uint8_t hash[VW_HASH_BYTES])
{
    if (user_id != 0 &&
        bfs_subtree_has_chunk(fs, user_id, 0, hash) == VW_OK)
        return VW_OK;

    if (!ss) return VW_ERR_NOT_FOUND;

    if (scope_share_id != 0) {
        vw_share_record_t share;
        int64_t now = (int64_t)time(NULL);
        if (vw_share_get_by_id(ss, scope_share_id, &share) == VW_OK &&
            !share.revoked && (share.expires_at == 0 || share.expires_at > now)) {
            vw_file_record_t rec;
            if (vw_store_file_get_by_id(fs, share.file_id, &rec) == VW_OK) {
                if (rec.entry_type == VW_ENTRY_FILE) {
                    if (rec.current_version_id != 0) {
                        vw_version_record_t ver;
                        if (vw_store_version_get(fs, rec.current_version_id, &ver) == VW_OK) {
                            uint8_t *hashes = NULL;
                            if (vw_store_version_get_chunks(fs, &ver, &hashes) == VW_OK) {
                                for (uint32_t c = 0; c < ver.chunk_count; c++) {
                                    if (memcmp(hashes + (size_t)c * VW_HASH_BYTES,
                                               hash, VW_HASH_BYTES) == 0) {
                                        free(hashes);
                                        return VW_OK;
                                    }
                                }
                                free(hashes);
                            }
                        }
                    }
                } else if (bfs_subtree_has_chunk(fs, rec.owner_id, rec.file_id, hash) == VW_OK) {
                    return VW_OK;
                }
            }
        }
        return VW_ERR_NOT_FOUND;
    }

    if (user_id != 0) {
        /* Scan every active grant targeting this user (share_id doubles as
         * the slot index — see vw_share.c — so this needs no separate
         * index) and BFS each one's subtree in turn. Stops at the first
         * hit. */
        vw_share_record_t rec;
        uint64_t share_id;
        for (share_id = 1; vw_share_get_by_id(ss, share_id, &rec) == VW_OK; share_id++) {
            if (rec.revoked || rec.share_type != VW_SHARE_TYPE_GRANT) continue;
            if (rec.target_user_id != user_id) continue;
            if (rec.expires_at != 0 && rec.expires_at <= (int64_t)time(NULL)) continue;

            vw_file_record_t grec;
            if (vw_store_file_get_by_id(fs, rec.file_id, &grec) != VW_OK) continue;

            if (grec.entry_type == VW_ENTRY_FILE) {
                if (grec.current_version_id == 0) continue;
                vw_version_record_t ver;
                if (vw_store_version_get(fs, grec.current_version_id, &ver) != VW_OK) continue;
                uint8_t *hashes = NULL;
                if (vw_store_version_get_chunks(fs, &ver, &hashes) != VW_OK) continue;
                int hit = 0;
                for (uint32_t c = 0; c < ver.chunk_count; c++) {
                    if (memcmp(hashes + (size_t)c * VW_HASH_BYTES, hash, VW_HASH_BYTES) == 0) {
                        hit = 1;
                        break;
                    }
                }
                free(hashes);
                if (hit) return VW_OK;
            } else if (bfs_subtree_has_chunk(fs, grec.owner_id, grec.file_id, hash) == VW_OK) {
                return VW_OK;
            }
        }
    }

    return VW_ERR_NOT_FOUND;
}

static vw_err_t handle_chunk_download(vw_store_t       *store,
                                       vw_file_store_t  *fs,
                                       vw_storage_t     *cs,
                                       vw_share_store_t *ss,
                                       vw_conn_t        *conn,
                                       const uint8_t    *payload,
                                       uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;

    /* [token 32][chunk_hash 32] */
    if (plen < VW_TOKEN_BYTES + VW_HASH_BYTES)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    const uint8_t *hash = payload + VW_TOKEN_BYTES;

    /* SEC.07-A-1: authorization check before chunk retrieval.
     * Returns VW_ERR_NOT_FOUND for both absent and non-owned chunks. */
    err = check_chunk_access(fs, ss, user_id, scope_share_id, hash);
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

static vw_err_t handle_file_commit(vw_store_t       *store,
                                    vw_file_store_t  *fs,
                                    vw_storage_t     *cs,
                                    vw_share_store_t *ss,
                                    vw_vault_store_t *vs,
                                    vw_conn_t        *conn,
                                    const uint8_t    *payload,
                                    uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;

    /* TASK-094 (SEC.07 finding): per-scoped-session write-count rate limit. */
    if (scope_share_id != 0 && ss &&
        vw_share_scoped_write_ratelimit_check(ss, payload) != VW_OK)
        return (send_error(conn, VW_ERR_RATE_LIMITED), VW_OK);

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

    /* Full absolute-path validation only applies to path-based addressing
     * (file_id == 0). For file_id != 0 targeting a directory, `path` is a
     * bare leaf name instead (TASK-104's discovery: this branch was
     * unreachable in practice before FILE_MKDIR existed to create a real
     * directory to target — validated separately below, in that branch,
     * with the bare-leaf-name rules it actually needs, not this
     * absolute-path check). For file_id != 0 targeting a file (update by
     * id), `path` is never read at all — see that branch below. */
    if (file_id == 0 && path_len > 0) {
        err = vw_path_validate(path_buf, (uint32_t)path_len);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);
    }

    /* Chunk hashes follow the path string */
    uint32_t hash_bytes = chunk_count * VW_HASH_BYTES;
    if (var_len - off < hash_bytes)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    const uint8_t *chunk_hashes = var + off;
    off += hash_bytes;

    /* TASK-098 (E2EE, docs/PROTOCOL.md §7.11.4): optional trailing fields
     * for a vault-encrypted file's version — vault_id(u64) + wrapped_dek
     * (string). Absent entirely (the payload simply ends after
     * chunk_hashes) means an unencrypted file, exactly how every
     * pre-TASK-098 client's FILE_COMMIT already looks — no version bump
     * needed in either direction: an old server ignores these trailing
     * bytes (it never reads past hash_bytes), and an old client simply
     * never sends them. Ownership/vault-existence validation happens
     * further below, once file_rec is resolved. */
    uint64_t vault_id = 0;
    const char *wrapped_dek = NULL;
    uint16_t wrapped_dek_len = 0;
    if (var_len - off >= 8u) {
        vault_id = vw_read_u64le(var + off); off += 8u;
        if (vault_id != 0) {
            err = vw_proto_read_str(var, var_len, &off, &wrapped_dek, &wrapped_dek_len);
            if (err != VW_OK)
                return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
            if (wrapped_dek_len == 0)
                return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);
        }
    }

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
        vw_file_record_t target_rec;
        err = vw_store_file_get_by_id(fs, file_id, &target_rec);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

        if (target_rec.entry_type == VW_ENTRY_DIR) {
            /* TASK-094: file_id names a FOLDER — "create a new file under
             * this folder" (needed for a grantee/scoped session to create
             * a file inside a shared folder, which they can't reach by
             * path since path lookups are namespaced by the caller's own
             * owner_id). A directory file_id was never meaningful as a
             * FILE_COMMIT target before this — old clients never sent one
             * here — so this reinterpretation doesn't collide with any
             * pre-existing valid usage. `path` is the new file's bare leaf
             * name in this case, not an absolute path. */
            vw_perm_t parent_perm = effective_permission(ss, fs, &target_rec, user_id, scope_share_id);
            if (!require_permission(conn, parent_perm, VW_PERM_EDIT)) return VW_OK;

            if (path_len == 0 || path_len >= sizeof(file_rec.name))
                return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);
            for (uint16_t i = 0; i < path_len; i++)
                if (path_buf[i] == '/' || path_buf[i] == '\0')
                    return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);

            memset(&file_rec, 0, sizeof(file_rec));
            /* Quota-resolution rule (§7.5): a new file created under a
             * shared folder is owned by the FOLDER's owner, not the
             * creating session — matches "the creator does not become the
             * owner of a file it creates inside someone else's shared
             * folder." */
            file_rec.owner_id      = target_rec.owner_id;
            file_rec.parent_dir_id = target_rec.file_id;
            file_rec.entry_type    = VW_ENTRY_FILE;
            memcpy(file_rec.name, path_buf, path_len);
            file_rec.name[path_len] = '\0';
            is_new  = 1;
            file_id = 0; /* new_file_id is assigned below on create */
        } else {
            file_rec = target_rec;
            vw_perm_t perm = effective_permission(ss, fs, &file_rec, user_id, scope_share_id);
            if (!require_permission(conn, perm, VW_PERM_EDIT)) return VW_OK;
        }
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
            {
                size_t leaf_n = strlen(leaf);
                if (leaf_n > sizeof(file_rec.name) - 1u)
                    leaf_n = sizeof(file_rec.name) - 1u;
                memcpy(file_rec.name, leaf, leaf_n);
                file_rec.name[leaf_n] = '\0';
            }
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

    /* TASK-098 (E2EE): a vault_id, if given, must reference a real vault
     * owned by this file's actual owner (file_rec.owner_id, resolved
     * above — not necessarily the acting session's user_id, mirroring the
     * quota/ownership resolution rule already applied to chunks below).
     * The server never inspects wrapped_dek's content — only its presence
     * and size ceiling (already checked above) — it is opaque bytes
     * stored alongside the version, exactly like wrapped_vk/kdf_params in
     * vw_vault.c. */
    if (vault_id != 0) {
        if (!vs) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);
        vw_vault_record_t vault_rec;
        uint8_t *unused_vk = NULL, *unused_params = NULL;
        err = vw_vault_get_by_id(vs, vault_id, &vault_rec, &unused_vk, &unused_params);
        free(unused_vk); free(unused_params);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
        if (vault_rec.owner_id != file_rec.owner_id)
            return (send_error(conn, VW_ERR_PERMISSION), VW_OK);
    }

    /* Create the version record. */
    vw_version_record_t ver_rec;
    memset(&ver_rec, 0, sizeof(ver_rec));
    ver_rec.file_id     = is_new ? 0 : file_id; /* filled in after file_create */
    ver_rec.created_at  = (uint64_t)time(NULL);
    ver_rec.size_bytes  = logical_size;
    ver_rec.chunk_count = chunk_count;
    ver_rec.vault_id    = vault_id;

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

    err = vw_store_version_create(fs, &ver_rec, chunk_hashes,
                                   (const uint8_t *)wrapped_dek, wrapped_dek_len,
                                   &new_version_id);
    if (err != VW_OK) {
        for (uint32_t c = 0; c < chunk_count; c++)
            (void)vw_storage_chunk_decref(cs, chunk_hashes + (size_t)c * VW_HASH_BYTES);
        return (send_error(conn, err), VW_OK);
    }

    /* TASK-094: quota resolution. Every chunk in chunk_hashes was verified
     * present by CHUNK_QUERY above; any of them that were freshly charged
     * to this acting session at CHUNK_UPLOAD time (rather than to a
     * pre-existing owner via dedup) must be re-attributed to the file's
     * real owner now that it's known — a no-op for chunks not currently
     * charged to user_id (dedup hits against someone else's content, or
     * (for a scoped session) chunks already charged directly to the right
     * owner by handle_chunk_upload's own resolution). Best-effort: a
     * reattribution failure (e.g. the owner's quota can't absorb it) does
     * not roll back the commit — the version is already durable, and
     * failing the whole commit over a billing-attribution nuance would be
     * a worse outcome than a transiently stale quota. */
    if (file_rec.owner_id != user_id) {
        for (uint32_t c = 0; c < chunk_count; c++) {
            (void)vw_storage_chunk_reattribute(cs, chunk_hashes + (size_t)c * VW_HASH_BYTES,
                                                user_id, file_rec.owner_id);
        }
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

static vw_err_t handle_file_delete(vw_store_t       *store,
                                    vw_file_store_t  *fs,
                                    vw_share_store_t *ss,
                                    vw_conn_t        *conn,
                                    const uint8_t    *payload,
                                    uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;

    /* TASK-094 (SEC.07 finding): per-scoped-session write-count rate limit. */
    if (scope_share_id != 0 && ss &&
        vw_share_scoped_write_ratelimit_check(ss, payload) != VW_OK)
        return (send_error(conn, VW_ERR_RATE_LIMITED), VW_OK);

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
    vw_perm_t perm = effective_permission(ss, fs, &rec, user_id, scope_share_id);
    if (!require_permission(conn, perm, VW_PERM_EDIT)) return VW_OK;

    /* For directories, reject if children exist. Children are owned by
     * rec.owner_id (ownership is per-owner-tree, unaffected by sharing —
     * see handle_file_list's list_owner_id comment), not necessarily
     * user_id. */
    if (rec.entry_type == VW_ENTRY_DIR) {
        vw_file_record_t *children = NULL;
        uint32_t child_count = 0;
        err = vw_store_file_list(fs, rec.owner_id, rec.file_id,
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

static vw_err_t handle_version_list(vw_store_t       *store,
                                     vw_file_store_t  *fs,
                                     vw_share_store_t *ss,
                                     vw_conn_t        *conn,
                                     const uint8_t    *payload,
                                     uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
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
    vw_perm_t perm = effective_permission(ss, fs, &file_rec, user_id, scope_share_id);
    if (!require_permission(conn, perm, VW_PERM_VIEW)) return VW_OK;

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

static vw_err_t handle_version_restore(vw_store_t       *store,
                                        vw_file_store_t  *fs,
                                        vw_storage_t     *cs,
                                        vw_share_store_t *ss,
                                        vw_conn_t        *conn,
                                        const uint8_t    *payload,
                                        uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
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

    /* Verify the caller has EDIT access to the owning file — restoring
     * content is a modification, not a read (§7.5's required-permission
     * table). */
    vw_file_record_t file_rec;
    err = vw_store_file_get_by_id(fs, src_ver.file_id, &file_rec);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);
    {
        vw_perm_t perm = effective_permission(ss, fs, &file_rec, user_id, scope_share_id);
        if (perm < VW_PERM_EDIT)
            return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);
    }

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

    /* Create a new version record copying src_ver's chunk list. TASK-098:
     * also carry forward vault_id/wrapped_dek unchanged if the restored
     * version was encrypted — this is re-pointing HEAD at the same
     * already-encrypted ciphertext, not a new encryption operation, so
     * there is no new DEK to generate (the "new version -> new DEK" rule,
     * §7.11.2, applies to genuinely new content, which a restore doesn't
     * produce). The wrapped_dek bytes themselves are duplicated into a
     * fresh blob region rather than referencing the old one, exactly like
     * src_hashes above — consistent with this function's existing
     * duplicate-don't-reference pattern for chunk hashes on restore. */
    uint8_t *src_wrapped_dek = NULL;
    if (src_ver.vault_id != 0) {
        err = vw_store_version_get_wrapped_dek(fs, &src_ver, &src_wrapped_dek);
        if (err != VW_OK) {
            for (uint32_t c = 0; c < src_ver.chunk_count; c++)
                (void)vw_storage_chunk_decref(cs, src_hashes + (size_t)c * VW_HASH_BYTES);
            free(src_hashes);
            return (send_error(conn, err), VW_OK);
        }
    }

    vw_version_record_t new_ver;
    memset(&new_ver, 0, sizeof(new_ver));
    new_ver.file_id     = src_ver.file_id;
    new_ver.created_at  = (uint64_t)time(NULL);
    new_ver.size_bytes  = src_ver.size_bytes;
    new_ver.chunk_count = src_ver.chunk_count;
    new_ver.vault_id    = src_ver.vault_id;

    uint64_t new_version_id = 0;
    err = vw_store_version_create(fs, &new_ver, src_hashes,
                                   src_wrapped_dek, src_ver.wrapped_dek_len,
                                   &new_version_id);
    free(src_wrapped_dek);
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

static vw_err_t handle_version_chunks(vw_store_t       *store,
                                       vw_file_store_t  *fs,
                                       vw_share_store_t *ss,
                                       vw_conn_t        *conn,
                                       const uint8_t    *payload,
                                       uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;

    /* [token 32][version_id u64] */
    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t version_id = vw_read_u64le(payload + VW_TOKEN_BYTES);

    vw_version_record_t ver;
    err = vw_store_version_get(fs, version_id, &ver);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);

    /* Verify the caller has VIEW+ access to the owning file. SEC.07-B-2. */
    vw_file_record_t file_rec;
    err = vw_store_file_get_by_id(fs, ver.file_id, &file_rec);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);
    if (effective_permission(ss, fs, &file_rec, user_id, scope_share_id) < VW_PERM_VIEW)
        return (send_error(conn, VW_ERR_VERSION_NOT_FOUND), VW_OK);

    uint8_t *hashes = NULL;
    err = vw_store_version_get_chunks(fs, &ver, &hashes);
    if (err != VW_OK)
        return (send_error(conn, err), VW_OK);

    /* TASK-099 (E2EE): surface the version's vault_id/wrapped_dek so a
     * downloading client knows whether and how to decrypt the chunks it is
     * about to fetch. This was deliberately deferred by TASK-098 until a
     * real consumer existed; the client-side vault module is that consumer.
     * Optional trailing fields, absent when vault_id == 0 (unencrypted) —
     * old clients never read past the hash array, so this is purely
     * additive and requires no protocol version bump.
     *
     * VERSION_CHUNKS_RESP: [chunk_count u32][hashes chunk_count*32]
     *                      [vault_id u64][wrapped_dek string] (only if vault_id != 0)
     */
    uint8_t *wrapped_dek = NULL;
    if (ver.vault_id != 0) {
        err = vw_store_version_get_wrapped_dek(fs, &ver, &wrapped_dek);
        if (err != VW_OK) { free(hashes); return (send_error(conn, err), VW_OK); }
    }

    uint32_t resp_size = 4u + ver.chunk_count * VW_HASH_BYTES;
    if (ver.vault_id != 0)
        resp_size += 8u + 2u + ver.wrapped_dek_len;
    uint8_t *resp = malloc(resp_size);
    if (!resp) { free(hashes); free(wrapped_dek); return (send_error(conn, VW_ERR_OOM), VW_OK); }
    uint32_t off = 0;
    vw_write_u32le(resp + off, ver.chunk_count); off += 4u;
    memcpy(resp + off, hashes, (size_t)ver.chunk_count * VW_HASH_BYTES);
    off += ver.chunk_count * VW_HASH_BYTES;
    free(hashes);
    if (ver.vault_id != 0) {
        vw_write_u64le(resp + off, ver.vault_id); off += 8u;
        vw_write_u16le(resp + off, (uint16_t)ver.wrapped_dek_len); off += 2u;
        memcpy(resp + off, wrapped_dek, ver.wrapped_dek_len); off += ver.wrapped_dek_len;
        free(wrapped_dek);
    }

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
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, NULL);
    if (err != VW_OK) return err;

    /* Minimum payload: token[32] + target_user_id(8) + quota_bytes(8) = 48 */
    if (plen < VW_TOKEN_BYTES + 8u + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    /* Verify admin status. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, user_id, &urec);
    if (err != VW_OK || !urec.is_admin) {
        secure_zero(&urec, sizeof(urec));
        send_error(conn, VW_ERR_AUTH_REQUIRED);
        return VW_OK;
    }
    /* TASK-092: authenticated admin, but does this one have quota-management
     * capability specifically? Distinct error code from the "not an admin at
     * all" case above — VW_ERR_PERMISSION, not VW_ERR_AUTH_REQUIRED. */
    if (!vw_admin_has_cap(&urec, VW_CAP_QUOTA_MGMT)) {
        secure_zero(&urec, sizeof(urec));
        send_error(conn, VW_ERR_PERMISSION);
        return VW_OK;
    }
    secure_zero(&urec, sizeof(urec));

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
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid, NULL);
    if (err != VW_OK) return err;

    /* Admin check. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);
    }
    /* TASK-092: user listing is user-management territory. */
    if (!vw_admin_has_cap(&urec, VW_CAP_USER_MGMT)) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);
    }
    secure_zero(&urec, sizeof(urec));

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
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid, NULL);
    if (err != VW_OK) return err;

    /* Minimum: token(32) + target_user_id(8) + is_active(1) = 41 */
    if (plen < VW_TOKEN_BYTES + 9u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);
    }
    /* TASK-092: suspending/unsuspending a user is user-management territory. */
    if (!vw_admin_has_cap(&urec, VW_CAP_USER_MGMT)) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);
    }
    secure_zero(&urec, sizeof(urec));

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
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid, NULL);
    if (err != VW_OK) return err;

    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);
    }
    /* TASK-092: reading the oplog/audit log is its own capability — a
     * helpdesk admin managing users/quotas need not also be able to read
     * the full audit trail. */
    if (!vw_admin_has_cap(&urec, VW_CAP_AUDIT_READ)) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);
    }
    secure_zero(&urec, sizeof(urec));

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
    vw_err_t err = validate_session(store, conn, payload, plen, &caller_uid, NULL);
    if (err != VW_OK) return err;

    /* Admin check. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, caller_uid, &urec);
    if (err != VW_OK || !urec.is_admin) {
        secure_zero(&urec, sizeof(urec));
        return (send_error(conn, VW_ERR_AUTH_REQUIRED), VW_OK);
    }
    /* TASK-092: cluster visibility is its own capability. */
    if (!vw_admin_has_cap(&urec, VW_CAP_CLUSTER_MGMT)) {
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
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, NULL);
    if (err != VW_OK) return err;

    /* Verify admin status. */
    vw_user_record_t urec;
    err = vw_store_user_get_by_id(store, user_id, &urec);
    if (err != VW_OK || !urec.is_admin) {
        secure_zero(&urec, sizeof(urec));
        send_error(conn, VW_ERR_AUTH_REQUIRED);
        return VW_OK;
    }
    /* TASK-092: minting invites creates new user accounts, so it's gated by
     * the same capability as USER_LIST/USER_SUSPEND. */
    if (!vw_admin_has_cap(&urec, VW_CAP_USER_MGMT)) {
        secure_zero(&urec, sizeof(urec));
        send_error(conn, VW_ERR_PERMISSION);
        return VW_OK;
    }
    secure_zero(&urec, sizeof(urec));

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

/* ── FILE_MOVE (TASK-094 — new; docs/PROTOCOL.md §7.5) ────────────────────── */

/*
 * FILE_MOVE never had a payload defined before this task (the opcodes
 * 0x020F/0x0210 existed but no handler did) — wire format defined here:
 *
 *   Request:  session_token[32] + file_id(u64) + new_parent_dir_id(u64,
 *             0 = mover's own root) + new_name (string, empty = keep the
 *             current name — supports move-only, rename-only, or both in
 *             one call).
 *   Response: error_code(u32).
 */

/*
 * Effective permission on a directory identified by dir_id, where dir_id
 * == 0 means "the root of the tree owned by root_owner_id" — there is no
 * on-disk record for the root, and no grant can target it directly (every
 * grant/link names a real file_id), so the only way to have EDIT-
 * equivalent access to a root is to literally own it.
 */
static vw_perm_t permission_on_dir_or_root(vw_share_store_t *ss, vw_file_store_t *fs,
                                            uint64_t dir_id, uint64_t root_owner_id,
                                            uint64_t user_id, uint64_t scope_share_id)
{
    if (dir_id == 0)
        return (user_id != 0 && user_id == root_owner_id) ? VW_PERM_OWNER : VW_PERM_NONE;
    vw_file_record_t dir_rec;
    if (vw_store_file_get_by_id(fs, dir_id, &dir_rec) != VW_OK) return VW_PERM_NONE;
    return effective_permission(ss, fs, &dir_rec, user_id, scope_share_id);
}

static vw_err_t handle_file_move(vw_store_t       *store,
                                  vw_file_store_t  *fs,
                                  vw_share_store_t *ss,
                                  vw_conn_t        *conn,
                                  const uint8_t    *payload,
                                  uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;

    /* TASK-094 (SEC.07 finding): per-scoped-session write-count rate limit. */
    if (scope_share_id != 0 && ss &&
        vw_share_scoped_write_ratelimit_check(ss, payload) != VW_OK)
        return (send_error(conn, VW_ERR_RATE_LIMITED), VW_OK);

    if (plen < VW_TOKEN_BYTES + 8u + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t file_id          = vw_read_u64le(payload + VW_TOKEN_BYTES);
    uint64_t new_parent_dir_id = vw_read_u64le(payload + VW_TOKEN_BYTES + 8u);

    const uint8_t *var = payload + VW_TOKEN_BYTES + 16u;
    uint32_t var_len   = plen - VW_TOKEN_BYTES - 16u;
    uint32_t off = 0;
    const char *new_name; uint16_t new_name_len;
    err = vw_proto_read_str(var, var_len, &off, &new_name, &new_name_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    if (new_name_len >= 64u)
        return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);
    for (uint16_t i = 0; i < new_name_len; i++)
        if (new_name[i] == '/' || new_name[i] == '\0')
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);

    vw_file_record_t rec;
    err = vw_store_file_get_by_id(fs, file_id, &rec);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    vw_perm_t file_perm = effective_permission(ss, fs, &rec, user_id, scope_share_id);
    if (file_perm == VW_PERM_NONE)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    /* §7.5 "FILE_MOVE ownership and cycle rules": EDIT on both the current
     * and destination parent, AND destination_parent.owner_id ==
     * file.owner_id — prevents a grantee from moving a shared file out of
     * the owner's tree. */
    vw_perm_t src_parent_perm = permission_on_dir_or_root(ss, fs, rec.parent_dir_id,
                                                           rec.owner_id, user_id, scope_share_id);
    if (src_parent_perm < VW_PERM_EDIT)
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);

    uint64_t dest_owner_id = rec.owner_id; /* root (dir_id==0) always belongs to rec.owner_id here */
    if (new_parent_dir_id != 0) {
        vw_file_record_t dest_rec;
        err = vw_store_file_get_by_id(fs, new_parent_dir_id, &dest_rec);
        if (err != VW_OK || dest_rec.entry_type != VW_ENTRY_DIR)
            return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);
        dest_owner_id = dest_rec.owner_id;
    }
    if (dest_owner_id != rec.owner_id)
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);

    vw_perm_t dest_parent_perm = permission_on_dir_or_root(ss, fs, new_parent_dir_id,
                                                            rec.owner_id, user_id, scope_share_id);
    if (dest_parent_perm < VW_PERM_EDIT)
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);

    /* Cycle check (general correctness requirement, independent of
     * sharing): a directory can never be moved into itself or one of its
     * own descendants — walk the destination's parent_dir_id chain up to
     * the root; if `file_id` appears in it, reject. */
    if (rec.entry_type == VW_ENTRY_DIR) {
        uint64_t cur = new_parent_dir_id;
        for (uint32_t hops = 0; hops < 2048u && cur != 0; hops++) {
            if (cur == file_id)
                return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);
            vw_file_record_t anc;
            if (vw_store_file_get_by_id(fs, cur, &anc) != VW_OK) break;
            cur = anc.parent_dir_id;
        }
    }

    vw_file_record_t updated = rec;
    updated.parent_dir_id = new_parent_dir_id;
    if (new_name_len > 0) {
        memcpy(updated.name, new_name, new_name_len);
        updated.name[new_name_len] = '\0';
        memset(updated.name + new_name_len + 1, 0, sizeof(updated.name) - new_name_len - 1);
    }

    err = vw_store_file_update(fs, file_id, &updated);

    uint8_t ack[4];
    vw_write_u32le(ack, (uint32_t)(err == VW_OK ? 0u : (uint32_t)err));
    vw_err_t send_err = vw_proto_send(conn, VW_MSG_FILE_MOVE_ACK, ack, sizeof(ack));

    LOG_DEBUG("FILE_MOVE uid=%llu fid=%llu new_parent=%llu rc=%d",
              (unsigned long long)user_id, (unsigned long long)file_id,
              (unsigned long long)new_parent_dir_id, (int)err);
    return send_err;
}

/* ── FILE_MKDIR (TASK-104) ─────────────────────────────────────────────────
 * session_token[32] + new_parent_dir_id(u64, 0 = caller's own root) +
 * name(string, bare leaf — no '/'). Creates exactly one directory record;
 * does not auto-create missing ancestors ("mkdir", not "mkdir -p" — see
 * docs/PROTOCOL.md §7.2). ACK: file_id(u64) + error_code(u32). */
static vw_err_t handle_file_mkdir(vw_store_t       *store,
                                   vw_file_store_t  *fs,
                                   vw_share_store_t *ss,
                                   vw_conn_t        *conn,
                                   const uint8_t    *payload,
                                   uint32_t          plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;

    /* Same per-scoped-session write-count rate limit as every other write
     * op (§7.5) — unbounded directory creation is the same small-object
     * abuse shape the limit already bounds for FILE_COMMIT et al. */
    if (scope_share_id != 0 && ss &&
        vw_share_scoped_write_ratelimit_check(ss, payload) != VW_OK)
        return (send_error(conn, VW_ERR_RATE_LIMITED), VW_OK);

    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t new_parent_dir_id = vw_read_u64le(payload + VW_TOKEN_BYTES);

    const uint8_t *var = payload + VW_TOKEN_BYTES + 8u;
    uint32_t var_len   = plen - VW_TOKEN_BYTES - 8u;
    uint32_t off = 0;
    const char *name; uint16_t name_len;
    err = vw_proto_read_str(var, var_len, &off, &name, &name_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    if (name_len == 0 || name_len >= 64u)
        return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);
    for (uint16_t i = 0; i < name_len; i++)
        if (name[i] == '/' || name[i] == '\0')
            return (send_error(conn, VW_ERR_PATH_INVALID), VW_OK);

    uint64_t dest_owner_id;
    if (new_parent_dir_id == 0) {
        if (user_id == 0)
            return (send_error(conn, VW_ERR_PERMISSION), VW_OK); /* anonymous has no root */
        dest_owner_id = user_id;
    } else {
        vw_file_record_t parent_rec;
        err = vw_store_file_get_by_id(fs, new_parent_dir_id, &parent_rec);
        if (err != VW_OK)
            return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
        if (parent_rec.entry_type != VW_ENTRY_DIR)
            return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);
        dest_owner_id = parent_rec.owner_id;
    }

    vw_perm_t parent_perm = permission_on_dir_or_root(ss, fs, new_parent_dir_id,
                                                       dest_owner_id, user_id, scope_share_id);
    if (!require_permission(conn, parent_perm, VW_PERM_EDIT)) return VW_OK;

    vw_file_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.owner_id      = dest_owner_id;
    rec.parent_dir_id = new_parent_dir_id;
    rec.entry_type    = VW_ENTRY_DIR;
    memcpy(rec.name, name, name_len);
    rec.name[name_len] = '\0';

    uint64_t new_file_id = 0;
    err = vw_store_file_create(fs, &rec, &new_file_id);

    uint8_t ack[12];
    vw_write_u64le(ack, new_file_id);
    vw_write_u32le(ack + 8u, (uint32_t)(err == VW_OK ? 0u : (uint32_t)err));
    vw_err_t send_err = vw_proto_send(conn, VW_MSG_FILE_MKDIR_ACK, ack, sizeof(ack));

    LOG_DEBUG("FILE_MKDIR uid=%llu parent=%llu name=%s rc=%d",
              (unsigned long long)user_id, (unsigned long long)new_parent_dir_id,
              rec.name, (int)err);
    return send_err;
}

/* ── Sharing (TASK-094; docs/PROTOCOL.md §7.5) ────────────────────────────── */

/*
 * SHARE_GRANT/SHARE_REVOKE/LINK_CREATE/LINK_REVOKE all additionally
 * require session.user_id != 0 (SEC.07 finding) — a scoped (anonymous)
 * session must never be able to mint an independent grant/link, or one
 * that would survive revocation of the link they used to get in. Checked
 * before any other handler logic, per the spec's explicit ordering.
 */
static int reject_if_scoped(vw_conn_t *conn, uint64_t scope_share_id)
{
    if (scope_share_id == 0) return 0;
    (void)send_error(conn, VW_ERR_PERMISSION);
    return 1;
}

/* SHARE_GRANT: session_token[32] + file_id(u64) + target_username(string)
 * + permission(u8) + expires_at(i64). ACK: error_code(u32) + share_id(u64). */
static vw_err_t handle_share_grant(vw_store_t *store, vw_file_store_t *fs,
                                    vw_share_store_t *ss, vw_conn_t *conn,
                                    const uint8_t *payload, uint32_t plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;
    if (reject_if_scoped(conn, scope_share_id)) return VW_OK;
    if (!ss) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    if (plen < VW_TOKEN_BYTES + 8u + 2u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t file_id = vw_read_u64le(payload + VW_TOKEN_BYTES);
    const uint8_t *var = payload + VW_TOKEN_BYTES + 8u;
    uint32_t var_len   = plen - VW_TOKEN_BYTES - 8u;
    uint32_t off = 0;
    const char *tgt_name; uint16_t tgt_name_len;
    err = vw_proto_read_str(var, var_len, &off, &tgt_name, &tgt_name_len);
    if (err != VW_OK || tgt_name_len == 0 || tgt_name_len > VW_MAX_USERNAME_BYTES ||
        off + 1u + 8u > var_len)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint8_t  permission = var[off]; off += 1u;
    int64_t  expires_at = (int64_t)vw_read_u64le(var + off);

    if (permission != (uint8_t)VW_PERM_VIEW && permission != (uint8_t)VW_PERM_EDIT)
        return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);

    vw_file_record_t file_rec;
    if (vw_store_file_get_by_id(fs, file_id, &file_rec) != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    /* A user can only grant up to their own effective permission (§7.5). */
    vw_perm_t granter_perm = effective_permission(ss, fs, &file_rec, user_id, 0);
    if (granter_perm == VW_PERM_NONE)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    if ((vw_perm_t)permission > granter_perm)
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);

    char uname[VW_MAX_USERNAME_BYTES + 1];
    memcpy(uname, tgt_name, tgt_name_len);
    uname[tgt_name_len] = '\0';
    vw_user_record_t target_user;
    err = vw_store_user_get_by_username(store, uname, &target_user);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    uint64_t share_id = 0;
    err = vw_share_grant_create(ss, file_id, file_rec.owner_id, target_user.user_id,
                                 (vw_perm_t)permission, expires_at, &share_id);
    if (err != VW_OK)
        return (send_error(conn, err), VW_OK);

    uint8_t ack[4 + 8];
    vw_write_u32le(ack, 0u);
    vw_write_u64le(ack + 4, share_id);
    return vw_proto_send(conn, VW_MSG_SHARE_GRANT_ACK, ack, sizeof(ack));
}

/* SHARE_REVOKE / LINK_REVOKE share the same wire shape:
 * session_token[32] + share_id(u64). ACK: error_code(u32). */
static vw_err_t handle_share_or_link_revoke(vw_store_t *store, vw_share_store_t *ss,
                                             vw_conn_t *conn, const uint8_t *payload,
                                             uint32_t plen, vw_msg_type_t ack_type)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;
    if (reject_if_scoped(conn, scope_share_id)) return VW_OK;
    if (!ss) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t share_id = vw_read_u64le(payload + VW_TOKEN_BYTES);
    /* vw_share_revoke itself enforces "caller must be the share's owner_id"
     * (§7.5: only the creator, not merely an EDIT grantee, may revoke). */
    err = vw_share_revoke(ss, share_id, user_id);

    uint8_t ack[4];
    vw_write_u32le(ack, (uint32_t)(err == VW_OK ? 0u : (uint32_t)err));
    return vw_proto_send(conn, ack_type, ack, sizeof(ack));
}

/*
 * SHARE_LIST: session_token[32] + mode(u8: 0=created by me, 1=granted to
 * me). SHARE_LIST_RESP: count(u32) + count * {share_id(u64), file_id(u64),
 * name(string — the shared item's leaf name; see task notes on why this
 * is a name, not a full path), share_type(u8), target_username-or-empty
 * (string), permission(u8), created_at(i64), expires_at(i64), revoked(u8)}.
 */
typedef struct {
    vw_store_t      *store;
    vw_file_store_t *fs;
    uint64_t         user_id;
    uint8_t          mode;
    uint8_t         *buf;
    uint32_t         cap, len, count;
} share_list_ctx_t;

static int share_list_cb(const vw_share_record_t *rec, void *ud)
{
    share_list_ctx_t *c = (share_list_ctx_t *)ud;
    if (rec->share_type != VW_SHARE_TYPE_GRANT) return 0;
    if (c->mode == 0 && rec->owner_id != c->user_id) return 0;
    if (c->mode == 1 && rec->target_user_id != c->user_id) return 0;

    /* "name" is the shared item's own leaf name (vw_file_record_t.name),
     * not a full path — path lookups are namespaced by owner_id (see
     * handle_file_list's list_owner_id comment), so a full path wouldn't
     * be resolvable in the viewer's own namespace anyway; this is a
     * display-only field. */
    char name[64] = {0};
    vw_file_record_t frec;
    if (vw_store_file_get_by_id(c->fs, rec->file_id, &frec) == VW_OK)
        snprintf(name, sizeof(name), "%s", frec.name);
    uint16_t name_len = (uint16_t)strnlen(name, sizeof(name) - 1);

    char tgt_name[65] = {0};
    if (rec->target_user_id != 0) {
        vw_user_record_t urec;
        if (vw_store_user_get_by_id(c->store, rec->target_user_id, &urec) == VW_OK)
            snprintf(tgt_name, sizeof(tgt_name), "%s", (const char *)urec.username);
    }
    uint16_t tgt_len = (uint16_t)strnlen(tgt_name, sizeof(tgt_name) - 1);

    uint32_t entry_cap = 8u + 8u + 2u + name_len + 1u + 2u + tgt_len + 1u + 8u + 8u + 1u;
    if (c->len + entry_cap > c->cap) {
        uint32_t new_cap = c->cap ? c->cap * 2u : 4096u;
        while (c->len + entry_cap > new_cap) new_cap *= 2u;
        uint8_t *p = (uint8_t *)realloc(c->buf, new_cap);
        if (!p) return 1;
        c->buf = p; c->cap = new_cap;
    }

    uint32_t off = c->len;
    vw_write_u64le(c->buf + off, rec->share_id); off += 8;
    vw_write_u64le(c->buf + off, rec->file_id);  off += 8;
    (void)vw_proto_write_str(c->buf, c->cap, &off, name, name_len);
    c->buf[off++] = rec->share_type;
    (void)vw_proto_write_str(c->buf, c->cap, &off, tgt_name, tgt_len);
    c->buf[off++] = rec->permission;
    vw_write_u64le(c->buf + off, (uint64_t)rec->created_at); off += 8;
    vw_write_u64le(c->buf + off, (uint64_t)rec->expires_at); off += 8;
    c->buf[off++] = rec->revoked;

    c->len = off;
    c->count++;
    return 0;
}

static vw_err_t handle_share_list(vw_store_t *store, vw_file_store_t *fs,
                                   vw_share_store_t *ss, vw_conn_t *conn,
                                   const uint8_t *payload, uint32_t plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, NULL);
    if (err != VW_OK) return err;
    if (!ss) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    if (plen < VW_TOKEN_BYTES + 1u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    uint8_t mode = payload[VW_TOKEN_BYTES];

    share_list_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.store = store; c.fs = fs; c.user_id = user_id; c.mode = mode;
    err = vw_share_scan(ss, share_list_cb, &c);
    if (err != VW_OK) { free(c.buf); return (send_error(conn, err), VW_OK); }

    uint8_t *resp = (uint8_t *)malloc(4u + c.len);
    if (!resp) { free(c.buf); return (send_error(conn, VW_ERR_OOM), VW_OK); }
    vw_write_u32le(resp, c.count);
    if (c.len) memcpy(resp + 4, c.buf, c.len);
    free(c.buf);

    err = vw_proto_send(conn, VW_MSG_SHARE_LIST_RESP, resp, 4u + c.len);
    free(resp);
    return err;
}

/* LINK_CREATE: session_token[32] + file_id(u64) + permission(u8) +
 * expires_at(i64). ACK: error_code(u32) + share_id(u64) + link_token[32]. */
static vw_err_t handle_link_create(vw_store_t *store, vw_file_store_t *fs,
                                    vw_share_store_t *ss, vw_conn_t *conn,
                                    const uint8_t *payload, uint32_t plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;
    if (reject_if_scoped(conn, scope_share_id)) return VW_OK;
    if (!ss) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    if (plen < VW_TOKEN_BYTES + 8u + 1u + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);

    uint64_t file_id     = vw_read_u64le(payload + VW_TOKEN_BYTES);
    uint8_t  permission  = payload[VW_TOKEN_BYTES + 8u];
    int64_t  expires_at  = (int64_t)vw_read_u64le(payload + VW_TOKEN_BYTES + 9u);

    if (permission != (uint8_t)VW_PERM_VIEW && permission != (uint8_t)VW_PERM_EDIT)
        return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);

    vw_file_record_t file_rec;
    if (vw_store_file_get_by_id(fs, file_id, &file_rec) != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);

    vw_perm_t granter_perm = effective_permission(ss, fs, &file_rec, user_id, 0);
    if (granter_perm == VW_PERM_NONE)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    if ((vw_perm_t)permission > granter_perm)
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);

    uint8_t  link_token[32];
    uint64_t share_id = 0;
    err = vw_share_link_create(ss, file_id, file_rec.owner_id, (vw_perm_t)permission,
                                expires_at, link_token, &share_id);
    if (err != VW_OK)
        return (send_error(conn, err), VW_OK);

    uint8_t ack[4 + 8 + 32];
    vw_write_u32le(ack, 0u);
    vw_write_u64le(ack + 4, share_id);
    memcpy(ack + 12, link_token, 32);
    vw_err_t send_err = vw_proto_send(conn, VW_MSG_LINK_CREATE_ACK, ack, sizeof(ack));
    secure_zero(ack, sizeof(ack)); /* raw link_token must not linger */
    secure_zero(link_token, sizeof(link_token));
    return send_err;
}

/* LINK_LIST: session_token[32] + file_id(u64, 0 = all my links).
 * LINK_LIST_RESP: count(u32) + count * {share_id(u64), file_id(u64),
 * name(string — leaf name, same display-only convention as
 * SHARE_LIST_RESP), permission(u8), created_at(i64), expires_at(i64),
 * revoked(u8)} — never the raw link_token. */
typedef struct {
    vw_file_store_t *fs;
    uint64_t          user_id;
    uint64_t          file_filter;
    uint8_t          *buf;
    uint32_t          cap, len, count;
} link_list_ctx_t;

static int link_list_cb(const vw_share_record_t *rec, void *ud)
{
    link_list_ctx_t *c = (link_list_ctx_t *)ud;
    if (rec->share_type != VW_SHARE_TYPE_LINK) return 0;
    if (rec->owner_id != c->user_id) return 0;
    if (c->file_filter != 0 && rec->file_id != c->file_filter) return 0;

    char name[64] = {0};
    vw_file_record_t frec;
    if (vw_store_file_get_by_id(c->fs, rec->file_id, &frec) == VW_OK)
        snprintf(name, sizeof(name), "%s", frec.name);
    uint16_t name_len = (uint16_t)strnlen(name, sizeof(name) - 1);

    uint32_t entry_cap = 8u + 8u + 2u + name_len + 1u + 8u + 8u + 1u;
    if (c->len + entry_cap > c->cap) {
        uint32_t new_cap = c->cap ? c->cap * 2u : 4096u;
        while (c->len + entry_cap > new_cap) new_cap *= 2u;
        uint8_t *p = (uint8_t *)realloc(c->buf, new_cap);
        if (!p) return 1;
        c->buf = p; c->cap = new_cap;
    }
    uint32_t off = c->len;
    vw_write_u64le(c->buf + off, rec->share_id); off += 8;
    vw_write_u64le(c->buf + off, rec->file_id);  off += 8;
    (void)vw_proto_write_str(c->buf, c->cap, &off, name, name_len);
    c->buf[off++] = rec->permission;
    vw_write_u64le(c->buf + off, (uint64_t)rec->created_at); off += 8;
    vw_write_u64le(c->buf + off, (uint64_t)rec->expires_at); off += 8;
    c->buf[off++] = rec->revoked;
    c->len = off;
    c->count++;
    return 0;
}

static vw_err_t handle_link_list(vw_store_t *store, vw_file_store_t *fs,
                                  vw_share_store_t *ss, vw_conn_t *conn,
                                  const uint8_t *payload, uint32_t plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, NULL);
    if (err != VW_OK) return err;
    if (!ss) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    uint64_t file_filter = vw_read_u64le(payload + VW_TOKEN_BYTES);

    link_list_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.fs = fs; c.user_id = user_id; c.file_filter = file_filter;
    err = vw_share_scan(ss, link_list_cb, &c);
    if (err != VW_OK) { free(c.buf); return (send_error(conn, err), VW_OK); }

    uint8_t *resp = (uint8_t *)malloc(4u + c.len);
    if (!resp) { free(c.buf); return (send_error(conn, VW_ERR_OOM), VW_OK); }
    vw_write_u32le(resp, c.count);
    if (c.len) memcpy(resp + 4, c.buf, c.len);
    free(c.buf);

    err = vw_proto_send(conn, VW_MSG_LINK_LIST_RESP, resp, 4u + c.len);
    free(resp);
    return err;
}

/* ── Vault / E2EE (TASK-098; docs/PROTOCOL.md §7.11) ──────────────────────
 * The server treats wrapped_vk/kdf_params as fully opaque bytes — no
 * parsing, no validation beyond size ceilings (vw_vault.h). No content
 * decryption or key material ever exists server-side; these handlers only
 * store/return already-wrapped blobs.
 */

/* VAULT_CREATE: session_token[32] + folder_file_id(u64) + wrapped_vk(string)
 * + kdf_salt[16] + kdf_params(string). ACK: error_code(u32) + vault_id(u64). */
static vw_err_t handle_vault_create(vw_store_t *store, vw_file_store_t *fs,
                                     vw_vault_store_t *vs, vw_conn_t *conn,
                                     const uint8_t *payload, uint32_t plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;
    if (reject_if_scoped(conn, scope_share_id)) return VW_OK;
    if (!vs) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    uint64_t folder_file_id = vw_read_u64le(payload + VW_TOKEN_BYTES);

    const uint8_t *var = payload + VW_TOKEN_BYTES + 8u;
    uint32_t var_len   = plen - VW_TOKEN_BYTES - 8u;
    uint32_t off = 0;

    const char *wrapped_vk; uint16_t wrapped_vk_len;
    err = vw_proto_read_str(var, var_len, &off, &wrapped_vk, &wrapped_vk_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    /* wrapped_vk_len == 0 / oversized are well-formed-but-invalid *values*,
     * not a malformed encoding — matches handle_share_grant's convention
     * of VW_ERR_INVALID_ARG for a semantically-invalid field value (e.g.
     * an out-of-range permission byte) vs. VW_ERR_PROTO_TRUNCATED/_INVALID
     * for the wire encoding itself being broken. */
    if (wrapped_vk_len == 0 || wrapped_vk_len > VW_VAULT_MAX_WRAPPED_VK_BYTES)
        return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);

    if (off + 16u > var_len)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    const uint8_t *kdf_salt = var + off; off += 16u;

    const char *kdf_params; uint16_t kdf_params_len;
    err = vw_proto_read_str(var, var_len, &off, &kdf_params, &kdf_params_len);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    if (kdf_params_len > VW_VAULT_MAX_KDF_PARAMS_BYTES)
        return (send_error(conn, VW_ERR_INVALID_ARG), VW_OK);

    /* Only the folder/file's owner may opt it into encryption. */
    vw_file_record_t folder_rec;
    if (vw_store_file_get_by_id(fs, folder_file_id, &folder_rec) != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    if (folder_rec.owner_id != user_id)
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);

    uint64_t vault_id = 0;
    err = vw_vault_create(vs, user_id, folder_file_id,
                           (const uint8_t *)wrapped_vk, wrapped_vk_len, kdf_salt,
                           kdf_params_len ? (const uint8_t *)kdf_params : NULL, kdf_params_len,
                           &vault_id);
    if (err != VW_OK)
        return (send_error(conn, err), VW_OK);

    uint8_t ack[12];
    vw_write_u32le(ack, 0u);
    vw_write_u64le(ack + 4u, vault_id);
    return vw_proto_send(conn, VW_MSG_VAULT_CREATE_ACK, ack, sizeof(ack));
}

/* VAULT_KEY_FETCH: session_token[32] + vault_id(u64).
 * RESP: error_code(u32) + wrapped_vk(string) + kdf_salt[16] + kdf_params(string). */
static vw_err_t handle_vault_key_fetch(vw_store_t *store, vw_vault_store_t *vs,
                                        vw_conn_t *conn,
                                        const uint8_t *payload, uint32_t plen)
{
    uint64_t user_id, scope_share_id = 0;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, &scope_share_id);
    if (err != VW_OK) return err;
    if (reject_if_scoped(conn, scope_share_id)) return VW_OK;
    if (!vs) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    if (plen < VW_TOKEN_BYTES + 8u)
        return (send_error(conn, VW_ERR_PROTO_TRUNCATED), VW_ERR_PROTO_TRUNCATED);
    uint64_t vault_id = vw_read_u64le(payload + VW_TOKEN_BYTES);

    vw_vault_record_t rec;
    uint8_t *wrapped_vk = NULL, *kdf_params = NULL;
    err = vw_vault_get_by_id(vs, vault_id, &rec, &wrapped_vk, &kdf_params);
    if (err != VW_OK)
        return (send_error(conn, VW_ERR_NOT_FOUND), VW_OK);
    /* Same "id exists but isn't yours -> PERMISSION" convention as
     * SHARE_REVOKE/LINK_REVOKE (§7.5) — vault_id is an opaque counter like
     * share_id, not something whose mere existence needs hiding. */
    if (rec.owner_id != user_id) {
        free(wrapped_vk); free(kdf_params);
        return (send_error(conn, VW_ERR_PERMISSION), VW_OK);
    }

    /* folder_file_id appended unconditionally (TASK-106 review finding):
     * vw_vault_unlock() needs it to support uploading a brand-new file
     * into a vault that was unlocked (not just created) this session —
     * without it, vw_vault_upload_file's file_id==0 create-path had
     * nowhere to point and every such upload was silently rejected by
     * the server as an invalid absolute-path commit. Nothing optional
     * follows it, so — same reasoning as FILE_STAT_RESP's vault_id —
     * appending it unconditionally is simplest with no compatibility
     * concern either way. */
    uint32_t resp_cap = 4u + 2u + rec.wrapped_vk_len + 16u + 2u + rec.kdf_params_len + 8u;
    uint8_t *resp = (uint8_t *)malloc(resp_cap);
    if (!resp) {
        free(wrapped_vk); free(kdf_params);
        return (send_error(conn, VW_ERR_OOM), VW_OK);
    }
    uint32_t roff = 0;
    vw_write_u32le(resp, 0u); roff += 4u;
    (void)vw_proto_write_str(resp, resp_cap, &roff,
                              (const char *)wrapped_vk, (uint16_t)rec.wrapped_vk_len);
    memcpy(resp + roff, rec.kdf_salt, 16); roff += 16u;
    (void)vw_proto_write_str(resp, resp_cap, &roff,
                              (const char *)kdf_params, (uint16_t)rec.kdf_params_len);
    vw_write_u64le(resp + roff, rec.folder_file_id); roff += 8u;

    vw_err_t send_err = vw_proto_send(conn, VW_MSG_VAULT_KEY_FETCH_RESP, resp, roff);
    free(wrapped_vk); free(kdf_params); free(resp);
    return send_err;
}

/* VAULT_LIST: session_token[32] (no other fields — always "my vaults").
 * RESP: count(u32) + count * {vault_id(u64), folder_file_id(u64), created_at(i64)}
 * — never the wrapped-key material (no legitimate client need to enumerate
 * other vaults' key blobs in a list view, matching LINK_LIST_RESP's
 * never-include-the-token convention). */
typedef struct {
    uint64_t user_id;
    uint8_t *buf;
    uint32_t cap, len, count;
} vault_list_ctx_t;

static int vault_list_cb(const vw_vault_record_t *rec, void *ud)
{
    vault_list_ctx_t *c = (vault_list_ctx_t *)ud;
    if (rec->owner_id != c->user_id) return 0;

    uint32_t entry_cap = 8u + 8u + 8u;
    if (c->len + entry_cap > c->cap) {
        uint32_t new_cap = c->cap ? c->cap * 2u : 4096u;
        while (c->len + entry_cap > new_cap) new_cap *= 2u;
        uint8_t *p = (uint8_t *)realloc(c->buf, new_cap);
        if (!p) return 1;
        c->buf = p; c->cap = new_cap;
    }
    uint32_t off = c->len;
    vw_write_u64le(c->buf + off, rec->vault_id);       off += 8u;
    vw_write_u64le(c->buf + off, rec->folder_file_id); off += 8u;
    vw_write_u64le(c->buf + off, (uint64_t)rec->created_at); off += 8u;
    c->len = off;
    c->count++;
    return 0;
}

static vw_err_t handle_vault_list(vw_store_t *store, vw_vault_store_t *vs,
                                   vw_conn_t *conn,
                                   const uint8_t *payload, uint32_t plen)
{
    uint64_t user_id;
    vw_err_t err = validate_session(store, conn, payload, plen, &user_id, NULL);
    if (err != VW_OK) return err;
    if (!vs) return (send_error(conn, VW_ERR_NOT_IMPL), VW_ERR_NOT_IMPL);

    vault_list_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.user_id = user_id;
    err = vw_vault_scan(vs, vault_list_cb, &c);
    if (err != VW_OK) { free(c.buf); return (send_error(conn, err), VW_OK); }

    uint8_t *resp = (uint8_t *)malloc(4u + c.len);
    if (!resp) { free(c.buf); return (send_error(conn, VW_ERR_OOM), VW_OK); }
    vw_write_u32le(resp, c.count);
    if (c.len) memcpy(resp + 4u, c.buf, c.len);
    free(c.buf);

    err = vw_proto_send(conn, VW_MSG_VAULT_LIST_RESP, resp, 4u + c.len);
    free(resp);
    return err;
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
    vw_share_store_t  *ss      = vw_server_ctx_share_store(ctx);
    vw_vault_store_t  *vs      = vw_server_ctx_vault_store(ctx);

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
        return handle_file_list(store, fs, ss, conn, payload, plen);
    case VW_MSG_FILE_STAT:
        return handle_file_stat(store, fs, ss, conn, payload, plen);
    case VW_MSG_CHUNK_QUERY:
        return handle_chunk_query(store, cs, conn, payload, plen);
    case VW_MSG_CHUNK_UPLOAD:
        return handle_chunk_upload(store, cs, ss, conn, payload, plen);
    case VW_MSG_CHUNK_DOWNLOAD_REQ:
        return handle_chunk_download(store, fs, cs, ss, conn, payload, plen);
    case VW_MSG_FILE_COMMIT:
        return handle_file_commit(store, fs, cs, ss, vs, conn, payload, plen);
    case VW_MSG_FILE_DELETE:
        return handle_file_delete(store, fs, ss, conn, payload, plen);
    case VW_MSG_FILE_MOVE:
        return handle_file_move(store, fs, ss, conn, payload, plen);
    case VW_MSG_FILE_MKDIR:
        return handle_file_mkdir(store, fs, ss, conn, payload, plen);
    case VW_MSG_VERSION_LIST:
        return handle_version_list(store, fs, ss, conn, payload, plen);
    case VW_MSG_VERSION_RESTORE:
        return handle_version_restore(store, fs, cs, ss, conn, payload, plen);
    case VW_MSG_VERSION_CHUNKS:
        return handle_version_chunks(store, fs, ss, conn, payload, plen);
    case VW_MSG_SHARE_GRANT:
        return handle_share_grant(store, fs, ss, conn, payload, plen);
    case VW_MSG_SHARE_REVOKE:
        return handle_share_or_link_revoke(store, ss, conn, payload, plen, VW_MSG_SHARE_REVOKE_ACK);
    case VW_MSG_SHARE_LIST:
        return handle_share_list(store, fs, ss, conn, payload, plen);
    case VW_MSG_LINK_CREATE:
        return handle_link_create(store, fs, ss, conn, payload, plen);
    case VW_MSG_LINK_REVOKE:
        return handle_share_or_link_revoke(store, ss, conn, payload, plen, VW_MSG_LINK_REVOKE_ACK);
    case VW_MSG_LINK_LIST:
        return handle_link_list(store, fs, ss, conn, payload, plen);
    case VW_MSG_VAULT_CREATE:
        return handle_vault_create(store, fs, vs, conn, payload, plen);
    case VW_MSG_VAULT_KEY_FETCH:
        return handle_vault_key_fetch(store, vs, conn, payload, plen);
    case VW_MSG_VAULT_LIST:
        return handle_vault_list(store, vs, conn, payload, plen);
    default:
        /* TASK-105: an unrecognized/misplaced message type on an
         * authenticated connection (e.g. a pre-auth-phase type like
         * AUTH_REQUEST re-sent after the handshake) must get an explicit
         * error, not silence — the caller in vw_server_main.c's per-
         * connection loop only logs a warning and waits for the *next*
         * message on VW_ERR_NOT_IMPL, so a client that sent this message
         * expecting a response would otherwise hang until its own
         * receive timeout, tying up a worker thread the whole time. */
        (void)send_error(conn, VW_ERR_PROTO_INVALID);
        return VW_ERR_NOT_IMPL;
    }
}
