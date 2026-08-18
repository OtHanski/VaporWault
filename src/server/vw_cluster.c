/*
 * vw_cluster.c — node record store and cluster handshake handler.
 *
 * See vw_cluster.h for the design description.
 *
 * SECURITY: auth_token is a 256-bit pre-shared secret. It is compared
 * using vw_crypto_constant_time_eq and never returned or logged.
 * NODE_HELLO_FAIL responses are sent for both unknown node_id and wrong
 * auth_token so the response is timing-equalized and non-enumerable.
 *
 * Rate-limiting: a fixed ring-buffer of 256 source IP entries tracks failure
 * counts. 5 failures within 60 s from one IP → connection silently dropped.
 */

#include "vw_cluster.h"
#include "vw_oplog.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_share.h"
#include "vw_vault.h"
#include "../core/vw_net.h"
#include "../core/vw_crypto.h"
#include "../core/vw_fs.h"
#include "../core/vw_proto.h"

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef SRWLOCK  vw_rwlock_t;
#   define rwlock_init(l)      InitializeSRWLock(l)
#   define rwlock_rdlock(l)    AcquireSRWLockShared(l)
#   define rwlock_rdunlock(l)  ReleaseSRWLockShared(l)
#   define rwlock_wrlock(l)    AcquireSRWLockExclusive(l)
#   define rwlock_wrunlock(l)  ReleaseSRWLockExclusive(l)
typedef HANDLE   vw_thread_t;
typedef volatile long vw_atomic_int_t;
#   define atomic_load_acq(p) (*(p))
#   define atomic_store_rel(p,v) (*(p) = (v))
#else
#   include <pthread.h>
#   include <unistd.h>
#   include <fcntl.h>
typedef pthread_rwlock_t vw_rwlock_t;
#   define rwlock_init(l)      pthread_rwlock_init(l, NULL)
#   define rwlock_rdlock(l)    pthread_rwlock_rdlock(l)
#   define rwlock_rdunlock(l)  pthread_rwlock_unlock(l)
#   define rwlock_wrlock(l)    pthread_rwlock_wrlock(l)
#   define rwlock_wrunlock(l)  pthread_rwlock_unlock(l)
typedef pthread_t vw_thread_t;
typedef volatile int vw_atomic_int_t;
#   define atomic_load_acq(p)  (*(volatile int *)(p))
#   define atomic_store_rel(p,v) (*(volatile int *)(p) = (v))
#endif

/* ── Rate-limit table ─────────────────────────────────────────────────────── */

#define RATE_TABLE_SIZE 256

/* TASK-086: sanity ceiling on client-supplied node_id (handle_node_register_self,
 * via vw_cluster_node_add_self). Without this, a typo'd huge node_id passed
 * straight to index_ensure() doubles ctx->nid_to_slot's capacity up to that
 * value. Low severity — this only ever runs over the trusted local-only
 * admin channel — but a ceiling costs nothing and avoids a large allocation
 * from a simple typo. 2^20 is far beyond any real cluster's node count. */
#define VW_CLUSTER_MAX_NODE_ID (1u << 20)
#define RATE_WINDOW_SECS 60
#define RATE_MAX_FAILURES 5

typedef struct {
    char     ip[48];         /* IPv4 or IPv6 source address string */
    uint32_t fail_count;
    time_t   first_fail_at;
} rate_entry_t;

/* ── Cluster context ──────────────────────────────────────────────────────── */

struct vw_cluster_ctx {
    /* Config copy */
    vw_cluster_cfg_t cfg;
    char cert_pem_path[512];
    char key_pem_path[512];
    char data_dir[512];

    /* Shared oplog reference (lifetime: owned by caller of vw_cluster_open) */
    vw_oplog_t *oplog;

    /* TASK-172: this server's own live store handles (borrowed — owned by
     * the caller of vw_cluster_open, same lifetime contract as oplog).
     * share_store/vault_store may be NULL (see vw_cluster_open's doc). */
    vw_store_t       *store;
    vw_file_store_t  *file_store;
    vw_storage_t     *chunks;
    vw_share_store_t *share_store;
    vw_vault_store_t *vault_store;

    /* Node store */
    char         nodes_path[600];  /* {data_dir}/cluster/nodes.db */
    vw_rwlock_t  nodes_lock;

    /* In-memory slot index: nid_to_slot[node_id] = 1-based slot, 0 = absent */
    uint32_t  *nid_to_slot;
    uint64_t   nid_to_slot_cap;  /* length of nid_to_slot array */
    uint64_t   node_slots;       /* total slots on disk (including free) */
    uint64_t   next_node_id;     /* monotonic counter for new nodes */

    /* Primary-mode accept thread */
    vw_net_ctx_t    *net_ctx;
    vw_thread_t      thread;
    vw_atomic_int_t  shutdown;
    int              running;

    /* Replica-mode replication thread */
    vw_thread_t      repl_thread;
    int              repl_running;

    /* IP rate-limit table (accessed only from accept thread; no lock needed) */
    rate_entry_t rate_table[RATE_TABLE_SIZE];
    uint32_t     rate_next_slot;  /* ring-buffer cursor */
};

/* ── Logging ──────────────────────────────────────────────────────────────── */

#define CLUSTER_TAG "CLUSTER"

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static void cluster_log(const char *level, const char *fmt, ...)
{
    fprintf(stderr, "[%s] %s  ", level, CLUSTER_TAG);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif
#define CL_INFO(fmt, ...)  cluster_log("INFO",  fmt, ##__VA_ARGS__)
#define CL_WARN(fmt, ...)  cluster_log("WARN",  fmt, ##__VA_ARGS__)
#define CL_DEBUG(fmt, ...) cluster_log("DEBUG", fmt, ##__VA_ARGS__)
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

/* ── Disk helpers ──────────────────────────────────────────────────────────── */

/* slot is 1-based (slot 1 == the first record on disk) — matches
 * vw_cluster_node_add's `ctx->node_slots + 1` and every scan loop in this
 * file (`for (s = 1; s <= total; s++)`). */
static int nodes_pread(const char *path, vw_node_record_t *out, uint64_t slot)
{
    uint64_t off = (slot - 1) * (uint64_t)sizeof(vw_node_record_t);
    /* Read via vw_fs_read_file would be slow; use platform pread/ReadFile. */
#ifdef _WIN32
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(fh, li, NULL, FILE_BEGIN)) { CloseHandle(fh); return -1; }
    DWORD rd = 0;
    int ok = ReadFile(fh, out, (DWORD)sizeof(*out), &rd, NULL) && rd == sizeof(*out);
    CloseHandle(fh);
    return ok ? 0 : -1;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, out, sizeof(*out), (off_t)off);
    close(fd);
    return (n == (ssize_t)sizeof(*out)) ? 0 : -1;
#endif
}

/* ── nid_to_slot index helpers ─────────────────────────────────────────────── */

/* TASK-086: shared append/sync/index-update tail of vw_cluster_node_add and
 * vw_cluster_node_add_self — both build a vw_node_record_t, then append it,
 * sync for durability, and record its slot in nid_to_slot the same way.
 * Caller holds ctx->nodes_lock write-locked and is responsible for zeroing
 * rec->auth_token, unlocking, and returning on failure — this only covers
 * the on-disk part that used to be duplicated ~verbatim between the two. */
static vw_err_t node_append_and_index(vw_cluster_t *ctx, vw_node_record_t *rec,
                                       uint64_t slot)
{
    vw_err_t rc = vw_fs_append(ctx->nodes_path, rec, sizeof(*rec));
    if (rc != VW_OK) return rc;

    rc = vw_fs_sync_file(ctx->nodes_path);
    if (rc != VW_OK) return rc;

    ctx->nid_to_slot[rec->node_id] = (uint32_t)slot;
    ctx->node_slots = slot;
    return VW_OK;
}

static vw_err_t index_ensure(vw_cluster_t *ctx, uint64_t node_id)
{
    /* TASK-086: structural ceiling — every caller (the trusted startup scan
     * in vw_cluster_open, which trusts whatever is on disk in nodes.db, and
     * vw_cluster_node_add_self, which takes a client-supplied node_id over
     * the admin socket) goes through here, so checking here protects both
     * a corrupted/tampered nodes.db and a typo'd register-self call alike,
     * rather than relying on every call site to remember its own guard. */
    if (node_id > VW_CLUSTER_MAX_NODE_ID) return VW_ERR_INVALID_ARG;
    if (node_id < ctx->nid_to_slot_cap) return VW_OK;
    uint64_t new_cap = ctx->nid_to_slot_cap ? ctx->nid_to_slot_cap * 2 : 64;
    while (new_cap <= node_id) new_cap *= 2;
    uint32_t *p = realloc(ctx->nid_to_slot, (size_t)new_cap * sizeof(uint32_t));
    if (!p) return VW_ERR_OOM;
    memset(p + ctx->nid_to_slot_cap, 0,
           (size_t)(new_cap - ctx->nid_to_slot_cap) * sizeof(uint32_t));
    ctx->nid_to_slot     = p;
    ctx->nid_to_slot_cap = new_cap;
    return VW_OK;
}

/* ── Rate-limit helpers ────────────────────────────────────────────────────── */

static rate_entry_t *rate_find_or_evict(vw_cluster_t *ctx, const char *ip)
{
    for (int i = 0; i < RATE_TABLE_SIZE; i++) {
        if (strcmp(ctx->rate_table[i].ip, ip) == 0)
            return &ctx->rate_table[i];
    }
    rate_entry_t *entry = &ctx->rate_table[ctx->rate_next_slot];
    ctx->rate_next_slot = (ctx->rate_next_slot + 1) % RATE_TABLE_SIZE;
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
    return entry;
}

/* Returns 1 if the IP has too many recent failures (do not reply, just drop). */
static int rate_is_blocked(vw_cluster_t *ctx, const char *ip)
{
    time_t now = time(NULL);
    for (int i = 0; i < RATE_TABLE_SIZE; i++) {
        if (strcmp(ctx->rate_table[i].ip, ip) != 0) continue;
        rate_entry_t *e = &ctx->rate_table[i];
        if (e->fail_count > 0 &&
            difftime(now, e->first_fail_at) >= RATE_WINDOW_SECS) {
            e->fail_count    = 0;
            e->first_fail_at = 0;
        }
        return e->fail_count >= RATE_MAX_FAILURES;
    }
    return 0;
}

/* Record one auth failure from ip; does NOT block reads or sends. */
static void rate_record_failure(vw_cluster_t *ctx, const char *ip)
{
    rate_entry_t *e = rate_find_or_evict(ctx, ip);
    time_t now = time(NULL);
    if (e->fail_count > 0 &&
        difftime(now, e->first_fail_at) >= RATE_WINDOW_SECS) {
        e->fail_count    = 0;
        e->first_fail_at = 0;
    }
    if (e->fail_count >= RATE_MAX_FAILURES) return;
    if (e->fail_count == 0) e->first_fail_at = now;
    e->fail_count++;
}

static void rate_reset_on_success(vw_cluster_t *ctx, const char *ip)
{
    for (int i = 0; i < RATE_TABLE_SIZE; i++) {
        if (strcmp(ctx->rate_table[i].ip, ip) == 0) {
            ctx->rate_table[i].fail_count    = 0;
            ctx->rate_table[i].first_fail_at = 0;
            return;
        }
    }
}

/* ── NODE_HELLO handler ────────────────────────────────────────────────────── */

static void send_hello_fail(vw_conn_t *conn)
{
    uint8_t payload[4];
    payload[0] = payload[1] = payload[2] = payload[3] = 0;  /* error_code = 0 */
    (void)vw_proto_send(conn, VW_MSG_NODE_HELLO_FAIL, payload, 4);
}

/* NODE_HELLO payload is at most: 8+32+8+2+2+127 = 179 bytes. 512 is generous. */
#define CLUSTER_RECV_BUF_SIZE 512u

/* Max entries per OPLOG_PULL request the primary will honour. */
#define OPLOG_PULL_MAX_ENTRIES 256u

/* ── TASK-172: replica hot-standby data replication (docs/PROTOCOL.md §7.7) ── */

/*
 * Send VW_MSG_ERROR with a numeric error code and no human-readable message.
 * Mirrors vw_file_handlers.c's send_error — duplicated rather than shared
 * across the module boundary (that one is file-local static there too).
 */
static vw_err_t cluster_send_error(vw_conn_t *conn, vw_err_t code)
{
    uint8_t buf[8];
    uint32_t len;
    vw_err_t err = vw_proto_encode_error((uint32_t)code, NULL, 0, buf, sizeof(buf), &len);
    if (err != VW_OK) return err;
    return vw_proto_send(conn, VW_MSG_ERROR, buf, len);
}

#define VW_CLUSTER_FILE_TAG_COUNT 8u

/* Fixed, non-negotiated file-tag -> path mapping (docs/PROTOCOL.md §7.7's
 * table). Deliberately never a free-form path string on the wire — see the
 * doc comment there for why. */
static const char *cluster_file_tag_rel_path(uint8_t tag)
{
    switch (tag) {
    case 1: return "store/users.dat";
    case 2: return "store/quotas.db";
    case 3: return "files/meta.dat";
    case 4: return "files/versions.dat";
    case 5: return "files/versions.blob";
    case 6: return "shares/shares.db";
    case 7: return "vaults/vaults.db";
    case 8: return "vaults/vaults.blob";
    default: return NULL;
    }
}

/*
 * Read a syncable file's full current content directly off disk (no live
 * store handle involved — see vw_cluster_open's doc for why this is safe)
 * and hash it. A file that doesn't exist yet hashes as if empty (size 0);
 * every one of these files is created empty-but-present by its owning
 * module's _open() on both primary and replica, so this only matters for
 * a not-yet-created replica data_dir mid-first-sync.
 */
static int cluster_hash_file_by_tag(const char *data_dir, uint8_t tag,
                                     uint64_t *out_size, uint8_t out_hash[32])
{
    const char *rel = cluster_file_tag_rel_path(tag);
    if (!rel) return -1;

    char path[700];
    snprintf(path, sizeof(path), "%s/%s", data_dir, rel);

    if (!vw_fs_exists(path)) {
        *out_size = 0;
        return (vw_crypto_sha256("", 0, out_hash) == VW_OK) ? 0 : -1;
    }

    void  *buf = NULL;
    size_t len = 0;
    if (vw_fs_read_file(path, &buf, &len) != VW_OK) return -1;
    *out_size = (uint64_t)len;
    int rc = (vw_crypto_sha256(buf, len, out_hash) == VW_OK) ? 0 : -1;
    free(buf);
    return rc;
}

/* ── Primary-side CLUSTER_FILE_SYNC_* / CLUSTER_CHUNK_* handlers ─────────── */

static vw_err_t handle_cluster_file_sync_list(vw_cluster_t *ctx, vw_conn_t *conn)
{
    uint8_t resp[1u + VW_CLUSTER_FILE_TAG_COUNT * (1u + 8u + 32u)];
    uint32_t off = 0;
    resp[off++] = (uint8_t)VW_CLUSTER_FILE_TAG_COUNT;

    for (uint8_t tag = 1; tag <= VW_CLUSTER_FILE_TAG_COUNT; tag++) {
        uint64_t size = 0;
        uint8_t  hash[32];
        if (cluster_hash_file_by_tag(ctx->data_dir, tag, &size, hash) != 0) {
            /* Read failure on the primary's own data — surface as an
             * all-zero entry rather than failing the whole LIST; the
             * replica will then unconditionally FETCH this tag and get a
             * definitive ERROR/DATA answer from handle_cluster_file_sync_fetch. */
            size = 0;
            memset(hash, 0, sizeof(hash));
        }
        resp[off++] = tag;
        vw_write_u64le(resp + off, size); off += 8;
        memcpy(resp + off, hash, 32);     off += 32;
    }

    return vw_proto_send(conn, VW_MSG_CLUSTER_FILE_SYNC_LIST_RESP, resp, off);
}

static vw_err_t handle_cluster_file_sync_fetch(vw_cluster_t *ctx, vw_conn_t *conn,
                                                const uint8_t *payload, uint32_t plen)
{
    if (plen < 1u) return cluster_send_error(conn, VW_ERR_PROTO_TRUNCATED);

    uint8_t tag = payload[0];
    const char *rel = cluster_file_tag_rel_path(tag);
    if (!rel) return cluster_send_error(conn, VW_ERR_INVALID_ARG);

    char path[700];
    snprintf(path, sizeof(path), "%s/%s", ctx->data_dir, rel);

    void  *buf = NULL;
    size_t len = 0;
    if (vw_fs_exists(path)) {
        if (vw_fs_read_file(path, &buf, &len) != VW_OK)
            return cluster_send_error(conn, VW_ERR_NOT_FOUND);
    }

    uint32_t resp_len = 1u + 8u + (uint32_t)len;
    uint8_t *resp = (uint8_t *)malloc(resp_len);
    if (!resp) { free(buf); return cluster_send_error(conn, VW_ERR_OOM); }

    resp[0] = tag;
    vw_write_u64le(resp + 1, (uint64_t)len);
    if (len > 0) memcpy(resp + 9, buf, len);
    free(buf);

    vw_err_t rc = vw_proto_send(conn, VW_MSG_CLUSTER_FILE_SYNC_DATA, resp, resp_len);
    free(resp);
    return rc;
}

static vw_err_t handle_cluster_chunk_query(vw_cluster_t *ctx, vw_conn_t *conn,
                                            const uint8_t *payload, uint32_t plen)
{
    if (plen < 2u) return cluster_send_error(conn, VW_ERR_PROTO_TRUNCATED);

    uint16_t count = vw_read_u16le(payload);
    if (count > 1024u) return cluster_send_error(conn, VW_ERR_PROTO_INVALID);

    uint32_t expected = 2u + (uint32_t)count * VW_HASH_BYTES;
    if (plen < expected) return cluster_send_error(conn, VW_ERR_PROTO_TRUNCATED);

    const uint8_t (*hashes)[VW_HASH_BYTES] =
        (const uint8_t (*)[VW_HASH_BYTES])(payload + 2u);

    uint32_t bitmask_bytes = count == 0u ? 0u : (count + 7u) / 8u;
    uint8_t resp[2 + 128];
    vw_write_u16le(resp, count);
    uint32_t roff = 2;
    if (count > 0) {
        memset(resp + roff, 0, bitmask_bytes);
        vw_err_t err = vw_storage_chunk_query(ctx->chunks, hashes, count, resp + roff);
        if (err != VW_OK) return cluster_send_error(conn, err);
        roff += bitmask_bytes;
    }

    return vw_proto_send(conn, VW_MSG_CLUSTER_CHUNK_QUERY_RESP, resp, roff);
}

static vw_err_t handle_cluster_chunk_fetch(vw_cluster_t *ctx, vw_conn_t *conn,
                                           const uint8_t *payload, uint32_t plen)
{
    if (plen < VW_HASH_BYTES) return cluster_send_error(conn, VW_ERR_PROTO_TRUNCATED);

    uint8_t *data = NULL;
    uint32_t data_len = 0;
    vw_err_t err = vw_storage_chunk_get(ctx->chunks, payload, &data, &data_len);
    if (err != VW_OK) return cluster_send_error(conn, VW_ERR_NOT_FOUND);

    uint32_t resp_size = VW_HASH_BYTES + 4u + data_len;
    uint8_t *resp = (uint8_t *)malloc(resp_size);
    if (!resp) { free(data); return cluster_send_error(conn, VW_ERR_OOM); }
    memcpy(resp, payload, VW_HASH_BYTES);
    vw_write_u32le(resp + VW_HASH_BYTES, data_len);
    memcpy(resp + VW_HASH_BYTES + 4u, data, data_len);
    free(data);

    vw_err_t rc = vw_proto_send(conn, VW_MSG_CLUSTER_CHUNK_DATA, resp, resp_size);
    free(resp);
    return rc;
}

/* ── Primary-side replication loop ─────────────────────────────────────────── */

/*
 * Called after a successful NODE_HELLO_OK exchange.
 * Handles the OPLOG_PULL → OPLOG_DATA → OPLOG_ACK loop for one replica.
 *
 * conn:    the accepted TLS connection (caller owns and will close it).
 * ctx:     cluster context (for node watermark updates).
 * node_id: the authenticated replica's node_id.
 */
static void primary_repl_loop(vw_cluster_t *ctx, vw_conn_t *conn, uint64_t node_id)
{
    /* Generous recv timeout for OPLOG_PULL: replicas may be slow. */
    vw_net_conn_set_recv_timeout(conn, 120000);

    /* Sized for the largest request this loop ever receives: a
     * CLUSTER_CHUNK_QUERY batch (up to 1024 hashes, ~32 KiB) dwarfs
     * OPLOG_PULL's 12 bytes, so one shared heap buffer replaces the old
     * per-message stack buffers. */
    uint8_t *buf = (uint8_t *)malloc(VW_MAX_MSG_BYTES);
    if (!buf) {
        CL_WARN("primary: OOM allocating recv buffer for node %llu",
                (unsigned long long)node_id);
        return;
    }

    for (;;) {
        if (atomic_load_acq(&ctx->shutdown)) break;

        /* Wait for OPLOG_PULL */
        vw_msg_type_t msg_type;
        uint32_t plen = 0;
        vw_err_t rc = vw_proto_recv(conn, &msg_type, buf, VW_MAX_MSG_BYTES, &plen);
        if (rc != VW_OK) {
            CL_DEBUG("primary: OPLOG_PULL recv failed for node %llu: %d",
                     (unsigned long long)node_id, (int)rc);
            break;
        }
        if (msg_type != VW_MSG_OPLOG_PULL) {
            /* Handle CLUSTER_STATUS request inline (TASK-050 will expand this). */
            if (msg_type == VW_MSG_CLUSTER_STATUS) {
                /* Placeholder: send empty CLUSTER_STATUS_RESP.  Full impl in TASK-050. */
                uint8_t resp[5] = {0};   /* role=0, node_count=0 (4 bytes) */
                (void)vw_proto_send(conn, VW_MSG_CLUSTER_STATUS_RESP, resp, 5);
                continue;
            }
            CL_WARN("primary: unexpected msg 0x%04x from node %llu",
                    (unsigned)msg_type, (unsigned long long)node_id);
            break;
        }
        if (plen != 12) {
            CL_WARN("primary: OPLOG_PULL bad len %u from node %llu", plen,
                    (unsigned long long)node_id);
            break;
        }

        uint64_t from_eid    = vw_read_u64le(buf + 0);
        uint32_t max_entries = vw_read_u32le(buf + 8);
        if (max_entries == 0 || max_entries > OPLOG_PULL_MAX_ENTRIES)
            max_entries = OPLOG_PULL_MAX_ENTRIES;

        /* Read entries from oplog */
        uint8_t *entries_buf       = NULL;
        uint32_t entries_count     = 0;
        uint64_t last_entry_id_out = 0;

        if (ctx->oplog) {
            rc = vw_oplog_read_range(ctx->oplog, from_eid, max_entries,
                                     &entries_buf, &entries_count, &last_entry_id_out);
            if (rc != VW_OK) {
                CL_WARN("primary: vw_oplog_read_range failed: %d", (int)rc);
                break;
            }
        }

        /* Compute total byte length of entries_buf by scanning each entry.
         * Each entry: [crc(4)][payload_len(4)][...] → total = VW_OPLOG_ENTRY_HDR_BYTES + payload_len.
         * Guard against uint32_t overflow in entries_bytes accumulation. */
        uint32_t entries_bytes = 0;
        if (entries_buf && entries_count > 0) {
            const uint8_t *p = entries_buf;
            for (uint32_t i = 0; i < entries_count; i++) {
                uint32_t plen_field = vw_read_u32le(p + 4);  /* stored_plen */
                uint32_t e_total    = VW_OPLOG_ENTRY_HDR_BYTES + plen_field;
                if (plen_field > VW_MAX_MSG_BYTES ||
                    entries_bytes > VW_MAX_MSG_BYTES - e_total)
                    break;  /* truncate — should not happen with internal data */
                entries_bytes      += e_total;
                p                  += e_total;
            }
        }

        uint32_t data_payload_len = 4u + 8u + entries_bytes;
        uint8_t *data_payload = (uint8_t *)malloc(data_payload_len);
        if (!data_payload) {
            free(entries_buf);
            CL_WARN("primary: OOM building OPLOG_DATA for node %llu",
                    (unsigned long long)node_id);
            break;
        }
        vw_write_u32le(data_payload + 0, entries_count);
        vw_write_u64le(data_payload + 4, last_entry_id_out);
        if (entries_bytes > 0 && entries_buf)
            memcpy(data_payload + 12, entries_buf, entries_bytes);
        free(entries_buf);

        rc = vw_proto_send(conn, VW_MSG_OPLOG_DATA, data_payload, data_payload_len);
        free(data_payload);
        if (rc != VW_OK) {
            CL_WARN("primary: OPLOG_DATA send failed for node %llu: %d",
                    (unsigned long long)node_id, (int)rc);
            break;
        }

        /* If no entries sent, skip waiting for OPLOG_ACK (replica will retry). */
        if (entries_count == 0) continue;

        /* TASK-172: between OPLOG_DATA and this batch's OPLOG_ACK, the
         * replica may run a whole file/chunk sync pass — any number of
         * CLUSTER_FILE_SYNC_LIST/_FETCH and CLUSTER_CHUNK_QUERY/_FETCH
         * round-trips — before finally sending OPLOG_ACK. Dispatch each
         * until OPLOG_ACK arrives. */
        int      got_ack      = 0;
        uint64_t confirmed_eid = 0;
        while (!got_ack) {
            rc = vw_proto_recv(conn, &msg_type, buf, VW_MAX_MSG_BYTES, &plen);
            if (rc != VW_OK) {
                CL_DEBUG("primary: recv failed while awaiting OPLOG_ACK from node %llu: %d",
                         (unsigned long long)node_id, (int)rc);
                goto conn_done;
            }
            switch (msg_type) {
            case VW_MSG_OPLOG_ACK:
                if (plen != 8) {
                    CL_WARN("primary: OPLOG_ACK bad len %u from node %llu", plen,
                            (unsigned long long)node_id);
                    goto conn_done;
                }
                confirmed_eid = vw_read_u64le(buf);
                got_ack = 1;
                break;
            case VW_MSG_CLUSTER_FILE_SYNC_LIST:
                rc = handle_cluster_file_sync_list(ctx, conn);
                if (rc != VW_OK) goto conn_done;
                break;
            case VW_MSG_CLUSTER_FILE_SYNC_FETCH:
                rc = handle_cluster_file_sync_fetch(ctx, conn, buf, plen);
                if (rc != VW_OK) goto conn_done;
                break;
            case VW_MSG_CLUSTER_CHUNK_QUERY:
                rc = handle_cluster_chunk_query(ctx, conn, buf, plen);
                if (rc != VW_OK) goto conn_done;
                break;
            case VW_MSG_CLUSTER_CHUNK_FETCH:
                rc = handle_cluster_chunk_fetch(ctx, conn, buf, plen);
                if (rc != VW_OK) goto conn_done;
                break;
            default:
                CL_WARN("primary: unexpected msg 0x%04x from node %llu while awaiting OPLOG_ACK",
                        (unsigned)msg_type, (unsigned long long)node_id);
                goto conn_done;
            }
        }

        vw_cluster_node_update_watermark(ctx, node_id, confirmed_eid);
        CL_DEBUG("primary: node %llu acked entry_id %llu",
                 (unsigned long long)node_id, (unsigned long long)confirmed_eid);
    }

conn_done:
    free(buf);
}

static void handle_cluster_conn(vw_cluster_t *ctx, vw_conn_t *conn)
{
    char peer_ip[64] = "";
    vw_net_peer_addr(conn, peer_ip, sizeof(peer_ip));

    /* Drop silently if this IP has too many recent auth failures. */
    if (rate_is_blocked(ctx, peer_ip)) {
        CL_WARN("cluster: rate-limited connection from %s — dropping", peer_ip);
        return;
    }

    /* 10 s timeout for the NODE_HELLO */
    vw_net_conn_set_recv_timeout(conn, 10000);

    uint8_t buf[CLUSTER_RECV_BUF_SIZE];
    vw_msg_type_t msg_type;
    uint32_t payload_len = 0;
    vw_err_t rc = vw_proto_recv(conn, &msg_type, buf, sizeof(buf), &payload_len);
    if (rc != VW_OK) {
        CL_DEBUG("cluster: recv from %s failed: err %d", peer_ip, (int)rc);
        return;
    }
    if (msg_type != VW_MSG_NODE_HELLO) {
        CL_WARN("cluster: unexpected msg 0x%04x from %s", (unsigned)msg_type, peer_ip);
        rate_record_failure(ctx, peer_ip);
        send_hello_fail(conn);
        return;
    }

    /* Decode NODE_HELLO payload:
     *   u64  node_id
     *   bytes[32] auth_token
     *   u64  sync_watermark
     *   u16  proto_version
     *   u16  hostname_len
     *   bytes[hostname_len] hostname
     */
    if (payload_len < (8u + 32u + 8u + 2u + 2u)) {
        CL_WARN("cluster: NODE_HELLO truncated from %s", peer_ip);
        rate_record_failure(ctx, peer_ip);
        send_hello_fail(conn);
        return;
    }

    uint32_t off = 0;
    uint64_t node_id        = vw_read_u64le(buf + off); off += 8;
    uint8_t  recv_token[32]; memcpy(recv_token, buf + off, 32); off += 32;
    /* sync_watermark and proto_version noted but not acted on in TASK-048 */
    (void)vw_read_u64le(buf + off); off += 8;
    (void)vw_read_u16le(buf + off); off += 2;
    uint16_t hname_len = vw_read_u16le(buf + off); off += 2;
    if ((uint32_t)(off + hname_len) > payload_len) {
        CL_WARN("cluster: NODE_HELLO hostname overrun from %s", peer_ip);
        memset(recv_token, 0, sizeof(recv_token));
        rate_record_failure(ctx, peer_ip);
        send_hello_fail(conn);
        return;
    }

    /* Look up the node under read lock. */
    rwlock_rdlock(&ctx->nodes_lock);

    int found = 0;
    vw_node_record_t stored_rec;
    memset(&stored_rec, 0, sizeof(stored_rec));

    if (node_id != 0 && node_id < ctx->nid_to_slot_cap &&
        ctx->nid_to_slot[node_id] != 0) {
        uint64_t slot = ctx->nid_to_slot[node_id];
        if (nodes_pread(ctx->nodes_path, &stored_rec, slot) == 0 &&
            stored_rec.node_id == node_id && stored_rec.is_active) {
            found = 1;
        }
    }

    /* Constant-time token compare — always run even if not found, using a
     * zero buffer, so timing is equivalent for unknown-node and wrong-token. */
    static const uint8_t zero_token[32] = {0};
    const uint8_t *cmp_token = found ? stored_rec.auth_token : zero_token;
    int token_ok = vw_crypto_constant_time_eq(recv_token, cmp_token, 32);

    uint64_t primary_nid = 0;  /* extended by TASK-049 */
    uint64_t last_eid    = 0;  /* extended by TASK-049 */

    rwlock_rdunlock(&ctx->nodes_lock);

    /* Zero token copies from stack immediately after comparison. */
    memset(recv_token, 0, sizeof(recv_token));
    memset(stored_rec.auth_token, 0, sizeof(stored_rec.auth_token));

    if (!found || !token_ok) {
        CL_WARN("cluster: NODE_HELLO auth failed from %s (node_id=%llu)",
                peer_ip, (unsigned long long)node_id);
        rate_record_failure(ctx, peer_ip);
        send_hello_fail(conn);
        return;
    }

    rate_reset_on_success(ctx, peer_ip);
    CL_INFO("cluster: NODE_HELLO OK from node %llu at %s",
            (unsigned long long)node_id, peer_ip);

    /* Build and send NODE_HELLO_OK:
     *   u64 primary_node_id    (0 for now; primary's own node_id not tracked yet)
     *   u64 current_last_entry_id
     */
    if (ctx->oplog)
        last_eid = vw_oplog_last_entry_id(ctx->oplog);

    uint8_t ok_payload[16];
    vw_write_u64le(ok_payload,     primary_nid);
    vw_write_u64le(ok_payload + 8, last_eid);
    rc = vw_proto_send(conn, VW_MSG_NODE_HELLO_OK, ok_payload, 16);
    if (rc != VW_OK) {
        CL_WARN("cluster: NODE_HELLO_OK send failed to node %llu: %d",
                (unsigned long long)node_id, (int)rc);
        return;
    }

    /* Enter the primary-side replication loop for this replica. */
    primary_repl_loop(ctx, conn, node_id);
    CL_INFO("cluster: replication session ended for node %llu", (unsigned long long)node_id);
}

/* ── Per-connection replica handler thread ───────────────────────────────── */

typedef struct {
    vw_cluster_t *ctx;
    vw_conn_t    *conn;
} per_replica_arg_t;

#ifdef _WIN32
static DWORD WINAPI per_replica_thread(LPVOID arg)
{
    per_replica_arg_t *a = (per_replica_arg_t *)arg;
    handle_cluster_conn(a->ctx, a->conn);
    vw_net_close(a->conn);
    free(a);
    return 0;
}
#else
static void *per_replica_thread(void *arg)
{
    per_replica_arg_t *a = (per_replica_arg_t *)arg;
    handle_cluster_conn(a->ctx, a->conn);
    vw_net_close(a->conn);
    free(a);
    return NULL;
}
#endif

/* ── Accept thread ─────────────────────────────────────────────────────────── */

#ifdef _WIN32
static DWORD WINAPI cluster_accept_thread(LPVOID arg)
{
    vw_cluster_t *ctx = (vw_cluster_t *)arg;
    while (!atomic_load_acq(&ctx->shutdown)) {
        vw_conn_t *conn = NULL;
        if (vw_net_accept(ctx->net_ctx, &conn) != VW_OK) break;
        per_replica_arg_t *a = (per_replica_arg_t *)malloc(sizeof(*a));
        if (!a) { vw_net_close(conn); continue; }
        a->ctx  = ctx;
        a->conn = conn;
        HANDLE h = CreateThread(NULL, 0, per_replica_thread, a, 0, NULL);
        if (!h) { vw_net_close(conn); free(a); continue; }
        CloseHandle(h);  /* detach */
    }
    return 0;
}
#else
static void *cluster_accept_thread(void *arg)
{
    vw_cluster_t *ctx = (vw_cluster_t *)arg;
    while (!atomic_load_acq(&ctx->shutdown)) {
        vw_conn_t *conn = NULL;
        if (vw_net_accept(ctx->net_ctx, &conn) != VW_OK) break;
        per_replica_arg_t *a = (per_replica_arg_t *)malloc(sizeof(*a));
        if (!a) { vw_net_close(conn); continue; }
        a->ctx  = ctx;
        a->conn = conn;
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, per_replica_thread, a) != 0) {
            vw_net_close(conn); free(a);
        }
        pthread_attr_destroy(&attr);
    }
    return NULL;
}
#endif

/* ── Replica-side replication thread ──────────────────────────────────────── */

#define REPLICA_BACKOFF_INIT_MS  2000u
#define REPLICA_BACKOFF_MAX_MS   60000u

static void replica_sleep_ms(vw_cluster_t *ctx, uint32_t ms)
{
    /* Sleep in 100ms intervals so shutdown is detected promptly. */
    uint32_t slept = 0;
    while (slept < ms && !atomic_load_acq(&ctx->shutdown)) {
#ifdef _WIN32
        Sleep(100);
#else
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
#endif
        slept += 100;
    }
}

/* ── Replica-side file/chunk sync pass (TASK-172) ─────────────────────────── */

typedef struct {
    uint8_t  tag;
    uint64_t size;
    uint8_t  hash[32];
} cluster_file_entry_t;

/* Send CLUSTER_FILE_SYNC_LIST, receive CLUSTER_FILE_SYNC_LIST_RESP into
 * out_entries (caller-provided, VW_CLUSTER_FILE_TAG_COUNT capacity). */
static vw_err_t replica_file_sync_list(vw_conn_t *conn, uint8_t *recv_buf,
                                        cluster_file_entry_t *out_entries,
                                        uint32_t *out_count)
{
    vw_err_t rc = vw_proto_send(conn, VW_MSG_CLUSTER_FILE_SYNC_LIST, NULL, 0);
    if (rc != VW_OK) return rc;

    vw_msg_type_t type;
    uint32_t plen = 0;
    rc = vw_proto_recv(conn, &type, recv_buf, VW_MAX_MSG_BYTES, &plen);
    if (rc != VW_OK) return rc;
    if (type != VW_MSG_CLUSTER_FILE_SYNC_LIST_RESP) return VW_ERR_PROTO_INVALID;
    if (plen < 1u) return VW_ERR_PROTO_TRUNCATED;

    uint8_t  count = recv_buf[0];
    uint32_t off   = 1;
    uint32_t n     = 0;
    for (uint8_t i = 0; i < count && n < VW_CLUSTER_FILE_TAG_COUNT; i++) {
        if (off + 1u + 8u + 32u > plen) return VW_ERR_PROTO_TRUNCATED;
        out_entries[n].tag  = recv_buf[off];               off += 1;
        out_entries[n].size = vw_read_u64le(recv_buf + off); off += 8;
        memcpy(out_entries[n].hash, recv_buf + off, 32);     off += 32;
        n++;
    }
    *out_count = n;
    return VW_OK;
}

/* Send CLUSTER_FILE_SYNC_FETCH for tag, receive CLUSTER_FILE_SYNC_DATA, and
 * atomically replace this replica's on-disk copy of that file. Does NOT
 * reload the owning module's live state — callers batch that per-group
 * (see replica_run_file_sync_pass) since tags 1/2, 3/4/5, and 7/8 each
 * reload via a single call regardless of how many of their tags changed. */
static vw_err_t replica_fetch_and_write_file(vw_cluster_t *ctx, vw_conn_t *conn,
                                              uint8_t *recv_buf, uint8_t tag)
{
    const char *rel = cluster_file_tag_rel_path(tag);
    if (!rel) return VW_ERR_INVALID_ARG;

    uint8_t req[1] = { tag };
    vw_err_t rc = vw_proto_send(conn, VW_MSG_CLUSTER_FILE_SYNC_FETCH, req, 1);
    if (rc != VW_OK) return rc;

    vw_msg_type_t type;
    uint32_t plen = 0;
    rc = vw_proto_recv(conn, &type, recv_buf, VW_MAX_MSG_BYTES, &plen);
    if (rc != VW_OK) return rc;
    if (type == VW_MSG_ERROR) return VW_ERR_NOT_FOUND;
    if (type != VW_MSG_CLUSTER_FILE_SYNC_DATA) return VW_ERR_PROTO_INVALID;
    if (plen < 9u) return VW_ERR_PROTO_TRUNCATED;

    uint8_t  resp_tag = recv_buf[0];
    uint64_t size      = vw_read_u64le(recv_buf + 1);
    if (resp_tag != tag) return VW_ERR_PROTO_INVALID;
    if (size > (uint64_t)(plen - 9u)) return VW_ERR_PROTO_TRUNCATED;

    char path[700];
    snprintf(path, sizeof(path), "%s/%s", ctx->data_dir, rel);
    return vw_fs_atomic_write(path, recv_buf + 9, (size_t)size);
}

/*
 * Run one CLUSTER_FILE_SYNC_LIST pass: compare the primary's reported
 * per-tag size+hash against this replica's own current on-disk copy,
 * fetch+write whichever differs, then reload each affected module's live
 * state exactly once (grouped, since e.g. tags 1+2 share one reload call).
 * *out_versions_changed is set if tag 4 (versions.dat) or tag 5
 * (versions.blob) was fetched — the signal that triggers the chunk sweep.
 */
static vw_err_t replica_run_file_sync_pass(vw_cluster_t *ctx, vw_conn_t *conn,
                                            uint8_t *recv_buf,
                                            int *out_versions_changed)
{
    *out_versions_changed = 0;

    cluster_file_entry_t remote[VW_CLUSTER_FILE_TAG_COUNT];
    uint32_t remote_count = 0;
    vw_err_t rc = replica_file_sync_list(conn, recv_buf, remote, &remote_count);
    if (rc != VW_OK) return rc;

    int store_dirty = 0, file_store_dirty = 0, share_dirty = 0, vault_dirty = 0;

    for (uint32_t i = 0; i < remote_count; i++) {
        uint8_t tag = remote[i].tag;
        if (!cluster_file_tag_rel_path(tag)) continue;

        uint64_t local_size = 0;
        uint8_t  local_hash[32];
        if (cluster_hash_file_by_tag(ctx->data_dir, tag, &local_size, local_hash) != 0) {
            memset(local_hash, 0, sizeof(local_hash));
            local_size = 0;
        }
        if (local_size == remote[i].size &&
            memcmp(local_hash, remote[i].hash, 32) == 0)
            continue;  /* already up to date */

        rc = replica_fetch_and_write_file(ctx, conn, recv_buf, tag);
        if (rc != VW_OK) return rc;

        switch (tag) {
        case 1: case 2:       store_dirty      = 1; break;
        case 3: case 4: case 5: file_store_dirty = 1; break;
        case 6:                share_dirty      = 1; break;
        case 7: case 8:        vault_dirty       = 1; break;
        default: break;
        }
        if (tag == 4 || tag == 5) *out_versions_changed = 1;
    }

    if (store_dirty && ctx->store) {
        rc = vw_store_reload_users_and_quotas(ctx->store, ctx->data_dir);
        if (rc != VW_OK) return rc;
    }
    if (file_store_dirty && ctx->file_store) {
        rc = vw_file_store_reload_meta_and_versions(ctx->file_store, ctx->data_dir);
        if (rc != VW_OK) return rc;
    }
    if (share_dirty && ctx->share_store) {
        rc = vw_share_store_reload(ctx->share_store, ctx->data_dir);
        if (rc != VW_OK) return rc;
    }
    if (vault_dirty && ctx->vault_store) {
        rc = vw_vault_store_reload(ctx->vault_store, ctx->data_dir);
        if (rc != VW_OK) return rc;
    }

    return VW_OK;
}

/*
 * Scan the replica's own current on-disk files/versions.dat + versions.blob
 * (just written and reloaded by replica_run_file_sync_pass) for every
 * chunk hash any live version references. Duplicates across versions are
 * not de-duplicated — CLUSTER_CHUNK_QUERY/CLUSTER_CHUNK_FETCH tolerate
 * redundant lookups; at this project's scale that's a simpler tradeoff
 * than de-duping, matching e.g. vw_share_scan's O(total) acceptance.
 */
static vw_err_t replica_collect_referenced_chunks(const char *data_dir,
                                                   uint8_t (**out_hashes)[VW_HASH_BYTES],
                                                   uint32_t *out_count)
{
    *out_hashes = NULL;
    *out_count  = 0;

    char dat_path[700], blob_path[700];
    snprintf(dat_path, sizeof(dat_path), "%s/files/versions.dat", data_dir);
    snprintf(blob_path, sizeof(blob_path), "%s/files/versions.blob", data_dir);

    void  *dat_buf = NULL;
    size_t dat_len = 0;
    vw_err_t rc = vw_fs_read_file(dat_path, &dat_buf, &dat_len);
    if (rc != VW_OK) return rc;

    void  *blob_buf = NULL;
    size_t blob_len = 0;
    rc = vw_fs_read_file(blob_path, &blob_buf, &blob_len);
    if (rc != VW_OK) { free(dat_buf); return rc; }

    uint64_t nslots = dat_len / sizeof(vw_version_record_t);

    uint64_t total_hashes = 0;
    for (uint64_t i = 0; i < nslots; i++) {
        vw_version_record_t rec;
        memcpy(&rec, (const uint8_t *)dat_buf + i * sizeof(rec), sizeof(rec));
        if (rec.version_id == 0) continue;
        total_hashes += rec.chunk_count;
    }

    uint8_t (*hashes)[VW_HASH_BYTES] = NULL;
    if (total_hashes > 0) {
        hashes = (uint8_t (*)[VW_HASH_BYTES])malloc((size_t)total_hashes * VW_HASH_BYTES);
        if (!hashes) { free(dat_buf); free(blob_buf); return VW_ERR_OOM; }
    }

    uint32_t n = 0;
    for (uint64_t i = 0; i < nslots; i++) {
        vw_version_record_t rec;
        memcpy(&rec, (const uint8_t *)dat_buf + i * sizeof(rec), sizeof(rec));
        if (rec.version_id == 0 || rec.chunk_count == 0) continue;
        uint64_t need = (uint64_t)rec.chunk_count * VW_HASH_BYTES;
        if (rec.blob_offset > blob_len || need > blob_len - rec.blob_offset) continue;
        memcpy(hashes + n, (const uint8_t *)blob_buf + rec.blob_offset, (size_t)need);
        n += rec.chunk_count;
    }

    free(dat_buf);
    free(blob_buf);
    *out_hashes = hashes;
    *out_count  = n;
    return VW_OK;
}

static int hash_memcmp(const void *a, const void *b)
{
    return memcmp(a, b, VW_HASH_BYTES);
}

static void hash_to_hex_dbg(const uint8_t *hash, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < VW_HASH_BYTES; i++) {
        out[i * 2]     = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    out[VW_HASH_BYTES * 2] = '\0';
}

/*
 * TASK-181: after every referenced hash is confirmed present locally (the
 * fetch loop below guarantees this), reconcile this replica's own
 * refcounts.db to the true occurrence count of each hash across `hashes`
 * (the full, non-deduplicated per-version list from
 * replica_collect_referenced_chunks) — matching ARCHITECTURE.md's/
 * TASK-172's stated design ("sets its own local refcount from its own
 * now-current versions.dat/versions.blob content"), which the old
 * skip-if-already-present fetch loop alone did not actually implement:
 * a hash already local from an earlier pass never got its ref_count
 * bumped for a newly-synced second (or later) referencing version.
 *
 * Sorts a working copy so every run of identical hashes is contiguous,
 * then calls vw_storage_chunk_set_refcount once per unique hash with its
 * true count — an authoritative overwrite, not an increment, so this is
 * safe to re-run every pass regardless of what any previous pass left
 * behind.
 */
static vw_err_t replica_reconcile_chunk_refcounts(vw_storage_t *chunks,
                                                   const uint8_t (*hashes)[VW_HASH_BYTES],
                                                   uint32_t count)
{
    if (count == 0) return VW_OK;

    uint8_t (*sorted)[VW_HASH_BYTES] =
        (uint8_t (*)[VW_HASH_BYTES])malloc((size_t)count * VW_HASH_BYTES);
    if (!sorted) return VW_ERR_OOM;
    memcpy(sorted, hashes, (size_t)count * VW_HASH_BYTES);
    qsort(sorted, count, VW_HASH_BYTES, hash_memcmp);

    vw_err_t rc = VW_OK;
    uint32_t i = 0;
    while (i < count) {
        uint32_t j = i + 1;
        while (j < count && memcmp(sorted[j], sorted[i], VW_HASH_BYTES) == 0) j++;

        vw_err_t src = vw_storage_chunk_set_refcount(chunks, sorted[i], j - i);
        if (src != VW_OK && src != VW_ERR_NOT_FOUND) { rc = src; break; }
        if (src == VW_ERR_NOT_FOUND) {
            /* Should not happen: the fetch loop above ensures every
             * referenced hash exists locally first. Skip defensively
             * rather than aborting the whole reconciliation pass over
             * one hash a concurrent local GC may have just zeroed. */
            char hex[VW_HASH_BYTES * 2 + 1];
            hash_to_hex_dbg(sorted[i], hex);
            CL_WARN("replica: set_refcount NOT_FOUND for %s (count %u) — skipping",
                    hex, (unsigned)(j - i));
        }

        i = j;
    }

    free(sorted);
    return rc;
}

/*
 * Sweep every chunk hash referenced by the replica's current versions.dat/
 * versions.blob: skip what it already has locally, confirm the rest exists
 * on the primary via CLUSTER_CHUNK_QUERY, then CLUSTER_CHUNK_FETCH and
 * vw_storage_chunk_put_replicated each confirmed hash — in batches of up
 * to 1024, matching CHUNK_QUERY's existing wire cap (§7.2). Once every
 * referenced hash is confirmed present, reconcile ref_counts to their true
 * occurrence counts (TASK-181; see replica_reconcile_chunk_refcounts).
 */
static vw_err_t replica_run_chunk_sync_pass(vw_cluster_t *ctx, vw_conn_t *conn,
                                             uint8_t *recv_buf)
{
    if (!ctx->chunks || !ctx->file_store) return VW_OK;

    uint8_t (*hashes)[VW_HASH_BYTES] = NULL;
    uint32_t count = 0;
    vw_err_t rc = replica_collect_referenced_chunks(ctx->data_dir, &hashes, &count);
    if (rc != VW_OK) return rc;

    for (uint32_t base = 0; base < count; base += 1024u) {
        uint16_t batch = (uint16_t)((count - base) > 1024u ? 1024u : (count - base));

        uint8_t local_bitmask[128];
        memset(local_bitmask, 0, sizeof(local_bitmask));
        rc = vw_storage_chunk_query(ctx->chunks,
                                     (const uint8_t (*)[VW_HASH_BYTES])(hashes + base),
                                     batch, local_bitmask);
        if (rc != VW_OK) { free(hashes); return rc; }

        uint8_t (*missing)[VW_HASH_BYTES] =
            (uint8_t (*)[VW_HASH_BYTES])malloc((size_t)batch * VW_HASH_BYTES);
        if (!missing) { free(hashes); return VW_ERR_OOM; }
        uint16_t missing_count = 0;
        for (uint16_t i = 0; i < batch; i++) {
            int have = (local_bitmask[i / 8] >> (7 - (i % 8))) & 1;
            if (!have) memcpy(missing[missing_count++], hashes[base + i], VW_HASH_BYTES);
        }
        if (missing_count == 0) { free(missing); continue; }

        uint32_t qlen = 2u + (uint32_t)missing_count * VW_HASH_BYTES;
        uint8_t *qbuf = (uint8_t *)malloc(qlen);
        if (!qbuf) { free(missing); free(hashes); return VW_ERR_OOM; }
        vw_write_u16le(qbuf, missing_count);
        memcpy(qbuf + 2, missing, (size_t)missing_count * VW_HASH_BYTES);
        rc = vw_proto_send(conn, VW_MSG_CLUSTER_CHUNK_QUERY, qbuf, qlen);
        free(qbuf);
        if (rc != VW_OK) { free(missing); free(hashes); return rc; }

        vw_msg_type_t rtype;
        uint32_t rplen = 0;
        rc = vw_proto_recv(conn, &rtype, recv_buf, VW_MAX_MSG_BYTES, &rplen);
        if (rc != VW_OK) { free(missing); free(hashes); return rc; }
        if (rtype != VW_MSG_CLUSTER_CHUNK_QUERY_RESP || rplen < 2u) {
            free(missing); free(hashes); return VW_ERR_PROTO_INVALID;
        }
        uint16_t resp_count = vw_read_u16le(recv_buf);
        uint32_t bitmask_bytes = resp_count == 0u ? 0u : (resp_count + 7u) / 8u;
        if (resp_count != missing_count || rplen < 2u + bitmask_bytes) {
            free(missing); free(hashes); return VW_ERR_PROTO_INVALID;
        }
        uint8_t primary_bitmask[128];
        memcpy(primary_bitmask, recv_buf + 2, bitmask_bytes);

        for (uint16_t i = 0; i < missing_count; i++) {
            int on_primary = (primary_bitmask[i / 8] >> (7 - (i % 8))) & 1;
            if (!on_primary) continue;  /* GC gating should prevent this; skip defensively */

            rc = vw_proto_send(conn, VW_MSG_CLUSTER_CHUNK_FETCH, missing[i], VW_HASH_BYTES);
            if (rc != VW_OK) { free(missing); free(hashes); return rc; }

            vw_msg_type_t dtype;
            uint32_t dplen = 0;
            rc = vw_proto_recv(conn, &dtype, recv_buf, VW_MAX_MSG_BYTES, &dplen);
            if (rc != VW_OK) { free(missing); free(hashes); return rc; }
            if (dtype == VW_MSG_ERROR) continue;  /* primary no longer has it; skip defensively */
            if (dtype != VW_MSG_CLUSTER_CHUNK_DATA || dplen < VW_HASH_BYTES + 4u) {
                free(missing); free(hashes); return VW_ERR_PROTO_INVALID;
            }
            uint32_t data_len = vw_read_u32le(recv_buf + VW_HASH_BYTES);
            if (dplen < VW_HASH_BYTES + 4u + data_len) {
                free(missing); free(hashes); return VW_ERR_PROTO_TRUNCATED;
            }
            rc = vw_storage_chunk_put_replicated(ctx->chunks, recv_buf,
                                                  recv_buf + VW_HASH_BYTES + 4u, data_len);
            if (rc != VW_OK) { free(missing); free(hashes); return rc; }
        }

        free(missing);
    }

    rc = replica_reconcile_chunk_refcounts(ctx->chunks, hashes, count);
    free(hashes);
    return rc;
}

static void replica_repl_session(vw_cluster_t *ctx)
{
    /* Connect to primary (TLS 1.3, certificate verification required).
     * Use the server's own cert as the CA cert — correct for self-signed
     * cluster setups where all nodes share the same certificate. */
    vw_conn_t *conn = NULL;
    vw_conn_opts_t copts;
    memset(&copts, 0, sizeof(copts));
    copts.connect_timeout_ms = 10000;
    copts.recv_timeout_ms    = 15000;
    vw_err_t rc = vw_net_connect_cluster(
        ctx->cfg.primary_host, ctx->cfg.primary_cluster_port,
        VW_CERT_VERIFY_REQUIRED, ctx->cert_pem_path, &copts, &conn);
    if (rc != VW_OK) {
        CL_WARN("replica: connect to %s:%u failed: %d",
                ctx->cfg.primary_host, (unsigned)ctx->cfg.primary_cluster_port, (int)rc);
        return;
    }

    /* Send NODE_HELLO.  We need our own node_id; find it by scanning the
     * nodes.db for a record with role==1 (PRIMARY self-record is role==0 on
     * primary, but replica stores its own record with role==1 on itself).
     * For TASK-049 simplicity: use node_id=0 and auth_token=zeroes as a
     * placeholder; the primary will reject this without a real node_id/token.
     * A real deployment registers the node first via the admin CLI. */
    uint64_t my_node_id = 0;
    uint8_t  my_token[32];
    memset(my_token, 0, sizeof(my_token));

    /* Scan nodes.db for a record with role==1 (our own registration). */
    {
        vw_node_record_t rec;
        for (uint64_t s = 1; s <= ctx->node_slots; s++) {
            if (nodes_pread(ctx->nodes_path, &rec, s) == 0 &&
                rec.node_id != 0 && rec.role == VW_NODE_ROLE_SELF && rec.is_active) {
                my_node_id = rec.node_id;
                /* Use the stored auth_token for authentication. */
                memcpy(my_token, rec.auth_token, 32);
                break;
            }
        }
    }

    if (my_node_id == 0) {
        CL_WARN("replica: no self-record (role=1) found in nodes.db — cannot authenticate");
        memset(my_token, 0, sizeof(my_token));
        vw_net_close(conn);
        return;
    }

    /* Build NODE_HELLO payload */
    uint64_t local_wm   = vw_oplog_last_entry_id(ctx->oplog);
    uint16_t proto_ver  = VW_PROTO_VERSION_CURRENT;
    const char *hname   = ctx->cfg.primary_host[0] ? ctx->cfg.primary_host : "replica";
    uint16_t hname_len  = (uint16_t)strlen(hname);
    if (hname_len > 127) hname_len = 127;

    uint32_t hello_len = 8u + 32u + 8u + 2u + 2u + hname_len;
    uint8_t *hello_buf = (uint8_t *)malloc(hello_len);
    if (!hello_buf) {
        memset(my_token, 0, sizeof(my_token));
        vw_net_close(conn);
        return;
    }

    uint32_t off = 0;
    vw_write_u64le(hello_buf + off, my_node_id); off += 8;
    memcpy(hello_buf + off, my_token, 32);       off += 32;
    vw_write_u64le(hello_buf + off, local_wm);   off += 8;
    vw_write_u16le(hello_buf + off, proto_ver);  off += 2;
    vw_write_u16le(hello_buf + off, hname_len);  off += 2;
    memcpy(hello_buf + off, hname, hname_len);

    memset(my_token, 0, sizeof(my_token));  /* zero token immediately after use */

    rc = vw_proto_send(conn, VW_MSG_NODE_HELLO, hello_buf, hello_len);
    memset(hello_buf, 0, hello_len); /* zero auth_token before freeing */
    free(hello_buf);
    if (rc != VW_OK) {
        CL_WARN("replica: NODE_HELLO send failed: %d", (int)rc);
        vw_net_close(conn);
        return;
    }

    /* Receive NODE_HELLO_OK or NODE_HELLO_FAIL */
    uint8_t resp_buf[16];
    vw_msg_type_t resp_type;
    uint32_t resp_len = 0;
    vw_net_conn_set_recv_timeout(conn, 15000);
    rc = vw_proto_recv(conn, &resp_type, resp_buf, sizeof(resp_buf), &resp_len);
    if (rc != VW_OK || resp_type != VW_MSG_NODE_HELLO_OK) {
        CL_WARN("replica: NODE_HELLO rejected by primary (rc=%d type=0x%04x)",
                (int)rc, (unsigned)resp_type);
        vw_net_close(conn);
        return;
    }

    /* resp_buf: primary_node_id(8) + current_last_entry_id(8) — informational. */
    uint64_t primary_last_eid = vw_read_u64le(resp_buf + 8);
    CL_INFO("replica: connected to primary; primary last_eid=%llu, local watermark=%llu",
            (unsigned long long)primary_last_eid, (unsigned long long)local_wm);

    /* Replication loop */
    uint64_t my_watermark = local_wm;
    vw_net_conn_set_recv_timeout(conn, 120000);

    /* Allocate OPLOG_DATA receive buffer once to avoid per-loop malloc. */
    uint8_t *data_buf = (uint8_t *)malloc(VW_MAX_MSG_BYTES);
    if (!data_buf) { vw_net_close(conn); return; }

    while (!atomic_load_acq(&ctx->shutdown)) {
        /* Send OPLOG_PULL */
        uint8_t pull_payload[12];
        vw_write_u64le(pull_payload + 0, my_watermark);
        vw_write_u32le(pull_payload + 8, OPLOG_PULL_MAX_ENTRIES);
        rc = vw_proto_send(conn, VW_MSG_OPLOG_PULL, pull_payload, 12);
        if (rc != VW_OK) {
            CL_WARN("replica: OPLOG_PULL send failed: %d", (int)rc);
            break;
        }

        /* Receive OPLOG_DATA */{

        vw_msg_type_t data_type;
        uint32_t data_plen = 0;
        rc = vw_proto_recv(conn, &data_type, data_buf, VW_MAX_MSG_BYTES, &data_plen);
        if (rc != VW_OK || data_type != VW_MSG_OPLOG_DATA) {
            CL_WARN("replica: expected OPLOG_DATA, got rc=%d type=0x%04x",
                    (int)rc, (unsigned)data_type);
            break;
        }

        if (data_plen < 12u) break;  /* count(4)+last_eid(8) minimum */
        uint32_t entry_count = vw_read_u32le(data_buf + 0);
        uint64_t batch_last  = vw_read_u64le(data_buf + 4);

        if (entry_count == 0) {
            /* Primary is caught up; wait before polling again. */
            replica_sleep_ms(ctx, ctx->cfg.replica_poll_interval_secs * 1000u);
            continue;
        }

        /* Apply each entry; verify CRC before applying (done inside append_raw). */
        const uint8_t *p = data_buf + 12;
        uint32_t remaining = data_plen - 12u;
        int apply_ok = 1;
        uint64_t last_applied = my_watermark;

        for (uint32_t i = 0; i < entry_count; i++) {
            if (remaining < VW_OPLOG_ENTRY_HDR_BYTES + 1u) { apply_ok = 0; break; }

            uint32_t entry_plen  = vw_read_u32le(p + 4);  /* stored_plen */
            uint32_t entry_total = VW_OPLOG_ENTRY_HDR_BYTES + entry_plen;
            if (entry_total > remaining) { apply_ok = 0; break; }

            uint64_t this_eid = vw_read_u64le(p + 8);
            rc = vw_oplog_append_raw(ctx->oplog, p, entry_total, this_eid);
            if (rc == VW_ERR_PROTO_INVALID) {
                CL_WARN("replica: CRC/sequence error on entry %llu — reconnecting",
                        (unsigned long long)this_eid);
                apply_ok = 0;
                break;
            }
            if (rc != VW_OK) {
                CL_WARN("replica: vw_oplog_append_raw failed: %d", (int)rc);
                apply_ok = 0;
                break;
            }

            last_applied  = this_eid;
            p            += entry_total;
            remaining    -= entry_total;
        }

        if (!apply_ok) break;

        /* TASK-172: run one file/chunk sync pass for this batch before
         * advancing/acking the watermark — the oplog entries themselves
         * carry no usable content, only a "something changed" signal
         * (docs/PROTOCOL.md §7.7). A failure here reconnects (backoff
         * retries the whole batch — safe: hash comparison makes both the
         * file and chunk passes idempotent). */
        {
            int versions_changed = 0;
            rc = replica_run_file_sync_pass(ctx, conn, data_buf, &versions_changed);
            if (rc != VW_OK) {
                CL_WARN("replica: file sync pass failed: %d — reconnecting", (int)rc);
                break;
            }
            if (versions_changed) {
                rc = replica_run_chunk_sync_pass(ctx, conn, data_buf);
                if (rc != VW_OK) {
                    CL_WARN("replica: chunk sync pass failed: %d — reconnecting", (int)rc);
                    break;
                }
            }
        }

        my_watermark = last_applied;

        /* Send OPLOG_ACK */
        uint8_t ack_payload[8];
        vw_write_u64le(ack_payload, my_watermark);
        rc = vw_proto_send(conn, VW_MSG_OPLOG_ACK, ack_payload, 8);
        if (rc != VW_OK) {
            CL_WARN("replica: OPLOG_ACK send failed: %d", (int)rc);
            break;
        }

        CL_DEBUG("replica: applied entries up to %llu, sent ACK",
                 (unsigned long long)my_watermark);
        (void)batch_last;  /* informational only */
        }  /* end OPLOG_DATA receive block */
    }

    free(data_buf);
    vw_net_close(conn);
}

#ifdef _WIN32
static DWORD WINAPI replica_thread_fn(LPVOID arg)
{
    vw_cluster_t *ctx = (vw_cluster_t *)arg;
    uint32_t backoff_ms = REPLICA_BACKOFF_INIT_MS;
    while (!atomic_load_acq(&ctx->shutdown)) {
        replica_repl_session(ctx);
        if (atomic_load_acq(&ctx->shutdown)) break;
        CL_INFO("replica: reconnecting in %u ms", backoff_ms);
        replica_sleep_ms(ctx, backoff_ms);
        backoff_ms = (backoff_ms * 2u < REPLICA_BACKOFF_MAX_MS)
                     ? backoff_ms * 2u : REPLICA_BACKOFF_MAX_MS;
    }
    return 0;
}
#else
static void *replica_thread_fn(void *arg)
{
    vw_cluster_t *ctx = (vw_cluster_t *)arg;
    uint32_t backoff_ms = REPLICA_BACKOFF_INIT_MS;
    while (!atomic_load_acq(&ctx->shutdown)) {
        replica_repl_session(ctx);
        if (atomic_load_acq(&ctx->shutdown)) break;
        CL_INFO("replica: reconnecting in %u ms", backoff_ms);
        replica_sleep_ms(ctx, backoff_ms);
        backoff_ms = (backoff_ms * 2u < REPLICA_BACKOFF_MAX_MS)
                     ? backoff_ms * 2u : REPLICA_BACKOFF_MAX_MS;
    }
    return NULL;
}
#endif

/* ── Public API ────────────────────────────────────────────────────────────── */

vw_err_t vw_cluster_open(const char *data_dir,
                          const vw_cluster_cfg_t *cfg,
                          const char *cert_pem_path,
                          const char *key_pem_path,
                          vw_oplog_t *oplog,
                          vw_store_t *store,
                          vw_file_store_t *file_store,
                          vw_storage_t *chunks,
                          vw_share_store_t *share_store,
                          vw_vault_store_t *vault_store,
                          vw_cluster_t **out)
{
    if (!data_dir || !cfg || !cert_pem_path || !key_pem_path || !oplog || !out ||
        !store || !file_store || !chunks)
        return VW_ERR_INVALID_ARG;

    vw_cluster_t *ctx = (vw_cluster_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->cfg         = *cfg;
    ctx->oplog       = oplog;
    ctx->store       = store;
    ctx->file_store  = file_store;
    ctx->chunks      = chunks;
    ctx->share_store = share_store;
    ctx->vault_store = vault_store;
    snprintf(ctx->cert_pem_path, sizeof(ctx->cert_pem_path), "%s", cert_pem_path);
    snprintf(ctx->key_pem_path,  sizeof(ctx->key_pem_path),  "%s", key_pem_path);
    snprintf(ctx->data_dir,      sizeof(ctx->data_dir),      "%s", data_dir);

    /* Ensure cluster directory exists */
    char cluster_dir[600];
    snprintf(cluster_dir, sizeof(cluster_dir), "%s/cluster", data_dir);
    vw_err_t rc = vw_fs_ensure_dir(cluster_dir);
    if (rc != VW_OK) { free(ctx); return rc; }

    {
        size_t clen = strlen(cluster_dir);
        if (clen + 10 > sizeof(ctx->nodes_path)) { free(ctx); return VW_ERR_INVALID_ARG; }
        memcpy(ctx->nodes_path, cluster_dir, clen);
        memcpy(ctx->nodes_path + clen, "/nodes.db", 10); /* 9 chars + NUL */
    }

    rwlock_init(&ctx->nodes_lock);

    /* Initial index capacity */
    ctx->nid_to_slot_cap = 64;
    ctx->nid_to_slot = (uint32_t *)calloc((size_t)ctx->nid_to_slot_cap, sizeof(uint32_t));
    if (!ctx->nid_to_slot) { free(ctx); return VW_ERR_OOM; }

    /* Scan existing records to build the index */
    uint64_t file_size = 0;
    vw_fs_file_size(ctx->nodes_path, &file_size);
    uint64_t total_slots = file_size / sizeof(vw_node_record_t);
    ctx->node_slots  = total_slots;
    ctx->next_node_id = 1;

    for (uint64_t s = 1; s <= total_slots; s++) {
        vw_node_record_t rec;
        if (nodes_pread(ctx->nodes_path, &rec, s) != 0) continue;
        if (rec.node_id == 0) continue;

        rc = index_ensure(ctx, rec.node_id);
        if (rc != VW_OK) {
            free(ctx->nid_to_slot);
            free(ctx);
            return rc;
        }
        ctx->nid_to_slot[rec.node_id] = (uint32_t)s;
        if (rec.node_id >= ctx->next_node_id)
            ctx->next_node_id = rec.node_id + 1;
    }

    *out = ctx;
    return VW_OK;
}

void vw_cluster_close(vw_cluster_t *ctx)
{
    if (!ctx) return;
    vw_cluster_stop(ctx);
    vw_net_ctx_close(ctx->net_ctx);
    free(ctx->nid_to_slot);
    free(ctx);
}

vw_err_t vw_cluster_start(vw_cluster_t *ctx)
{
    if (!ctx) return VW_ERR_INVALID_ARG;

    atomic_store_rel(&ctx->shutdown, 0);

    /* Start primary-mode accept thread (if cluster_port is set and not a replica) */
    if (ctx->cfg.cluster_port != 0 && !ctx->cfg.is_replica) {
        vw_err_t rc = vw_net_listen_cluster(
            NULL, ctx->cfg.cluster_port,
            ctx->cert_pem_path, ctx->key_pem_path, &ctx->net_ctx);
        if (rc != VW_OK) return rc;

#ifdef _WIN32
        ctx->thread = CreateThread(NULL, 0, cluster_accept_thread, ctx, 0, NULL);
        if (!ctx->thread) {
            vw_net_ctx_close(ctx->net_ctx); ctx->net_ctx = NULL;
            return VW_ERR_IO;
        }
#else
        if (pthread_create(&ctx->thread, NULL, cluster_accept_thread, ctx) != 0) {
            vw_net_ctx_close(ctx->net_ctx); ctx->net_ctx = NULL;
            return VW_ERR_IO;
        }
#endif
        ctx->running = 1;
        CL_INFO("cluster accept thread started on port %u", (unsigned)ctx->cfg.cluster_port);
    }

    /* Start replica-mode replication thread */
    if (ctx->cfg.is_replica && ctx->cfg.primary_host[0] != '\0') {
#ifdef _WIN32
        ctx->repl_thread = CreateThread(NULL, 0, replica_thread_fn, ctx, 0, NULL);
        if (!ctx->repl_thread) {
            vw_cluster_stop(ctx);
            return VW_ERR_IO;
        }
#else
        if (pthread_create(&ctx->repl_thread, NULL, replica_thread_fn, ctx) != 0) {
            vw_cluster_stop(ctx);
            return VW_ERR_IO;
        }
#endif
        ctx->repl_running = 1;
        CL_INFO("replica replication thread started → %s:%u",
                ctx->cfg.primary_host, (unsigned)ctx->cfg.primary_cluster_port);
    }

    return VW_OK;
}

void vw_cluster_stop(vw_cluster_t *ctx)
{
    if (!ctx) return;
    atomic_store_rel(&ctx->shutdown, 1);

    if (ctx->running) {
        /* Interrupt vw_net_accept by closing the listen context. */
        if (ctx->net_ctx) {
            vw_net_ctx_close(ctx->net_ctx);
            ctx->net_ctx = NULL;
        }
#ifdef _WIN32
        WaitForSingleObject(ctx->thread, INFINITE);
        CloseHandle(ctx->thread);
#else
        pthread_join(ctx->thread, NULL);
#endif
        ctx->running = 0;
    }

    if (ctx->repl_running) {
        /* replica_repl_session will see shutdown flag and exit its loops. */
#ifdef _WIN32
        WaitForSingleObject(ctx->repl_thread, INFINITE);
        CloseHandle(ctx->repl_thread);
#else
        pthread_join(ctx->repl_thread, NULL);
#endif
        ctx->repl_running = 0;
    }
}

/* ── Node record API ───────────────────────────────────────────────────────── */

vw_err_t vw_cluster_node_add(vw_cluster_t *ctx,
                              const char *hostname,
                              uint8_t role,
                              uint64_t *out_node_id,
                              uint8_t  out_token[32])
{
    if (!ctx || !hostname || !out_node_id || !out_token) return VW_ERR_INVALID_ARG;

    vw_node_record_t rec;
    memset(&rec, 0, sizeof(rec));

    vw_err_t rc = vw_crypto_random(rec.auth_token, 32);
    if (rc != VW_OK) return rc;

    rwlock_wrlock(&ctx->nodes_lock);

    rec.node_id  = ctx->next_node_id;
    rec.is_active = 1;
    rec.role      = role;
    snprintf((char *)rec.hostname, sizeof(rec.hostname), "%s", hostname);

    uint64_t slot = ctx->node_slots + 1;
    rc = index_ensure(ctx, rec.node_id);
    if (rc != VW_OK) { rwlock_wrunlock(&ctx->nodes_lock); return rc; }

    rc = node_append_and_index(ctx, &rec, slot);
    if (rc != VW_OK) {
        memset(rec.auth_token, 0, sizeof(rec.auth_token));
        rwlock_wrunlock(&ctx->nodes_lock);
        return rc;
    }

    *out_node_id     = rec.node_id;
    ctx->next_node_id++;

    /* Return token to caller (only opportunity); zero from record copy */
    memcpy(out_token, rec.auth_token, 32);
    memset(rec.auth_token, 0, sizeof(rec.auth_token));

    rwlock_wrunlock(&ctx->nodes_lock);
    return VW_OK;
}

vw_err_t vw_cluster_node_add_self(vw_cluster_t *ctx,
                                   uint64_t node_id,
                                   const uint8_t token[32],
                                   const char *hostname)
{
    if (!ctx || node_id == 0 || !token || !hostname) return VW_ERR_INVALID_ARG;
    /* node_id is client-supplied here (via the admin socket's
     * NODE_REGISTER_SELF_REQ) — index_ensure() below enforces the
     * VW_CLUSTER_MAX_NODE_ID ceiling (TASK-086) structurally, for every
     * caller, rather than being re-checked at each call site. */

    vw_node_record_t rec;
    memset(&rec, 0, sizeof(rec));

    rwlock_wrlock(&ctx->nodes_lock);

    vw_err_t rc = index_ensure(ctx, node_id);
    if (rc != VW_OK) { rwlock_wrunlock(&ctx->nodes_lock); return rc; }

    if (ctx->nid_to_slot[node_id] != 0) {
        rwlock_wrunlock(&ctx->nodes_lock);
        return VW_ERR_ALREADY_EXISTS;
    }

    rec.node_id   = node_id;
    rec.is_active = 1;
    rec.role      = VW_NODE_ROLE_SELF;
    memcpy(rec.auth_token, token, 32);
    snprintf((char *)rec.hostname, sizeof(rec.hostname), "%s", hostname);

    uint64_t slot = ctx->node_slots + 1;

    rc = node_append_and_index(ctx, &rec, slot);
    if (rc != VW_OK) {
        memset(rec.auth_token, 0, sizeof(rec.auth_token));
        rwlock_wrunlock(&ctx->nodes_lock);
        return rc;
    }

    if (node_id >= ctx->next_node_id) ctx->next_node_id = node_id + 1;

    memset(rec.auth_token, 0, sizeof(rec.auth_token));
    rwlock_wrunlock(&ctx->nodes_lock);
    return VW_OK;
}

vw_err_t vw_cluster_node_get(vw_cluster_t *ctx,
                              uint64_t node_id,
                              vw_node_record_t *out_rec)
{
    if (!ctx || node_id == 0 || !out_rec) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->nodes_lock);
    if (node_id >= ctx->nid_to_slot_cap || ctx->nid_to_slot[node_id] == 0) {
        rwlock_rdunlock(&ctx->nodes_lock);
        return VW_ERR_NOT_FOUND;
    }
    uint64_t slot = ctx->nid_to_slot[node_id];
    int read_ok = (nodes_pread(ctx->nodes_path, out_rec, slot) == 0);
    rwlock_rdunlock(&ctx->nodes_lock);

    if (!read_ok || out_rec->node_id != node_id) return VW_ERR_NOT_FOUND;

    /* Zero auth_token — callers must not log or return it */
    memset(out_rec->auth_token, 0, sizeof(out_rec->auth_token));
    return VW_OK;
}

vw_err_t vw_cluster_node_update_watermark(vw_cluster_t *ctx,
                                            uint64_t node_id,
                                            uint64_t watermark)
{
    if (!ctx || node_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->nodes_lock);
    if (node_id >= ctx->nid_to_slot_cap || ctx->nid_to_slot[node_id] == 0) {
        rwlock_rdunlock(&ctx->nodes_lock);
        return VW_ERR_NOT_FOUND;
    }
    uint64_t slot = ctx->nid_to_slot[node_id];
    rwlock_rdunlock(&ctx->nodes_lock);

    /* sync_watermark is at offset 40 in vw_node_record_t (8+32 = 40).
     * slot is 1-based — see nodes_pread's comment. */
    uint64_t field_off = (slot - 1) * sizeof(vw_node_record_t)
                         + offsetof(vw_node_record_t, sync_watermark);

    uint8_t le[8];
    vw_write_u64le(le, watermark);
    /* Single 8-byte naturally-aligned pwrite — POSIX-atomic */
    vw_err_t rc = vw_fs_pwrite(ctx->nodes_path, field_off, le, 8);
    if (rc != VW_OK) return rc;

    /* Update in-memory index: we store only slot numbers; watermark is on disk.
     * No in-memory watermark cache needed — GC reads from disk via node_list. */
    return VW_OK;
}

vw_err_t vw_cluster_node_set_active(vw_cluster_t *ctx,
                                     uint64_t node_id,
                                     uint8_t is_active)
{
    if (!ctx || node_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&ctx->nodes_lock);
    if (node_id >= ctx->nid_to_slot_cap || ctx->nid_to_slot[node_id] == 0) {
        rwlock_wrunlock(&ctx->nodes_lock);
        return VW_ERR_NOT_FOUND;
    }
    uint64_t slot      = ctx->nid_to_slot[node_id];
    /* slot is 1-based — see nodes_pread's comment. */
    uint64_t field_off = (slot - 1) * sizeof(vw_node_record_t)
                         + offsetof(vw_node_record_t, is_active);

    vw_err_t rc = vw_fs_pwrite(ctx->nodes_path, field_off, &is_active, 1);
    if (rc == VW_OK) rc = vw_fs_sync_file(ctx->nodes_path);
    rwlock_wrunlock(&ctx->nodes_lock);
    return rc;
}

vw_err_t vw_cluster_node_list(vw_cluster_t *ctx,
                               vw_node_record_t **out_recs,
                               uint32_t *out_count)
{
    if (!ctx || !out_recs || !out_count) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->nodes_lock);
    uint64_t total = ctx->node_slots;
    rwlock_rdunlock(&ctx->nodes_lock);

    if (total == 0) { *out_recs = NULL; *out_count = 0; return VW_OK; }

    vw_node_record_t *arr = (vw_node_record_t *)malloc((size_t)total * sizeof(*arr));
    if (!arr) return VW_ERR_OOM;

    uint32_t count = 0;
    for (uint64_t s = 1; s <= total; s++) {
        vw_node_record_t rec;
        if (nodes_pread(ctx->nodes_path, &rec, s) != 0) continue;
        if (rec.node_id == 0) continue;
        /* Zero auth_token in every returned copy */
        memset(rec.auth_token, 0, sizeof(rec.auth_token));
        arr[count++] = rec;
    }

    *out_recs  = arr;
    *out_count = count;
    return VW_OK;
}

/* ── GC helpers ────────────────────────────────────────────────────────────── */

uint64_t vw_cluster_min_sync_watermark(vw_cluster_t *ctx)
{
    if (!ctx) return UINT64_MAX;

    uint64_t min_wm = UINT64_MAX;
    int      found  = 0;

    rwlock_rdlock(&ctx->nodes_lock);
    uint64_t total = ctx->node_slots;
    rwlock_rdunlock(&ctx->nodes_lock);

    for (uint64_t s = 1; s <= total; s++) {
        vw_node_record_t rec;
        if (nodes_pread(ctx->nodes_path, &rec, s) != 0) continue;
        if (rec.node_id == 0 || !rec.is_active || rec.role != 0) continue;
        if (rec.sync_watermark < min_wm) min_wm = rec.sync_watermark;
        found = 1;
    }

    return found ? min_wm : UINT64_MAX;
}

int vw_cluster_has_active_replicas(vw_cluster_t *ctx)
{
    if (!ctx) return 0;

    rwlock_rdlock(&ctx->nodes_lock);
    uint64_t total = ctx->node_slots;
    rwlock_rdunlock(&ctx->nodes_lock);

    for (uint64_t s = 1; s <= total; s++) {
        vw_node_record_t rec;
        if (nodes_pread(ctx->nodes_path, &rec, s) != 0) continue;
        if (rec.node_id != 0 && rec.is_active && rec.role == VW_NODE_ROLE_REPLICA)
            return 1;
    }
    return 0;
}

int vw_cluster_is_replica(const vw_cluster_t *ctx)
{
    if (!ctx) return 0;
    return ctx->cfg.is_replica ? 1 : 0;
}
