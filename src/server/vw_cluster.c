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

    /* Shared oplog reference (lifetime: owned by caller of vw_cluster_open) */
    vw_oplog_t *oplog;

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

static int nodes_pread(const char *path, vw_node_record_t *out, uint64_t slot)
{
    uint64_t off = slot * (uint64_t)sizeof(vw_node_record_t);
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

static vw_err_t index_ensure(vw_cluster_t *ctx, uint64_t node_id)
{
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

    uint8_t pull_buf[12];  /* from_entry_id(8) + max_entries(4) */

    for (;;) {
        if (atomic_load_acq(&ctx->shutdown)) break;

        /* Wait for OPLOG_PULL */
        vw_msg_type_t msg_type;
        uint32_t plen = 0;
        vw_err_t rc = vw_proto_recv(conn, &msg_type, pull_buf, sizeof(pull_buf), &plen);
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

        uint64_t from_eid    = vw_read_u64le(pull_buf + 0);
        uint32_t max_entries = vw_read_u32le(pull_buf + 8);
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
         * Each entry: [crc(4)][payload_len(4)][...] → total = 17 + payload_len.
         * Guard against uint32_t overflow in entries_bytes accumulation. */
        uint32_t entries_bytes = 0;
        if (entries_buf && entries_count > 0) {
            const uint8_t *p = entries_buf;
            for (uint32_t i = 0; i < entries_count; i++) {
                uint32_t plen_field = vw_read_u32le(p + 4);  /* stored_plen */
                uint32_t e_total    = 17u + plen_field;
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

        /* Wait for OPLOG_ACK */
        uint8_t ack_buf[8];
        rc = vw_proto_recv(conn, &msg_type, ack_buf, sizeof(ack_buf), &plen);
        if (rc != VW_OK) {
            CL_DEBUG("primary: OPLOG_ACK recv failed for node %llu: %d",
                     (unsigned long long)node_id, (int)rc);
            break;
        }
        if (msg_type != VW_MSG_OPLOG_ACK || plen != 8) {
            CL_WARN("primary: expected OPLOG_ACK from node %llu, got 0x%04x",
                    (unsigned long long)node_id, (unsigned)msg_type);
            break;
        }

        uint64_t confirmed_eid = vw_read_u64le(ack_buf);
        vw_cluster_node_update_watermark(ctx, node_id, confirmed_eid);
        CL_DEBUG("primary: node %llu acked entry_id %llu",
                 (unsigned long long)node_id, (unsigned long long)confirmed_eid);
    }
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
    vw_err_t rc = vw_net_connect(
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
            if (remaining < 17u + 1u) { apply_ok = 0; break; }

            uint32_t entry_plen  = vw_read_u32le(p + 4);  /* stored_plen */
            uint32_t entry_total = 17u + entry_plen;
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
                          vw_cluster_t **out)
{
    if (!data_dir || !cfg || !cert_pem_path || !key_pem_path || !oplog || !out)
        return VW_ERR_INVALID_ARG;

    vw_cluster_t *ctx = (vw_cluster_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->cfg   = *cfg;
    ctx->oplog = oplog;
    snprintf(ctx->cert_pem_path, sizeof(ctx->cert_pem_path), "%s", cert_pem_path);
    snprintf(ctx->key_pem_path,  sizeof(ctx->key_pem_path),  "%s", key_pem_path);

    /* Ensure cluster directory exists */
    char cluster_dir[600];
    snprintf(cluster_dir, sizeof(cluster_dir), "%s/cluster", data_dir);
    vw_err_t rc = vw_fs_ensure_dir(cluster_dir);
    if (rc != VW_OK) { free(ctx); return rc; }

    snprintf(ctx->nodes_path, sizeof(ctx->nodes_path), "%s/nodes.db", cluster_dir);

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

    /* Append the record to the file */
    rc = vw_fs_append(ctx->nodes_path, &rec, sizeof(rec));
    if (rc != VW_OK) {
        memset(rec.auth_token, 0, sizeof(rec.auth_token));
        rwlock_wrunlock(&ctx->nodes_lock);
        return rc;
    }

    /* Sync to ensure durability before returning the token */
    rc = vw_fs_sync_file(ctx->nodes_path);
    if (rc != VW_OK) {
        memset(rec.auth_token, 0, sizeof(rec.auth_token));
        rwlock_wrunlock(&ctx->nodes_lock);
        return rc;
    }

    ctx->nid_to_slot[rec.node_id] = (uint32_t)slot;
    ctx->node_slots  = slot;
    *out_node_id     = rec.node_id;
    ctx->next_node_id++;

    /* Return token to caller (only opportunity); zero from record copy */
    memcpy(out_token, rec.auth_token, 32);
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

    /* sync_watermark is at offset 40 in vw_node_record_t (8+32 = 40) */
    uint64_t field_off = slot * sizeof(vw_node_record_t)
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
    uint64_t field_off = slot * sizeof(vw_node_record_t)
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
