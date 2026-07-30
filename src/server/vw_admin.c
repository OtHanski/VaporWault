/* _GNU_SOURCE must precede all system headers to expose struct ucred
 * (SO_PEERCRED) and other Linux-specific extensions. */
#define _GNU_SOURCE

/*
 * vw_admin.c — admin IPC server for VaporWault.
 *
 * POSIX-only implementation. On Windows, the start/stop functions are stubs.
 * See vw_admin.h for the wire format.
 *
 * SRV.01 [2026-07-12]: TASK-040 implementation.
 */

#include "vw_admin.h"
#include "vw_auth.h"      /* vw_auth_hash_password */
#include "../core/vw_crypto.h"  /* vw_crypto_sha256 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>  /* offsetof */

/* ── Windows stubs ─────────────────────────────────────────────────────────── */

#ifdef _WIN32

struct vw_admin_server { int _dummy; };

vw_err_t vw_admin_server_start(const char *socket_path, const vw_admin_ctx_t *ctx,
                                vw_admin_server_t **out)
{
    (void)socket_path; (void)ctx;
    *out = NULL;
    return VW_OK;
}

void vw_admin_server_stop(vw_admin_server_t *srv) { (void)srv; }

#else /* POSIX */

#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#if defined(LOCAL_PEERCRED)
#   include <sys/ucred.h>
#endif

/* TASK-077: secrets (password hashes/salts, tokens) must be cleared with a
 * memset the optimizer cannot prove dead and elide — a plain memset()
 * immediately followed by free()/return can be optimized away, leaving the
 * secret in freed/stack memory. Same pattern as vw_auth.c's secure_zero. */
static void *(* volatile g_memset_fn)(void *, int, size_t) = memset;
#define secure_zero(p, n) ((void)(g_memset_fn)((p), 0, (size_t)(n)))

/* ── Frame helpers ─────────────────────────────────────────────────────────── */

#define ADMIN_HDR_SIZE      8u
#define ADMIN_MAX_PAYLOAD   65520u  /* 64 KiB - 16 bytes headroom */
#define ADMIN_PROTO_VER     1u

static void w16le(uint8_t *b, uint16_t v) {
    b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8);
}
static void w32le(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)v;       b[1] = (uint8_t)(v >>  8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}
static void w64le(uint8_t *b, uint64_t v) {
    w32le(b,     (uint32_t)v);
    w32le(b + 4, (uint32_t)(v >> 32));
}
static uint16_t r16le(const uint8_t *b) {
    return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}
static uint32_t r32le(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static uint64_t r64le(const uint8_t *b) {
    return (uint64_t)r32le(b) | ((uint64_t)r32le(b + 4) << 32);
}

static int recv_all(int fd, void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = recv(fd, (char *)buf + done, n - done, 0);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t s = send(fd, (const char *)buf + done, n - done, MSG_NOSIGNAL);
        if (s <= 0) return -1;
        done += (size_t)s;
    }
    return 0;
}

static int send_frame(int fd, uint16_t msg_type,
                       const uint8_t *payload, uint32_t plen)
{
    uint8_t hdr[ADMIN_HDR_SIZE];
    w32le(hdr,     plen + ADMIN_HDR_SIZE);
    w16le(hdr + 4, msg_type);
    w16le(hdr + 6, ADMIN_PROTO_VER);
    if (send_all(fd, hdr, sizeof(hdr)) < 0) return -1;
    if (plen && payload && send_all(fd, payload, plen) < 0) return -1;
    return 0;
}

/* Send a response with only a u32 error code. */
static void send_u32_resp(int fd, vw_admin_msg_t type, vw_err_t rc)
{
    uint8_t resp[4];
    w32le(resp, (uint32_t)rc);
    send_frame(fd, (uint16_t)type, resp, sizeof(resp));
}

/* ── Request handlers ──────────────────────────────────────────────────────── */

typedef struct vw_admin_server vw_admin_server_t;

struct vw_admin_server {
    int              sock_fd;
    volatile int     shutdown;
    pthread_t        thread;
    vw_admin_ctx_t   ctx;
    char             socket_path[108]; /* AF_UNIX sun_path max; unlinked on stop */
};

static void handle_user_create(vw_admin_server_t *srv, int fd,
                                const uint8_t *p, uint32_t plen)
{
    uint8_t          is_admin;
    uint16_t         uname_len, pw_len;
    char             username[65];
    uint8_t          hash[32], salt[16];
    vw_user_record_t rec;
    uint64_t         uid = 0;
    vw_err_t         rc;
    uint8_t          resp[12]; /* u32 error_code + u64 user_id */

    if (plen < 5u) { send_u32_resp(fd, VW_ADMIN_USER_CREATE_RESP, VW_ERR_INVALID_ARG); return; }

    is_admin  = p[0];
    uname_len = r16le(p + 1);
    if (uname_len == 0 || uname_len > 63u || plen < (uint32_t)(3u + uname_len + 2u)) {
        send_u32_resp(fd, VW_ADMIN_USER_CREATE_RESP, VW_ERR_INVALID_ARG); return;
    }
    memcpy(username, p + 3, uname_len);
    username[uname_len] = '\0';

    pw_len = r16le(p + 3 + uname_len);
    if (pw_len == 0 || plen < (uint32_t)(3u + uname_len + 2u + pw_len)) {
        send_u32_resp(fd, VW_ADMIN_USER_CREATE_RESP, VW_ERR_INVALID_ARG); return;
    }

    /* Every stored credential is Argon2id(SHA-256(password)) — hash the raw
     * operator password here first so admin-created accounts match what
     * login verification expects. */
    {
        uint8_t pw_token[32];
        rc = vw_crypto_sha256(p + 3 + uname_len + 2, pw_len, pw_token);
        if (rc != VW_OK) {
            secure_zero(pw_token, sizeof(pw_token));
            send_u32_resp(fd, VW_ADMIN_USER_CREATE_RESP, rc); return;
        }
        rc = vw_auth_hash_password(pw_token, sizeof(pw_token), hash, salt);
        secure_zero(pw_token, sizeof(pw_token));
    }
    if (rc != VW_OK) {
        secure_zero(hash, sizeof(hash)); secure_zero(salt, sizeof(salt));
        send_u32_resp(fd, VW_ADMIN_USER_CREATE_RESP, rc); return;
    }

    memset(&rec, 0, sizeof(rec));
    memcpy(rec.username, username, uname_len + 1);
    memcpy(rec.password_hash, hash, 32);
    memcpy(rec.password_salt, salt, 16);
    secure_zero(hash, sizeof(hash)); secure_zero(salt, sizeof(salt));
    rec.is_admin  = is_admin ? 1 : 0;
    rec.is_active = 1;

    rc = vw_store_user_create(srv->ctx.store, &rec, &uid);
    secure_zero(rec.password_hash, sizeof(rec.password_hash));
    secure_zero(rec.password_salt, sizeof(rec.password_salt));

    w32le(resp,     (uint32_t)rc);
    w64le(resp + 4, uid);
    send_frame(fd, VW_ADMIN_USER_CREATE_RESP, resp, sizeof(resp));
}

/* Callback context for user-list collection */
typedef struct {
    uint8_t  *buf;
    size_t    cap;
    size_t    len;
    uint32_t  count;
    vw_store_t *store;
} ulist_ctx_t;

/* u64 user_id(8) + u8 is_admin(1) + u8 is_active(1) + u8[2] pad(2)
 * + u8[64] username(64) + u64 quota_bytes(8) + u64 used_bytes(8)
 * + u32 admin_caps(4, TASK-092 — appended, does not disturb prior fields) = 96 */
#define ULIST_ENTRY_SIZE 96u

static int ulist_cb(const vw_user_record_t *rec, void *ud)
{
    ulist_ctx_t       *c = (ulist_ctx_t *)ud;
    vw_quota_record_t  quota;
    uint8_t            entry[ULIST_ENTRY_SIZE];
    uint64_t           quota_bytes = 0, used_bytes = 0;

    /* Grow buffer if needed */
    if (c->len + ULIST_ENTRY_SIZE > c->cap) {
        size_t   new_cap = c->cap ? c->cap * 2 : 4096u;
        uint8_t *p = (uint8_t *)realloc(c->buf, new_cap);
        if (!p) return 1; /* stop — OOM */
        c->buf = p; c->cap = new_cap;
    }

    if (vw_store_quota_get(c->store, rec->user_id, &quota) == VW_OK) {
        quota_bytes = quota.quota_bytes;
        used_bytes  = quota.used_bytes;
    }

    memset(entry, 0, sizeof(entry));
    w64le(entry,      rec->user_id);
    entry[8]  = rec->is_admin;
    entry[9]  = rec->is_active;
    /* entry[10..11] = pad (zeroed by memset) */
    memcpy(entry + 12, rec->username, 64);
    w64le(entry + 76, quota_bytes);
    w64le(entry + 84, used_bytes);
    w32le(entry + 92, rec->admin_caps);

    memcpy(c->buf + c->len, entry, ULIST_ENTRY_SIZE);
    c->len   += ULIST_ENTRY_SIZE;
    c->count++;
    return 0;
}

static void handle_user_list(vw_admin_server_t *srv, int fd)
{
    ulist_ctx_t  uc;
    uint8_t      hdr[4];
    vw_err_t     rc;

    memset(&uc, 0, sizeof(uc));
    uc.store = srv->ctx.store;

    rc = vw_store_user_scan(srv->ctx.store, ulist_cb, &uc);
    if (rc != VW_OK) {
        free(uc.buf);
        send_u32_resp(fd, VW_ADMIN_USER_LIST_RESP, rc);
        return;
    }

    /* Build response: u32 count + entries */
    w32le(hdr, uc.count);
    {
        uint8_t frm_hdr[ADMIN_HDR_SIZE];
        uint32_t total = (uint32_t)(ADMIN_HDR_SIZE + 4u + uc.len);
        w32le(frm_hdr,     total);
        w16le(frm_hdr + 4, (uint16_t)VW_ADMIN_USER_LIST_RESP);
        w16le(frm_hdr + 6, ADMIN_PROTO_VER);
        send_all(fd, frm_hdr, ADMIN_HDR_SIZE);
        send_all(fd, hdr, 4);
        if (uc.len) send_all(fd, uc.buf, uc.len);
    }
    free(uc.buf);
}

static void handle_set_quota(vw_admin_server_t *srv, int fd,
                              const uint8_t *p, uint32_t plen)
{
    uint16_t         uname_len;
    char             username[65];
    uint64_t         quota_bytes;
    vw_user_record_t rec;
    vw_err_t         rc;

    if (plen < 3u) { send_u32_resp(fd, VW_ADMIN_SET_QUOTA_RESP, VW_ERR_INVALID_ARG); return; }

    uname_len = r16le(p);
    if (uname_len == 0 || uname_len > 63u || plen < (uint32_t)(2u + uname_len + 8u)) {
        send_u32_resp(fd, VW_ADMIN_SET_QUOTA_RESP, VW_ERR_INVALID_ARG); return;
    }
    memcpy(username, p + 2, uname_len);
    username[uname_len] = '\0';
    quota_bytes = r64le(p + 2 + uname_len);

    rc = vw_store_user_get_by_username(srv->ctx.store, username, &rec);
    if (rc != VW_OK) {
        secure_zero(&rec, sizeof(rec)); /* rec may be partially written */
        send_u32_resp(fd, VW_ADMIN_SET_QUOTA_RESP, rc); return;
    }

    rc = vw_store_quota_set(srv->ctx.store, rec.user_id, quota_bytes);

    /* SEC.07 [2026-07-12]: Log every quota change to the audit oplog.
     * ARCH.00 required this; the original implementation omitted it.
     * Payload: u64 user_id (8 bytes) + u64 new_quota_bytes (8 bytes).
     * We use VW_OPLOG_USER_WRITE because quota is part of the user record.
     * Logging is best-effort: a log failure does not roll back the store write,
     * but it is surfaced as a WARNING so operators notice log inconsistencies. */
    if (rc == VW_OK && srv->ctx.oplog) {
        uint8_t oplog_payload[16];
        w64le(oplog_payload,     rec.user_id);
        w64le(oplog_payload + 8, quota_bytes);
        uint64_t eid = 0;
        vw_err_t log_rc = vw_oplog_append(srv->ctx.oplog, VW_OPLOG_USER_WRITE,
                                           oplog_payload, sizeof(oplog_payload),
                                           &eid);
        if (log_rc == VW_OK)
            vw_oplog_confirm(srv->ctx.oplog, eid);
        else
            (void)fprintf(stderr,
                "[WARN] admin: set-quota oplog append failed (rc=%d) "
                "for user_id=%llu — quota was changed but audit log is incomplete\n",
                (int)log_rc, (unsigned long long)rec.user_id);
    }

    secure_zero(&rec, sizeof(rec)); /* zero password_hash/salt from the fetched record */
    send_u32_resp(fd, VW_ADMIN_SET_QUOTA_RESP, rc);
}

/* TASK-092: set (replace) a user's fine-grained admin capability bitmask.
 * Only meaningful for is_admin==1 targets; see vw_admin_cap_t in vw_proto.h
 * for the "caps==0 means full/legacy admin" convention. */
static void handle_set_admin_caps(vw_admin_server_t *srv, int fd,
                                    const uint8_t *p, uint32_t plen)
{
    uint16_t         uname_len;
    char             username[65];
    uint32_t         caps;
    vw_user_record_t rec;
    vw_err_t         rc;

    if (plen < 3u) { send_u32_resp(fd, VW_ADMIN_SET_CAPS_RESP, VW_ERR_INVALID_ARG); return; }

    uname_len = r16le(p);
    if (uname_len == 0 || uname_len > 63u || plen < (uint32_t)(2u + uname_len + 4u)) {
        send_u32_resp(fd, VW_ADMIN_SET_CAPS_RESP, VW_ERR_INVALID_ARG); return;
    }
    memcpy(username, p + 2, uname_len);
    username[uname_len] = '\0';
    caps = r32le(p + 2 + uname_len);

    rc = vw_store_user_get_by_username(srv->ctx.store, username, &rec);
    if (rc != VW_OK) {
        secure_zero(&rec, sizeof(rec));
        send_u32_resp(fd, VW_ADMIN_SET_CAPS_RESP, rc); return;
    }

    rc = vw_store_user_update_field(srv->ctx.store, rec.user_id,
                                     (uint32_t)offsetof(vw_user_record_t, admin_caps),
                                     &caps, sizeof(caps));

    /* Audit log — same best-effort convention as handle_set_quota above. */
    if (rc == VW_OK && srv->ctx.oplog) {
        uint8_t oplog_payload[12];
        w64le(oplog_payload, rec.user_id);
        w32le(oplog_payload + 8, caps);
        uint64_t eid = 0;
        vw_err_t log_rc = vw_oplog_append(srv->ctx.oplog, VW_OPLOG_USER_WRITE,
                                           oplog_payload, sizeof(oplog_payload),
                                           &eid);
        if (log_rc == VW_OK)
            vw_oplog_confirm(srv->ctx.oplog, eid);
        else
            (void)fprintf(stderr,
                "[WARN] admin: set-admin-caps oplog append failed (rc=%d) "
                "for user_id=%llu — capabilities were changed but audit log "
                "is incomplete\n",
                (int)log_rc, (unsigned long long)rec.user_id);
    }

    secure_zero(&rec, sizeof(rec));
    send_u32_resp(fd, VW_ADMIN_SET_CAPS_RESP, rc);
}

/* Callback context for oplog tail */
#define TAIL_MAX 100u

typedef struct {
    uint64_t entry_id[TAIL_MAX];
    uint8_t  op_type[TAIL_MAX];
    uint32_t write_pos;   /* circular: next slot to overwrite */
    uint32_t total_seen;
    uint32_t max_count;   /* requested count <= TAIL_MAX */
} tail_ctx_t;

static int tail_cb(uint64_t entry_id, vw_oplog_op_t op_type,
                   const void *payload, uint32_t payload_len, void *ud)
{
    tail_ctx_t *tc = (tail_ctx_t *)ud;
    uint32_t    idx = tc->write_pos % TAIL_MAX;
    (void)payload; (void)payload_len;
    tc->entry_id[idx] = entry_id;
    tc->op_type[idx]  = (uint8_t)op_type;
    tc->write_pos      = (tc->write_pos + 1) % TAIL_MAX;
    tc->total_seen++;
    return 0;
}

static void handle_oplog_tail(vw_admin_server_t *srv, int fd,
                               const uint8_t *p, uint32_t plen)
{
    uint32_t   count = 20;
    tail_ctx_t tc;
    uint32_t   stored, i;
    uint8_t    frm_hdr[ADMIN_HDR_SIZE];
    uint8_t    cnt_buf[4];

    if (plen >= 4u) {
        count = r32le(p);
        if (count > TAIL_MAX) count = TAIL_MAX;
        if (count == 0) count = 20;
    }

    memset(&tc, 0, sizeof(tc));
    tc.max_count = count;
    vw_oplog_replay_from(srv->ctx.oplog, 0, tail_cb, &tc);

    /* How many entries are in the circular buffer? */
    stored = tc.total_seen < TAIL_MAX ? tc.total_seen : TAIL_MAX;
    if (stored > count) stored = count;

    /* Compute frame size: 8 hdr + 4 count + stored * 16 */
    {
        uint32_t entry_sz   = 16u;   /* u64 entry_id + u8 op_type + u8[7] pad */
        uint32_t payload_sz = 4u + stored * entry_sz;
        uint32_t total      = ADMIN_HDR_SIZE + payload_sz;
        w32le(frm_hdr,     total);
        w16le(frm_hdr + 4, (uint16_t)VW_ADMIN_OPLOG_TAIL_RESP);
        w16le(frm_hdr + 6, ADMIN_PROTO_VER);
        send_all(fd, frm_hdr, ADMIN_HDR_SIZE);

        w32le(cnt_buf, stored);
        send_all(fd, cnt_buf, 4);

        /* Read last `stored` entries in chronological order.
         * oldest_idx: first (oldest) entry to send in the circular buffer. */
        uint32_t oldest_idx;
        if (tc.total_seen <= TAIL_MAX) {
            oldest_idx = tc.total_seen - stored;
        } else {
            oldest_idx = (tc.write_pos + TAIL_MAX - stored) % TAIL_MAX;
        }
        for (i = 0; i < stored; i++) {
            uint32_t idx = (oldest_idx + i) % TAIL_MAX;
            uint8_t entry[16];
            memset(entry, 0, sizeof(entry));
            w64le(entry,    tc.entry_id[idx]);
            entry[8] = tc.op_type[idx];
            send_all(fd, entry, sizeof(entry));
        }
    }
}

/* u64 conn_id(8) + u64 user_id(8) + i64 connected_since(8) + u8[64] peer_addr(64) = 88 */
#define CONN_ENTRY_SIZE 88u

static void handle_conn_list(vw_admin_server_t *srv, int fd)
{
    vw_conn_info_t *entries = NULL;
    uint32_t        count   = 0;

    if (srv->ctx.conn_registry) {
        if (vw_conn_registry_list(srv->ctx.conn_registry, &entries, &count) != VW_OK) {
            entries = NULL;
            count   = 0;
        }
    }

    {
        uint8_t  frm_hdr[ADMIN_HDR_SIZE];
        uint8_t  cnt_buf[4];
        uint32_t total = (uint32_t)(ADMIN_HDR_SIZE + 4u + count * CONN_ENTRY_SIZE);
        uint32_t i;

        w32le(frm_hdr,     total);
        w16le(frm_hdr + 4, (uint16_t)VW_ADMIN_CONN_LIST_RESP);
        w16le(frm_hdr + 6, ADMIN_PROTO_VER);
        send_all(fd, frm_hdr, ADMIN_HDR_SIZE);

        w32le(cnt_buf, count);
        send_all(fd, cnt_buf, 4);

        for (i = 0; i < count; i++) {
            uint8_t entry[CONN_ENTRY_SIZE];
            size_t  n = strnlen(entries[i].peer_addr, sizeof(entries[i].peer_addr));
            memset(entry, 0, sizeof(entry));
            w64le(entry,      entries[i].conn_id);
            w64le(entry + 8,  entries[i].user_id);
            w64le(entry + 16, (uint64_t)entries[i].connected_since);
            memcpy(entry + 24, entries[i].peer_addr, n);
            send_all(fd, entry, sizeof(entry));
        }
    }

    free(entries);
}

#undef CONN_ENTRY_SIZE

static void handle_reload_cert(vw_admin_server_t *srv, int fd)
{
    /* Phase 5: cert reload is triggered via SIGHUP on the server process.
     * The admin channel does not currently hold a reference to net_ctx. */
    (void)srv;
    send_u32_resp(fd, VW_ADMIN_RELOAD_CERT_RESP, VW_ERR_INVALID_ARG);
}

static void handle_node_add(vw_admin_server_t *srv, int fd,
                             const uint8_t *p, uint32_t plen)
{
    uint16_t hlen;
    char     hostname[128];
    uint64_t node_id = 0;
    uint8_t  token[32];
    vw_err_t rc;
    uint8_t  resp[44]; /* u32 error_code + u64 node_id + u8[32] auth_token */

    if (!srv->ctx.cluster) {
        send_u32_resp(fd, VW_ADMIN_NODE_ADD_RESP, VW_ERR_INVALID_ARG);
        return;
    }
    if (plen < 2u) { send_u32_resp(fd, VW_ADMIN_NODE_ADD_RESP, VW_ERR_INVALID_ARG); return; }

    hlen = r16le(p);
    if (hlen == 0 || hlen > 127u || plen < (uint32_t)(2u + hlen)) {
        send_u32_resp(fd, VW_ADMIN_NODE_ADD_RESP, VW_ERR_INVALID_ARG); return;
    }
    memcpy(hostname, p + 2, hlen);
    hostname[hlen] = '\0';

    rc = vw_cluster_node_add(srv->ctx.cluster, hostname, VW_NODE_ROLE_REPLICA,
                              &node_id, token);

    memset(resp, 0, sizeof(resp));
    w32le(resp, (uint32_t)rc);
    if (rc == VW_OK) {
        w64le(resp + 4, node_id);
        memcpy(resp + 12, token, 32);
    }
    send_frame(fd, VW_ADMIN_NODE_ADD_RESP, resp, sizeof(resp));
    secure_zero(token, sizeof(token));
    secure_zero(resp, sizeof(resp)); /* auth_token must not linger in memory */
}

static void handle_node_register_self(vw_admin_server_t *srv, int fd,
                                       const uint8_t *p, uint32_t plen)
{
    uint64_t node_id;
    uint8_t  token[32];
    uint16_t hlen;
    char     hostname[128];
    vw_err_t rc;

    if (!srv->ctx.cluster) {
        send_u32_resp(fd, VW_ADMIN_NODE_REGISTER_SELF_RESP, VW_ERR_INVALID_ARG);
        return;
    }
    if (plen < 8u + 32u + 2u) {
        send_u32_resp(fd, VW_ADMIN_NODE_REGISTER_SELF_RESP, VW_ERR_INVALID_ARG);
        return;
    }

    node_id = r64le(p);
    memcpy(token, p + 8, 32);
    hlen = r16le(p + 40);
    if (hlen == 0 || hlen > 127u || plen < (uint32_t)(42u + hlen)) {
        secure_zero(token, sizeof(token));
        send_u32_resp(fd, VW_ADMIN_NODE_REGISTER_SELF_RESP, VW_ERR_INVALID_ARG);
        return;
    }
    memcpy(hostname, p + 42, hlen);
    hostname[hlen] = '\0';

    rc = vw_cluster_node_add_self(srv->ctx.cluster, node_id, token, hostname);
    secure_zero(token, sizeof(token));
    send_u32_resp(fd, VW_ADMIN_NODE_REGISTER_SELF_RESP, rc);
}

/* u64 file_id(8) + i64 deleted_at(8) + u8[64] name(64) = 80 */
#define DELETED_ENTRY_SIZE 80u

typedef struct {
    uint8_t  *buf;
    size_t    cap;
    size_t    len;
    uint32_t  count;
    uint64_t  owner_id;
} deleted_collect_ctx_t;

static int deleted_list_cb(const vw_file_record_t *rec, void *ud)
{
    deleted_collect_ctx_t *c = (deleted_collect_ctx_t *)ud;
    uint8_t entry[DELETED_ENTRY_SIZE];
    size_t  n;

    if (rec->owner_id != c->owner_id) return 0;

    if (c->len + DELETED_ENTRY_SIZE > c->cap) {
        size_t   new_cap = c->cap ? c->cap * 2 : 4096u;
        uint8_t *p = (uint8_t *)realloc(c->buf, new_cap);
        if (!p) return 1; /* stop — OOM */
        c->buf = p; c->cap = new_cap;
    }

    memset(entry, 0, sizeof(entry));
    w64le(entry, rec->file_id);
    w64le(entry + 8, (uint64_t)rec->deleted_at);
    n = strnlen(rec->name, sizeof(rec->name));
    memcpy(entry + 16, rec->name, n);

    memcpy(c->buf + c->len, entry, DELETED_ENTRY_SIZE);
    c->len += DELETED_ENTRY_SIZE;
    c->count++;
    return 0;
}

static void handle_list_deleted(vw_admin_server_t *srv, int fd,
                                 const uint8_t *p, uint32_t plen)
{
    uint16_t         uname_len;
    char             username[65];
    vw_user_record_t urec;
    vw_err_t         rc;
    deleted_collect_ctx_t dc;

    if (plen < 2u) {
        uint8_t resp[8];
        w32le(resp, (uint32_t)VW_ERR_INVALID_ARG); w32le(resp + 4, 0u);
        send_frame(fd, VW_ADMIN_LIST_DELETED_RESP, resp, sizeof(resp));
        return;
    }
    uname_len = r16le(p);
    if (uname_len == 0 || uname_len > 63u || plen < (uint32_t)(2u + uname_len)) {
        uint8_t resp[8];
        w32le(resp, (uint32_t)VW_ERR_INVALID_ARG); w32le(resp + 4, 0u);
        send_frame(fd, VW_ADMIN_LIST_DELETED_RESP, resp, sizeof(resp));
        return;
    }
    memcpy(username, p + 2, uname_len);
    username[uname_len] = '\0';

    rc = vw_store_user_get_by_username(srv->ctx.store, username, &urec);
    if (rc == VW_OK && !srv->ctx.file_store) rc = VW_ERR_INVALID_ARG;
    if (rc != VW_OK) {
        uint8_t resp[8];
        w32le(resp, (uint32_t)rc); w32le(resp + 4, 0u);
        send_frame(fd, VW_ADMIN_LIST_DELETED_RESP, resp, sizeof(resp));
        return;
    }

    memset(&dc, 0, sizeof(dc));
    dc.owner_id = urec.user_id;

    rc = vw_store_file_scan_deleted(srv->ctx.file_store, deleted_list_cb, &dc);
    if (rc != VW_OK) {
        free(dc.buf);
        uint8_t resp[8];
        w32le(resp, (uint32_t)rc); w32le(resp + 4, 0u);
        send_frame(fd, VW_ADMIN_LIST_DELETED_RESP, resp, sizeof(resp));
        return;
    }

    {
        uint8_t  frm_hdr[ADMIN_HDR_SIZE];
        uint8_t  hdr8[8];
        uint32_t total = (uint32_t)(ADMIN_HDR_SIZE + 8u + dc.len);

        w32le(frm_hdr,     total);
        w16le(frm_hdr + 4, (uint16_t)VW_ADMIN_LIST_DELETED_RESP);
        w16le(frm_hdr + 6, ADMIN_PROTO_VER);
        send_all(fd, frm_hdr, ADMIN_HDR_SIZE);

        w32le(hdr8,     (uint32_t)VW_OK);
        w32le(hdr8 + 4, dc.count);
        send_all(fd, hdr8, 8);
        if (dc.len) send_all(fd, dc.buf, dc.len);
    }

    free(dc.buf);
}

#undef DELETED_ENTRY_SIZE

static void handle_restore_file(vw_admin_server_t *srv, int fd,
                                 const uint8_t *p, uint32_t plen)
{
    uint64_t file_id;
    vw_err_t rc;

    if (plen < 8u) {
        send_u32_resp(fd, VW_ADMIN_RESTORE_FILE_RESP, VW_ERR_INVALID_ARG);
        return;
    }
    file_id = r64le(p);

    if (!srv->ctx.file_store) {
        send_u32_resp(fd, VW_ADMIN_RESTORE_FILE_RESP, VW_ERR_INVALID_ARG);
        return;
    }

    rc = vw_store_file_restore(srv->ctx.file_store, file_id);
    send_u32_resp(fd, VW_ADMIN_RESTORE_FILE_RESP, rc);
}

static void handle_cluster_status(vw_admin_server_t *srv, int fd)
{
    vw_node_record_t *recs = NULL;
    uint32_t           count = 0;
    vw_err_t           rc;

/* u64 node_id(8) + u8 role(1) + u8 is_active(1) + u8[2] pad(2)
 * + u8[128] hostname(128) + u64 sync_watermark(8) = 148 */
#define NODE_ENTRY_SIZE 148u

    if (!srv->ctx.cluster) {
        uint8_t resp[8];
        w32le(resp,     (uint32_t)VW_ERR_INVALID_ARG);
        w32le(resp + 4, 0u);
        send_frame(fd, VW_ADMIN_CLUSTER_STATUS_RESP, resp, sizeof(resp));
        return;
    }

    rc = vw_cluster_node_list(srv->ctx.cluster, &recs, &count);
    if (rc != VW_OK) {
        uint8_t resp[8];
        w32le(resp,     (uint32_t)rc);
        w32le(resp + 4, 0u);
        send_frame(fd, VW_ADMIN_CLUSTER_STATUS_RESP, resp, sizeof(resp));
        return;
    }

    {
        uint8_t  frm_hdr[ADMIN_HDR_SIZE];
        uint8_t  hdr8[8];
        uint32_t total = (uint32_t)(ADMIN_HDR_SIZE + 8u + count * NODE_ENTRY_SIZE);
        uint32_t i;

        w32le(frm_hdr,     total);
        w16le(frm_hdr + 4, (uint16_t)VW_ADMIN_CLUSTER_STATUS_RESP);
        w16le(frm_hdr + 6, ADMIN_PROTO_VER);
        send_all(fd, frm_hdr, ADMIN_HDR_SIZE);

        w32le(hdr8,     (uint32_t)VW_OK);
        w32le(hdr8 + 4, count);
        send_all(fd, hdr8, 8);

        for (i = 0; i < count; i++) {
            uint8_t entry[NODE_ENTRY_SIZE];
            memset(entry, 0, sizeof(entry));
            w64le(entry, recs[i].node_id);
            entry[8] = recs[i].role;
            entry[9] = recs[i].is_active;
            memcpy(entry + 12, recs[i].hostname, 128);
            w64le(entry + 140, recs[i].sync_watermark);
            send_all(fd, entry, sizeof(entry));
        }
    }
#undef NODE_ENTRY_SIZE

    free(recs);
}

/* ── Connection handler ────────────────────────────────────────────────────── */

static void handle_admin_connection(vw_admin_server_t *srv, int fd)
{
    uint8_t  hdr[ADMIN_HDR_SIZE];
    uint32_t total_len, plen;
    uint16_t msg_type;
    uint8_t *payload = NULL;

    if (recv_all(fd, hdr, sizeof(hdr)) < 0) return;

    total_len = r32le(hdr);
    msg_type  = r16le(hdr + 4);

    if (total_len < ADMIN_HDR_SIZE ||
        total_len > ADMIN_MAX_PAYLOAD + ADMIN_HDR_SIZE) return;

    plen = total_len - ADMIN_HDR_SIZE;
    if (plen > 0) {
        payload = (uint8_t *)malloc(plen);
        if (!payload) return;
        if (recv_all(fd, payload, plen) < 0) { free(payload); return; }
    }

    switch ((vw_admin_msg_t)msg_type) {
    case VW_ADMIN_USER_CREATE_REQ: handle_user_create(srv, fd, payload, plen); break;
    case VW_ADMIN_USER_LIST_REQ:   handle_user_list(srv, fd);                  break;
    case VW_ADMIN_SET_QUOTA_REQ:   handle_set_quota(srv, fd, payload, plen);   break;
    case VW_ADMIN_OPLOG_TAIL_REQ:  handle_oplog_tail(srv, fd, payload, plen);  break;
    case VW_ADMIN_CONN_LIST_REQ:   handle_conn_list(srv, fd);                  break;
    case VW_ADMIN_RELOAD_CERT_REQ: handle_reload_cert(srv, fd);                break;
    case VW_ADMIN_NODE_ADD_REQ:            handle_node_add(srv, fd, payload, plen);            break;
    case VW_ADMIN_CLUSTER_STATUS_REQ:      handle_cluster_status(srv, fd);                     break;
    case VW_ADMIN_NODE_REGISTER_SELF_REQ:  handle_node_register_self(srv, fd, payload, plen);  break;
    case VW_ADMIN_LIST_DELETED_REQ:        handle_list_deleted(srv, fd, payload, plen);        break;
    case VW_ADMIN_RESTORE_FILE_REQ:        handle_restore_file(srv, fd, payload, plen);        break;
    case VW_ADMIN_SET_CAPS_REQ:            handle_set_admin_caps(srv, fd, payload, plen);      break;
    default: break;
    }

    if (payload) secure_zero(payload, plen); /* zero before free — may contain password */
    free(payload);
}

/* ── Listener thread ───────────────────────────────────────────────────────── */

static void *admin_listener(void *arg)
{
    vw_admin_server_t *srv = (vw_admin_server_t *)arg;

    while (!srv->shutdown) {
        fd_set rset;
        struct timeval tv;
        int n, client_fd;

        FD_ZERO(&rset);
        FD_SET(srv->sock_fd, &rset);
        tv.tv_sec  = 2;
        tv.tv_usec = 0;

        n = select(srv->sock_fd + 1, &rset, NULL, NULL, &tv);
        if (n <= 0) continue;

        client_fd = accept(srv->sock_fd, NULL, NULL);
        if (client_fd < 0) continue;

        /* Verify the connecting process belongs to the same UID as the server.
         * SO_PEERCRED works on AF_UNIX sockets (it does NOT work on AF_INET;
         * that was the original bug — SEC.07 TASK-040 blocking finding). */
#ifdef __linux__
        {
            struct ucred cred;
            socklen_t    cred_len = (socklen_t)sizeof(cred);
            if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                           &cred, &cred_len) < 0 ||
                cred.uid != getuid()) {
                close(client_fd);
                continue;
            }
        }
#elif defined(LOCAL_PEERCRED)
        {
            struct xucred cred;
            socklen_t     cred_len = (socklen_t)sizeof(cred);
            if (getsockopt(client_fd, SOL_LOCAL, LOCAL_PEERCRED,
                           &cred, &cred_len) < 0 ||
                cred.cr_uid != getuid()) {
                close(client_fd);
                continue;
            }
        }
#endif

        handle_admin_connection(srv, client_fd);
        close(client_fd);
    }

    return NULL;
}

/* ── Public API ────────────────────────────────────────────────────────────── */

vw_err_t vw_admin_server_start(const char *socket_path, const vw_admin_ctx_t *ctx,
                                vw_admin_server_t **out)
{
    vw_admin_server_t  *srv;
    int                 sock;
    struct sockaddr_un  addr;
    mode_t              old_umask;

    if (!out) return VW_ERR_INVALID_ARG;
    *out = NULL;

    if (!socket_path || !socket_path[0]) return VW_OK; /* admin disabled */

    if (strlen(socket_path) >= sizeof(addr.sun_path)) return VW_ERR_INVALID_ARG;

    srv = (vw_admin_server_t *)calloc(1, sizeof(*srv));
    if (!srv) return VW_ERR_OOM;
    srv->ctx = *ctx;
    strncpy(srv->socket_path, socket_path, sizeof(srv->socket_path) - 1);

    /* Remove any stale socket file from a previous run. */
    unlink(socket_path);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { free(srv); return VW_ERR_IO; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    /* Create the socket file with mode 0600 so only the owner can connect.
     * Set umask to 0177 around bind so the kernel assigns mode 0600 atomically. */
    old_umask = umask(0177);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(sock, 4) < 0) {
        umask(old_umask);
        close(sock); free(srv); return VW_ERR_IO;
    }
    umask(old_umask);

    srv->sock_fd  = sock;
    srv->shutdown = 0;

    if (pthread_create(&srv->thread, NULL, admin_listener, srv) != 0) {
        close(sock); unlink(socket_path); free(srv); return VW_ERR_IO;
    }

    *out = srv;
    return VW_OK;
}

void vw_admin_server_stop(vw_admin_server_t *srv)
{
    if (!srv) return;
    srv->shutdown = 1;
    pthread_join(srv->thread, NULL);
    close(srv->sock_fd);
    if (srv->socket_path[0])
        unlink(srv->socket_path);
    free(srv);
}

#endif /* !_WIN32 */
