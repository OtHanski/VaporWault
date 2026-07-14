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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

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

    rc = vw_auth_hash_password(p + 3 + uname_len + 2, pw_len, hash, salt);
    if (rc != VW_OK) {
        memset(hash, 0, sizeof(hash)); memset(salt, 0, sizeof(salt));
        send_u32_resp(fd, VW_ADMIN_USER_CREATE_RESP, rc); return;
    }

    memset(&rec, 0, sizeof(rec));
    memcpy(rec.username, username, uname_len + 1);
    memcpy(rec.password_hash, hash, 32);
    memcpy(rec.password_salt, salt, 16);
    memset(hash, 0, sizeof(hash)); memset(salt, 0, sizeof(salt));
    rec.is_admin  = is_admin ? 1 : 0;
    rec.is_active = 1;

    rc = vw_store_user_create(srv->ctx.store, &rec, &uid);
    memset(rec.password_hash, 0, sizeof(rec.password_hash));
    memset(rec.password_salt, 0, sizeof(rec.password_salt));

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
 * + u8[64] username(64) + u64 quota_bytes(8) + u64 used_bytes(8) = 92 */
#define ULIST_ENTRY_SIZE 92u

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
        memset(&rec, 0, sizeof(rec)); /* rec may be partially written */
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

    memset(&rec, 0, sizeof(rec)); /* zero password_hash/salt from the fetched record */
    send_u32_resp(fd, VW_ADMIN_SET_QUOTA_RESP, rc);
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

static void handle_conn_list(vw_admin_server_t *srv, int fd)
{
    /* Phase 5: active connections are not tracked centrally. Return empty list. */
    uint8_t resp[4];
    (void)srv;
    w32le(resp, 0u);
    send_frame(fd, VW_ADMIN_CONN_LIST_RESP, resp, sizeof(resp));
}

static void handle_reload_cert(vw_admin_server_t *srv, int fd)
{
    /* Phase 5: cert reload is triggered via SIGHUP on the server process.
     * The admin channel does not currently hold a reference to net_ctx. */
    (void)srv;
    send_u32_resp(fd, VW_ADMIN_RELOAD_CERT_RESP, VW_ERR_INVALID_ARG);
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
    default: break;
    }

    if (payload) memset(payload, 0, plen); /* zero before free — may contain password */
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
