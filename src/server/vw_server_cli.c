/*
 * vw_server_cli.c — VaporWault server admin CLI.
 *
 * Connects to the admin IPC port (default 47833) and dispatches subcommands.
 * Prints results to stdout. Exits 0 on success, 1 on error.
 *
 * SRV.01 [2026-07-12]: TASK-040 implementation.
 */

#include "vw_server_cli.h"
#include "vw_admin.h"
#include "vw_cluster.h"
#include "../core/vw_crypto.h"
#include "vw_version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifndef _WIN32
#  include <unistd.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  define MSG_NOSIGNAL_FLAG MSG_NOSIGNAL
#else
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  define MSG_NOSIGNAL_FLAG 0
typedef int ssize_t;
#endif

/* ── Wire helpers (same framing as vw_admin.c) ─────────────────────────────── */

#define ADMIN_HDR_SIZE  8u
#define ADMIN_PROTO_VER 1u
#define MAX_RESP        (128u * 1024u)  /* 128 KiB response cap */

static void w16le(uint8_t *b, uint16_t v) {
    b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8);
}
static void w32le(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)v; b[1]=(uint8_t)(v>>8); b[2]=(uint8_t)(v>>16); b[3]=(uint8_t)(v>>24);
}
static void w64le(uint8_t *b, uint64_t v) {
    w32le(b, (uint32_t)v); w32le(b+4, (uint32_t)(v>>32));
}
static uint16_t r16le(const uint8_t *b) {
    return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}
static uint32_t r32le(const uint8_t *b) {
    return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);
}
static uint64_t r64le(const uint8_t *b) {
    return (uint64_t)r32le(b) | ((uint64_t)r32le(b+4) << 32);
}

static int recv_all(int fd, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = recv(fd, (char*)buf + done, (int)(n - done), 0);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}
static int send_all(int fd, const void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t s = send(fd, (const char*)buf + done, (int)(n - done), MSG_NOSIGNAL_FLAG);
        if (s <= 0) return -1;
        done += (size_t)s;
    }
    return 0;
}

/* ── Admin connection ──────────────────────────────────────────────────────── */

static int admin_connect(const char *socket_path) {
#ifdef _WIN32
    (void)socket_path;
    fprintf(stderr, "error: admin IPC is not supported on Windows\n");
    return -1;
#else
    struct sockaddr_un addr;
    int fd;

    if (!socket_path || strlen(socket_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "error: invalid admin socket path\n");
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error: cannot create socket\n");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "error: cannot connect to admin socket '%s' — is vapourwaultd running?\n",
                socket_path);
        close(fd);
        return -1;
    }
    return fd;
#endif
}

/* Send a framed request and receive the full response into *out_buf (heap-alloc'd).
 * Returns 0 on success; *out_buf must be freed by caller. */
static int admin_rpc(int fd,
                     uint16_t req_type, const uint8_t *req_payload, uint32_t req_plen,
                     uint16_t *out_resp_type, uint8_t **out_buf, uint32_t *out_plen)
{
    uint8_t  hdr[ADMIN_HDR_SIZE];
    uint32_t total, resp_plen;
    uint16_t resp_type;
    uint8_t *buf;

    /* Send request */
    w32le(hdr,     req_plen + ADMIN_HDR_SIZE);
    w16le(hdr + 4, req_type);
    w16le(hdr + 6, ADMIN_PROTO_VER);
    if (send_all(fd, hdr, ADMIN_HDR_SIZE) < 0 ||
        (req_plen && req_payload && send_all(fd, req_payload, req_plen) < 0)) {
        fprintf(stderr, "error: send failed\n");
        return -1;
    }

    /* Receive response header */
    if (recv_all(fd, hdr, ADMIN_HDR_SIZE) < 0) {
        fprintf(stderr, "error: no response from server\n");
        return -1;
    }
    total     = r32le(hdr);
    resp_type = r16le(hdr + 4);
    if (total < ADMIN_HDR_SIZE || total > MAX_RESP) {
        fprintf(stderr, "error: malformed response (len=%u)\n", (unsigned)total);
        return -1;
    }
    resp_plen = total - ADMIN_HDR_SIZE;

    buf = (uint8_t*)malloc(resp_plen + 1);
    if (!buf) { fprintf(stderr, "error: out of memory\n"); return -1; }
    buf[resp_plen] = '\0';

    if (resp_plen && recv_all(fd, buf, resp_plen) < 0) {
        free(buf);
        fprintf(stderr, "error: truncated response\n");
        return -1;
    }

    *out_resp_type = resp_type;
    *out_buf       = buf;
    *out_plen      = resp_plen;
    return 0;
}

/* Matches vw_err_t (vw_proto.h) — every admin response code is a vw_err_t
 * cast directly to u32, so this must track that enum exactly. */
static const char *err_str(uint32_t code) {
    switch (code) {
    case VW_OK:                 return "ok";
    case VW_ERR_IO:              return "io";
    case VW_ERR_OOM:              return "oom";
    case VW_ERR_INVALID_ARG:      return "invalid_arg";
    case VW_ERR_TIMEOUT:          return "timeout";
    case VW_ERR_NOT_FOUND:        return "not_found";
    case VW_ERR_ALREADY_EXISTS:   return "already_exists";
    case VW_ERR_PERMISSION:       return "permission";
    case VW_ERR_QUOTA_EXCEEDED:   return "quota_exceeded";
    case VW_ERR_NOT_IMPL:         return "not_implemented";
    default: return "unknown";
    }
}

/* TASK-092: single source of truth for capability bit <-> name, shared by
 * caps_str() and parse_caps() below (CQR.08 finding: these were previously
 * two independently-maintained copies of the same table). */
typedef struct { uint32_t bit; const char *name; } vw_cap_name_t;
static const vw_cap_name_t VW_CAP_NAMES[] = {
    { VW_CAP_USER_MGMT,    "user_mgmt"    },
    { VW_CAP_QUOTA_MGMT,   "quota_mgmt"   },
    { VW_CAP_AUDIT_READ,   "audit_read"   },
    { VW_CAP_CLUSTER_MGMT, "cluster_mgmt" },
    { VW_CAP_CERT_RELOAD,  "cert_reload"  },
};
#define VW_CAP_NAMES_COUNT (sizeof(VW_CAP_NAMES) / sizeof(VW_CAP_NAMES[0]))

/* TASK-092: render an admin_caps bitmask for display. Mirrors
 * vw_admin_has_cap()'s "0 == full/legacy admin" convention (vw_store.h). */
static void caps_str(uint8_t is_admin, uint32_t caps, char *buf, size_t buflen)
{
    if (!is_admin) { snprintf(buf, buflen, "-"); return; }
    if (caps == 0 || caps == (uint32_t)VW_CAP_ALL) { snprintf(buf, buflen, "full"); return; }

    buf[0] = '\0';
    size_t used = 0;
    for (size_t i = 0; i < VW_CAP_NAMES_COUNT; i++) {
        if (!(caps & VW_CAP_NAMES[i].bit)) continue;
        int n = snprintf(buf + used, buflen - used, "%s%s",
                          used ? "," : "", VW_CAP_NAMES[i].name);
        if (n < 0 || (size_t)n >= buflen - used) break;
        used += (size_t)n;
    }
    if (buf[0] == '\0') snprintf(buf, buflen, "none");
}

/* ── Subcommands ────────────────────────────────────────────────────────────── */

static int cmd_user_create(int fd, const char *username, const char *password,
                            int is_admin)
{
    uint16_t uname_len = (uint16_t)strlen(username);
    uint16_t pw_len    = (uint16_t)strlen(password);
    uint32_t plen      = 1u + 2u + uname_len + 2u + pw_len;
    uint8_t *req       = (uint8_t*)malloc(plen);
    if (!req) { fprintf(stderr, "error: out of memory\n"); return 1; }

    uint32_t off = 0;
    req[off++] = (uint8_t)(is_admin ? 1 : 0);
    w16le(req + off, uname_len); off += 2;
    memcpy(req + off, username, uname_len); off += uname_len;
    w16le(req + off, pw_len); off += 2;
    memcpy(req + off, password, pw_len);

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    int rc = admin_rpc(fd, (uint16_t)VW_ADMIN_USER_CREATE_REQ, req, plen,
                        &resp_type, &resp, &resp_plen);
    free(req);
    if (rc < 0) return 1;

    if (resp_plen < 4) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    uint64_t uid  = (resp_plen >= 12) ? r64le(resp + 4) : 0;
    free(resp);

    if (code != 0) {
        fprintf(stderr, "error: user-create failed: %s (code %u)\n", err_str(code), code);
        return 1;
    }
    printf("created user '%s' (id=%llu%s)\n",
           username, (unsigned long long)uid, is_admin ? ", admin" : "");
    return 0;
}

static int cmd_user_list(int fd)
{
    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_USER_LIST_REQ, NULL, 0,
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    if (resp_plen < 4) { free(resp); return 0; }

    uint32_t count = r32le(resp);
    uint32_t off   = 4;

#define UENTRY 96u
    printf("%-8s  %-5s  %-5s  %-64s  %-16s  %-16s  %s\n",
           "USER_ID", "ADMIN", "ACTV", "USERNAME", "QUOTA", "USED", "ADMIN_CAPS");

    for (uint32_t i = 0; i < count; i++) {
        if (off + UENTRY > resp_plen) break;
        uint64_t uid        = r64le(resp + off);
        uint8_t  is_admin   = resp[off + 8];
        uint8_t  is_active  = resp[off + 9];
        char     uname[65];
        memcpy(uname, resp + off + 12, 64); uname[64] = '\0';
        uint64_t qb   = r64le(resp + off + 76);
        uint64_t ub   = r64le(resp + off + 84);
        uint32_t caps = r32le(resp + off + 92);
        off += UENTRY;

        char capbuf[128];
        caps_str(is_admin, caps, capbuf, sizeof(capbuf));

        printf("%-8llu  %-5s  %-5s  %-64s  %-16llu  %-16llu  %s\n",
               (unsigned long long)uid,
               is_admin  ? "yes" : "no",
               is_active ? "yes" : "no",
               uname,
               (unsigned long long)qb,
               (unsigned long long)ub,
               capbuf);
    }
#undef UENTRY

    free(resp);
    return 0;
}

static int cmd_set_quota(int fd, const char *username, uint64_t quota_bytes)
{
    uint16_t uname_len = (uint16_t)strlen(username);
    uint32_t plen      = 2u + uname_len + 8u;
    uint8_t *req       = (uint8_t*)malloc(plen);
    if (!req) { fprintf(stderr, "error: out of memory\n"); return 1; }

    w16le(req, uname_len);
    memcpy(req + 2, username, uname_len);
    w64le(req + 2 + uname_len, quota_bytes);

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    int rc = admin_rpc(fd, (uint16_t)VW_ADMIN_SET_QUOTA_REQ, req, plen,
                        &resp_type, &resp, &resp_plen);
    free(req);
    if (rc < 0) return 1;

    if (resp_plen < 4) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    free(resp);

    if (code != 0) {
        fprintf(stderr, "error: set-quota failed: %s (code %u)\n", err_str(code), code);
        return 1;
    }
    printf("quota for '%s' set to %llu bytes\n", username, (unsigned long long)quota_bytes);
    return 0;
}

/* TASK-092: parse a comma-separated capability list (or "all") into a
 * vw_admin_cap_t bitmask. Returns 0 and sets *out_caps on success; returns
 * non-zero (with a message on stderr) on an unrecognized token. */
static int parse_caps(const char *spec, uint32_t *out_caps)
{
    if (strcmp(spec, "all") == 0) { *out_caps = (uint32_t)VW_CAP_ALL; return 0; }

    uint32_t caps = 0;
    char     buf[256];
    if (strlen(spec) >= sizeof(buf)) {
        fprintf(stderr, "error: capability list too long\n");
        return 1;
    }
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Manual comma split — avoid strtok_r/strtok_s, whose names differ
     * between POSIX and MSVC. */
    char *cursor = buf;
    while (*cursor) {
        char *comma = strchr(cursor, ',');
        if (comma) *comma = '\0';

        if (*cursor) {
            int found = 0;
            for (size_t i = 0; i < VW_CAP_NAMES_COUNT; i++) {
                if (strcmp(cursor, VW_CAP_NAMES[i].name) == 0) { caps |= VW_CAP_NAMES[i].bit; found = 1; break; }
            }
            if (!found) {
                fprintf(stderr, "error: unknown capability '%s' "
                                "(valid: user_mgmt, quota_mgmt, audit_read, "
                                "cluster_mgmt, cert_reload, or 'all')\n", cursor);
                return 1;
            }
        }

        cursor = comma ? comma + 1 : cursor + strlen(cursor);
    }

    if (caps == 0) {
        fprintf(stderr, "error: no capabilities specified — an empty "
                        "capability set is not a supported state for an "
                        "admin account (it would read back as 'full' per "
                        "the on-disk default); use 'all' to grant everything "
                        "or a specific non-empty subset\n");
        return 1;
    }

    *out_caps = caps;
    return 0;
}

static int cmd_set_admin_caps(int fd, const char *username, uint32_t caps)
{
    uint16_t uname_len = (uint16_t)strlen(username);
    uint32_t plen      = 2u + uname_len + 4u;
    uint8_t *req       = (uint8_t*)malloc(plen);
    if (!req) { fprintf(stderr, "error: out of memory\n"); return 1; }

    w16le(req, uname_len);
    memcpy(req + 2, username, uname_len);
    w32le(req + 2 + uname_len, caps);

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    int rc = admin_rpc(fd, (uint16_t)VW_ADMIN_SET_CAPS_REQ, req, plen,
                        &resp_type, &resp, &resp_plen);
    free(req);
    if (rc < 0) return 1;

    if (resp_plen < 4) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    free(resp);

    if (code != 0) {
        fprintf(stderr, "error: set-admin-caps failed: %s (code %u)\n", err_str(code), code);
        return 1;
    }
    char capbuf[128];
    caps_str(1, caps, capbuf, sizeof(capbuf));
    printf("admin capabilities for '%s' set to: %s\n", username, capbuf);
    return 0;
}

static int cmd_oplog_tail(int fd, uint32_t count)
{
    uint8_t  req[4];
    w32le(req, count);

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_OPLOG_TAIL_REQ, req, sizeof(req),
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    if (resp_plen < 4) { free(resp); return 0; }

    uint32_t n   = r32le(resp);
    uint32_t off = 4;

    static const char *op_names[] = {
        "?",           /* 0x00 */
        "USER_WRITE",  /* 0x01 */
        "FILE_WRITE",  /* 0x02 */
        "FILE_DELETE", /* 0x03 */
        "PERM_WRITE",  /* 0x04 */
        "SESS_WRITE",  /* 0x05 */
        "CHUNK_WRITE", /* 0x06 */
    };

    printf("%-20s  %s\n", "ENTRY_ID", "OP_TYPE");
    for (uint32_t i = 0; i < n; i++) {
        if (off + 16u > resp_plen) break;
        uint64_t eid = r64le(resp + off);
        uint8_t  ot  = resp[off + 8];
        off += 16;

        const char *name = (ot < 7) ? op_names[ot] : "?";
        printf("%-20llu  %s\n", (unsigned long long)eid, name);
    }

    free(resp);
    return 0;
}

static void format_connected_since(int64_t unix_ts, char *buf, size_t bufsz) {
    time_t t = (time_t)unix_ts;
    struct tm tm_val;
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S UTC", &tm_val);
}

static int cmd_list_connections(int fd)
{
    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_CONN_LIST_REQ, NULL, 0,
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    if (resp_plen < 4) { free(resp); return 0; }

    uint32_t count = r32le(resp);
    uint32_t off   = 4;

#define CENTRY 88u
    printf("%-8s  %-8s  %-24s  %s\n", "CONN_ID", "USER_ID", "CONNECTED_SINCE", "PEER_ADDR");
    for (uint32_t i = 0; i < count; i++) {
        if (off + CENTRY > resp_plen) break;
        uint64_t conn_id = r64le(resp + off);
        uint64_t user_id = r64le(resp + off + 8);
        int64_t  since   = (int64_t)r64le(resp + off + 16);
        char     peer[65];
        memcpy(peer, resp + off + 24, 64); peer[64] = '\0';
        off += CENTRY;

        char ts_buf[32];
        format_connected_since(since, ts_buf, sizeof(ts_buf));
        char uid_buf[24];
        if (user_id == 0) snprintf(uid_buf, sizeof(uid_buf), "-");
        else snprintf(uid_buf, sizeof(uid_buf), "%llu", (unsigned long long)user_id);

        printf("%-8llu  %-8s  %-24s  %s\n",
               (unsigned long long)conn_id, uid_buf, ts_buf, peer);
    }
#undef CENTRY

    printf("%u active connection(s)\n", (unsigned)count);
    free(resp);
    return 0;
}

static int cmd_list_deleted(int fd, const char *username)
{
    uint16_t uname_len = (uint16_t)strlen(username);
    uint32_t plen = 2u + uname_len;
    uint8_t *req  = (uint8_t*)malloc(plen);
    if (!req) { fprintf(stderr, "error: out of memory\n"); return 1; }
    w16le(req, uname_len);
    memcpy(req + 2, username, uname_len);

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    int rc = admin_rpc(fd, (uint16_t)VW_ADMIN_LIST_DELETED_REQ, req, plen,
                        &resp_type, &resp, &resp_plen);
    free(req);
    if (rc < 0) return 1;

    if (resp_plen < 8) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    if (code != 0) {
        free(resp);
        fprintf(stderr, "error: list-deleted failed: %s (code %u)\n", err_str(code), code);
        return 1;
    }

    uint32_t count = r32le(resp + 4);
    uint32_t off   = 8;

#define DENTRY 80u
    printf("%-8s  %-24s  %s\n", "FILE_ID", "DELETED_AT", "NAME");
    for (uint32_t i = 0; i < count; i++) {
        if (off + DENTRY > resp_plen) break;
        uint64_t file_id    = r64le(resp + off);
        int64_t  deleted_at = (int64_t)r64le(resp + off + 8);
        char     name[65];
        memcpy(name, resp + off + 16, 64); name[64] = '\0';
        off += DENTRY;

        char ts_buf[32];
        format_connected_since(deleted_at, ts_buf, sizeof(ts_buf));
        printf("%-8llu  %-24s  %s\n", (unsigned long long)file_id, ts_buf, name);
    }
#undef DENTRY

    printf("%u file(s) in trash for '%s'\n", (unsigned)count, username);
    free(resp);
    return 0;
}

static int cmd_restore_file(int fd, uint64_t file_id)
{
    uint8_t req[8];
    w64le(req, file_id);

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    int rc = admin_rpc(fd, (uint16_t)VW_ADMIN_RESTORE_FILE_REQ, req, sizeof(req),
                        &resp_type, &resp, &resp_plen);
    if (rc < 0) return 1;

    if (resp_plen < 4) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    free(resp);
    if (code != 0) {
        fprintf(stderr, "error: restore-file failed: %s (code %u)\n", err_str(code), code);
        if (code == VW_ERR_INVALID_ARG)
            fprintf(stderr, "hint: file_id %llu exists but is not currently deleted\n",
                    (unsigned long long)file_id);
        else if (code == VW_ERR_NOT_FOUND)
            fprintf(stderr, "hint: file_id %llu does not exist\n", (unsigned long long)file_id);
        return 1;
    }
    printf("restored file_id=%llu\n", (unsigned long long)file_id);
    return 0;
}

static int cmd_reload_cert(int fd)
{
    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_RELOAD_CERT_REQ, NULL, 0,
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    if (resp_plen < 4) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    free(resp);

    if (code != 0) {
        fprintf(stderr, "error: reload-cert: %s (code %u)\n", err_str(code), code);
        fprintf(stderr, "hint: send SIGHUP to vapourwaultd to reload the certificate\n");
        return 1;
    }
    printf("certificate reloaded\n");
    return 0;
}

static int cmd_cluster_node_add(int fd, const char *hostname)
{
    uint16_t hlen = (uint16_t)strlen(hostname);
    uint32_t plen = 2u + hlen;
    uint8_t *req  = (uint8_t*)malloc(plen);
    if (!req) { fprintf(stderr, "error: out of memory\n"); return 1; }

    w16le(req, hlen);
    memcpy(req + 2, hostname, hlen);

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    int rc = admin_rpc(fd, (uint16_t)VW_ADMIN_NODE_ADD_REQ, req, plen,
                        &resp_type, &resp, &resp_plen);
    free(req);
    if (rc < 0) return 1;

    if (resp_plen < 4) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    if (code != 0) {
        memset(resp, 0, resp_plen);
        free(resp);
        fprintf(stderr, "error: cluster node-add failed: %s (code %u)\n", err_str(code), code);
        if (code == VW_ERR_INVALID_ARG)
            fprintf(stderr, "hint: cluster mode must be enabled in server.conf "
                            "(cluster_port != 0 or cluster_is_replica = 1)\n");
        return 1;
    }
    if (resp_plen < 44) { memset(resp, 0, resp_plen); free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }

    uint64_t node_id = r64le(resp + 4);
    printf("registered node_id=%llu hostname=%s role=replica\n",
           (unsigned long long)node_id, hostname);
    printf("auth_token (record this now, it cannot be retrieved again):\n");
    for (int i = 0; i < 32; i++) printf("%02x", resp[12 + i]);
    printf("\n");
    printf("\nOn the replica's own server, run:\n"
           "  vapourwault-server-cli cluster register-self %llu <token-above> <this-server's-hostname>\n",
           (unsigned long long)node_id);
    memset(resp, 0, resp_plen); /* auth_token must not linger in freed heap */
    free(resp);
    return 0;
}

static int cmd_cluster_register_self(int fd, uint64_t node_id, const char *token_hex,
                                      const char *hostname)
{
    uint8_t token[32];
    static char stdin_token[256];
    const char *token_src = token_hex;

    /* Read the token from stdin when '-' or '--stdin-token' is specified, to
     * avoid exposing it in /proc/<pid>/cmdline and ps output — same rationale
     * as user-create's '-'/'--stdin-password'. */
    if (strcmp(token_hex, "-") == 0 || strcmp(token_hex, "--stdin-token") == 0) {
        if (!fgets(stdin_token, (int)sizeof(stdin_token), stdin)) {
            fprintf(stderr, "error: failed to read token from stdin\n");
            return 1;
        }
        size_t slen = strlen(stdin_token);
        if (slen > 0 && stdin_token[slen - 1] == '\n') stdin_token[--slen] = '\0';
        token_src = stdin_token;
    }

    size_t hexlen = strlen(token_src);
    if (hexlen != 64 || vw_crypto_hex_decode(token_src, hexlen, token) != VW_OK) {
        memset(stdin_token, 0, sizeof(stdin_token));
        fprintf(stderr, "error: token must be exactly 64 hex characters (32 bytes)\n");
        return 1;
    }
    memset(stdin_token, 0, sizeof(stdin_token));

    uint16_t hlen = (uint16_t)strlen(hostname);
    uint32_t plen = 8u + 32u + 2u + hlen;
    uint8_t *req  = (uint8_t*)malloc(plen);
    if (!req) { memset(token, 0, sizeof(token)); fprintf(stderr, "error: out of memory\n"); return 1; }

    uint32_t off = 0;
    w64le(req + off, node_id); off += 8;
    memcpy(req + off, token, 32); off += 32;
    w16le(req + off, hlen); off += 2;
    memcpy(req + off, hostname, hlen);
    memset(token, 0, sizeof(token));

    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    int rc = admin_rpc(fd, (uint16_t)VW_ADMIN_NODE_REGISTER_SELF_REQ, req, plen,
                        &resp_type, &resp, &resp_plen);
    memset(req, 0, plen); /* zero the token copy before freeing */
    free(req);
    if (rc < 0) return 1;

    if (resp_plen < 4) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    free(resp);
    if (code != 0) {
        fprintf(stderr, "error: cluster register-self failed: %s (code %u)\n", err_str(code), code);
        if (code == VW_ERR_INVALID_ARG)
            fprintf(stderr, "hint: cluster mode must be enabled in server.conf "
                            "(cluster_port != 0 or cluster_is_replica = 1)\n");
        else if (code == VW_ERR_ALREADY_EXISTS)
            fprintf(stderr, "hint: node_id %llu is already registered on this server\n",
                    (unsigned long long)node_id);
        return 1;
    }
    printf("registered self-record: node_id=%llu hostname=%s\n",
           (unsigned long long)node_id, hostname);
    return 0;
}

static int cmd_cluster_status(int fd)
{
    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_CLUSTER_STATUS_REQ, NULL, 0,
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    if (resp_plen < 8) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    if (code != 0) {
        free(resp);
        fprintf(stderr, "error: cluster-status failed: %s (code %u)\n", err_str(code), code);
        if (code == VW_ERR_INVALID_ARG)
            fprintf(stderr, "hint: cluster mode is not enabled on this server\n");
        return 1;
    }

    uint32_t count = r32le(resp + 4);
    uint32_t off   = 8;

#define NENTRY 148u
    printf("%-8s  %-7s  %-5s  %-40s  %s\n",
           "NODE_ID", "ROLE", "ACTV", "HOSTNAME", "SYNC_WATERMARK");
    for (uint32_t i = 0; i < count; i++) {
        if (off + NENTRY > resp_plen) break;
        uint64_t node_id   = r64le(resp + off);
        uint8_t  role      = resp[off + 8];
        uint8_t  is_active = resp[off + 9];
        char     hostname[129];
        memcpy(hostname, resp + off + 12, 128); hostname[128] = '\0';
        uint64_t watermark = r64le(resp + off + 140);
        off += NENTRY;

        printf("%-8llu  %-7s  %-5s  %-40s  %llu\n",
               (unsigned long long)node_id,
               role == VW_NODE_ROLE_SELF ? "self" : "replica",
               is_active ? "yes" : "no",
               hostname,
               (unsigned long long)watermark);
    }
#undef NENTRY

    free(resp);
    return 0;
}

static void print_scrub_stats(uint32_t code, int64_t last_run_unix,
                               uint64_t scanned, uint64_t corrupt, uint64_t tombstoned)
{
    if (code != 0) {
        fprintf(stderr, "error: scrub: %s (code %u)\n", err_str(code), code);
        return;
    }
    if (last_run_unix == 0) {
        printf("no scrub pass has run yet\n");
        return;
    }
    char timebuf[32];
    time_t t = (time_t)last_run_unix;
    struct tm *tmv = localtime(&t);
    if (tmv) strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tmv);
    else     snprintf(timebuf, sizeof(timebuf), "%lld", (long long)last_run_unix);

    printf("last run:   %s\n", timebuf);
    printf("scanned:    %llu\n", (unsigned long long)scanned);
    printf("corrupt:    %llu%s\n", (unsigned long long)corrupt,
           corrupt > 0 ? "  (still referenced — see server logs; not yet auto-repaired)" : "");
    printf("tombstoned: %llu  (ref_count==0 — not reported as an error)\n",
           (unsigned long long)tombstoned);
}

static int cmd_scrub_run(int fd)
{
    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_SCRUB_RUN_REQ, NULL, 0,
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    if (resp_plen < 28) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    if (code != 0) {
        free(resp);
        fprintf(stderr, "error: scrub run failed: %s (code %u)\n", err_str(code), code);
        return 1;
    }
    uint64_t scanned    = r64le(resp + 4);
    uint64_t corrupt    = r64le(resp + 12);
    uint64_t tombstoned = r64le(resp + 20);
    free(resp);

    print_scrub_stats(0, (int64_t)time(NULL), scanned, corrupt, tombstoned);
    return 0;
}

static int cmd_scrub_status(int fd)
{
    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_SCRUB_STATUS_REQ, NULL, 0,
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    if (resp_plen < 36) { free(resp); fprintf(stderr, "error: truncated response\n"); return 1; }
    uint32_t code = r32le(resp);
    if (code != 0) {
        free(resp);
        fprintf(stderr, "error: scrub status failed: %s (code %u)\n", err_str(code), code);
        return 1;
    }
    int64_t  last_run   = (int64_t)r64le(resp + 4);
    uint64_t scanned    = r64le(resp + 12);
    uint64_t corrupt    = r64le(resp + 20);
    uint64_t tombstoned = r64le(resp + 28);
    free(resp);

    print_scrub_stats(0, last_run, scanned, corrupt, tombstoned);
    return 0;
}

/* ── Usage ─────────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--admin-socket <path>] <command> [args]\n"
        "\n"
        "Commands:\n"
        "  user-create <username> <password> [--admin]   Create a user account\n"
        "  user-list                                      List all users\n"
        "  set-quota <username> <bytes>                   Set quota (0 = unlimited)\n"
        "  set-admin-caps <username> <all|cap1,cap2,...>  Delegate a narrower admin role\n"
        "                                                  Capabilities: user_mgmt,\n"
        "                                                  quota_mgmt, audit_read,\n"
        "                                                  cluster_mgmt, cert_reload\n"
        "  oplog-tail [--count N]                         Print last N oplog entries (default 20)\n"
        "  list-connections                               List active connections\n"
        "  list-deleted <username>                        List a user's trashed (soft-deleted) files\n"
        "  restore-file <file_id>                         Restore a trashed file (from list-deleted)\n"
        "  reload-cert                                    Reload TLS certificate\n"
        "  cluster node-add <hostname>                    Register a replica (run on the primary)\n"
        "  cluster register-self <node_id> <token|-|--stdin-token> <host>\n"
        "                                                  Complete pairing (run on the replica,\n"
        "                                                  using node-add's printed node_id/token).\n"
        "                                                  Pass '-' or '--stdin-token' to read the\n"
        "                                                  token from stdin instead of argv.\n"
        "  cluster status                                 List registered cluster nodes\n"
        "  cluster-status                                 Alias for 'cluster status' (v0.1.0 spelling)\n"
        "  scrub run                                      Run one full chunk-store integrity scan now\n"
        "                                                  (detection only — see docs/PROTOCOL.md and\n"
        "                                                  ARCHITECTURE.md Phase 22 for repair status)\n"
        "  scrub status                                   Report results of the most recent scan\n"
        "\n"
        "Options:\n"
        "  --admin-socket <path>  Admin Unix socket path (default: %s)\n"
        "  --version              Print version and exit\n"
        "  --help, -h             Show this help\n",
        prog, VW_ADMIN_DEFAULT_SOCKET);
}

/* ── Entry point ────────────────────────────────────────────────────────────── */

int vw_server_cli_main(int argc, char *argv[])
{
    const char *admin_socket = VW_ADMIN_DEFAULT_SOCKET;
    int         argi         = 1;
    int         fd           = -1;
    int         rc           = 1;

    /* Parse global flags */
    while (argi < argc) {
        if (strcmp(argv[argi], "--admin-socket") == 0 && argi + 1 < argc) {
            admin_socket = argv[++argi];
            argi++;
        } else if (strcmp(argv[argi], "--help") == 0 ||
                   strcmp(argv[argi], "-h") == 0) {
            usage(argv[0]); rc = 0; goto done;
        } else if (strcmp(argv[argi], "--version") == 0) {
            printf("vapourwault-server-cli %s\n", VW_VERSION_STRING);
            rc = 0; goto done;
        } else {
            break;
        }
    }

    if (argi >= argc) { usage(argv[0]); goto done; }

    fd = admin_connect(admin_socket);
    if (fd < 0) goto done;

    const char *cmd = argv[argi++];

    if (strcmp(cmd, "user-create") == 0) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "Usage: %s user-create <username> <password|-|--stdin-password> [--admin]\n"
                            "  Pass '-' or '--stdin-password' to read the password from stdin.\n",
                    argv[0]);
            goto done;
        }
        const char *uname = argv[argi++];
        const char *pw_arg = argv[argi++];
        int is_admin = (argi < argc && strcmp(argv[argi], "--admin") == 0);

        /* Read password from stdin when '-' or '--stdin-password' is specified,
         * to avoid exposing it in /proc/<pid>/cmdline and ps output. */
        static char stdin_pw[256];
        const char *pw;
        if (strcmp(pw_arg, "-") == 0 || strcmp(pw_arg, "--stdin-password") == 0) {
            if (!fgets(stdin_pw, (int)sizeof(stdin_pw), stdin)) {
                fprintf(stderr, "error: failed to read password from stdin\n");
                goto done;
            }
            /* Strip trailing newline */
            size_t plen = strlen(stdin_pw);
            if (plen > 0 && stdin_pw[plen - 1] == '\n') stdin_pw[--plen] = '\0';
            pw = stdin_pw;
        } else {
            pw = pw_arg;
        }
        rc = cmd_user_create(fd, uname, pw, is_admin);

    } else if (strcmp(cmd, "user-list") == 0) {
        rc = cmd_user_list(fd);

    } else if (strcmp(cmd, "set-quota") == 0) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "Usage: %s set-quota <username> <bytes>\n", argv[0]);
            goto done;
        }
        const char *uname = argv[argi++];
        uint64_t    bytes = (uint64_t)strtoull(argv[argi++], NULL, 10);
        rc = cmd_set_quota(fd, uname, bytes);

    } else if (strcmp(cmd, "set-admin-caps") == 0) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "Usage: %s set-admin-caps <username> <all|cap1,cap2,...>\n"
                            "  Capabilities: user_mgmt, quota_mgmt, audit_read, "
                            "cluster_mgmt, cert_reload\n",
                    argv[0]);
            goto done;
        }
        const char *uname = argv[argi++];
        const char *spec  = argv[argi++];
        uint32_t    caps;
        if (parse_caps(spec, &caps) != 0) goto done;
        rc = cmd_set_admin_caps(fd, uname, caps);

    } else if (strcmp(cmd, "oplog-tail") == 0) {
        uint32_t count = 20;
        if (argi < argc && strcmp(argv[argi], "--count") == 0 && argi + 1 < argc) {
            argi++;
            count = (uint32_t)strtoul(argv[argi++], NULL, 10);
            if (count == 0 || count > 100) count = 20;
        }
        rc = cmd_oplog_tail(fd, count);

    } else if (strcmp(cmd, "list-connections") == 0) {
        rc = cmd_list_connections(fd);

    } else if (strcmp(cmd, "list-deleted") == 0) {
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s list-deleted <username>\n", argv[0]);
            goto done;
        }
        rc = cmd_list_deleted(fd, argv[argi++]);

    } else if (strcmp(cmd, "restore-file") == 0) {
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s restore-file <file_id>\n", argv[0]);
            goto done;
        }
        uint64_t file_id = (uint64_t)strtoull(argv[argi++], NULL, 10);
        rc = cmd_restore_file(fd, file_id);

    } else if (strcmp(cmd, "reload-cert") == 0) {
        rc = cmd_reload_cert(fd);

    } else if (strcmp(cmd, "cluster") == 0) {
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s cluster node-add <hostname>\n"
                            "       %s cluster register-self <node_id> <token> <hostname>\n"
                            "       %s cluster status\n",
                    argv[0], argv[0], argv[0]);
            goto done;
        }
        const char *sub = argv[argi++];
        if (strcmp(sub, "node-add") == 0) {
            if (argi >= argc) {
                fprintf(stderr, "Usage: %s cluster node-add <hostname>\n", argv[0]);
                goto done;
            }
            const char *hostname = argv[argi++];
            rc = cmd_cluster_node_add(fd, hostname);

        } else if (strcmp(sub, "register-self") == 0) {
            if (argi + 2 >= argc) {
                fprintf(stderr, "Usage: %s cluster register-self <node_id> <token> <hostname>\n", argv[0]);
                goto done;
            }
            uint64_t node_id   = (uint64_t)strtoull(argv[argi++], NULL, 10);
            const char *token  = argv[argi++];
            const char *hostname = argv[argi++];
            rc = cmd_cluster_register_self(fd, node_id, token, hostname);

        } else if (strcmp(sub, "status") == 0) {
            /* TASK-086: "cluster status" nested form, added for symmetry with
             * "cluster node-add"/"cluster register-self". "cluster-status"
             * (flat, below) is v0.1.0's original spelling and is kept
             * indefinitely as an alias — v0.1.0 already shipped with it, so
             * removing it would break any existing script/muscle-memory for
             * no functional gain. */
            rc = cmd_cluster_status(fd);

        } else {
            fprintf(stderr, "error: unknown cluster subcommand '%s'\n", sub);
        }

    } else if (strcmp(cmd, "cluster-status") == 0) {
        rc = cmd_cluster_status(fd);

    } else if (strcmp(cmd, "scrub") == 0) {
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s scrub run\n"
                            "       %s scrub status\n",
                    argv[0], argv[0]);
            goto done;
        }
        const char *sub = argv[argi++];
        if (strcmp(sub, "run") == 0) {
            rc = cmd_scrub_run(fd);
        } else if (strcmp(sub, "status") == 0) {
            rc = cmd_scrub_status(fd);
        } else {
            fprintf(stderr, "error: unknown scrub subcommand '%s'\n", sub);
        }

    } else {
        fprintf(stderr, "error: unknown command '%s'\n", cmd);
        usage(argv[0]);
    }

done:
#ifndef _WIN32
    if (fd >= 0) close(fd);
#endif
    return rc;
}
