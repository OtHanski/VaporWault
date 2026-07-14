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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef _WIN32
#  include <unistd.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  define MSG_NOSIGNAL_FLAG MSG_NOSIGNAL
#else
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

static const char *err_str(uint32_t code) {
    switch (code) {
    case 0:  return "ok";
    case 1:  return "invalid_arg";
    case 2:  return "oom";
    case 3:  return "io";
    case 4:  return "not_found";
    case 5:  return "already_exists";
    case 6:  return "quota_exceeded";
    case 7:  return "auth_bad_creds";
    default: return "unknown";
    }
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

#define UENTRY 92u
    printf("%-8s  %-5s  %-5s  %-64s  %-16s  %-16s\n",
           "USER_ID", "ADMIN", "ACTV", "USERNAME", "QUOTA", "USED");

    for (uint32_t i = 0; i < count; i++) {
        if (off + UENTRY > resp_plen) break;
        uint64_t uid        = r64le(resp + off);
        uint8_t  is_admin   = resp[off + 8];
        uint8_t  is_active  = resp[off + 9];
        char     uname[65];
        memcpy(uname, resp + off + 12, 64); uname[64] = '\0';
        uint64_t qb = r64le(resp + off + 76);
        uint64_t ub = r64le(resp + off + 84);
        off += UENTRY;

        printf("%-8llu  %-5s  %-5s  %-64s  %-16llu  %-16llu\n",
               (unsigned long long)uid,
               is_admin  ? "yes" : "no",
               is_active ? "yes" : "no",
               uname,
               (unsigned long long)qb,
               (unsigned long long)ub);
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

static int cmd_list_connections(int fd)
{
    uint16_t resp_type;
    uint8_t *resp = NULL;
    uint32_t resp_plen = 0;
    if (admin_rpc(fd, (uint16_t)VW_ADMIN_CONN_LIST_REQ, NULL, 0,
                   &resp_type, &resp, &resp_plen) < 0) return 1;

    uint32_t count = (resp_plen >= 4) ? r32le(resp) : 0;
    free(resp);
    printf("%u active connection(s)\n", (unsigned)count);
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

/* ── Usage ─────────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--admin-socket <path>] <command> [args]\n"
        "\n"
        "Commands:\n"
        "  user-create <username> <password> [--admin]   Create a user account\n"
        "  user-list                                      List all users\n"
        "  set-quota <username> <bytes>                   Set quota (0 = unlimited)\n"
        "  oplog-tail [--count N]                         Print last N oplog entries (default 20)\n"
        "  list-connections                               List active connections\n"
        "  reload-cert                                    Reload TLS certificate\n"
        "\n"
        "Options:\n"
        "  --admin-socket <path>  Admin Unix socket path (default: %s)\n"
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
            fprintf(stderr, "Usage: %s user-create <username> <password> [--admin]\n", argv[0]);
            goto done;
        }
        const char *uname = argv[argi++];
        const char *pw    = argv[argi++];
        int is_admin = (argi < argc && strcmp(argv[argi], "--admin") == 0);
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

    } else if (strcmp(cmd, "reload-cert") == 0) {
        rc = cmd_reload_cert(fd);

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
