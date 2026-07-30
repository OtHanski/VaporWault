#if defined(__linux__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE
#endif
#include "vw_ipc.h"
#include "vw_ipc_internal.h"
#include "../core/vw_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <windows.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "advapi32.lib")
typedef SOCKET          sock_fd_t;
#  define SOCK_INVALID  INVALID_SOCKET
static int sock_close(SOCKET s) { return closesocket(s); }
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <errno.h>
typedef int             sock_fd_t;
#  define SOCK_INVALID  (-1)
static int sock_close(int s) { return close(s); }
#endif

/* ── Linux peer-UID verification (TASK-093) ─────────────────────────────────
 *
 * This channel is AF_INET/TCP (unlike the admin.sock AF_UNIX channel in
 * vw_admin.c), so SO_PEERCRED does not apply — see this file's header
 * comment and vw_ipc.h for why an earlier version's use of it silently
 * rejected every connection on at least one real kernel. /proc/net/tcp
 * exposes the owning uid of every TCP socket on the system (loopback
 * connections included) without needing SO_PEERCRED at all: each line is
 * one socket, keyed by its local/remote address:port pair and state. */

#ifdef __linux__
#define VW_TCP_ESTABLISHED 1u

/* See vw_ipc_internal.h for this function's full contract. */
int vw_ipc_linux_proc_net_tcp_uid(FILE *f, uint16_t local_port, uint16_t peer_port,
                                   unsigned long *out_uid)
{
    char line[512];
    uint32_t loopback_be;

    if (!f || !out_uid) return 1;

    /* /proc/net/tcp prints each address as the raw in-memory bytes of the
     * kernel's network-byte-order __be32, reinterpreted as an unsigned int
     * in the host's own endianness — so the printed hex value is endian-
     * dependent and must be computed the same way here, not hardcoded as
     * "0100007F" (only true on little-endian hosts). */
    {
        struct in_addr ia;
        ia.s_addr = htonl(INADDR_LOOPBACK);
        memcpy(&loopback_be, &ia, sizeof(loopback_be));
    }

    /* Header line ("sl  local_address rem_address ..."); discard. */
    if (!fgets(line, sizeof(line), f)) return 1;

    while (fgets(line, sizeof(line), f)) {
        unsigned local_addr, lport, rem_addr, rport, state;
        unsigned long uid;

        /* "  N: LLLLLLLL:PPPP RRRRRRRR:PPPP SS tx:rx tr:tm retrnsmt uid ..." */
        int n = sscanf(line, " %*x: %x:%x %x:%x %x %*x:%*x %*x:%*x %*x %lu",
                       &local_addr, &lport, &rem_addr, &rport, &state, &uid);
        if (n != 6) continue;
        if (state != VW_TCP_ESTABLISHED) continue;
        if (lport != (unsigned)local_port || rport != (unsigned)peer_port) continue;
        /* This channel is loopback-only by construction (vw_ipc_server_open
         * binds INADDR_LOOPBACK) — reject any match against a non-loopback
         * address rather than silently trusting a coincidental port match
         * on a different interface. */
        if (local_addr != loopback_be || rem_addr != loopback_be) continue;

        *out_uid = uid;
        return 0;
    }
    return 1;
}
#endif /* __linux__ */

/* ── Windows peer-UID (SID) verification (TASK-103) ─────────────────────────
 *
 * GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL) is the Windows
 * equivalent of /proc/net/tcp: a system-wide snapshot of TCP connections,
 * each row carrying the owning PID. Same subtlety as Linux applies — see
 * vw_ipc_server_accept() below for which way round to pass the ports. */

#ifdef _WIN32

/* See vw_ipc_internal.h for this function's full contract. */
int vw_ipc_win_tcp_table_pid(const MIB_TCPROW_OWNER_PID *rows, DWORD row_count,
                              uint16_t local_port, uint16_t peer_port,
                              uint32_t loopback_be, DWORD *out_pid)
{
    DWORD i;

    if (!rows || !out_pid) return 1;

    for (i = 0; i < row_count; i++) {
        const MIB_TCPROW_OWNER_PID *r = &rows[i];

        if (r->dwState != MIB_TCP_STATE_ESTAB) continue;
        /* dwLocalPort/dwRemotePort store the port in network byte order in
         * the low 16 bits of the DWORD. */
        if (ntohs((uint16_t)r->dwLocalPort)  != local_port) continue;
        if (ntohs((uint16_t)r->dwRemotePort) != peer_port)  continue;
        if ((uint32_t)r->dwLocalAddr != loopback_be) continue;
        if ((uint32_t)r->dwRemoteAddr != loopback_be) continue;

        *out_pid = r->dwOwningPid;
        return 0;
    }
    return 1;
}

/* Fetches process `pid`'s token-user SID into a caller-owned buffer.
 * Returns 0 on success (*out_sid points inside *out_buf; free *out_buf with
 * free()), nonzero on any failure (insufficient privilege, PID already
 * exited, etc.) — every failure here is meant to be non-fatal to the caller,
 * which must fall back to "trust", not "reject", per this task's acceptance
 * criteria. */
static int win_get_process_user_sid(DWORD pid, uint8_t **out_buf, PSID *out_sid)
{
    HANDLE  proc = NULL, token = NULL;
    DWORD   needed = 0;
    uint8_t *buf = NULL;
    int      ok = 1;

    *out_buf = NULL;
    *out_sid = NULL;

    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return 1;

    if (!OpenProcessToken(proc, TOKEN_QUERY, &token)) goto done;

    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (needed == 0) goto done;
    buf = (uint8_t *)malloc(needed);
    if (!buf) goto done;
    if (!GetTokenInformation(token, TokenUser, buf, needed, &needed)) goto done;

    *out_sid = ((TOKEN_USER *)buf)->User.Sid;
    *out_buf = buf;
    buf = NULL; /* ownership transferred to *out_buf */
    ok = 0;

done:
    if (buf) free(buf);
    if (token) CloseHandle(token);
    if (proc) CloseHandle(proc);
    return ok;
}

#endif /* _WIN32 */

/* ── Internal structs ────────────────────────────────────────────────────── */

struct vw_ipc_conn {
    sock_fd_t fd;
};

struct vw_ipc_server {
    sock_fd_t listen_fd;
};

/* ── One-time platform init (idempotent) ─────────────────────────────────── */

static void ipc_platform_init(void) {
#ifdef _WIN32
    static int done = 0;
    if (!done) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        done = 1;
    }
#endif
}

/* ── Raw socket I/O (no TLS) ─────────────────────────────────────────────── */

static vw_err_t raw_send_all(sock_fd_t fd, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        int n = send(fd, (const char *)(p + sent), (int)(len - sent), 0);
        if (n == SOCKET_ERROR) return VW_ERR_NET_CLOSED;
#else
        ssize_t n;
        do {
            n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) return VW_ERR_NET_CLOSED;
#endif
        sent += (size_t)n;
    }
    return VW_OK;
}

static vw_err_t raw_recv_all(sock_fd_t fd, void *data, size_t len) {
    uint8_t *p = (uint8_t *)data;
    size_t got = 0;
    while (got < len) {
#ifdef _WIN32
        int n = recv(fd, (char *)(p + got), (int)(len - got), 0);
        if (n == 0) return VW_ERR_NET_CLOSED;
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            return (e == WSAETIMEDOUT) ? VW_ERR_NET_TIMEOUT : VW_ERR_NET_CLOSED;
        }
#else
        ssize_t n;
        do {
            n = recv(fd, p + got, len - got, 0);
        } while (n < 0 && errno == EINTR);
        if (n == 0) return VW_ERR_NET_CLOSED;
        if (n < 0) {
            return (errno == EAGAIN || errno == EWOULDBLOCK)
                   ? VW_ERR_NET_TIMEOUT : VW_ERR_NET_CLOSED;
        }
#endif
        got += (size_t)n;
    }
    return VW_OK;
}

/* ── IPC send / recv ─────────────────────────────────────────────────────── */

vw_err_t vw_ipc_send(vw_ipc_conn_t *conn, vw_ipc_msg_t type,
                      const void *payload, uint32_t payload_len) {
    if (!conn) return VW_ERR_INVALID_ARG;

    uint32_t total_len = VW_PROTO_HEADER_SIZE + payload_len;
    /* overflow guard */
    if (total_len < VW_PROTO_HEADER_SIZE) return VW_ERR_PROTO_TOO_LARGE;
    if (total_len > VW_MAX_MSG_BYTES)     return VW_ERR_PROTO_TOO_LARGE;

    uint8_t hdr[VW_PROTO_HEADER_SIZE];
    vw_write_u32le(hdr + 0, total_len);
    vw_write_u16le(hdr + 4, (uint16_t)type);
    vw_write_u16le(hdr + 6, VW_PROTO_VERSION_CURRENT);

    vw_err_t err = raw_send_all(conn->fd, hdr, VW_PROTO_HEADER_SIZE);
    if (err != VW_OK) return err;
    if (payload_len > 0)
        err = raw_send_all(conn->fd, payload, payload_len);
    return err;
}

vw_err_t vw_ipc_recv(vw_ipc_conn_t *conn, vw_ipc_msg_t *out_type,
                      void *out_buf, uint32_t buf_size,
                      uint32_t *out_payload_len) {
    if (!conn || !out_type || !out_payload_len) return VW_ERR_INVALID_ARG;

    uint8_t hdr[VW_PROTO_HEADER_SIZE];
    vw_err_t err = raw_recv_all(conn->fd, hdr, VW_PROTO_HEADER_SIZE);
    if (err != VW_OK) return err;

    uint32_t total_len = vw_read_u32le(hdr + 0);
    if (total_len < VW_PROTO_HEADER_SIZE) return VW_ERR_PROTO_INVALID;
    if (total_len > VW_MAX_MSG_BYTES)     return VW_ERR_PROTO_TOO_LARGE;

    uint32_t payload_len = total_len - VW_PROTO_HEADER_SIZE;
    if (payload_len > buf_size) return VW_ERR_PROTO_TOO_LARGE;

    *out_type = (vw_ipc_msg_t)vw_read_u16le(hdr + 4);

    if (payload_len > 0) {
        err = raw_recv_all(conn->fd, out_buf, payload_len);
        if (err != VW_OK) return err;
    }
    *out_payload_len = payload_len;
    return VW_OK;
}

void vw_ipc_conn_close(vw_ipc_conn_t *conn) {
    if (!conn) return;
    if (conn->fd != SOCK_INVALID)
        sock_close(conn->fd);
    free(conn);
}

vw_err_t vw_ipc_conn_set_recv_timeout(vw_ipc_conn_t *conn, uint32_t timeout_ms) {
    if (!conn) return VW_ERR_INVALID_ARG;
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&tv, sizeof(tv)) != 0)
        return VW_ERR_IO;
#else
    struct timeval tv;
    tv.tv_sec  = (long)(timeout_ms / 1000u);
    tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
    if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        return VW_ERR_IO;
#endif
    return VW_OK;
}

/* ── Server ──────────────────────────────────────────────────────────────── */

vw_err_t vw_ipc_server_open(uint16_t port, vw_ipc_server_t **out) {
    if (!out) return VW_ERR_INVALID_ARG;
    ipc_platform_init();

    sock_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == SOCK_INVALID) return VW_ERR_NET_CONNECT;

    int yes = 1;
#ifdef _WIN32
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
#else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 only */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sock_close(fd);
        return VW_ERR_NET_CONNECT;
    }
    if (listen(fd, 8) != 0) {
        sock_close(fd);
        return VW_ERR_NET_CONNECT;
    }

    vw_ipc_server_t *srv = malloc(sizeof(*srv));
    if (!srv) { sock_close(fd); return VW_ERR_OOM; }
    srv->listen_fd = fd;
    *out = srv;
    return VW_OK;
}

void vw_ipc_server_close(vw_ipc_server_t *srv) {
    if (!srv) return;
    if (srv->listen_fd != SOCK_INVALID)
        sock_close(srv->listen_fd);
    free(srv);
}

vw_err_t vw_ipc_server_accept(vw_ipc_server_t *srv, vw_ipc_conn_t **out_conn) {
    if (!srv || !out_conn) return VW_ERR_INVALID_ARG;

    struct sockaddr_in client_addr;
#ifdef _WIN32
    int addr_len = (int)sizeof(client_addr);
#else
    socklen_t addr_len = sizeof(client_addr);
#endif
    sock_fd_t cfd = accept(srv->listen_fd,
                            (struct sockaddr *)&client_addr, &addr_len);
    if (cfd == SOCK_INVALID) return VW_ERR_NET_CLOSED;

#if defined(_WIN32)
    /* TASK-103: real peer-UID (SID) verification via GetExtendedTcpTable.
     *
     * Deliberately permissive on any failure to positively identify a
     * *mismatched* SID: unlike /proc/net/tcp, GetExtendedTcpTable is a
     * heavier whole-system snapshot with a real race window between our
     * accept() and the table read, and PROCESS_QUERY_LIMITED_INFORMATION/
     * token access can legitimately fail for reasons unrelated to the
     * connecting process's identity. Rejecting on any of that would risk
     * regressing to "every connection fails" — the exact class of bug
     * TASK-093 fixed on Linux. So: only reject when we successfully
     * resolve the peer's owning SID AND it does not match ours; every
     * other outcome (table fetch failed, PID not found in the table,
     * OpenProcess/OpenProcessToken/GetTokenInformation failed) falls back
     * to trusting the loopback bind alone. */
    {
        struct sockaddr_in local_addr;
        int      local_len = (int)sizeof(local_addr);
        int      verified = 1;

        if (getsockname(cfd, (struct sockaddr *)&local_addr, &local_len) == 0) {
            uint16_t our_port  = ntohs(local_addr.sin_port);
            uint16_t peer_port = ntohs(client_addr.sin_port);
            uint32_t loopback_be = htonl(INADDR_LOOPBACK);
            DWORD    table_size = 0;
            DWORD    rc = GetExtendedTcpTable(NULL, &table_size, FALSE, AF_INET,
                                               TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc == ERROR_INSUFFICIENT_BUFFER && table_size > 0) {
                PMIB_TCPTABLE_OWNER_PID table =
                    (PMIB_TCPTABLE_OWNER_PID)malloc(table_size);
                if (table) {
                    rc = GetExtendedTcpTable(table, &table_size, FALSE, AF_INET,
                                              TCP_TABLE_OWNER_PID_ALL, 0);
                    if (rc == NO_ERROR) {
                        DWORD pid = 0;
                        /* Swapped on purpose — see the Linux branch's comment
                         * above for why (same two-rows-per-connection issue). */
                        int found = vw_ipc_win_tcp_table_pid(
                            table->table, table->dwNumEntries,
                            peer_port, our_port, loopback_be, &pid);
                        if (found == 0) {
                            uint8_t *sid_buf = NULL, *self_sid_buf = NULL;
                            PSID     peer_sid = NULL, self_sid = NULL;

                            if (win_get_process_user_sid(pid, &sid_buf, &peer_sid) == 0 &&
                                win_get_process_user_sid(GetCurrentProcessId(),
                                                          &self_sid_buf, &self_sid) == 0) {
                                if (!EqualSid(peer_sid, self_sid))
                                    verified = 0;
                            }
                            free(sid_buf);
                            free(self_sid_buf);
                        }
                    }
                    free(table);
                }
            }
        }

        if (!verified) {
            sock_close(cfd);
            return VW_ERR_AUTH_REQUIRED;
        }
    }
#endif
#ifdef __linux__
    /* TASK-093: real peer-UID verification via /proc/net/tcp. SO_PEERCRED
     * doesn't apply to this AF_INET/TCP channel (see this file's header
     * comment) — /proc/net/tcp instead exposes the owning uid of every TCP
     * socket, keyed by local/remote port pair, without it.
     *
     * SUBTLE: a single loopback TCP connection has *two* rows in
     * /proc/net/tcp, one per socket — and the two sockets can be (and here,
     * always are) owned by different processes/uids. The row for *our own*
     * just-accepted socket (local=our port, remote=client's port) is always
     * owned by us, the daemon — accept() creates that socket in our own
     * process regardless of who connected. The row that actually tells us
     * who connected is the *client's* socket: local=client's port,
     * remote=our port — i.e. the address pair swapped. Searching with the
     * un-swapped pair is a tautology that always finds our own uid and
     * verifies nothing; the swap below is the actual check.
     *
     * If /proc/net/tcp can't be read at all (e.g. some restricted container
     * profiles), fall back to trusting loopback binding alone rather than
     * rejecting every connection outright — regressing to that would be
     * exactly the bug this task was filed to fix. But if it *can* be read
     * and either no matching ESTABLISHED entry is found or the owning uid
     * doesn't match ours, reject: retrying accept() is cheap for a local
     * daemon, so failing closed on a genuine anomaly (or the very small
     * TOCTOU window between accept() and this read) costs nothing. */
    {
        struct sockaddr_in local_addr;
        socklen_t local_len = sizeof(local_addr);
        int verified = 1;

        if (getsockname(cfd, (struct sockaddr *)&local_addr, &local_len) == 0) {
            uint16_t our_port   = ntohs(local_addr.sin_port);
            uint16_t peer_port  = ntohs(client_addr.sin_port);
            FILE *f = fopen("/proc/net/tcp", "r");
            if (f) {
                unsigned long uid = 0;
                /* Swapped on purpose — see the comment above. */
                int rc = vw_ipc_linux_proc_net_tcp_uid(f, peer_port, our_port, &uid);
                fclose(f);
                verified = (rc == 0 && (uid_t)uid == getuid());
            }
        }

        if (!verified) {
            sock_close(cfd);
            return VW_ERR_AUTH_REQUIRED;
        }
    }
#endif
    /* macOS: no peer-UID check here (see vw_ipc.h header comment). macOS
     * support is deferred project-wide, so this is not tracked further. */

    vw_ipc_conn_t *conn = malloc(sizeof(*conn));
    if (!conn) { sock_close(cfd); return VW_ERR_OOM; }
    conn->fd = cfd;
    *out_conn = conn;
    return VW_OK;
}

vw_err_t vw_ipc_server_try_accept(vw_ipc_server_t *srv, vw_ipc_conn_t **out_conn) {
    if (!srv || !out_conn) return VW_ERR_INVALID_ARG;
#ifdef _WIN32
    /* Windows select(): first arg is ignored; fd_set uses SOCKET handles */
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(srv->listen_fd, &rset);
    TIMEVAL tv = {0, 0};
    int sel = select(0, &rset, NULL, NULL, &tv);
#else
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(srv->listen_fd, &rset);
    struct timeval tv = {0, 0};
    int sel = select((int)srv->listen_fd + 1, &rset, NULL, NULL, &tv);
#endif
    if (sel <= 0) return VW_ERR_TIMEOUT;
    return vw_ipc_server_accept(srv, out_conn);
}

/* ── Client ──────────────────────────────────────────────────────────────── */

vw_err_t vw_ipc_connect(uint16_t port, vw_ipc_conn_t **out_conn) {
    if (!out_conn) return VW_ERR_INVALID_ARG;
    ipc_platform_init();

    sock_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == SOCK_INVALID) return VW_ERR_IPC_NOT_RUNNING;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sock_close(fd);
        return VW_ERR_IPC_NOT_RUNNING;
    }

    vw_ipc_conn_t *conn = malloc(sizeof(*conn));
    if (!conn) { sock_close(fd); return VW_ERR_OOM; }
    conn->fd = fd;
    *out_conn = conn;
    return VW_OK;
}

/* ── String encode / decode helpers ──────────────────────────────────────── */

vw_err_t vw_ipc_write_str(uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                            const char *str, uint16_t str_len) {
    if (!buf || !offset) return VW_ERR_INVALID_ARG;
    uint32_t needed = 2u + (uint32_t)str_len;
    if (*offset + needed > buf_size) return VW_ERR_PROTO_TOO_LARGE;
    vw_write_u16le(buf + *offset, str_len);
    *offset += 2u;
    if (str_len > 0 && str) {
        memcpy(buf + *offset, str, str_len);
        *offset += str_len;
    }
    return VW_OK;
}

vw_err_t vw_ipc_read_str(const uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                           const char **out_str, uint16_t *out_len) {
    if (!buf || !offset || !out_str || !out_len) return VW_ERR_INVALID_ARG;
    if (*offset + 2u > buf_size) return VW_ERR_PROTO_TRUNCATED;
    uint16_t slen = vw_read_u16le(buf + *offset);
    *offset += 2u;
    if (*offset + (uint32_t)slen > buf_size) return VW_ERR_PROTO_TRUNCATED;
    *out_str = (const char *)(buf + *offset);
    *out_len = slen;
    *offset += slen;
    return VW_OK;
}
