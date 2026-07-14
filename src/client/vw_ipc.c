#include "vw_ipc.h"
#include "../core/vw_proto.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
typedef SOCKET          sock_fd_t;
#  define SOCK_INVALID  INVALID_SOCKET
static int sock_close(SOCKET s) { return closesocket(s); }
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <errno.h>
#  ifdef __linux__
#    include <sys/un.h>   /* struct ucred */
#  endif
typedef int             sock_fd_t;
#  define SOCK_INVALID  (-1)
static int sock_close(int s) { return close(s); }
#endif

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

#if defined(__linux__)
    /* UID check: refuse connections from processes owned by other users. */
    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0) {
        if (cred.uid != getuid()) {
            sock_close(cfd);
            return VW_ERR_AUTH_REQUIRED;
        }
    }
#elif defined(_WIN32)
    /* TODO Phase 6: use GetExtendedTcpTable to verify connecting process UID.
     * Risk is low for Phase 3; loopback binding limits exposure to localhost. */
#endif
    /* macOS: SO_PEERCRED not available; UID check deferred (loopback only). */

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
