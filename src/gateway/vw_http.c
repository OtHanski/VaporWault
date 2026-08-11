#include "vw_http.h"

#include <mbedtls/net_sockets.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

struct vw_http_ctx {
    mbedtls_net_context listen_fd;
};

struct vw_http_conn {
    mbedtls_net_context fd;
};

/* ── Small local helpers (no libc case-insensitive compare is portable
 * across MSVC/GCC/Clang without platform #ifdefs, so hand-roll one) ──────── */

static int ascii_ieq(const char *a, const char *b) {
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static const char *http_status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 409: return "Conflict";
        case 500: return "Internal Server Error";
        default:  return "Unknown";
    }
}

static vw_err_t parse_method(const char *tok, size_t len, vw_http_method_t *out) {
    if (len == 3 && memcmp(tok, "GET", 3) == 0)    { *out = VW_HTTP_GET;    return VW_OK; }
    if (len == 4 && memcmp(tok, "POST", 4) == 0)   { *out = VW_HTTP_POST;   return VW_OK; }
    if (len == 3 && memcmp(tok, "PUT", 3) == 0)    { *out = VW_HTTP_PUT;    return VW_OK; }
    if (len == 6 && memcmp(tok, "DELETE", 6) == 0) { *out = VW_HTTP_DELETE; return VW_OK; }
    return VW_ERR_PROTO_INVALID;
}

/* ── Listen / accept ─────────────────────────────────────────────────────── */

vw_err_t vw_http_listen(const char *host, uint16_t port, vw_http_ctx_t **out_ctx) {
    if (host == NULL || out_ctx == NULL) return VW_ERR_INVALID_ARG;

    vw_http_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return VW_ERR_OOM;

    mbedtls_net_init(&ctx->listen_fd);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    if (mbedtls_net_bind(&ctx->listen_fd, host, port_str, MBEDTLS_NET_PROTO_TCP) != 0) {
        mbedtls_net_free(&ctx->listen_fd);
        free(ctx);
        return VW_ERR_NET_CONNECT;
    }

    *out_ctx = ctx;
    return VW_OK;
}

void vw_http_ctx_close(vw_http_ctx_t *ctx) {
    if (ctx == NULL) return;
    mbedtls_net_free(&ctx->listen_fd);
    free(ctx);
}

vw_err_t vw_http_accept(vw_http_ctx_t *ctx, vw_http_conn_t **out_conn) {
    if (ctx == NULL || out_conn == NULL) return VW_ERR_INVALID_ARG;

    vw_http_conn_t *conn = calloc(1, sizeof(*conn));
    if (conn == NULL) return VW_ERR_OOM;

    mbedtls_net_init(&conn->fd);

    if (mbedtls_net_accept(&ctx->listen_fd, &conn->fd, NULL, 0, NULL) != 0) {
        mbedtls_net_free(&conn->fd);
        free(conn);
        return VW_ERR_NET_CONNECT;
    }

    *out_conn = conn;
    return VW_OK;
}

void vw_http_conn_close(vw_http_conn_t *conn) {
    if (conn == NULL) return;
    mbedtls_net_free(&conn->fd);
    free(conn);
}

/* ── Request parsing ─────────────────────────────────────────────────────── */

/*
 * Reads from conn until buf contains "\r\n\r\n", bufsize is exhausted, or
 * the peer closes. *out_header_len is the byte offset immediately after the
 * blank line (start of any body bytes). *out_total is the total number of
 * bytes actually read into buf (>= *out_header_len when the client sent
 * body bytes in the same TCP segment(s) as the header block).
 */
static vw_err_t read_header_block(vw_http_conn_t *conn, uint8_t *buf, size_t bufsize,
                                   size_t *out_header_len, size_t *out_total) {
    size_t total = 0;

    for (;;) {
        if (total >= bufsize) return VW_ERR_PROTO_TOO_LARGE;

        int n = mbedtls_net_recv(&conn->fd, buf + total, bufsize - total);
        if (n <= 0) return VW_ERR_NET_CLOSED;
        total += (size_t)n;

        /* Scan from 3 bytes before the newly-read region so a terminator
         * split across two recv() calls is never missed. */
        size_t new_start = total - (size_t)n;
        size_t scan_from = (new_start >= 3) ? (new_start - 3) : 0;
        for (size_t i = scan_from; i + 4 <= total; i++) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' &&
                buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                *out_header_len = i + 4;
                *out_total = total;
                return VW_OK;
            }
        }
    }
}

vw_err_t vw_http_recv_request(vw_http_conn_t *conn, vw_http_request_t *out_req) {
    if (conn == NULL || out_req == NULL) return VW_ERR_INVALID_ARG;
    memset(out_req, 0, sizeof(*out_req));

    uint8_t *buf = malloc(VW_HTTP_MAX_HEADER_BLOCK);
    if (buf == NULL) return VW_ERR_OOM;

    size_t header_len = 0, total = 0;
    vw_err_t err = read_header_block(conn, buf, VW_HTTP_MAX_HEADER_BLOCK, &header_len, &total);
    if (err != VW_OK) {
        free(buf);
        return err;
    }

    /* Split the header block (excluding the terminating blank line's own
     * CRLF) into lines on "\r\n". */
    size_t pos = 0;
    int first_line = 1;

    while (pos < header_len - 2) {
        size_t line_start = pos;
        size_t line_end = line_start;
        while (line_end + 1 < header_len &&
               !(buf[line_end] == '\r' && buf[line_end + 1] == '\n')) {
            line_end++;
        }
        size_t line_len = line_end - line_start;
        pos = line_end + 2;
        const uint8_t *line = buf + line_start;

        if (first_line) {
            first_line = 0;
            if (line_len == 0) { free(buf); return VW_ERR_PROTO_INVALID; }

            size_t sp1 = 0;
            while (sp1 < line_len && line[sp1] != ' ') sp1++;
            if (sp1 == line_len) { free(buf); return VW_ERR_PROTO_INVALID; }
            if (parse_method((const char *)line, sp1, &out_req->method) != VW_OK) {
                free(buf);
                return VW_ERR_PROTO_INVALID;
            }

            size_t path_start = sp1 + 1;
            size_t sp2 = path_start;
            while (sp2 < line_len && line[sp2] != ' ') sp2++;
            if (sp2 == line_len) { free(buf); return VW_ERR_PROTO_INVALID; }

            size_t path_len = sp2 - path_start;
            if (path_len == 0 || path_len >= VW_HTTP_MAX_PATH_BYTES) {
                free(buf);
                return VW_ERR_PROTO_TOO_LARGE;
            }
            memcpy(out_req->path, line + path_start, path_len);
            out_req->path[path_len] = '\0';
            out_req->path_len = (uint16_t)path_len;
            /* The remainder ("HTTP/1.1") is not further validated — this
             * listener's only client is nginx, which always sends
             * well-formed HTTP/1.1 requests (see module scope note). */
            continue;
        }

        if (line_len == 0) break;  /* defensive; loop bound already excludes this */

        size_t colon = 0;
        while (colon < line_len && line[colon] != ':') colon++;
        if (colon == line_len) { free(buf); return VW_ERR_PROTO_INVALID; }

        if (out_req->header_count >= VW_HTTP_MAX_HEADERS) {
            free(buf);
            return VW_ERR_PROTO_TOO_LARGE;
        }

        size_t name_len = colon;
        size_t val_start = colon + 1;
        while (val_start < line_len && line[val_start] == ' ') val_start++;
        size_t val_len = line_len - val_start;

        if (name_len >= VW_HTTP_MAX_HEADER_NAME || val_len >= VW_HTTP_MAX_HEADER_VALUE) {
            free(buf);
            return VW_ERR_PROTO_TOO_LARGE;
        }

        vw_http_header_t *h = &out_req->headers[out_req->header_count++];
        memcpy(h->name, line, name_len);
        h->name[name_len] = '\0';
        memcpy(h->value, line + val_start, val_len);
        h->value[val_len] = '\0';
    }

    /* Body, if any, per Content-Length. */
    uint32_t content_length = 0;
    const char *cl = vw_http_header_get(out_req, "Content-Length");
    if (cl != NULL) {
        char *endptr = NULL;
        unsigned long v = strtoul(cl, &endptr, 10);
        if (endptr == cl || *endptr != '\0') {
            free(buf);
            return VW_ERR_PROTO_INVALID;
        }
        if (v > VW_HTTP_MAX_BODY_BYTES) {
            free(buf);
            return VW_ERR_PROTO_TOO_LARGE;
        }
        content_length = (uint32_t)v;
    }

    if (content_length > 0) {
        uint8_t *body = malloc(content_length);
        if (body == NULL) {
            free(buf);
            return VW_ERR_OOM;
        }

        size_t already_buffered = total - header_len;
        if (already_buffered > content_length) already_buffered = content_length;
        if (already_buffered > 0) memcpy(body, buf + header_len, already_buffered);

        size_t got = already_buffered;
        while (got < content_length) {
            int n = mbedtls_net_recv(&conn->fd, body + got, content_length - got);
            if (n <= 0) {
                free(body);
                free(buf);
                return VW_ERR_NET_CLOSED;
            }
            got += (size_t)n;
        }

        out_req->body = body;
        out_req->body_len = content_length;
    }

    free(buf);
    return VW_OK;
}

void vw_http_request_free(vw_http_request_t *req) {
    if (req == NULL) return;
    free(req->body);
    req->body = NULL;
    req->body_len = 0;
}

const char *vw_http_header_get(const vw_http_request_t *req, const char *name) {
    if (req == NULL || name == NULL) return NULL;
    for (uint32_t i = 0; i < req->header_count; i++) {
        if (ascii_ieq(req->headers[i].name, name)) return req->headers[i].value;
    }
    return NULL;
}

/* ── Response writing ────────────────────────────────────────────────────── */

vw_err_t vw_http_send_response(vw_http_conn_t *conn, int status_code,
                                const char *content_type,
                                const char *set_cookie,
                                const void *body, uint32_t body_len) {
    if (conn == NULL) return VW_ERR_INVALID_ARG;

    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "%s%s%s"
        "%s%s%s"
        "\r\n",
        status_code, http_status_text(status_code),
        (unsigned)body_len,
        content_type ? "Content-Type: " : "", content_type ? content_type : "", content_type ? "\r\n" : "",
        set_cookie ? "Set-Cookie: " : "", set_cookie ? set_cookie : "", set_cookie ? "\r\n" : "");

    if (header_len < 0 || (size_t)header_len >= sizeof(header)) return VW_ERR_INVALID_ARG;

    int n = mbedtls_net_send(&conn->fd, (const unsigned char *)header, (size_t)header_len);
    if (n < 0 || (size_t)n != (size_t)header_len) return VW_ERR_NET_CLOSED;

    if (body_len > 0 && body != NULL) {
        size_t sent = 0;
        while (sent < body_len) {
            n = mbedtls_net_send(&conn->fd, (const unsigned char *)body + sent, body_len - sent);
            if (n <= 0) return VW_ERR_NET_CLOSED;
            sent += (size_t)n;
        }
    }

    return VW_OK;
}
