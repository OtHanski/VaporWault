#ifndef VW_HTTP_H
#define VW_HTTP_H

/*
 * vw_http — minimal HTTP/1.1 request/response layer for
 * vapourwault-web-gateway (TASK-129).
 *
 * Scope: this module trusts nginx as its ONLY upstream — nginx
 * reverse-proxies "/api/" paths from the browser and terminates browser-facing
 * TLS; this listener speaks plain HTTP on loopback only (vw_net.h cannot be
 * reused here: it is TLS-only by design). Deliberately out of scope, since
 * the only client is a well-behaved reverse proxy: HTTP/1.0, pipelining,
 * chunked transfer-encoding, keep-alive (every response sends
 * "Connection: close"), and tolerance of malformed input beyond "reject
 * cleanly." This listener must NEVER be exposed directly to untrusted
 * networks — see ARCHITECTURE.md's Gateway listener bind address decision,
 * which defaults callers to binding 127.0.0.1 only.
 */

#include "../core/vw_proto.h"  /* vw_err_t */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vw_http_ctx  vw_http_ctx_t;   /* listen context */
typedef struct vw_http_conn vw_http_conn_t;  /* one accepted connection */

typedef enum {
    VW_HTTP_GET    = 0,
    VW_HTTP_POST   = 1,
    VW_HTTP_PUT    = 2,
    VW_HTTP_DELETE = 3,
} vw_http_method_t;

#define VW_HTTP_MAX_HEADERS       32u
#define VW_HTTP_MAX_HEADER_NAME   64u
#define VW_HTTP_MAX_HEADER_VALUE  512u
#define VW_HTTP_MAX_PATH_BYTES    2048u
#define VW_HTTP_MAX_HEADER_BLOCK  16384u  /* request-line + headers ceiling */
/* One 4 MiB chunk (VW_CHUNK_SIZE_DEFAULT) plus headroom for JSON/base64
 * framing overhead around it. */
#define VW_HTTP_MAX_BODY_BYTES    (6u * 1024u * 1024u)

typedef struct {
    char name[VW_HTTP_MAX_HEADER_NAME];
    char value[VW_HTTP_MAX_HEADER_VALUE];
} vw_http_header_t;

typedef struct {
    vw_http_method_t  method;
    char              path[VW_HTTP_MAX_PATH_BYTES];
    uint16_t          path_len;
    vw_http_header_t  headers[VW_HTTP_MAX_HEADERS];
    uint32_t          header_count;
    uint8_t          *body;      /* malloc'd; free via vw_http_request_free() */
    uint32_t          body_len;
} vw_http_request_t;

/*
 * Create a listen context bound to host:port (plain TCP, no TLS).
 * Per ARCHITECTURE.md's Gateway listener bind address decision, callers
 * should pass "127.0.0.1" unless a documented, explicit opt-in to a wider
 * bind has been made elsewhere.
 */
vw_err_t vw_http_listen(const char *host, uint16_t port, vw_http_ctx_t **out_ctx);

void vw_http_ctx_close(vw_http_ctx_t *ctx);

/*
 * Accept one incoming connection. Blocks until a connection arrives.
 * *out_conn is heap-allocated; free with vw_http_conn_close().
 */
vw_err_t vw_http_accept(vw_http_ctx_t *ctx, vw_http_conn_t **out_conn);

/*
 * Receive and parse one HTTP/1.1 request. Rejects (VW_ERR_PROTO_INVALID)
 * anything that isn't a well-formed request this module supports.
 * Returns VW_ERR_PROTO_TOO_LARGE if the header block exceeds
 * VW_HTTP_MAX_HEADER_BLOCK, the path exceeds VW_HTTP_MAX_PATH_BYTES, a
 * header name/value exceeds its max, header_count exceeds
 * VW_HTTP_MAX_HEADERS, or Content-Length exceeds VW_HTTP_MAX_BODY_BYTES.
 * Returns VW_ERR_NET_CLOSED if the peer disconnects before a full
 * request/body arrives.
 * On success, *out_req is populated; free with vw_http_request_free().
 */
vw_err_t vw_http_recv_request(vw_http_conn_t *conn, vw_http_request_t *out_req);

void vw_http_request_free(vw_http_request_t *req);

/* Look up a header by case-insensitive name (ASCII only). Returns NULL if absent. */
const char *vw_http_header_get(const vw_http_request_t *req, const char *name);

/*
 * Write a complete HTTP/1.1 response: status line + Content-Length +
 * "Connection: close" + an optional Content-Type header (NULL to omit) +
 * an optional Set-Cookie header (NULL to omit) + body.
 */
vw_err_t vw_http_send_response(vw_http_conn_t *conn, int status_code,
                                const char *content_type,
                                const char *set_cookie,
                                const void *body, uint32_t body_len);

void vw_http_conn_close(vw_http_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* VW_HTTP_H */
