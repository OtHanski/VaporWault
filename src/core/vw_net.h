#ifndef VW_NET_H
#define VW_NET_H

/*
 * vw_net — TLS socket abstraction for VaporWault.
 *
 * Wraps mbedTLS for TLS 1.3. All connections are encrypted; plaintext is
 * not supported. Minimum TLS version enforced at context creation.
 *
 * Thread safety: each vw_conn_t is owned by one thread at a time. The
 * vw_net_ctx_t (server listen context) is thread-safe for vw_net_accept.
 */

#include "vw_proto.h"   /* vw_err_t */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque types ────────────────────────────────────────────────────────── */

typedef struct vw_net_ctx  vw_net_ctx_t;   /* server listen context */
typedef struct vw_conn     vw_conn_t;      /* one client/server connection */

/* ── Certificate verification mode ──────────────────────────────────────── */

typedef enum {
    VW_CERT_VERIFY_REQUIRED = 0,   /* default: verify peer certificate */
    VW_CERT_VERIFY_NONE     = 1,   /* disable verification (testing only) */
} vw_cert_verify_t;

/* ── Connection options ──────────────────────────────────────────────────── */

typedef struct {
    /* TCP connect deadline. 0 = no timeout. Enforced via non-blocking connect
     * + select; the TLS handshake uses recv_timeout_ms once the socket is up. */
    uint32_t connect_timeout_ms;
    /* Per-recv deadline. 0 = no timeout. vw_net_recv returns VW_ERR_NET_TIMEOUT
     * when a single read blocks longer than this many milliseconds. */
    uint32_t recv_timeout_ms;
    uint64_t upload_bps;           /* 0 = unlimited */
    uint64_t download_bps;         /* 0 = unlimited */
} vw_conn_opts_t;

/* ── Server context API ──────────────────────────────────────────────────── */

/*
 * Create a server listen context. Loads the TLS certificate and key from PEM
 * files. Binds and listens on host:port (host may be NULL to bind all interfaces).
 *
 * The ALPN protocol string for server-client connections is "vw/1".
 * For cluster connections use vw_net_listen_cluster().
 *
 * Returns VW_ERR_NET_TLS if certificate loading fails.
 */
vw_err_t vw_net_listen(const char *host, uint16_t port,
                        const char *cert_pem_path,
                        const char *key_pem_path,
                        vw_net_ctx_t **out_ctx);

/*
 * Same as vw_net_listen but uses ALPN "vw-cluster/1" for server-to-server
 * connections (mutual TLS, both sides present certificates).
 */
vw_err_t vw_net_listen_cluster(const char *host, uint16_t port,
                                const char *cert_pem_path,
                                const char *key_pem_path,
                                vw_net_ctx_t **out_ctx);

/*
 * Accept one incoming connection and perform the TLS handshake.
 * Blocks until a connection arrives. Thread-safe (multiple threads may call
 * accept concurrently to implement a thread-per-connection model).
 *
 * *out_conn is heap-allocated; free with vw_net_close().
 */
vw_err_t vw_net_accept(vw_net_ctx_t *ctx, vw_conn_t **out_conn);

/*
 * Stop accepting connections and release the server context.
 * Does not close existing accepted connections.
 */
void vw_net_ctx_close(vw_net_ctx_t *ctx);

/* ── Client connection API ───────────────────────────────────────────────── */

/*
 * Connect to host:port with TLS. verify controls certificate validation.
 * opts may be NULL to use defaults.
 *
 * ca_cert_pem_path: path to CA cert PEM file for verifying the server
 * certificate. Must not be NULL when verify == VW_CERT_VERIFY_REQUIRED
 * (returns VW_ERR_INVALID_ARG if it is). Ignored when verify is NONE.
 *
 * *out_conn is heap-allocated; free with vw_net_close().
 */
vw_err_t vw_net_connect(const char *host, uint16_t port,
                         vw_cert_verify_t verify,
                         const char *ca_cert_pem_path,
                         const vw_conn_opts_t *opts,
                         vw_conn_t **out_conn);

/* ── Per-connection API ──────────────────────────────────────────────────── */

/*
 * Send exactly len bytes. Retries on EAGAIN / EINTR.
 * Returns VW_ERR_NET_CLOSED if the connection was closed by the peer.
 */
vw_err_t vw_net_send(vw_conn_t *conn, const void *data, size_t len);

/*
 * Receive exactly len bytes into buf. Blocks until all bytes arrive or an
 * error occurs. Returns VW_ERR_NET_TIMEOUT on recv timeout.
 * Returns VW_ERR_NET_CLOSED if the peer closed gracefully.
 */
vw_err_t vw_net_recv(vw_conn_t *conn, void *buf, size_t len);

/*
 * Receive up to buf_size bytes. *out_len is set to the actual number received.
 * Unlike vw_net_recv, this does not block for exactly len bytes.
 */
vw_err_t vw_net_recv_partial(vw_conn_t *conn, void *buf, size_t buf_size,
                              size_t *out_len);

/*
 * Set per-connection rate limits (token bucket). Pass 0 for unlimited.
 * Takes effect immediately for subsequent sends/recvs.
 */
void vw_net_set_rate_limit(vw_conn_t *conn,
                            uint64_t upload_bps, uint64_t download_bps);

/*
 * Close the connection: TLS close_notify, then socket close.
 * Frees *conn. Safe to call with conn == NULL.
 */
void vw_net_close(vw_conn_t *conn);

/*
 * Return the peer's IP address string (IPv4 or IPv6) into out_buf.
 * out_buf must be at least 46 bytes.
 */
vw_err_t vw_net_peer_addr(const vw_conn_t *conn, char *out_buf, size_t buf_size);

/*
 * Return the negotiated ALPN protocol string, or NULL if not negotiated.
 */
const char *vw_net_alpn(const vw_conn_t *conn);

/*
 * Set a per-connection recv deadline. Call immediately after vw_net_accept
 * to guard against slow-loris attacks before authentication completes.
 * timeout_ms == 0 disables the timeout. Safe to call multiple times.
 * Returns VW_ERR_INVALID_ARG if conn is NULL.
 */
vw_err_t vw_net_conn_set_recv_timeout(vw_conn_t *conn, uint32_t timeout_ms);

/* ── TLS context (shared across connections from the same cert) ──────────── */

/*
 * Load a new certificate and key into an existing server context.
 * Used by vw_acme to hot-swap a renewed Let's Encrypt certificate.
 * Thread-safe; in-flight connections continue using the old cert.
 */
vw_err_t vw_net_ctx_reload_cert(vw_net_ctx_t *ctx,
                                 const char *cert_pem_path,
                                 const char *key_pem_path);

#ifdef __cplusplus
}
#endif

#endif /* VW_NET_H */
