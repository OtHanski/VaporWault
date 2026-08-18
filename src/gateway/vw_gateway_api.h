#ifndef VW_GATEWAY_API_H
#define VW_GATEWAY_API_H

/*
 * vw_gateway_api — HTTP/JSON endpoint dispatch (TASK-132-135).
 *
 * Maps vw_http_request_t onto vw_client_core calls and writes a
 * vw_http response. Every endpoint here is a thin translator: no
 * authorization logic of its own beyond "does this cookie map to a live
 * session" — the server remains the sole authority on permissions
 * (ARCHITECTURE.md's Gateway↔server TLS verification / session model
 * decisions).
 */

#include "vw_gateway_session.h"
#include "vw_gateway_remember.h"
#include "vw_http.h"
#include "../client/vw_client_core.h"
#include "../core/vw_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *server_host;
    uint16_t    server_port;
    /* Mandatory per ARCHITECTURE.md's Gateway<->server TLS verification
     * decision: the gateway must verify the server's certificate, never
     * VW_CERT_VERIFY_NONE. The gateway refuses to start without this set
     * (TASK-132's main() enforces it, not this struct itself). */
    const char *ca_cert_pem_path;
    /*
     * TASK-176: optional read-only fallback — an already cluster-paired
     * replica of the primary above (same requirement as the daemon's own
     * per-account fallback, TASK-172/173). fallback_host == NULL (or
     * empty) means "not configured," this deployment's whole behavior is
     * then unchanged from before this task. When fallback_host is set,
     * fallback_ca_cert_pem_path must also be set — never optional, same
     * "no disabled-verification path" rule as ca_cert_pem_path above
     * (main.c enforces this pairing, not this struct itself).
     */
    const char *fallback_host;
    uint16_t    fallback_port;
    const char *fallback_ca_cert_pem_path;
} vw_gateway_server_cfg_t;

/*
 * Handle one HTTP request end-to-end: routes by method+path, performs the
 * corresponding vw_client_core operation(s), and writes the HTTP response
 * via conn. Never returns an error to the caller for a well-formed
 * request that the server itself rejects (that becomes a normal HTTP
 * error response) - only truly unexpected failures (OOM, etc.) propagate.
 */
void vw_gateway_dispatch(vw_gateway_session_pool_t *pool,
                          const vw_gateway_server_cfg_t *cfg,
                          const vw_http_request_t *req,
                          vw_http_conn_t *conn);

/*
 * Enables "remember me" persistence (TASK-165): a `remember: true` login
 * writes to store, and a cookie-miss in require_session() consults it
 * before failing. Pass NULL (the default - main.c never calls this
 * without --state-dir) to leave the feature entirely disabled: a
 * `remember: true` login is then silently treated as a normal
 * session-only login rather than erroring, matching this feature's own
 * "opt-in" framing at both the operator (--state-dir) and user
 * (remember: true) level. Not thread-safe to call after dispatch begins
 * handling requests - call once, at startup, before the accept loop
 * (matches this whole module's single-threaded-only calling convention).
 */
void vw_gateway_api_set_remember_store(vw_gateway_remember_store_t *store);

#ifdef __cplusplus
}
#endif

#endif /* VW_GATEWAY_API_H */
