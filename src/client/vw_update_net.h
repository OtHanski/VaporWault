#ifndef VW_UPDATE_NET_H
#define VW_UPDATE_NET_H

/*
 * vw_update_net — minimal outbound HTTPS GET client for the client
 * auto-update feature (TASK-00296, ARCHITECTURE.md Phase 23).
 *
 * This is the ONLY place in the client that connects to a non-pinned,
 * non-VaporWault-server TLS endpoint — deliberately narrow in scope
 * (GET-only, one optional redirect, bounded response size, no chunked
 * encoding support) rather than a general HTTP client, since the only
 * caller is a fixed pair of well-known GitHub Releases URLs
 * (src/client/vw_update_manifest.c, src/client/vw_update.c).
 *
 * Built on vw_net_connect_generic() (src/core/vw_net.h) rather than a
 * second hand-rolled TLS/socket stack — reuses that module's already-
 * audited connect/timeout/BIO/send/recv machinery, verified against the
 * live OS trust store (VW_CERT_VERIFY_SYSTEM_STORE) instead of a pinned
 * PEM, since the target host's cert chain isn't ours to pin.
 */

#include "../core/vw_proto.h"   /* vw_err_t */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *body;      /* heap-allocated; NULL if body_len == 0 */
    size_t   body_len;
    size_t   body_cap;  /* == body_len on a successful fetch; present for
                            symmetry with the project's other growable-
                            buffer structs, not currently used for partial
                            fills */
} vw_update_response_t;

/*
 * Fetch https://host:port/path via HTTP/1.1 GET.
 *
 *   host            : DNS name only (no scheme).
 *   port             : real callers always pass 443 (the constructor
 *                      exists at all only so tests can point this at a
 *                      local server — see VW_UPDATE_NET_TEST_HOOKS below;
 *                      there is no production reason to ever pass
 *                      anything but 443).
 *   path             : absolute path + optional query string, e.g.
 *                      "/OtHanski/VaporWault/releases/latest/download/update-manifest.json".
 *   max_body_bytes   : hard cap on the response body size. A
 *                      Content-Length exceeding this is rejected BEFORE
 *                      any body bytes are read (never partially buffers
 *                      an oversized response).
 *   out              : populated on VW_OK; caller must
 *                      vw_update_response_free() it. Left zeroed on any
 *                      failure.
 *
 * Follows at most ONE 301/302/307/308 redirect (a second redirect is a
 * hard failure — bounds redirect-loop/SSRF-shaped risk); the redirect
 * target's host may differ from the original (GitHub's `releases/latest`
 * alias redirects to a different, versioned asset host). Requires
 * Content-Length on the final (non-redirect) response; rejects
 * Transfer-Encoding: chunked outright — this client's only real-world
 * peer (GitHub's release infrastructure) always frames responses with
 * Content-Length, so chunked support is unneeded surface, not merely
 * unimplemented.
 *
 * Returns VW_ERR_UPDATE_NET on any TLS/connect/protocol-shape failure
 * (including a non-2xx, non-redirect HTTP status, a second redirect,
 * missing/oversized Content-Length, or chunked encoding).
 */
vw_err_t vw_update_https_get(const char *host, uint16_t port, const char *path,
                              size_t max_body_bytes,
                              vw_update_response_t *out);

void vw_update_response_free(vw_update_response_t *r);

/*
 * Test-only seam (compiled in only when VW_UPDATE_NET_TEST_HOOKS is
 * defined — see vw_update_net.c's own comment above do_connect_for_fetch
 * for why): overrides the connect step vw_update_https_get() uses, so
 * tests can point it at a local server (VW_CERT_VERIFY_NONE) or a
 * deliberately failing/slow connect, instead of the real
 * VW_CERT_VERIFY_SYSTEM_STORE path a local self-signed test server can
 * never satisfy. Pass NULL to restore the real connect behavior.
 */
#ifdef VW_UPDATE_NET_TEST_HOOKS
#include "../core/vw_net.h" /* vw_conn_opts_t, vw_conn_t */
void vw_update_net_test_set_connect_hook(
        vw_err_t (*fn)(const char *host, uint16_t port,
                        const vw_conn_opts_t *opts, vw_conn_t **out_conn));
#endif

#ifdef __cplusplus
}
#endif

#endif /* VW_UPDATE_NET_H */
