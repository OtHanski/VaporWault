#ifndef VW_GATEWAY_SESSION_H
#define VW_GATEWAY_SESSION_H

/*
 * vw_gateway_session — per-browser-session vw_client_sess_t pool
 * (TASK-131).
 *
 * Unlike vapourwault-daemon (one server session for one desktop user), the
 * gateway is a genuine multi-user, multi-session process: every logged-in
 * browser needs its own live vw_client_sess_t connected to the VaporWault
 * server. This module owns that pool, keyed by a gateway-issued session
 * cookie distinct from the underlying vw_client_core session_token (the
 * browser must never see the raw server session token directly).
 *
 * Mandatory hard cap (ARCHITECTURE.md's Gateway session model decision,
 * hardened during TASK-127's SEC.07 review): VW_GATEWAY_MAX_SESSIONS is a
 * real limit, not a tunable nice-to-have — an unbounded pool is a trivial
 * resource-exhaustion DoS against this shared process.
 *
 * Threading: this module's own operations are safe to call from a single
 * thread only (no internal locking) — the gateway's MVP request loop
 * (TASK-131/main.c) is deliberately single-threaded (one HTTP request
 * handled at a time), matching the personal-self-hosted-use scale this
 * project targets. A future move to a thread-per-connection or thread-pool
 * model would need to add locking here; noted explicitly rather than
 * pretending this is already concurrent-safe.
 */

#include "../client/vw_client_core.h"
#include "../core/vw_proto.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VW_GATEWAY_COOKIE_BYTES      32u
#define VW_GATEWAY_COOKIE_HEX_LEN    (VW_GATEWAY_COOKIE_BYTES * 2u)
/* Mandatory hard cap - see module doc above. */
#define VW_GATEWAY_MAX_SESSIONS      256u
/* Idle sessions (no request for this long) are evicted by
 * vw_gateway_session_reap_idle(). */
#define VW_GATEWAY_SESSION_IDLE_SECS (30u * 60u)

typedef struct vw_gateway_session_pool vw_gateway_session_pool_t;

vw_err_t vw_gateway_session_pool_create(vw_gateway_session_pool_t **out_pool);
void vw_gateway_session_pool_destroy(vw_gateway_session_pool_t *pool);

/*
 * Register a newly-authenticated vw_client_sess_t under a fresh
 * gateway-issued cookie. On success the pool owns sess (it is closed via
 * vw_client_logout/_close when removed/evicted) and out_cookie_hex
 * (caller-provided buffer, must be at least VW_GATEWAY_COOKIE_HEX_LEN+1
 * bytes) receives the NUL-terminated hex cookie value.
 * Returns VW_ERR_QUOTA_EXCEEDED if the pool is already at its hard cap —
 * caller must not free/logout sess itself in that case; the caller is
 * still responsible for it since the pool never took ownership.
 *
 * username (TASK-164) is a display-only label for /api/accounts — never
 * used for authorization (the server remains the sole authority on that,
 * per this module's own doc). Pass NULL/empty for a session that has no
 * real logged-in user (a redeemed public link, vw_gateway_api.c's
 * handle_link_access) — vw_gateway_session_get_username() below then
 * reports an empty string for it, which handle_accounts's own JSON
 * response leaves for the frontend to render distinctly (e.g. "(shared
 * link)") rather than encoding that meaning in this module itself.
 */
/*
 * read_only (TASK-176): 1 if `sess` is connected to this deployment's
 * configured read-only fallback server rather than the primary (the
 * gateway's own analogue of the daemon's per-account fallback,
 * TASK-172/173) — every write endpoint checks
 * vw_gateway_session_is_read_only() and rejects rather than attempting a
 * write against the fallback. 0 for every session created before this
 * task's fallback support existed, and for every ordinary primary-
 * connected session today.
 */
vw_err_t vw_gateway_session_create(vw_gateway_session_pool_t *pool,
                                    vw_client_sess_t *sess,
                                    const char *username,
                                    int read_only,
                                    char *out_cookie_hex);

/*
 * Look up a live session by its cookie. Returns VW_ERR_AUTH_REQUIRED if
 * the cookie is unknown or malformed. Touches the entry's last-active
 * timestamp on success (resets its idle-eviction countdown).
 */
vw_err_t vw_gateway_session_get(vw_gateway_session_pool_t *pool,
                                 const char *cookie_hex,
                                 vw_client_sess_t **out_sess);

/*
 * Insert sess into the pool under a SPECIFIC, pre-existing cookie value
 * (TASK-165's remember-me resume path) rather than generating a fresh one
 * — a resumed session must stay transparent to the browser (same cookie,
 * no new Set-Cookie needed). cookie_hex must be exactly
 * VW_GATEWAY_COOKIE_HEX_LEN hex chars. username follows
 * vw_gateway_session_create()'s own NULL/empty convention.
 * Returns VW_ERR_ALREADY_EXISTS if the pool already has a live entry
 * under this exact cookie — defensive only; vw_gateway_api.c's
 * require_session() only ever calls this after its own
 * vw_gateway_session_get() lookup for the same cookie already missed, so
 * this should never actually trigger. Returns VW_ERR_QUOTA_EXCEEDED at
 * the pool's hard cap, same as vw_gateway_session_create().
 */
vw_err_t vw_gateway_session_reinsert(vw_gateway_session_pool_t *pool,
                                      const char *cookie_hex,
                                      vw_client_sess_t *sess,
                                      const char *username);

/*
 * Fetch the display username stored for this cookie at
 * vw_gateway_session_create() time (TASK-164's /api/accounts). Does NOT
 * touch last_active (unlike vw_gateway_session_get() above) — a status
 * check should never itself reset a session's idle-eviction countdown.
 * Returns VW_ERR_AUTH_REQUIRED if the cookie is unknown/malformed.
 * out_buf receives a NUL-terminated string, empty ("") if this session
 * was created with a NULL/empty username (a redeemed public link).
 */
vw_err_t vw_gateway_session_get_username(vw_gateway_session_pool_t *pool,
                                          const char *cookie_hex,
                                          char *out_buf, size_t out_buf_size);

/*
 * TASK-176: report whether this session is connected to the configured
 * read-only fallback rather than the primary (set at creation time —
 * see vw_gateway_session_create's read_only parameter; never changes for
 * the lifetime of a session, unlike the daemon's per-account state, since
 * the gateway never migrates a live session between servers). Returns
 * VW_ERR_AUTH_REQUIRED for an unknown/malformed cookie, same convention
 * as vw_gateway_session_get_username.
 */
vw_err_t vw_gateway_session_is_read_only(vw_gateway_session_pool_t *pool,
                                          const char *cookie_hex,
                                          int *out_read_only);

/*
 * Remove and log out (vw_client_logout) the session for this cookie.
 * Safe to call with an unknown/malformed cookie (no-op, returns VW_OK
 * either way — logout is idempotent from the caller's perspective).
 */
void vw_gateway_session_remove(vw_gateway_session_pool_t *pool,
                                const char *cookie_hex);

/*
 * Evict (vw_client_close — not _logout, since an idle-timed-out session
 * was never explicitly ended by the user) any session idle longer than
 * VW_GATEWAY_SESSION_IDLE_SECS. Call periodically from the gateway's main
 * loop.
 */
void vw_gateway_session_reap_idle(vw_gateway_session_pool_t *pool);

/* Current live session count (for diagnostics/tests). */
uint32_t vw_gateway_session_count(const vw_gateway_session_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* VW_GATEWAY_SESSION_H */
