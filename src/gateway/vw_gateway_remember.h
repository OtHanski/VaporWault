#ifndef VW_GATEWAY_REMEMBER_H
#define VW_GATEWAY_REMEMBER_H

/*
 * vw_gateway_remember — on-disk store for "remember me" logins (TASK-165).
 *
 * Maps a gateway-issued cookie value (the same VW_GATEWAY_COOKIE_HEX_LEN
 * hex string vw_gateway_session.h's in-memory pool keys sessions by) to a
 * resumable vw_client_get_token() value plus a display username, so a
 * `remember: true` login survives a gateway process restart — see
 * vw_gateway_api.c's require_session()/handle_login() for how this store
 * is actually consulted (only on an in-memory-pool cookie-miss) and kept
 * in sync (a resume rotates its token here immediately; logout/a failed
 * resume deletes the entry).
 *
 * SECURITY: this file is a bearer-credential store exactly as sensitive
 * as a password — anyone who can read it can impersonate every
 * remembered account (ARCHITECTURE.md's Risks table already flags this
 * exact gap for vw_daemon.c's session.tok and explicitly warns against
 * carrying it into "a richer multi-session gateway target" — this is
 * that target). vw_gateway_remember_open() hardens the file's
 * permissions immediately after creating it (POSIX 0600; a real Windows
 * ACL restricting access to the current user, not default NTFS
 * inheritance) — see vw_gateway_remember.c's harden_file_perms().
 *
 * Threading: like vw_gateway_session.h, safe to call from a single
 * thread only — matches the gateway's own single-threaded request loop
 * (main.c). No internal locking.
 *
 * Scale: a small, single self-hosted-deployment store, not a database —
 * fixed-size records in one flat file (this codebase's established
 * vw_cache.c-style convention), fully mirrored in memory, with a
 * mandatory hard cap (VW_GATEWAY_REMEMBER_MAX_ENTRIES) matching this
 * project's existing "no unbounded anything" philosophy
 * (vw_gateway_session.h's VW_GATEWAY_MAX_SESSIONS).
 */

#include "../core/vw_proto.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VW_GATEWAY_REMEMBER_MAX_ENTRIES 256u

typedef struct vw_gateway_remember_store vw_gateway_remember_store_t;

/*
 * Opens (creating if absent) {state_dir}/remember.db. Creates state_dir
 * itself if needed. Hardens the file's permissions right after creating
 * it (a pre-existing file's permissions are left as-is — this project has
 * no migration story yet, matching vw_daemon.c's own precedent — but see
 * vw_gateway_remember_verify_perms() below for a way to check).
 */
vw_err_t vw_gateway_remember_open(const char *state_dir,
                                   vw_gateway_remember_store_t **out_store);

void vw_gateway_remember_close(vw_gateway_remember_store_t *store);

/*
 * Create or overwrite (matching by cookie_hex) the entry for a remembered
 * login. Persists to disk (pwrite + sync) before returning.
 * Returns VW_ERR_QUOTA_EXCEEDED if the store is full and cookie_hex is
 * not already a known entry.
 */
vw_err_t vw_gateway_remember_put(vw_gateway_remember_store_t *store,
                                  const char *cookie_hex,
                                  const uint8_t token[32],
                                  const char *username);

/*
 * Look up cookie_hex. Returns VW_ERR_NOT_FOUND if absent. On success,
 * out_username receives a NUL-terminated string (empty for a link
 * session, mirroring vw_gateway_session_create()'s own convention).
 */
vw_err_t vw_gateway_remember_get(vw_gateway_remember_store_t *store,
                                  const char *cookie_hex,
                                  uint8_t out_token[32],
                                  char *out_username, size_t out_username_size);

/* Idempotent — a no-op on an absent/unknown cookie_hex. Persists the
 * deletion to disk before returning. */
void vw_gateway_remember_remove(vw_gateway_remember_store_t *store,
                                 const char *cookie_hex);

/*
 * Verifies the on-disk file still has the hardened permissions this
 * module applies at creation (SEC.07's own acceptance criterion: this
 * must be checked by a test, not just code inspection). Returns VW_OK if
 * hardened, VW_ERR_PERMISSION if not (or the file is missing).
 */
vw_err_t vw_gateway_remember_verify_perms(const vw_gateway_remember_store_t *store);

#ifdef __cplusplus
}
#endif

#endif /* VW_GATEWAY_REMEMBER_H */
