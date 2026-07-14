#ifndef VW_AUTH_H
#define VW_AUTH_H

/*
 * vw_auth — authentication layer for VaporWault.
 *
 * Owns: password hashing (Argon2id), session lifecycle, and the login flow
 * including optional email OTP second factor. All operations are thread-safe.
 *
 * Caller lifecycle:
 *   1. vw_auth_open — create context (borrows store and smtp_cfg)
 *   2. vw_auth_begin_login — verify credentials, emit OTP if 2FA enabled
 *      Returns VW_OK (no 2FA) or VW_ERR_AUTH_2FA_REQUIRED
 *   3a. No 2FA: vw_auth_create_session(ctx, state.user_id, ...)
 *   3b. 2FA:    vw_auth_verify_2fa(ctx, &state, otp_code, out_token)
 *   4. vw_auth_validate_session — authenticate every subsequent request
 *   5. vw_auth_revoke_session — logout
 *   6. vw_auth_close — release context
 */

#include "../core/vw_proto.h"
#include "vw_smtp.h"
#include "vw_store.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Config ──────────────────────────────────────────────────────────────── */

typedef struct {
    uint32_t session_ttl_secs;   /* session hard expiry; 0 = 30 days       */
    uint32_t session_idle_secs;  /* sliding-window idle timeout; 0 = off   */
    uint32_t otp_window_secs;    /* OTP validity window; 0 = 600 s         */
    uint32_t otp_max_attempts;   /* max OTP failures per window; 0 = 5     */
} vw_auth_cfg_t;

/* ── Pending auth state (stack-allocated, never persisted) ───────────────── */

/*
 * Caller allocates vw_auth_state_t on the stack before calling
 * vw_auth_begin_login. The struct is zeroed automatically by begin_login
 * before writing; the caller must NOT reuse it for a second attempt.
 *
 * magic: set to VW_AUTH_STATE_MAGIC by begin_login; zeroed by verify_2fa
 * on success. If magic != VW_AUTH_STATE_MAGIC, verify_2fa returns
 * VW_ERR_INVALID_ARG (use-after-clear / uninitialised detection).
 *
 * In the no-2FA path (begin_login returns VW_OK):
 *   state.user_id is set; otp_hash is zeroed.
 *   Caller creates a session via vw_auth_create_session(ctx, state.user_id, ...).
 */
#define VW_AUTH_STATE_MAGIC 0x41555448u

typedef struct {
    uint32_t magic;
    uint64_t user_id;
    uint64_t window_start;     /* unix time when OTP was generated  */
    uint32_t attempt_count;    /* failed OTP attempts in this window */
    uint8_t  otp_hash[32];     /* SHA-256(otp_string); zeroed if no 2FA */
} vw_auth_state_t;

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_auth_ctx vw_auth_ctx_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Create an auth context. Borrows store and smtp_cfg (caller keeps them alive).
 * cfg may be NULL; all fields default to 0 (see vw_auth_cfg_t for defaults).
 * Returns VW_OK and sets *out_ctx on success; VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_auth_open(vw_store_t *store, const vw_smtp_cfg_t *smtp_cfg,
                       const vw_auth_cfg_t *cfg, vw_auth_ctx_t **out_ctx);

void vw_auth_close(vw_auth_ctx_t *ctx);

/* ── Password ────────────────────────────────────────────────────────────── */

/*
 * Hash a password with Argon2id and a freshly generated random salt.
 * out_hash[32] and out_salt[16] must be provided.
 */
vw_err_t vw_auth_hash_password(const void *password, size_t pw_len,
                                uint8_t out_hash[32], uint8_t out_salt[16]);

/*
 * Verify a password against a stored hash+salt in constant time.
 * Returns VW_OK on match, VW_ERR_AUTH_BAD_CREDS otherwise.
 */
vw_err_t vw_auth_verify_password(const void *password, size_t pw_len,
                                  const uint8_t hash[32],
                                  const uint8_t salt[16]);

/* ── Session ─────────────────────────────────────────────────────────────── */

/*
 * Create a new session for user_id. client_ip is accepted for audit purposes
 * but not stored in Phase 1 (session record has no IP field).
 * out_token[32] receives the cryptographic random session token.
 */
vw_err_t vw_auth_create_session(vw_auth_ctx_t *ctx, uint64_t user_id,
                                 const char *client_ip,
                                 uint8_t out_token[32]);

/*
 * Validate a session token. *out_user_id receives the authenticated user ID.
 * Returns VW_ERR_AUTH_SESSION_EXPIRED if expired or not found.
 */
vw_err_t vw_auth_validate_session(vw_auth_ctx_t *ctx,
                                   const uint8_t token[32],
                                   uint64_t *out_user_id);

/*
 * Revoke a session (logout). Returns VW_ERR_NOT_FOUND if the token is unknown.
 */
vw_err_t vw_auth_revoke_session(vw_auth_ctx_t *ctx, const uint8_t token[32]);

/* ── Login flow ──────────────────────────────────────────────────────────── */

/*
 * Begin a login attempt: verify username+password, then:
 *  - No 2FA (otp_enabled==0): populate out_state, return VW_OK.
 *    Caller creates a session with vw_auth_create_session(ctx, state.user_id, ...).
 *  - 2FA required (otp_enabled==1): generate OTP, email it, populate out_state,
 *    return VW_ERR_AUTH_2FA_REQUIRED.
 *    Caller presents out_state to vw_auth_verify_2fa.
 *
 * Always runs Argon2id even when the username is not found (timing normalisation).
 * Never reveals whether a username exists in the error response.
 */
vw_err_t vw_auth_begin_login(vw_auth_ctx_t *ctx,
                              const char *username,
                              const void *password, size_t pw_len,
                              vw_auth_state_t *out_state);

/*
 * Complete a 2FA login. state must be the value populated by vw_auth_begin_login.
 * otp_code is the user-submitted digit string; otp_len is its byte length.
 * out_token[32] receives the session token on success.
 *
 * Security invariants:
 *   - attempt_count is incremented before the OTP comparison.
 *   - After otp_max_attempts failures, returns VW_ERR_AUTH_2FA_LOCKED.
 *   - state->magic is zeroed before every non-INVALID_ARG return (including on
 *     session-creation failure) to prevent any reuse of the auth state.
 *   - The OTP must be verified within otp_window_secs of when it was generated.
 */
vw_err_t vw_auth_verify_2fa(vw_auth_ctx_t *ctx,
                              vw_auth_state_t *state,
                              const char *otp_code, uint16_t otp_len,
                              uint8_t out_token[32]);

#ifdef __cplusplus
}
#endif

#endif /* VW_AUTH_H */
