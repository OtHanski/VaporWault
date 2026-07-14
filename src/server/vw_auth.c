#include "vw_auth.h"
#include "../core/vw_crypto.h"
#include "vw_smtp.h"
#include "vw_store.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Defeat dead-store elimination for sensitive buffers. */
static void *(* volatile g_memset_fn)(void *, int, size_t) = memset;
#define secure_zero(p, n) ((void)(g_memset_fn)((p), 0, (size_t)(n)))

/* ── Defaults ────────────────────────────────────────────────────────────── */

#define DEFAULT_SESSION_TTL_SECS   (30u * 24u * 3600u)   /* 30 days */
#define DEFAULT_OTP_WINDOW_SECS    600u
#define DEFAULT_OTP_MAX_ATTEMPTS   5u

/* ── Internal context ────────────────────────────────────────────────────── */

struct vw_auth_ctx {
    vw_store_t          *store;      /* borrowed */
    const vw_smtp_cfg_t *smtp_cfg;   /* borrowed; may be NULL if 2FA unused */
    vw_auth_cfg_t        cfg;
};

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_auth_open(vw_store_t *store, const vw_smtp_cfg_t *smtp_cfg,
                       const vw_auth_cfg_t *cfg, vw_auth_ctx_t **out_ctx)
{
    vw_auth_ctx_t *ctx;

    if (!store || !out_ctx) return VW_ERR_INVALID_ARG;

    ctx = (vw_auth_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->store    = store;
    ctx->smtp_cfg = smtp_cfg;

    if (cfg) ctx->cfg = *cfg;

    if (ctx->cfg.session_ttl_secs == 0)
        ctx->cfg.session_ttl_secs = DEFAULT_SESSION_TTL_SECS;
    if (ctx->cfg.otp_window_secs == 0)
        ctx->cfg.otp_window_secs = DEFAULT_OTP_WINDOW_SECS;
    if (ctx->cfg.otp_max_attempts == 0)
        ctx->cfg.otp_max_attempts = DEFAULT_OTP_MAX_ATTEMPTS;

    *out_ctx = ctx;
    return VW_OK;
}

void vw_auth_close(vw_auth_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx);
}

/* ── Password ────────────────────────────────────────────────────────────── */

vw_err_t vw_auth_hash_password(const void *password, size_t pw_len,
                                uint8_t out_hash[32], uint8_t out_salt[16])
{
    if (!password || !out_hash || !out_salt) return VW_ERR_INVALID_ARG;
    return vw_crypto_argon2id_hash(password, pw_len, NULL, out_salt, out_hash);
}

vw_err_t vw_auth_verify_password(const void *password, size_t pw_len,
                                  const uint8_t hash[32],
                                  const uint8_t salt[16])
{
    if (!password || !hash || !salt) return VW_ERR_INVALID_ARG;
    return vw_crypto_argon2id_verify(hash, salt, password, pw_len);
}

/* ── Session ─────────────────────────────────────────────────────────────── */

vw_err_t vw_auth_create_session(vw_auth_ctx_t *ctx, uint64_t user_id,
                                 const char *client_ip,
                                 uint8_t out_token[32])
{
    vw_session_record_t rec;
    vw_user_record_t    user;
    vw_err_t            rc;
    uint64_t            now;

    (void)client_ip;   /* accepted for audit; not stored in Phase 1 */

    if (!ctx || !out_token || user_id == 0) return VW_ERR_INVALID_ARG;

    rc = vw_store_user_get_by_id(ctx->store, user_id, &user);
    if (rc != VW_OK) return VW_ERR_AUTH_BAD_CREDS;
    if (!user.is_active) return VW_ERR_AUTH_BAD_CREDS;

    now = (uint64_t)time(NULL);

    memset(&rec, 0, sizeof(rec));
    rec.user_id    = user_id;
    rec.created_at = now;
    rec.expires_at = now + ctx->cfg.session_ttl_secs;
    rec.is_active  = 1;

    return vw_store_session_create(ctx->store, &rec, out_token);
}

vw_err_t vw_auth_validate_session(vw_auth_ctx_t *ctx,
                                   const uint8_t token[32],
                                   uint64_t *out_user_id)
{
    vw_session_record_t rec;
    vw_err_t            rc;

    if (!ctx || !token || !out_user_id) return VW_ERR_INVALID_ARG;

    rc = vw_store_session_get(ctx->store, token, &rec);
    if (rc != VW_OK) return VW_ERR_AUTH_SESSION_EXPIRED;

    /* Sliding-window refresh not implemented in Phase 1: session_idle_secs is
     * accepted in cfg but ignored; the session record has no last-access field. */

    *out_user_id = rec.user_id;
    return VW_OK;
}

vw_err_t vw_auth_revoke_session(vw_auth_ctx_t *ctx, const uint8_t token[32])
{
    if (!ctx || !token) return VW_ERR_INVALID_ARG;
    return vw_store_session_delete(ctx->store, token);
}

/* ── Login flow helpers ──────────────────────────────────────────────────── */

/*
 * Run Argon2id against a fixed dummy salt so "user not found" and "wrong
 * password" take the same wall-clock time. Return value intentionally discarded.
 */
static void run_dummy_hash(const void *password, size_t pw_len)
{
    uint8_t dummy_salt[16];
    uint8_t dummy_hash[32];

    memset(dummy_salt, 0xAA, sizeof(dummy_salt));
    (void)vw_crypto_argon2id_hash(password, pw_len, dummy_salt, NULL, dummy_hash);

    secure_zero(dummy_hash, sizeof(dummy_hash));
    secure_zero(dummy_salt, sizeof(dummy_salt));
}

static vw_err_t send_otp_email(const vw_smtp_cfg_t *smtp_cfg,
                                const char *to_email,
                                const char *otp_str)
{
    char body[320];
    snprintf(body, sizeof(body),
             "Your VaporWault verification code is: %s\r\n\r\n"
             "This code expires in 10 minutes. Do not share it with anyone.",
             otp_str);
    return vw_smtp_send(smtp_cfg, to_email,
                        "VaporWault verification code",
                        body, NULL, 0);
}

/* ── vw_auth_begin_login ─────────────────────────────────────────────────── */

vw_err_t vw_auth_begin_login(vw_auth_ctx_t *ctx,
                              const char *username,
                              const void *password, size_t pw_len,
                              vw_auth_state_t *out_state)
{
    vw_user_record_t rec;
    uint8_t          real_hash[32];
    uint8_t          real_salt[16];
    uint8_t          otp_hash[32];
    uint8_t          rand_buf[4];
    uint32_t         val;
    char             otp_str[7];   /* 6 digits + NUL */
    int              user_found;
    vw_err_t         cred_rc;
    vw_err_t         pw_rc;
    vw_err_t         rc;

    if (!ctx || !username || !password || !out_state) return VW_ERR_INVALID_ARG;

    /* Zero out_state at entry: on any error return, caller must not use it.
     * Ensures magic == 0 so vw_auth_verify_2fa rejects stale/failed states. */
    memset(out_state, 0, sizeof(*out_state));

    memset(real_hash, 0, sizeof(real_hash));
    memset(real_salt, 0, sizeof(real_salt));

    user_found = (vw_store_user_get_by_username(ctx->store, username, &rec) == VW_OK);

    if (user_found) {
        cred_rc = vw_store_user_get_credentials(ctx->store, rec.user_id,
                                                 real_hash, real_salt);
        if (cred_rc != VW_OK) {
            /*
             * Credential read failed despite user existing (I/O error or
             * corrupt slot). Run dummy hash to preserve timing; return
             * VW_ERR_AUTH_BAD_CREDS to avoid leaking that the user exists.
             */
            run_dummy_hash(password, pw_len);
            return VW_ERR_AUTH_BAD_CREDS;
        }
        pw_rc = vw_crypto_argon2id_verify(real_hash, real_salt, password, pw_len);
    } else {
        run_dummy_hash(password, pw_len);
        pw_rc = VW_ERR_AUTH_BAD_CREDS;
    }

    secure_zero(real_hash, sizeof(real_hash));
    secure_zero(real_salt, sizeof(real_salt));

    if (pw_rc != VW_OK) return VW_ERR_AUTH_BAD_CREDS;

    /* Credentials verified. Populate base state. */
    out_state->magic        = VW_AUTH_STATE_MAGIC;
    out_state->user_id      = rec.user_id;
    out_state->window_start = (uint64_t)time(NULL);

    if (!rec.otp_enabled) return VW_OK;   /* no 2FA; caller creates session */

    if (!ctx->smtp_cfg) {
        memset(out_state, 0, sizeof(*out_state));
        return VW_ERR_INVALID_ARG;
    }

    /* Generate a 6-digit random OTP, SHA-256 it, email it to the user. */
    rc = vw_crypto_random(rand_buf, sizeof(rand_buf));
    if (rc != VW_OK) {
        memset(out_state, 0, sizeof(*out_state));
        return rc;
    }

    memcpy(&val, rand_buf, sizeof(val));
    secure_zero(rand_buf, sizeof(rand_buf));
    snprintf(otp_str, sizeof(otp_str), "%06u", (unsigned)(val % 1000000u));

    rc = vw_crypto_sha256(otp_str, 6, otp_hash);
    if (rc != VW_OK) {
        secure_zero(otp_str, sizeof(otp_str));
        secure_zero(otp_hash, sizeof(otp_hash));
        memset(out_state, 0, sizeof(*out_state));
        return rc;
    }

    rc = send_otp_email(ctx->smtp_cfg, (const char *)rec.email, otp_str);
    secure_zero(otp_str, sizeof(otp_str));
    if (rc != VW_OK) {
        secure_zero(otp_hash, sizeof(otp_hash));
        memset(out_state, 0, sizeof(*out_state));
        return rc;
    }

    memcpy(out_state->otp_hash, otp_hash, sizeof(otp_hash));
    secure_zero(otp_hash, sizeof(otp_hash));

    return VW_ERR_AUTH_2FA_REQUIRED;
}

/* ── vw_auth_verify_2fa ──────────────────────────────────────────────────── */

vw_err_t vw_auth_verify_2fa(vw_auth_ctx_t *ctx,
                              vw_auth_state_t *state,
                              const char *otp_code, uint16_t otp_len,
                              uint8_t out_token[32])
{
    uint8_t  submitted_hash[32];
    uint64_t now;
    vw_err_t rc;
    int      match;

    if (!ctx || !state || !otp_code || !out_token) return VW_ERR_INVALID_ARG;
    if (state->magic != VW_AUTH_STATE_MAGIC)       return VW_ERR_INVALID_ARG;

    now = (uint64_t)time(NULL);
    if (now - state->window_start > (uint64_t)ctx->cfg.otp_window_secs) {
        state->magic = 0;
        return VW_ERR_AUTH_SESSION_EXPIRED;
    }

    /*
     * Increment attempt_count BEFORE the OTP comparison so that even a
     * timing side-channel on the comparison cannot be used to bypass the limit.
     */
    state->attempt_count++;
    if (state->attempt_count > ctx->cfg.otp_max_attempts) {
        state->magic = 0;
        return VW_ERR_AUTH_2FA_LOCKED;
    }

    rc = vw_crypto_sha256(otp_code, (size_t)otp_len, submitted_hash);
    if (rc != VW_OK) {
        secure_zero(submitted_hash, sizeof(submitted_hash));
        return rc;
    }

    match = vw_crypto_constant_time_eq(submitted_hash, state->otp_hash, 32);
    secure_zero(submitted_hash, sizeof(submitted_hash));

    if (!match) return VW_ERR_AUTH_2FA_INVALID;

    /* OTP verified — create session, then invalidate the auth state. */
    rc = vw_auth_create_session(ctx, state->user_id, NULL, out_token);

    /* Zero state regardless of session-creation result to prevent token reuse. */
    secure_zero(state->otp_hash, sizeof(state->otp_hash));
    state->magic = 0;

    return rc;
}
