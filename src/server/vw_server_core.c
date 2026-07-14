#include "vw_server_core.h"
#include "vw_auth.h"
#include "vw_invite.h"
#include "vw_recovery.h"
#include "vw_smtp.h"
#include "../core/vw_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
#endif

#define AUTH_TIMEOUT_MS_DEFAULT 10000u
#define AUTH_LOCKOUT_SECS        600u   /* PROTOCOL.md §8.3: 10-minute lockout window */

/* Receive buffer for auth-phase messages.  The largest expected payload is
 * AUTH_REQUEST: 2 (username_len) + 64 (username) + 32 (auth_token) = 98 B.
 * 256 bytes is ample headroom. */
#define AUTH_BUF_SIZE 256u

/* Volatile-function-pointer trick: defeats dead-store elimination on stack
 * buffers holding sensitive credential data (auth_token, session token). */
static void *(* volatile g_memset_fn)(void *, int, size_t) = memset;
#define secure_zero(p, n) ((void)g_memset_fn((p), 0, (n)))

struct vw_server_ctx {
    vw_auth_ctx_t       *auth;
    vw_store_t          *store;
    vw_file_store_t     *file_store;
    vw_storage_t        *chunk_store;
    vw_invite_store_t   *invite_store;    /* NULL = invites disabled     */
    vw_recovery_store_t *recovery_store;  /* NULL = recovery disabled    */
    const vw_smtp_cfg_t *smtp_cfg;        /* NULL = no email             */
    vw_oplog_t          *oplog;           /* NULL = audit queries return empty */
    vw_cluster_t        *cluster;         /* NULL = cluster status returns empty list */
    uint32_t             auth_timeout_ms;
};

/* ── Internal helpers ────────────────────────────────────────────────────── */

static vw_err_t send_auth_fail(vw_conn_t *conn, uint32_t error_code,
                                 uint16_t lockout_secs)
{
    vw_payload_auth_fail_t fail;
    fail.error_code            = error_code;
    fail.lockout_remaining_secs = lockout_secs;

    uint8_t buf[8];
    uint32_t len;
    vw_err_t err = vw_proto_encode_auth_fail(&fail, buf, sizeof(buf), &len);
    if (err != VW_OK) return err;
    return vw_proto_send(conn, VW_MSG_AUTH_FAIL, buf, len);
}

/*
 * Look up the newly-created session and user, build AUTH_OK, send it, and
 * optionally populate out_info.
 */
static vw_err_t build_and_send_auth_ok(vw_server_ctx_t *ctx, vw_conn_t *conn,
                                         const uint8_t token[VW_TOKEN_BYTES],
                                         uint64_t user_id,
                                         vw_session_info_t *out_info)
{
    vw_session_record_t sess_rec;
    vw_err_t err = vw_store_session_get(ctx->store, token, &sess_rec);
    if (err != VW_OK) return err;

    vw_user_record_t user_rec;
    err = vw_store_user_get_by_id(ctx->store, user_id, &user_rec);
    if (err != VW_OK) return err;

    vw_payload_auth_ok_t ok;
    memcpy(ok.session_token, token, VW_TOKEN_BYTES);
    ok.expires_at  = (int64_t)sess_rec.expires_at;
    ok.is_admin    = user_rec.is_admin;
    ok.quota_bytes = 0;  /* TODO(SRV.01): populate from vw_store_quota_get */
    ok.used_bytes  = 0;
    ok.user_id     = user_id;

    /* AUTH_OK payload: 32 + 8 + 1 + 8 + 8 + 8 = 65 bytes */
    uint8_t buf[72];
    uint32_t len;
    err = vw_proto_encode_auth_ok(&ok, buf, sizeof(buf), &len);
    if (err != VW_OK) return err;

    err = vw_proto_send(conn, VW_MSG_AUTH_OK, buf, len);
    if (err != VW_OK) return err;

    if (out_info) {
        out_info->user_id = user_id;
        memcpy(out_info->session_token, token, VW_TOKEN_BYTES);
        out_info->expires_at = ok.expires_at;
        out_info->is_admin   = ok.is_admin;
    }
    return VW_OK;
}

/* ── AUTH_REQUEST handler ────────────────────────────────────────────────── */

static vw_err_t handle_auth_request(vw_server_ctx_t *ctx, vw_conn_t *conn,
                                      const uint8_t *payload, uint32_t plen,
                                      const char *peer_ip,
                                      vw_session_info_t *out_info)
{
    vw_payload_auth_request_t req;
    vw_err_t err = vw_proto_decode_auth_request(payload, plen, &req);
    if (err != VW_OK) return VW_ERR_PROTO_INVALID;
    /* Enforce application-level limit: decoder only checks against recv buffer size */
    if (req.username_len > VW_MAX_USERNAME_BYTES) return VW_ERR_PROTO_INVALID;

    /* Null-terminate username for vw_auth_begin_login (takes C string) */
    char uname[VW_MAX_USERNAME_BYTES + 1];
    memcpy(uname, req.username, req.username_len);
    uname[req.username_len] = '\0';

    vw_auth_state_t state;
    err = vw_auth_begin_login(ctx->auth, uname,
                               req.auth_token, VW_TOKEN_BYTES,
                               &state);
    secure_zero(req.auth_token, VW_TOKEN_BYTES);  /* wipe credential immediately */

    if (err == VW_OK) {
        /* No 2FA required — create a session and send AUTH_OK */
        uint64_t uid = state.user_id;
        secure_zero(&state, sizeof(state));
        uint8_t token[VW_TOKEN_BYTES];
        vw_err_t sess_err = vw_auth_create_session(ctx->auth, uid, peer_ip, token);
        if (sess_err != VW_OK) {
            /* non-fatal: conn closed immediately after; always BAD_CREDS —
             * VW_ERR_IO would confirm credentials were accepted */
            (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
            return sess_err;
        }
        return build_and_send_auth_ok(ctx, conn, token, uid, out_info);

    } else if (err == VW_ERR_AUTH_2FA_REQUIRED) {
        /* Send AUTH_CHALLENGE */
        static const char hint[] = "Code sent to registered email";
        vw_payload_auth_challenge_t ch;
        ch.challenge_type = (uint8_t)VW_2FA_EMAIL_OTP;
        ch.hint           = hint;
        ch.hint_len       = (uint16_t)(sizeof(hint) - 1u);

        uint8_t ch_buf[64];
        uint32_t ch_len;
        vw_err_t enc_err;

        enc_err = vw_proto_encode_auth_challenge(&ch, ch_buf, sizeof(ch_buf), &ch_len);
        if (enc_err != VW_OK) return enc_err;
        enc_err = vw_proto_send(conn, VW_MSG_AUTH_CHALLENGE, ch_buf, ch_len);
        if (enc_err != VW_OK) return enc_err;

        /* Wait for AUTH_OTP */
        vw_msg_type_t otp_type;
        uint8_t otp_buf[AUTH_BUF_SIZE];
        uint32_t otp_plen;
        enc_err = vw_proto_recv(conn, &otp_type, otp_buf, sizeof(otp_buf), &otp_plen);
        if (enc_err != VW_OK) return enc_err;
        if (otp_type != VW_MSG_AUTH_OTP) return VW_ERR_PROTO_INVALID;

        vw_payload_auth_otp_t otp_payload;
        enc_err = vw_proto_decode_auth_otp(otp_buf, otp_plen, &otp_payload);
        if (enc_err != VW_OK) return enc_err;

        /* capture before vw_auth_verify_2fa clears state->magic */
        uint64_t uid = state.user_id;
        uint8_t token[VW_TOKEN_BYTES];
        vw_err_t v2fa_err = vw_auth_verify_2fa(ctx->auth, &state,
                                                 otp_payload.otp_code,
                                                 otp_payload.otp_len,
                                                 token);
        secure_zero(&state, sizeof(state));
        if (v2fa_err != VW_OK) {
            uint16_t lockout = (v2fa_err == VW_ERR_AUTH_2FA_LOCKED) ? AUTH_LOCKOUT_SECS : 0u;
            /* non-fatal: conn closed immediately after */
            (void)send_auth_fail(conn, (uint32_t)v2fa_err, lockout);
            return v2fa_err;
        }
        return build_and_send_auth_ok(ctx, conn, token, uid, out_info);

    } else {
        /* Always BAD_CREDS with lockout_secs=0 — VW_ERR_AUTH_LOCKED applies only
         * to existing accounts, so a non-zero lockout would confirm username
         * existence. (PROTOCOL.md §7.1)
         * non-fatal: conn closed immediately after. */
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return err;
    }
}

/* ── SESSION_RESUME handler ──────────────────────────────────────────────── */

static vw_err_t handle_session_resume(vw_server_ctx_t *ctx, vw_conn_t *conn,
                                       const uint8_t *payload, uint32_t plen,
                                       const char *peer_ip,
                                       vw_session_info_t *out_info)
{
    if (plen < VW_TOKEN_BYTES) return VW_ERR_PROTO_TRUNCATED;
    if (plen > VW_TOKEN_BYTES) return VW_ERR_PROTO_INVALID;

    uint64_t user_id;
    vw_err_t err = vw_auth_validate_session(ctx->auth, payload, &user_id);
    if (err != VW_OK) {
        /* non-fatal: conn closed immediately after; always BAD_CREDS —
         * distinct codes (expired/revoked/not-found) would enable token-oracle attacks */
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return err;
    }

    /* Create a new session BEFORE revoking the old one so the user is never
     * locked out due to a session-creation failure (PROTOCOL.md §7.1:
     * single-use token replacement). */
    uint8_t new_token[VW_TOKEN_BYTES];
    err = vw_auth_create_session(ctx->auth, user_id, peer_ip, new_token);
    if (err != VW_OK) {
        /* non-fatal: conn closed immediately after; always BAD_CREDS —
         * VW_ERR_IO would confirm the old token was valid */
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return err;
    }

    /* Revoke old token — best-effort.  On failure the old token remains valid
     * until its natural expiry; this is acceptable because the new token is
     * already in the client's hands and the TTL is bounded.
     * TODO: log at WARN when the logging subsystem is available. */
    vw_err_t revoke_err = vw_auth_revoke_session(ctx->auth, payload);
    if (revoke_err != VW_OK && revoke_err != VW_ERR_NOT_FOUND) {
        /* TODO: vw_log_warn("session revoke failed: %d", revoke_err); */
    }

    return build_and_send_auth_ok(ctx, conn, new_token, user_id, out_info);
}

/* ── AUTH_RECOVER handlers ───────────────────────────────────────────────── */

/*
 * Blocking sleep for timing normalisation.
 * AUTH_RECOVER_REQUEST must always take ≥ RECOVERY_RESPONSE_MS regardless of
 * whether the email is registered, to prevent email enumeration via timing.
 *
 * Advisory: this is a FLOOR, not a fixed delay. Under high server load, actual
 * response time may exceed RECOVERY_RESPONSE_MS, potentially distinguishing
 * valid from invalid codes via timing. For stronger guarantees, replace with an
 * unconditional sleep(RECOVERY_RESPONSE_MS) that ignores the processing time.
 */
#define RECOVERY_RESPONSE_MS 200u
#define RECOVERY_CODE_TTL_SECS 600u
#define RECOVERY_MAX_UNEXPIRED  3u

static void recovery_sleep_ms(uint32_t ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec  = ms / 1000u;
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

/* Send AUTH_RECOVER_FAIL with reason byte always 0 (prevents email enumeration). */
static vw_err_t send_recover_fail(vw_conn_t *conn)
{
    uint8_t reason = 0;
    return vw_proto_send(conn, VW_MSG_AUTH_RECOVER_FAIL, &reason, 1);
}

/* Send AUTH_RECOVER_OK (empty payload). */
static vw_err_t send_recover_ok(vw_conn_t *conn)
{
    return vw_proto_send(conn, VW_MSG_AUTH_RECOVER_OK, NULL, 0);
}

/*
 * AUTH_RECOVER_REQUEST payload: email[128] (NUL-padded fixed-size).
 *
 * Always responds AUTH_RECOVER_OK after a constant sleep, whether or not the
 * email exists. When it does exist and SMTP is configured, generates a 6-digit
 * OTP, stores SHA-256(code) in the recovery store, and sends the email.
 */
static vw_err_t handle_recover_request(vw_server_ctx_t *ctx, vw_conn_t *conn,
                                        const uint8_t *payload, uint32_t plen)
{
    if (plen < 128u) {
        (void)send_recover_ok(conn); /* always OK — no enumeration */
        return VW_ERR_PROTO_TRUNCATED;
    }

    char email[129];
    memcpy(email, payload, 128);
    email[128] = '\0';

    /* Constant-time processing begins here — start the clock. */
    recovery_sleep_ms(RECOVERY_RESPONSE_MS);

    if (!ctx->recovery_store || !ctx->smtp_cfg || ctx->smtp_cfg->host[0] == '\0') {
        /* Recovery disabled on this server — still return OK, no code sent. */
        return send_recover_ok(conn);
    }

    /* Look up user by email. Failure is silent (same response either way). */
    vw_user_record_t user_rec;
    vw_err_t err = vw_store_user_get_by_email(ctx->store, email, &user_rec);
    if (err != VW_OK) {
        return send_recover_ok(conn); /* unknown email — still OK */
    }

    uint64_t now = (uint64_t)time(NULL);

    /* Rate-limit: skip if ≥ RECOVERY_MAX_UNEXPIRED unexpired records. */
    uint32_t pending = 0;
    (void)vw_recovery_count_unexpired(ctx->recovery_store, user_rec.user_id,
                                      now, &pending);
    if (pending >= RECOVERY_MAX_UNEXPIRED) {
        return send_recover_ok(conn); /* rate limited — silent drop */
    }

    /* Generate 6-digit code: 4 random bytes → uint32 → % 1000000. */
    uint8_t rand_buf[4];
    err = vw_crypto_random(rand_buf, sizeof(rand_buf));
    if (err != VW_OK) return send_recover_ok(conn);

    uint32_t rand32 = (uint32_t)rand_buf[0]         |
                      ((uint32_t)rand_buf[1] <<  8)  |
                      ((uint32_t)rand_buf[2] << 16)  |
                      ((uint32_t)rand_buf[3] << 24);
    secure_zero(rand_buf, sizeof(rand_buf));
    char code_str[7];
    (void)snprintf(code_str, sizeof(code_str), "%06u",
                   (unsigned)(rand32 % 1000000u));

    /* Store SHA-256(code), never the plaintext. */
    uint8_t code_hash[32];
    err = vw_crypto_sha256(code_str, 6, code_hash);
    secure_zero(code_str, sizeof(code_str)); /* plaintext gone from stack */
    if (err != VW_OK) return send_recover_ok(conn);

    /* Regenerate printable code for email body — we still have the hash.
     * We need the plaintext for the email body; re-derive it before zeroing. */
    char email_code[7];
    (void)snprintf(email_code, sizeof(email_code), "%06u",
                   (unsigned)(rand32 % 1000000u));

    /* Write recovery record. */
    err = vw_recovery_write(ctx->recovery_store, user_rec.user_id,
                             code_hash, RECOVERY_CODE_TTL_SECS);
    if (err != VW_OK) {
        secure_zero(email_code, sizeof(email_code));
        return send_recover_ok(conn); /* write failure — silent */
    }

    /* Send email. */
    char body[256];
    (void)snprintf(body, sizeof(body),
                   "Your VaporWault password reset code is: %s\n"
                   "This code expires in 10 minutes.\n",
                   email_code);
    secure_zero(email_code, sizeof(email_code));

    (void)vw_smtp_send(ctx->smtp_cfg, email,
                        "VaporWault password recovery",
                        body, NULL, 0);
    secure_zero(body, sizeof(body));

    return send_recover_ok(conn);
}

/*
 * AUTH_RECOVER_CONFIRM payload:
 *   email[128] + code[8] (NUL-padded 6-digit ASCII) + new_password_token[32]
 * Total: 168 bytes.
 *
 * Verifies the code using constant-time comparison, resets the password,
 * invalidates all existing sessions, and responds AUTH_RECOVER_OK.
 * Any failure → AUTH_RECOVER_FAIL (reason=0).
 */
static vw_err_t handle_recover_confirm(vw_server_ctx_t *ctx, vw_conn_t *conn,
                                        const uint8_t *payload, uint32_t plen)
{
    if (plen < 128u + 8u + 32u) {
        /* Sleep even on truncated input so payload length is not a timing signal. */
        recovery_sleep_ms(RECOVERY_RESPONSE_MS);
        (void)send_recover_fail(conn);
        return VW_ERR_PROTO_TRUNCATED;
    }
    if (!ctx->recovery_store) {
        recovery_sleep_ms(RECOVERY_RESPONSE_MS);
        (void)send_recover_fail(conn);
        return VW_ERR_NOT_IMPL;
    }

    char    email[129];
    uint8_t submitted_code[8];   /* 6-digit ASCII, NUL-padded to 8 */
    uint8_t new_password_token[VW_TOKEN_BYTES];

    memcpy(email, payload, 128);
    email[128] = '\0';
    memcpy(submitted_code, payload + 128, 8);
    memcpy(new_password_token, payload + 128 + 8, VW_TOKEN_BYTES);

    /* Constant-time processing begins here.  All paths that return FAIL or OK
     * below happen AFTER this sleep, so the caller cannot distinguish "email
     * unknown" from "code wrong" via response time.  (SEC.07 requirement.) */
    recovery_sleep_ms(RECOVERY_RESPONSE_MS);

    /* 1. Look up user by email. */
    vw_user_record_t user_rec;
    vw_err_t err = vw_store_user_get_by_email(ctx->store, email, &user_rec);
    if (err != VW_OK) {
        secure_zero(new_password_token, VW_TOKEN_BYTES);
        (void)send_recover_fail(conn);
        return err;
    }

    uint64_t now = (uint64_t)time(NULL);

    /* 2. Find the most recent valid recovery record. */
    vw_recovery_record_t rec;
    uint64_t rec_slot;
    err = vw_recovery_find_latest(ctx->recovery_store, user_rec.user_id,
                                   now, &rec, &rec_slot);
    if (err != VW_OK) {
        secure_zero(new_password_token, VW_TOKEN_BYTES);
        (void)send_recover_fail(conn);
        return err;
    }

    /* 3. Hash the submitted code and compare in constant time. */
    uint8_t submitted_hash[32];
    err = vw_crypto_sha256(submitted_code, 6, submitted_hash);
    int code_matches = (err == VW_OK) &&
                       vw_crypto_constant_time_eq(submitted_hash, rec.code_hash, 32);
    secure_zero(submitted_hash, 32);

    if (!code_matches) {
        /* Consume the recovery record on failure to prevent brute-force enumeration
         * of the 6-digit code space.  The user must request a new code.
         * (SEC.07: without this, an attacker can try all 1 000 000 codes in the
         * 10-minute TTL window.) */
        (void)vw_recovery_mark_used(ctx->recovery_store, rec_slot);
        secure_zero(new_password_token, VW_TOKEN_BYTES);
        (void)send_recover_fail(conn);
        return VW_ERR_AUTH_BAD_CREDS;
    }

    /* 4. Mark record used (prevent replay). */
    err = vw_recovery_mark_used(ctx->recovery_store, rec_slot);
    if (err != VW_OK) {
        secure_zero(new_password_token, VW_TOKEN_BYTES);
        (void)send_recover_fail(conn);
        return err;
    }

    /* 5. Rehash the new password and update the user record. */
    uint8_t pw_hash[32], pw_salt[16];
    err = vw_auth_hash_password(new_password_token, VW_TOKEN_BYTES,
                                 pw_hash, pw_salt);
    secure_zero(new_password_token, VW_TOKEN_BYTES);
    if (err != VW_OK) {
        secure_zero(pw_hash, 32);
        secure_zero(pw_salt, 16);
        (void)send_recover_fail(conn);
        return err;
    }

    /* Write password_hash and password_salt in a single 48-byte call.
     * The two fields are contiguous in vw_user_record_t (hash at offsetof
     * password_hash, salt immediately following), so one pwrite covers both.
     * A single call eliminates the window where hash is updated but salt is not
     * (which would leave credentials in a permanently broken state). */
    uint8_t hash_and_salt[48];
    memcpy(hash_and_salt,      pw_hash, 32);
    memcpy(hash_and_salt + 32, pw_salt, 16);
    secure_zero(pw_hash, 32);
    secure_zero(pw_salt, 16);
    err = vw_store_user_update_field(ctx->store, user_rec.user_id,
                                      (uint32_t)offsetof(vw_user_record_t,
                                                         password_hash),
                                      hash_and_salt, 48);
    secure_zero(hash_and_salt, 48);

    if (err != VW_OK) {
        (void)send_recover_fail(conn);
        return err;
    }

    /* 6. Invalidate all existing sessions for this user. */
    (void)vw_store_sessions_revoke_by_user(ctx->store, user_rec.user_id, NULL);

    return send_recover_ok(conn);
}

/* ── INVITE_REDEEM handler ───────────────────────────────────────────────── */

/*
 * INVITE_REDEEM payload: code[32] + username (u16le len + bytes) + password_token[32]
 *
 * Handled in the unauthenticated auth phase (alongside AUTH_REQUEST) because it
 * creates a new account and returns a session, matching the same flow.
 *
 * Security: all failure paths send AUTH_FAIL with BAD_CREDS regardless of the
 * actual failure reason to prevent oracle attacks (unknown invite, expired,
 * username taken, etc. all look identical to the caller).
 */
static vw_err_t handle_invite_redeem(vw_server_ctx_t *ctx, vw_conn_t *conn,
                                      const uint8_t *payload, uint32_t plen,
                                      const char *peer_ip,
                                      vw_session_info_t *out_info)
{
    /* Minimum: code[32] + u16 len + 1-byte name + password_token[32] */
    if (plen < 32u + 2u + 1u + 32u) {
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return VW_ERR_PROTO_TRUNCATED;
    }
    if (!ctx->invite_store) {
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return VW_ERR_NOT_IMPL;
    }

    uint32_t off = 0;

    uint8_t code[32];
    memcpy(code, payload + off, 32); off += 32;

    uint16_t uname_len = (uint16_t)(payload[off] | ((uint16_t)payload[off + 1] << 8));
    off += 2;

    if (uname_len == 0 || uname_len > VW_MAX_USERNAME_BYTES ||
        off + (uint32_t)uname_len + 32u > plen) {
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return VW_ERR_PROTO_INVALID;
    }

    char uname[VW_MAX_USERNAME_BYTES + 1];
    memcpy(uname, payload + off, uname_len);
    uname[uname_len] = '\0';
    off += uname_len;

    uint8_t password_token[VW_TOKEN_BYTES];
    memcpy(password_token, payload + off, VW_TOKEN_BYTES);

    /* 1. Validate username character set: [A-Za-z0-9_.-], 1–63 bytes. */
    for (uint16_t i = 0; i < uname_len; i++) {
        unsigned char c = (unsigned char)uname[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) {
            secure_zero(password_token, VW_TOKEN_BYTES);
            (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
            return VW_ERR_PROTO_INVALID;
        }
    }

    /* 2. Username must not already exist — checked BEFORE claiming the invite so
     *    a rejected username does not permanently consume the invite code. */
    {
        vw_user_record_t existing;
        vw_err_t chk = vw_store_user_get_by_username(ctx->store, uname, &existing);
        if (chk != VW_ERR_NOT_FOUND) {
            secure_zero(password_token, VW_TOKEN_BYTES);
            (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
            return (chk == VW_OK) ? VW_ERR_ALREADY_EXISTS : chk;
        }
    }

    /* 3. Atomically validate and claim the invite under a write lock.
     *    vw_invite_claim prevents the TOCTOU where two concurrent INVITE_REDEEM
     *    requests could both observe is_used=0 before either commits the mark.
     *    The invite is permanently consumed by this call. */
    vw_invite_record_t inv;
    vw_err_t err = vw_invite_claim(ctx->invite_store, code, &inv);
    if (err != VW_OK) {
        secure_zero(password_token, VW_TOKEN_BYTES);
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return err;
    }

    /* 4. Hash the password token with Argon2id. */
    uint8_t pw_hash[32], pw_salt[16];
    err = vw_auth_hash_password(password_token, VW_TOKEN_BYTES, pw_hash, pw_salt);
    secure_zero(password_token, VW_TOKEN_BYTES);
    if (err != VW_OK) {
        /* Invite already consumed. Admin must reissue if this user retries. */
        secure_zero(pw_hash, 32);
        secure_zero(pw_salt, 16);
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return err;
    }

    /* 5. Create the user record. */
    vw_user_record_t rec;
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.username, uname, uname_len);
    memcpy(rec.password_hash, pw_hash, 32);
    memcpy(rec.password_salt, pw_salt, 16);
    rec.is_active = 1;
    secure_zero(pw_hash, 32);
    secure_zero(pw_salt, 16);

    uint64_t uid = 0;
    err = vw_store_user_create(ctx->store, &rec, &uid);
    secure_zero(rec.password_hash, 32);
    secure_zero(rec.password_salt, 16);
    if (err != VW_OK) {
        /* Invite consumed but user creation failed — admin must reissue invite. */
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return err;
    }

    /* 6. Apply quota from invite (best-effort; 0 = unlimited, no call needed). */
    if (inv.quota_bytes > 0) {
        (void)vw_store_quota_set(ctx->store, uid, inv.quota_bytes);
    }

    /* 7. Create session and send INVITE_REDEEM_ACK (= AUTH_OK payload). */
    uint8_t token[VW_TOKEN_BYTES];
    err = vw_auth_create_session(ctx->auth, uid, peer_ip, token);
    if (err != VW_OK) {
        (void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
        return err;
    }

    return build_and_send_auth_ok(ctx, conn, token, uid, out_info);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_server_ctx_open(vw_auth_ctx_t *auth, vw_store_t *store,
                              const vw_server_cfg_t *cfg,
                              vw_server_ctx_t **out_ctx)
{
    if (!auth || !store || !out_ctx) return VW_ERR_INVALID_ARG;

    vw_server_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->auth  = auth;
    ctx->store = store;
    ctx->auth_timeout_ms = (cfg && cfg->auth_timeout_ms)
                           ? cfg->auth_timeout_ms
                           : AUTH_TIMEOUT_MS_DEFAULT;
    *out_ctx = ctx;
    return VW_OK;
}

void vw_server_ctx_set_file_stores(vw_server_ctx_t *ctx,
                                    vw_file_store_t *file_store,
                                    vw_storage_t    *chunk_store)
{
    if (!ctx) return;
    ctx->file_store  = file_store;
    ctx->chunk_store = chunk_store;
}

void vw_server_ctx_set_invite_store(vw_server_ctx_t  *ctx,
                                     vw_invite_store_t *invite_store)
{
    if (!ctx) return;
    ctx->invite_store = invite_store;
}

void vw_server_ctx_set_recovery(vw_server_ctx_t       *ctx,
                                 vw_recovery_store_t   *recovery_store,
                                 const vw_smtp_cfg_t   *smtp_cfg)
{
    if (!ctx) return;
    ctx->recovery_store = recovery_store;
    ctx->smtp_cfg       = smtp_cfg;
}

vw_store_t *vw_server_ctx_store(const vw_server_ctx_t *ctx)
{
    return ctx ? ctx->store : NULL;
}

vw_file_store_t *vw_server_ctx_file_store(const vw_server_ctx_t *ctx)
{
    return ctx ? ctx->file_store : NULL;
}

vw_storage_t *vw_server_ctx_chunk_store(const vw_server_ctx_t *ctx)
{
    return ctx ? ctx->chunk_store : NULL;
}

vw_invite_store_t *vw_server_ctx_invite_store(const vw_server_ctx_t *ctx)
{
    return ctx ? ctx->invite_store : NULL;
}

void vw_server_ctx_set_oplog(vw_server_ctx_t *ctx, vw_oplog_t *oplog)
{
    if (ctx) ctx->oplog = oplog;
}

vw_oplog_t *vw_server_ctx_oplog(const vw_server_ctx_t *ctx)
{
    return ctx ? ctx->oplog : NULL;
}

void vw_server_ctx_set_cluster(vw_server_ctx_t *ctx, vw_cluster_t *cluster)
{
    if (ctx) ctx->cluster = cluster;
}

vw_cluster_t *vw_server_ctx_cluster(const vw_server_ctx_t *ctx)
{
    return ctx ? ctx->cluster : NULL;
}

void vw_server_ctx_close(vw_server_ctx_t *ctx)
{
    free(ctx);
}

vw_err_t vw_server_conn_handle(vw_server_ctx_t *ctx,
                                 vw_conn_t *conn,
                                 vw_session_info_t *out_info)
{
    if (!ctx || !conn) return VW_ERR_INVALID_ARG;
    if (out_info) memset(out_info, 0, sizeof(*out_info));

    char peer_ip[46] = {0};
    (void)vw_net_peer_addr(conn, peer_ip, sizeof(peer_ip));

    vw_err_t err = vw_net_conn_set_recv_timeout(conn, ctx->auth_timeout_ms);
    if (err != VW_OK) return err;

    uint16_t version;
    err = vw_proto_negotiate(conn, 1 /*is_server*/, &version);
    if (err != VW_OK) return err;

    vw_msg_type_t type;
    uint8_t buf[AUTH_BUF_SIZE];
    uint32_t plen;
    err = vw_proto_recv(conn, &type, buf, sizeof(buf), &plen);
    if (err != VW_OK) return err;

    if (type == VW_MSG_AUTH_REQUEST) {
        return handle_auth_request(ctx, conn, buf, plen, peer_ip, out_info);
    }
    if (type == VW_MSG_SESSION_RESUME) {
        return handle_session_resume(ctx, conn, buf, plen, peer_ip, out_info);
    }
    if (type == VW_MSG_AUTH_RECOVER_REQUEST) {
        return handle_recover_request(ctx, conn, buf, plen);
    }
    if (type == VW_MSG_AUTH_RECOVER_CONFIRM) {
        return handle_recover_confirm(ctx, conn, buf, plen);
    }
    if (type == VW_MSG_INVITE_REDEEM) {
        return handle_invite_redeem(ctx, conn, buf, plen, peer_ip, out_info);
    }
    return VW_ERR_PROTO_INVALID;
}
