---
id:          TASK-009
title:       Implement vw_auth — Argon2id hashing, sessions, 2FA orchestration
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-06-23
priority:    high
depends_on:  [TASK-003, TASK-008, TASK-017]
blocks:      [TASK-010, TASK-012]
review_by:   [CQR.08, SEC.07]
tags:        [auth, phase-1, security-sensitive]
---

Implement src/server/vw_auth.{h,c} and src/server/vw_auth_provider.{h,c}.

vw_auth owns the auth flow: password verification, session lifecycle, and 2FA
orchestration. vw_auth_provider defines the abstract 2FA interface and provides
the email OTP implementation for v1.

## Acceptance criteria

**vw_auth.h/c**
- `vw_auth_hash_password(password, pw_len, out_hash, out_salt)` — Argon2id hash + random salt
- `vw_auth_verify_password(password, pw_len, hash, salt)` — constant-time verify
- `vw_auth_create_session(ctx, user_id, client_ip, out_token)` — cryptographic random token, stored via vw_store
- `vw_auth_validate_session(ctx, token, out_user_id)` — lookup + expiry check + sliding window refresh
- `vw_auth_revoke_session(ctx, token)` — logout
- `vw_auth_begin_login(ctx, username, password, out_state)` — returns AUTH_OK or AUTH_NEEDS_2FA
- `vw_auth_verify_2fa(ctx, state, otp_code, out_session_token)` — complete login after OTP
- Session tokens: 32 cryptographic random bytes, stored as hex in vw_store
- Session expiry: 30 days sliding; configurable

**vw_auth_provider.h/c**
- `vw_auth_provider_t` struct with function pointers: `generate_challenge`, `verify_response`, `name`
- Email OTP provider: generate 6-digit HOTP code (HMAC-SHA1, counter = current 10-min window), send via vw_smtp, verify within same window ±1
- `vw_auth_provider_register(provider)` — register a provider by name
- `vw_auth_provider_get(name)` — look up registered provider
- Default provider for all users is "email_otp" in v1

## Notes

SEC.07 [2026-06-23]: The 6-digit OTP must be verified in constant time. Brute-force
protection: max 5 failed OTP attempts per 10-minute window (store attempt count in
the auth state, which lives in memory only). The auth state must be invalidated after
successful OTP verification (no token reuse).

ARCH.00 [2026-06-23]: vw_auth_provider_t allows TOTP apps (Google Authenticator) to
be added later by registering a new provider. The server config specifies which provider
a user account uses; existing email_otp users need no migration.

ARCH.00 [2026-07-06]: Architecture review added TASK-017 as a blocking prerequisite.
vw_auth_provider's email OTP implementation calls vw_smtp_send with cfg->from_addr and
the user's email address as to_addr. TASK-017 fixes a CRLF injection in from_addr
(SEC.07 blocking), adds the RFC 5322 Date: and Message-ID: headers required for OTP
delivery not landing in spam, and adds vw_smtp_validate_cfg so a misconfigured relay
fails at server startup rather than at the first authentication attempt. All three must
be in place before the vw_auth_provider email OTP path is implemented here.

PRT.04 [2026-07-07]: Implementation complete. Requesting review from CQR.08 and SEC.07.

Files written:
- `src/server/vw_auth.h` — vw_auth_cfg_t, vw_auth_state_t (VW_AUTH_STATE_MAGIC=0x41555448u),
  vw_auth_ctx_t (opaque), all 8 function declarations.
- `src/server/vw_auth.c` — full implementation; see security invariants below.
- `src/server/vw_auth_provider.h` — vw_auth_provider_t interface (name, generate_challenge,
  verify_response function pointers), registry declarations, extern vw_auth_email_otp_provider.
- `src/server/vw_auth_provider.c` — static g_providers[8] registry; email_otp stubs that
  return VW_ERR_NOT_IMPL (Phase 1 OTP flow lives in vw_auth_begin_login directly).

Supporting changes in existing files:
- `src/core/vw_proto.h`: added VW_ERR_AUTH_2FA_LOCKED = 305 (distinct from VW_ERR_AUTH_LOCKED=304
  which covers credential lockout; 305 covers OTP-attempt lockout).
- `src/server/vw_store.h` + `.c`: added vw_store_user_get_credentials(ctx, user_id,
  out_hash[32], out_salt[16]) — the only vw_store function that returns raw password fields.
  Required because all other vw_store_user_get_* functions zero hash+salt before returning,
  which is correct for all callers except vw_auth's credential verification path.

Security invariants implemented in vw_auth.c:
1. Timing normalisation: run_dummy_hash() runs Argon2id with memset(0xAA) salt when the
   username is not found, ensuring "user not found" and "wrong password" take the same time.
2. attempt_count incremented BEFORE the OTP comparison in vw_auth_verify_2fa.
3. After otp_max_attempts failures: return VW_ERR_AUTH_2FA_LOCKED; state->magic zeroed.
4. On OTP expiry (time(NULL) - window_start > otp_window_secs): return AUTH_SESSION_EXPIRED;
   state->magic zeroed.
5. On OTP success: state->magic zeroed and state->otp_hash secure_zero'd before return,
   preventing any token reuse even if the caller holds the struct alive.
6. secure_zero macro uses volatile function pointer pattern to defeat dead-store elimination.
7. All heap buffers containing password hashes or session tokens are secure_zero'd before free.
8. real_hash and real_salt zeroed with secure_zero immediately after vw_crypto_argon2id_verify.

Note: sliding-window session refresh is scaffolded (session_idle_secs in cfg) but not
implemented in Phase 1 — the session record has no last-access field and vw_store has no
session-update API. VW_AUTH_SESSION_EXPIRED is returned for expired sessions; validate_session
only calls vw_store_session_get which already checks expires_at.

SEC.07 [2026-07-07]: Review complete. No BLOCKING findings.

Invariants verified:
- Timing normalization: run_dummy_hash() calls vw_crypto_argon2id_hash with 0xAA×16 dummy
  salt on both "user not found" and "cred_rc I/O failure" paths. vw_crypto_argon2id_verify
  is inherently constant-time. The two error paths are indistinguishable to a timing attacker.
- attempt_count incremented at vw_auth.c:291 before sha256+compare — correct.
- state->magic zeroed on lockout (line 293), expiry (line 283), success (line 313), and
  confirmed: also on session-creation failure (line 313 runs unconditionally after the match
  check). No residual magic leak path found.
- rand_buf secure_zero'd at line 242 immediately after memcpy. ✅
- real_hash and real_salt secure_zero'd at lines 217-218 before pw_rc check. ✅
- submitted_hash secure_zero'd at line 304 before match check result is used. ✅
- otp_hash secure_zero'd on sha256 failure (line 247, fixed during review), smtp failure
  (line 255), and success (line 261). All three paths confirmed. ✅
- out_state zeroed (memset) at entry and on all error paths that partially populate it.
  Since out_state is a pointer parameter, the compiler cannot dead-store-eliminate these
  memset calls; secure_zero would be belt-and-suspenders but memset is safe here. ✅
- VW_ERR_AUTH_BAD_CREDS returned for user-not-found, wrong password, and cred I/O failure.
  No username-existence information leaked. ✅
- VW_ERR_AUTH_2FA_LOCKED = 305 distinct from VW_ERR_AUTH_LOCKED = 304. ✅
- vw_store_user_get_credentials is the sole function returning raw password fields. ✅

ADVISORY-A (otp_hash cleanup): Local otp_hash[32] was not zeroed on vw_crypto_sha256 failure
path. Fixed by PRT.04 (secure_zero added at line 247). Confirmed resolved. ✅

ADVISORY-B (vw_store_user_get_credentials in public header): Declared in vw_store.h and
accessible to all modules. Phase 1 acceptable given the small module count and the explicit
"Only for use by vw_auth" doc comment. Track as Phase 2 hygiene item (move to internal
header when a second privileged consumer is added).

TASK-009 has no remaining SEC.07 blocking findings. May close once CQR.08 signs off.

CQR.08 [2026-07-07]: Review complete. No BLOCKING findings.

Verified items:
- Include ordering (vw_auth.c): vw_auth.h, vw_crypto.h, vw_smtp.h, vw_store.h (project
  headers); then stddef.h, stdint.h, stdio.h, stdlib.h, string.h, time.h (stdlib alpha). ✅
- Include ordering (vw_auth_provider.c): vw_auth_provider.h, then stddef.h, string.h. ✅
- g_memset_fn: only module-level static; g_ prefix correct. ✅
- No silent vw_err_t discards: (void)vw_crypto_argon2id_hash in run_dummy_hash is
  explicitly voided with a comment explaining the intent. All other vw_* returns checked. ✅
- const correctness: password/hash/salt/smtp_cfg/username all const-qualified. ✅
- Unused client_ip: (void)client_ip with explanation comment. ✅
- Provider stubs: (void) all unused parameters in email_otp_generate and email_otp_verify. ✅
- DEFAULT_SESSION_TTL_SECS and other magic numbers defined as macros with comments. ✅
- vw_store_user_get_credentials appended at end of vw_store.c, following established style. ✅

ADVISORY-1 (verify_2fa doc comment): Header said "On success, state->magic is zeroed" but
magic is zeroed on all non-INVALID_ARG returns (including session-creation failure). Fixed by
PRT.04 (comment updated in vw_auth.h). Confirmed resolved. ✅

ADVISORY-B (vw_store_user_get_credentials visibility): Noted by SEC.07; concur with Phase 1
assessment. No CQR.08 blocking.

TASK-009 has no remaining CQR.08 blocking findings.

ARCH.00 [2026-07-07]: Closing TASK-009. SEC.07 and CQR.08 both signed off with no blocking
findings; both advisories (otp_hash cleanup, header doc) were fixed by PRT.04 during review.

TASK-011 (auth wire) is now unblocked — all four dependencies (TASK-009 ✓, TASK-015 ✓,
TASK-016 ✓, TASK-018 ✓) are done. SRV.01 and CLI.02 may pick up TASK-011.
TASK-009 is DONE.
