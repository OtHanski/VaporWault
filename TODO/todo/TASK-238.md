---
id:          TASK-238
title:       "2FA login OTP is re-minted and re-emailed on every AUTH_REQUEST, making email-OTP login structurally unreachable"
status:      todo
assignee:    SRV.01
created_by:  MOB.10
created:     2026-09-02
priority:    critical
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive]
---

Discovered while running TASK-229's mandatory real-`vapourwaultd` runtime
verification of the Android app's email-2FA login flow (first genuine
end-to-end test of email-OTP login in this project — no prior task appears to
have exercised it against a real SMTP relay; `TODO/done/TASK-219.md`-`221.md`
only cover the self-service *toggle*, not a full login round-trip).

**The bug**: `vw_auth_begin_login` (`src/server/vw_auth.c:491-528`) runs in
full on *every* `AUTH_REQUEST` for an account with `otp_enabled`. If the
password check passes, it unconditionally generates a brand-new random OTP,
hashes it into a fresh, connection-local `vw_auth_state_t`, and emails it
(`send_otp_email`, line 517) — there is no per-user "pending challenge" cache
and no reuse of an outstanding OTP across connections. The state produced is
purely a local variable in the per-connection request handler
(`src/server/vw_server_core.c`, the `AUTH_REQUEST`/`AUTH_CHALLENGE`/`AUTH_OTP`
block around line 173), so it only exists for the lifetime of that one TCP
connection.

**Why this breaks every client, not just Android**: both existing 2FA-capable
clients use the identical "pre-supplied OTP" pattern — the JNI bridge's
`otp_callback` (`android/app/src/main/cpp/vw_jni_bridge.c:163`) and the
daemon's `login_otp_cb` (`src/client/vw_daemon.c:781`), both documented as
"the code was already collected ... before this connect attempt." The
intended UX is: (1) call `vw_client_connect` with no OTP → server emails a
code and returns `VW_ERR_AUTH_2FA_REQUIRED` → (2) the user reads the email and
types the code → (3) call `vw_client_connect` *again*, now with the code, to
actually log in.

But step (3) opens a **new** connection and therefore triggers **another**
full `AUTH_REQUEST`, which re-runs the same unconditional OTP-mint-and-email
logic — generating and emailing a *different* code and discarding the
connection-local state from step (1) entirely. The code the user just read
from their inbox (step 1's email) is validated against step (3)'s freshly
generated `otp_hash`, which is a different value, so it always mismatches.
There is no sequence of client-visible steps that lets a real user submit a
code that matches what the server is actually checking: the correct code for
a given `AUTH_REQUEST` is only known *after* that same call has already
blocked waiting to submit whatever OTP string was in the field beforehand.

**Confirmed empirically** (Android app against a real `vapourwaultd` +
`aiosmtpd` debug relay, account `androidtest`, 2FA enabled via
`vapourwault-cli.exe account 2fa on`):
- Attempt 1 (empty OTP): server emailed code `784478`, client correctly got
  `VW_ERR_AUTH_2FA_REQUIRED`, no `AUTH_OTP` sent (matches the "probe" path).
- Attempt 2 (typed `784478`): server emailed a **second, different** code
  `320766` as a side effect of this attempt's own `AUTH_REQUEST`, then
  rejected the submitted `784478` — the app surfaced `Connect failed:
  vw_err_t=0`, which is itself a secondary bug (see below) but the underlying
  auth failure is expected/correct given the code mismatch.
- There is no third attempt that can succeed: submitting `320766` would
  itself trigger a fresh `AUTH_REQUEST` (attempt 3) that mints code `#3`
  before evaluating `320766`, ad infinitum.

**Secondary bug to check while fixing this**: attempt 2 above surfaced
`vw_err_t=0` (`VW_OK`) on a failed connect, not the expected
`VW_ERR_AUTH_2FA_INVALID` (302). Tracing the error-propagation chain
(`vw_auth_verify_2fa` → `send_auth_fail`/`vw_proto_encode_auth_fail` →
client's `recv_auth_result`/`vw_proto_decode_auth_fail` → JNI bridge's
`g_last_error` → Kotlin's `VwClient.lastError()`) did not turn up an obvious
mismatch in the source read during this investigation, so this may be a
different, not-yet-isolated bug (or an artifact of a stale build/timing
issue) — needs its own repro once the primary issue above has a fix to test
against.

**Suggested direction** (SRV.01/PRT.04 to design, not prescribed here): cache
the pending OTP challenge per-user (not per-connection) for the configured
`otp_window_secs`, and have a repeat `AUTH_REQUEST` with valid credentials
during that window reuse the existing pending challenge (and optionally
re-send the same email, or rate-limit resends) instead of unconditionally
minting a new one. This is a protocol-flow change, so per `CLAUDE.md`'s
routing rules PRT.04 should weigh in on `docs/PROTOCOL.md` §8.3 before SRV.01
implements it.

## Acceptance criteria

- A real end-to-end login (fresh connect → 2FA challenge → email received →
  correct code typed by a human → login succeeds) is achievable via the
  existing client pattern (empty-OTP probe, then retry with the code), tested
  against a real SMTP relay, not just unit/mock coverage of the hash-compare
  logic.
- The secondary `vw_err_t=0`-on-failed-2FA-connect symptom is either
  reproduced and fixed, or confirmed to no longer occur once the primary fix
  lands and documented as such.
- Regression test added per `CLAUDE.md`'s QA.06 routing rule (every resolved
  SEC.07 finding needs a regression test — this is `security-sensitive`).

## Notes

- MOB.10, 2026-09-02: Filed while executing TASK-229's runtime verification.
  Out of MOB.10's domain (server auth flow) — not fixed inline per
  `CLAUDE.md`'s out-of-domain discovery rule. TASK-229's own Notes record
  this as the reason its 2FA acceptance criterion could not be fully
  exercised to a successful login, independent of the Android client code
  itself (which correctly implements the existing, already-established
  client-side 2FA contract shared with the desktop daemon).
