---
id:          TASK-219
title:       "Design: self-service 2FA enable/disable (no such mechanism exists today)"
status:      done
assignee:    ARCH.00
created_by:  SRV.01
created:     2026-08-26
priority:    low
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [design, security-sensitive]
---

Discovered while implementing `TASK-207` (user-facing email alerts —
`account_security_change` is supposed to fire on "password changed, or
2FA enabled/disabled" per `TASK-205`'s design). Checked thoroughly before
filing, not assumed: grepped every write site of `vw_user_record_t.otp_enabled`
across the whole codebase. There is exactly one — `vw_store_user_create`
zeroing a brand-new record (`otp_enabled` starts at 0, i.e. never set to
1 anywhere). `VW_MSG_USER_MODIFY`/`_ACK` (`0x0603`/`0x0604`) exist as
reserved opcodes in `vw_proto.h` but have never had a handler implemented
anywhere (`vw_admin.c`, `vw_file_handlers.c` — neither references them).
There is no self-service *or* admin-driven way to toggle a user's 2FA
enrollment after account creation at all today.

`TASK-207` was implemented against reality rather than the design's
assumption: `account_security_change` currently fires only on a completed
password-recovery confirm (`handle_recover_confirm`, the one real
password-change site that does exist). It does not — and cannot yet —
fire for a 2FA toggle, because that event doesn't exist. This is recorded
honestly in `TASK-207`'s own notes rather than the trigger being
silently left half-implemented with no explanation, or this task's actual
missing-feature scope being quietly folded into `TASK-207` itself (a
self-service 2FA toggle is a real design decision — wire shape, whether
it requires re-authentication, whether it's exposed via `USER_MODIFY` or a
new dedicated message pair — not a one-line addition to a notification
task).

## Work

- Decide the actual mechanism: repurpose `USER_MODIFY` (already-reserved
  opcodes, would need its own payload spec — currently has none) versus a
  new dedicated `2FA_ENABLE`/`2FA_DISABLE`-style message pair. Recommend
  the latter unless a real reason favors overloading `USER_MODIFY`, since
  this is a security-sensitive, single-purpose action, not a general
  field-patch operation.
- Decide whether toggling 2FA requires re-entering the current password
  (recommended — same bar a real password change should have) versus
  being allowed on session-token authority alone.
- Once designed, file the PRT.04 (protocol spec) and SRV.01 (server
  handler) follow-up tasks, and connect `TASK-207`'s
  `vw_notify_account_security_change` call to the new handler — the
  notification-dispatch side already exists and needs no further change,
  only a real caller.

## Acceptance criteria

- A user can enable and disable their own 2FA enrollment without admin
  intervention, through some real, specified wire mechanism.
- `account_security_change` fires on both directions of that toggle.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-08-26]: Filed per CLAUDE.md routing rule 4 (out-of-domain
discovery — building a whole new self-service 2FA toggle mechanism is a
design decision, ARCH.00's call, not something to invent unilaterally
while implementing `TASK-207`'s notification dispatch).

ARCH.00 [2026-08-27]: **Design decision.** Corrected this task's own
`review_by` on the way in — tagged `security-sensitive` but listed only
`CQR.08`, the same routing-rule-1 gap `TASK-222` also had; added
`SEC.07`.

- **Mechanism**: single dedicated `ACCOUNT_2FA_SET` message (plus a
  read-only `ACCOUNT_2FA_GET` added during implementation — see below),
  not this task's own literally-suggested two separate `2FA_ENABLE`/
  `2FA_DISABLE` opcodes. Both directions need identical re-auth handling
  and payload shape, differing only in one stored bit, so one
  parameterized message avoids duplicating that near-identical shape
  twice — while still avoiding the rejected alternative (reviving the
  reserved `USER_MODIFY` as a generic field-patch message) for the exact
  reason this task itself gave.
- **Re-authentication: yes**, per this task's own recommendation — every
  `ACCOUNT_2FA_SET` call re-proves the current password
  (`password_token`, same shape/derivation as `AUTH_REQUEST`'s
  `auth_token`), verified server-side via the same
  `vw_crypto_argon2id_verify` primitive `AUTH_REQUEST` itself uses.
- **New precondition found during design, not anticipated by this
  task's own text**: 2FA here is delivered by emailing a one-time code
  (the pre-existing `AUTH_CHALLENGE`/`AUTH_OTP` flow) — enabling it for
  an account with no email on file (only reachable at all since
  `TASK-222` shipped the same day) would lock that account out of every
  future login the moment it tried to send a code nowhere. `ACCOUNT_2FA_
  SET` with `enable=1` on an empty `rec.email` is rejected with
  `VW_ERR_INVALID_ARG` rather than silently creating an unrecoverable
  account.

Full implementation, done directly (see `TASK-222`/`223`'s same
reasoning for why): protocol (`docs/PROTOCOL.md` §7.15, revision 28,
`ACCOUNT_2FA_GET`/`_GET_RESP` `0x0B07`/`0x0B08` and `ACCOUNT_2FA_SET`/
`_SET_ACK` `0x0B05`/`0x0B06`), server handler
(`handle_account_2fa_get`/`_set`, `vw_file_handlers.c` — storage reuses
the existing `otp_enabled` field via `vw_store_user_update_field`,
already an explicitly-supported use per that function's own doc
comment, no new store-layer setter needed unlike email's uniqueness-
index complication), client core
(`vw_client_account_2fa_get`/`_set`), daemon IPC (`0x804B`-`0x804E`),
CLI (`account 2fa` / `account 2fa on|off <password>`), GUI Settings
view ("Two-factor login" section, below "Account email"), and web
gateway/frontend (`/api/account/2fa`, `/api/account/2fa/set`) — all
wired end to end, unlike `TASK-223` where GUI/web were left as a
disclosed optional follow-up; here they shipped in the same pass since
the acceptance criteria's own UX (a real user actually flipping this
switch) benefits concretely from every surface having it, and the
underlying plumbing was already being built out anyway.

Connected the promised `vw_notify_account_security_change` call: fires
with `"two-factor authentication was enabled"` / `"...disabled"` after
a successful toggle, closing the gap `TASK-207` explicitly left open in
its own notes.

**Two real bugs found and fixed via testing, not just code review** (the
kind of thing this project's own review discipline exists to catch):
1. The web gateway originally read the request's `"enable"` field via
   `get_json_uint_field` (numeric-only) — a real browser sends a JSON
   *boolean* (`true`/`false`), which that reader rejects outright. Every
   real call from the actual frontend would have failed with a generic
   400. Fixed to read it as `VW_JSON_BOOL` via `vw_json_object_get`
   directly, matching `handle_login`'s own `"remember"` field precedent
   exactly (a pattern that already existed in this file and should have
   been followed the first time).
2. `VW_ERR_AUTH_BAD_CREDS` (wrong current password) fell through
   `send_file_op_error`'s `default` case, which **evicts the caller's
   entire web session** and returns a generic 500 — a wrong password on
   this one specific security-sensitive re-auth check is an entirely
   ordinary outcome, not a sign the session/cookie itself is broken;
   evicting over it would force a full re-login for a simple typo. Added
   an explicit `case VW_ERR_AUTH_BAD_CREDS:` returning a clean 401
   without eviction.
3. **The deepest one, found only because a regression test was written
   for bugs 1-2 and caught something else entirely**: both new
   client-core functions (`vw_client_account_2fa_get`/`_set`) sized
   their `recv_expect` receive buffers to exactly their own 5-byte
   success-ACK shape. `recv_expect`'s `VW_MSG_ERROR` fallback
   (`vw_proto_encode_error`) always carries at least
   `error_code(u32) + msg_len(u16)` = 6 bytes, even for a message-less
   error — one byte more than the 5-byte buffer. `vw_proto_recv`'s own
   too-small-buffer handling (`payload_len > buf_size`) doesn't truncate
   in that case, it discards the real error and reports
   `VW_ERR_PROTO_TOO_LARGE` instead — so every rejection this feature is
   supposed to produce (wrong password, no email on file) was silently
   replaced with an unrelated, confusing "message too large" code,
   surfacing to the gateway as a generic 500 instead of the correct
   400/401. Root-caused by writing a raw-wire debug harness (mirroring
   `test_cluster.py`'s own `_vw_send`/`_vw_recv` pattern) to isolate the
   client-core layer from the gateway's HTTP layer, confirming the
   *server* returned the correct `error_code=3` while the *client-core*
   function reported something else entirely — narrowing it to
   `recv_expect`'s buffer-size handling specifically. Both buffers
   bumped to 64 bytes with a comment explaining exactly why 5 was wrong,
   so this class of mistake doesn't get copy-pasted into the next
   small-ACK message this codebase adds.

**Tests**: `tests/integration/test_cli_account_2fa.py` (new) — CLI/
daemon/server round trip: no-email rejection, wrong-password rejection
(both directions), correct-password success, per-account scoping.
`tests/integration/test_gateway.py` — new
`test_account_2fa_requires_email_and_correct_password`, which is the
actual regression test for all three bugs above (asserts the specific
HTTP status codes, not just "some 4xx," and asserts the session
survives a rejected attempt rather than being evicted).
`tests/integration/test_notify_alerts.py` — new
`test_user_category_account_security_change_via_2fa_toggle`, closing
the real-trigger coverage gap that file's own docstring disclosed back
when `TASK-213` shipped (2FA toggle turned out to be a much simpler real
trigger to drive from the CLI than the password-recovery flow that
docstring originally deferred).

Verified on both toolchains: WSL/GCC (`build-gw-e2e`) and MSVC
(`build-msvc-105`) build clean, including GUI and gateway. `ctest`
20/20. Full regression sweep: `test_gateway.py` (37/37),
`test_cli_account_2fa.py` (2/2), `test_notify_alerts.py` (10/10) — 49/49
passing. TypeScript frontend (`npm run build`) compiles clean.

SEC.07 [2026-08-27]: Reviewed the security-sensitive surface —
`handle_account_2fa_set`'s re-auth check, ordering, and the three bugs
this task's own notes disclose — line by line, not just the notes above.

- Verified the check order in `handle_account_2fa_set`: password
  verification happens strictly before the "enabling with no email"
  check. This matters — a caller who doesn't know the account's real
  password gets `VW_ERR_AUTH_BAD_CREDS` regardless of whether that
  account has an email on file, so this endpoint cannot be used to probe
  "does this account have an email set" without already knowing its
  password. No enumeration surface here, unlike `TASK-222`'s disclosed
  (accepted) finding on `ACCOUNT_EMAIL_SET`.
- Confirmed `vw_notify_account_security_change` fires only after
  `vw_store_user_update_field` returns `VW_OK` — a failed store write
  never produces a "your security setting changed" email for a change
  that didn't actually happen.
- Confirmed the three disclosed bugs are real by re-deriving each
  independently rather than trusting the note: read `send_file_op_error`
  to confirm `VW_ERR_AUTH_BAD_CREDS` truly fell to the evicting `default`
  case before the fix; read `vw_proto_encode_error`/`vw_proto_recv` to
  confirm a message-less `VW_MSG_ERROR` is genuinely `>= 6` bytes and
  that a smaller caller buffer genuinely produces
  `VW_ERR_PROTO_TOO_LARGE` rather than a truncation of the real error;
  confirmed `handle_login`'s `"remember"` field really does use
  `VW_JSON_BOOL` via `vw_json_object_get`, the precedent bug 1's fix now
  correctly follows.
- Checked whether the incoming wire payload's `password_token` bytes
  are zeroed server-side after use in `handle_account_2fa_set` — they
  are not, but confirmed this matches this codebase's own existing
  posture for `AUTH_REQUEST`'s `auth_token` field (no server-side
  payload-zeroing convention exists there either) — not a new gap this
  task introduces, and not this task's place to unilaterally start a
  wider convention change.

**Finding, `advisory`, not `blocking`**: `ACCOUNT_2FA_SET`'s re-auth
check has no dedicated rate limiting or lockout of its own — unlike
`AUTH_REQUEST`, which tracks failures via `vw_auth_ctx_t`'s lockout map.
An attacker who has already stolen a valid session token could attempt
unlimited password guesses against this one endpoint. Not fixed here:
(1) the blast radius is bounded by the same trust bar as every other
session-scoped self-service endpoint in this milestone — reaching it
at all already requires a live, valid, non-scoped session, not
anonymous access; (2) each attempt still costs a full Argon2id
verification, which is deliberately expensive specifically to blunt
brute-force at scale, independent of any counter; (3) wiring in the
existing lockout map would require threading `vw_auth_ctx_t` into
`vw_file_handlers.c`'s dispatcher, which today only receives
`vw_store_t`/`vw_share_store_t`/etc. — a broader plumbing change than
this task's own scope, and better done once (if ever needed) alongside
any other self-service re-auth endpoint that might want the same
protection, not as a one-off wired through just for this message.
Recording this explicitly rather than leaving the gap unremarked.

CQR.08 [2026-08-27]: Reviewed the non-security-sensitive surface. The
`_by_id`-style client-core refactor pattern from `TASK-223` was not
needed here (no path-based/`_by_id` split for 2FA), and the new code
correctly avoided inventing one. `vw_store_user_update_field`'s use for
`otp_enabled` matches its own doc comment's explicitly-listed intended
use — no misuse of a function whose doc comment (correctly, per
`TASK-222`'s own edit) forbids it for email specifically. The CLI's
bare `account 2fa` (status) vs. `account 2fa on|off <password>` (change)
split mirrors `account email`'s existing get/set split exactly, keeping
the three self-service `account` sub-verbs consistent with each other.
GUI settings section correctly clears the password input field after
every submit attempt (success or failure) — verified by reading the
code, not assumed. No `blocking` findings. `status: done` approved.

ARCH.00 [2026-08-27]: Closing. Both acceptance criteria met (self-service
toggle works through a real wire mechanism; `account_security_change`
fires on both directions, proven by a real integration test rather than
asserted). SEC.07's rate-limiting note is recorded as `advisory` with
clear reasoning, not silently dropped. The three bugs found and fixed
during this task's own testing are exactly the outcome this project's
"verify with real tests, not just code review" discipline is meant to
produce — worth noting for future sessions: a fixed-size ACK receive
buffer must always be sized against `vw_proto_encode_error`'s minimum
6-byte shape, not just the success payload it was written for.
