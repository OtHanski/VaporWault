---
id:          TASK-075
title:       Implement account lockout after repeated failed login attempts (VW_ERR_AUTH_LOCKED never returned)
status:      todo
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-19
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [bug, ci, auth, security-sensitive]
---

Discovered while verifying TASK-073 end-to-end against the full pytest
integration suite (not part of TASK-073's own scope — filed separately per
CLAUDE.md's out-of-domain/out-of-task-scope discovery rule; noted in
TASK-073's notes pending ARCH.00 triage).

## Symptom

`tests/integration/test_auth.py::test_brute_force_lockout` expects that
after 5 failed login attempts, the 6th attempt against an **existing**
account returns `AUTH_FAIL` with `code=304` (`VW_ERR_AUTH_LOCKED`) and a
non-zero `lockout_remaining_secs`. In practice every attempt — including
the 6th — returns `code=300` (`VW_ERR_AUTH_BAD_CREDS`), i.e. no lockout
ever kicks in.

## Root cause (grep-verified, not assumed)

`VW_ERR_AUTH_LOCKED` is a fully-defined wire error code
(`src/core/vw_proto.h:71`: `VW_ERR_AUTH_LOCKED = 304, /* account locked
(too many password attempts) */`) but it is **never returned or even
referenced anywhere in `src/`** — confirmed via a project-wide grep for
`VW_ERR_AUTH_LOCKED`; the only two hits are its definition in
`vw_proto.h:71` and a comment in
`src/server/vw_server_core.c:187-190` inside `handle_auth_request`'s
final `else` branch (the "bad credentials / user not found" path):

```c
/* Always BAD_CREDS with lockout_secs=0 — VW_ERR_AUTH_LOCKED applies only
 * to existing accounts, so a non-zero lockout would confirm username
 * existence. (PROTOCOL.md §7.1) */
(void)send_auth_fail(conn, (uint32_t)VW_ERR_AUTH_BAD_CREDS, 0);
```

That comment describes the *intended* anti-enumeration behavior (don't
leak lockout state for nonexistent usernames) but the actual
attempt-counting/lockout logic it presupposes does not exist anywhere in
the call chain. Traced the full login path,
`handle_auth_request` (`src/server/vw_server_core.c:105-193`) →
`vw_auth_begin_login` (`src/server/vw_auth.c:171-265`): the latter reads
the user record, verifies the password via
`vw_crypto_argon2id_verify`, and returns `VW_ERR_AUTH_BAD_CREDS` on
mismatch (`vw_auth.c:220`) — there is no per-user or per-IP failed-attempt
counter, no timestamp/window tracking, and no persisted or in-memory state
that could ever produce `VW_ERR_AUTH_LOCKED` for a bad-password case. This
is architecturally distinct from the **existing, working** OTP-attempt
lockout: `vw_auth_verify_2fa` (`vw_auth.c:269-295`) does increment
`state->attempt_count` per 2FA-code attempt and returns
`VW_ERR_AUTH_2FA_LOCKED` (305) past `otp_max_attempts` — but that only
guards the 2FA-code-entry step *after* a password has already been
verified correctly, not repeated *password* guessing, which is what
`test_brute_force_lockout` and `AUTH_LOCKOUT_SECS` (`vw_server_core.c:19`,
"PROTOCOL.md §8.3: 10-minute lockout window") are about.

**Conclusion: this is a missing feature, not a regressed/broken one.**
`AUTH_LOCKOUT_SECS` and `VW_ERR_AUTH_LOCKED` exist as forward-declared
plumbing (constant + error code + the anti-enumeration comment explaining
how it should behave once implemented) but the actual failed-attempt
counter and the code path that would return `VW_ERR_AUTH_LOCKED` were
never written.

## Suggested approach (for SRV.01 to confirm/adjust during implementation)

- Track failed password attempts per user account (in `vw_store`, since it
  needs to persist/be visible across connections — an in-memory-only
  counter in `vw_auth_ctx_t` would not survive server restart and
  wouldn't be shared across worker threads without its own
  synchronization; check whether `vw_store`'s existing quota-lock-style
  pattern, `src/server/vw_store.c:1580-1595`, is a reasonable model for
  the locking discipline needed here).
- Check `docs/PROTOCOL.md` §8.3 (referenced by the existing
  `AUTH_LOCKOUT_SECS` comment) for the exact intended threshold/window
  semantics before implementing — the comment already names it, but
  confirm the failure-count threshold (5, per the test) and window/reset
  behavior are specified there, and if not, flag PRT.04 per routing rule
  4 rather than inventing the policy unilaterally.
- Only return `VW_ERR_AUTH_LOCKED` (with non-zero `lockout_secs`) for
  **existing** accounts past the threshold — the existing anti-enumeration
  comment at `vw_server_core.c:187-190` must remain true after this fix:
  a nonexistent username must never produce a distinguishable
  lockout-vs-bad-creds response.
- Reset or age out the counter appropriately (e.g. on a successful login,
  or after the lockout window elapses) — check `docs/PROTOCOL.md` §8.3 for
  the specified reset semantics before inventing one.

## Acceptance criteria

- `test_auth.py::test_brute_force_lockout` passes: the 6th consecutive
  failed login attempt against an existing account returns `AUTH_FAIL`
  with `code=304` and a non-zero `lockout_remaining_secs`.
- A nonexistent username never returns `code=304` regardless of attempt
  count (anti-enumeration property preserved — add/confirm a regression
  test for this alongside the fix, per QA.06's usual SEC.07-finding
  regression-test convention).
- Lockout state is scoped per account (not global) and does not
  permanently lock an account out — confirm reset/expiry behavior matches
  `docs/PROTOCOL.md` §8.3.
- Full pytest integration suite passes locally (or in CI) against the
  real server binary for this test.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-19]: Filing per SRV.01's note in TASK-073 (found while
running the full pytest suite end-to-end; not filed as a task yet pending
triage). Assigning to SRV.01: this is server-side auth/session state
(account lockout tracking, most plausibly in `vw_auth.c`/`vw_server_core.c`
and persisted via `vw_store`), squarely "user account management, session
tokens" per SRV.01's domain in the roster — not a protocol *design*
question (the wire error code and lockout-window constant already exist
and are already correctly specified/named), so this doesn't go to PRT.04.
Verified by grep that `VW_ERR_AUTH_LOCKED` truly has zero live call sites
before filing this, so the bug is confirmed to be "never implemented," not
"implemented but broken" — narrowing scope for SRV.01 to a straight
implementation task rather than a debugging task. Tagged
`security-sensitive` per routing rule 1: this is squarely a brute-force/
account-lockout control, so both SEC.07 and CQR.08 are required in
`review_by` (neither may be omitted). Priority `high` (not `critical`
like TASK-070/072/073): this is a missing hardening control on an
already-otherwise-working auth path, not a fully-red-CI blocker — it is
one isolated test failure, not blocking the rest of the suite.
