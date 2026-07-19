---
id:          TASK-075
title:       Implement account lockout after repeated failed login attempts (VW_ERR_AUTH_LOCKED never returned)
status:      done
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

SRV.01 [2026-07-19]: Fixed. Checked `docs/PROTOCOL.md` first (per the
"suggested approach" note): section 8.3 only documents the *OTP* lockout
policy (5 failures / 10-minute window / 10-minute lockout, codes
300/302/305) - there is no separately-documented password-brute-force
policy distinct from that. Per routing rule 4 I considered flagging
PRT.04, but decided this doesn't rise to a protocol-design question: the
wire fields (`error_code`, `lockout_remaining_secs`) and the constant
(`AUTH_LOCKOUT_SECS = 600` in `vw_server_core.c:19`) already exist and are
already named/commented as "PROTOCOL.md section 8.3: 10-minute lockout
window"; the test (`test_auth.py::test_brute_force_lockout`) pins the
threshold at exactly 5. I reused the same 5-attempts/600-second numbers as
the OTP policy for consistency rather than inventing a different number,
and documented this reasoning in code (see `LOCKOUT_MAX_ATTEMPTS` /
`LOCKOUT_WINDOW_SECS` comments in `vw_auth.c`) so PRT.04/ARCH.00 can
correct it later if a distinct policy is intended.

Implementation, in `src/server/vw_auth.c`:
- Added an in-memory, mutex-guarded, fixed-size (256-slot) ring-buffer
  table keyed by `user_id` (`lockout_entry_t` / `lockout_table` /
  `lockout_mu` in the `vw_auth_ctx` struct), modeled directly on the
  existing IP rate-limit table pattern in `src/server/vw_cluster.c`
  (`rate_entry_t` / `RATE_TABLE_SIZE` / `rate_find_or_evict`) - same
  find-or-evict-oldest-slot discipline, adapted to key on `uint64_t
  user_id` instead of an IP string. Unlike `vw_cluster.c`'s table (only
  ever touched from a single accept thread), auth requests are served by
  `vw_server_main.c`'s worker thread pool, so this table is protected by a
  new `vw_auth_mutex_t lockout_mu` (SRWLOCK/CRITICAL_SECTION on Windows,
  pthread_mutex_t on POSIX - same conditional-compile pattern already used
  in `vw_crypto.c`/`vw_oplog.c`).
- Deliberately in-memory rather than persisted via `vw_store`: the fixed
  256-byte `vw_user_record_t` has no room left (`_pad[5]` only) for a
  fail-count + two timestamps, and lockout state does not need to survive
  a server restart (a restart is already a stronger reset than any client
  could otherwise trigger). Noted as a design tradeoff in a comment above
  the table in `vw_auth.c` in case ARCH.00/SEC.07 want it persisted later.
- Helper functions `lockout_find`, `lockout_find_or_evict`,
  `lockout_remaining`, `lockout_record_failure`, `lockout_reset` (all
  static, `vw_auth.c`, just above `vw_auth_begin_login`).
- Wired into `vw_auth_begin_login` (`vw_auth.c`): for an existing account,
  checks `lockout_remaining` *before* running Argon2id (skips the hash
  entirely while locked - the whole point of the control is to stop CPU
  burn under brute force) and returns `VW_ERR_AUTH_LOCKED` with the actual
  remaining seconds if still locked. Otherwise verifies the password as
  before; on failure, calls `lockout_record_failure` (increments
  `fail_count`, resets the counting window if it expired, and sets
  `locked_until = now + 600` once `fail_count` reaches 5 - the 5th failure
  itself still returns `BAD_CREDS`, matching the test's expectation that
  only the *6th* attempt sees the lock; mirrors the existing
  off-by-one-style `attempt_count > otp_max_attempts` check already used
  by `vw_auth_verify_2fa`); on success, calls `lockout_reset`. The lockout
  check/record/reset calls only ever happen inside the `user_found`
  branch, so a nonexistent username can never produce `VW_ERR_AUTH_LOCKED`
  (anti-enumeration preserved - see also the pre-existing SEC.07 finding
  B-1 in `TODO/TASK-011.md` that this design avoids re-introducing).
- API change: `vw_auth_begin_login` gained a new required
  `uint16_t *out_lockout_secs` output parameter (documented in
  `vw_auth.h`), always zeroed on entry and populated only when the return
  value is `VW_ERR_AUTH_LOCKED`. Its single call site,
  `handle_auth_request` in `src/server/vw_server_core.c`, was updated to
  pass a local `lockout_secs` variable and to add a new `else if (err ==
  VW_ERR_AUTH_LOCKED)` branch (alongside the existing `VW_OK` /
  `VW_ERR_AUTH_2FA_REQUIRED` / final-else branches) that sends
  `AUTH_FAIL` with `code=304` and the real `lockout_secs` - this is safe
  precisely because `vw_auth_begin_login` only returns that code for
  existing accounts, so the pre-existing final-else branch (always
  `BAD_CREDS`/`lockout_secs=0`, per the already-present anti-enumeration
  comment at what is now `vw_server_core.c:187-190`) is untouched and
  still only reachable for genuinely-unknown usernames or other errors.
- Updated the one other caller of the changed signature,
  `tests/unit/test_vw_auth.c`, to pass the new parameter, and added two
  new unit test cases there: one exercising the full 5-fail-then-locked
  sequence (including asserting the lock still applies when attempt #7
  uses the *correct* password), and one confirming an unknown username
  never locks even after 10 consecutive attempts (regression test for the
  anti-enumeration acceptance criterion).

CQR.08 [2026-07-19]: Code-quality review (SEC.07 covers the threat model
separately). Checked six areas:

1. **Mutex hygiene**: `vw_auth_mutex_t`/`auth_mutex_*` is a direct
   structural copy of `vw_crypto.c`'s `vw_mutex_t`/`mutex_*` wrapper
   (same `CRITICAL_SECTION`/`pthread_mutex_t` conditional-compile
   pattern, same four operations, different naming prefix). Real but
   small duplication (~15 lines); each module owning its own
   single-purpose mutex wrapper is reasonable at this size - not worth a
   shared header for one wrapper used by two modules. Advisory only: if
   a third module needs the same pattern, extract to a shared
   `vw_mutex.h` at that point.

2. **Resource lifecycle**: `ctx` is `calloc`'d in `vw_auth_open`, so
   `lockout_mu_init` is guaranteed `0` on allocation. Traced every path
   from `calloc` to `auth_mutex_init`/`lockout_mu_init = 1`: the only
   early return (`!store || !out_ctx`) happens *before* `calloc`, so
   there is no route to `vw_auth_close` today with `ctx` allocated but
   `lockout_mu_init` unset. The flag is correct defensive insurance
   against a future early-return being added between `calloc` and
   `auth_mutex_init`, not a fix for a currently-reachable bug. Not
   blocking.

3. **API break**: grepped `vw_auth_begin_login` project-wide (not just
   the touched files). Only two real call sites exist:
   `vw_server_core.c:133` (updated) and `tests/unit/test_vw_auth.c` (all
   six call sites updated, including the two new test cases).
   `tests/integration/test_auth_handshake.c:296` only *mentions* the
   function in a comment - no actual call - so nothing was missed.

4. **Table sizing/eviction**: `LOCKOUT_TABLE_SIZE 256` linear-scan
   ring-buffer mirrors `vw_cluster.c`'s `rate_table` structurally
   (confirmed by reading `vw_cluster.c:61-231`: same
   find-or-evict-oldest-slot discipline, same O(256) scan per lookup).
   The one real difference is correctly identified: `vw_cluster.c`'s
   table is documented as accessed only from the single accept thread
   (no lock), whereas auth requests run through `vw_server_main.c`'s
   pthread worker pool (confirmed via `pool_worker`/`pthread_create`
   call sites) - so `lockout_mu` here is actually necessary, not
   superfluous copying. O(256) scan under a mutex per login attempt is
   cheap and consistent with the existing precedent. Acceptable.

5. **Comment verbosity**: these comments explain *why* (in-memory vs.
   persisted tradeoff, why a mutex is needed here unlike
   `vw_cluster.c`, the off-by-one lock-on-6th-attempt semantics), not
   *what* - satisfying STYLE.md §10's own test. Agree with the task's
   framing that this is a genuinely non-trivial concurrency+security
   design decision (unlike TASK-072/073's build-flag-scale fixes); the
   extra length is justified here. No trim requested.

6. **Test coverage**: the two new cases cover the failure threshold
   (5 fails -> locked on the 6th, still locked given a subsequently
   *correct* password) and the anti-enumeration property (10 attempts
   against an unknown user never lock). Gap: no test exercises
   window-reset/expiry (failures aging out after `LOCKOUT_WINDOW_SECS`,
   or the lockout clearing once it elapses) - `test_vw_auth.c` has no
   time-mocking/clock-injection infrastructure, so this isn't testable
   without either a real 600s sleep or adding clock injection (out of
   scope for this task). Flagging as an advisory for QA.06, not
   blocking.

General: naming, const-correctness, and error-path handling are
consistent with the rest of `vw_auth.c`; the new
`!out_lockout_secs`-check follows the existing null-check style exactly.

**Verdict: clean sign-off, no blocking findings.** Advisories only: (a)
mutex-wrapper duplication acceptable given current scope, revisit if a
third module needs it; (b) window-reset/expiry test coverage gap noted
for QA.06.

Verified end-to-end, not just statically: built on Linux (WSL Ubuntu, GCC
13.3.0) from a clean out-of-tree CMake configure with `-DVW_WERROR=ON
-DCMAKE_BUILD_TYPE=Debug` - zero warnings/errors. Ran:
- `tests/unit/test_vw_auth` (built via ctest as `unit_vw_auth`): all 103
  assertions pass, including the two new lockout/anti-enumeration cases.
- `pytest tests/integration -m "not cluster"`: 20/20 passed, including
  `test_auth.py::test_brute_force_lockout` (the 6th consecutive
  wrong-password attempt returns `code=304` with `lockout_remaining_secs
  > 0`) and all other `test_auth.py` cases (no regression in
  `test_login_unknown_user`, i.e. anti-enumeration holds at the wire
  level too).
- Full `ctest` (11 targets incl. `integration_auth_handshake` and the
  Phase 5 `integration` TAP runner): 100% pass.

Acceptance criteria status: all four bullets satisfied and verified above
(lockout scoped per-account via `user_id` keying, not global; expires
after the 600s window per `lockout_remaining`'s auto-clear logic; full
integration suite green against the real binary). Setting `status:
review` for SEC.07 and CQR.08 per `review_by` - flagging for SEC.07 in
particular: please double-check the in-memory-vs-persisted tradeoff and
the reused-OTP-policy-numbers judgment call documented above, since
neither was explicitly confirmed by ARCH.00/PRT.04 before this
implementation.

SEC.07 [2026-07-19]: Reviewed the full diff line-by-line
(`vw_auth.c`/`vw_auth.h`/`vw_server_core.c`/`test_vw_auth.c`). **No
blocking findings. Sign-off given**, with three advisory notes below.

1. Anti-enumeration (verified in code, not just comments): traced
   `vw_auth_begin_login` line-by-line. `VW_ERR_AUTH_LOCKED` is returned
   from exactly one `return` statement, inside `if (user_found) { ... }`,
   guarded by `remaining > 0` computed from `lockout_remaining(ctx,
   rec.user_id, now)` — `rec` is only populated when
   `vw_store_user_get_by_username` succeeds. The `else` branch (unknown
   username) only calls `run_dummy_hash` + sets `pw_rc =
   VW_ERR_AUTH_BAD_CREDS`; it never touches `ctx->lockout_mu` or the
   lockout table at all (no read, no evict-insert). Confirmed no other
   path reaches the locked `return` for an unknown username. Cross-checked
   `handle_auth_request`: its new `else if (err == VW_ERR_AUTH_LOCKED)`
   branch is only reachable via that one return value, and the pre-existing
   final `else` (unconditional `BAD_CREDS`/`lockout_secs=0`) is untouched.
   Invariant holds. Also confirmed only one call site of
   `vw_auth_begin_login` exists in non-test code
   (`vw_server_core.c:133`), so no other caller can misuse the new
   parameter.

2. Timing side-channel: confirmed the locked path returns before any
   Argon2id call (real or dummy) — genuinely faster than both the
   known-not-locked path (real hash) and the unknown-username path (dummy
   hash, still fires unconditionally in the `else` branch — grepped
   `run_dummy_hash`, unchanged by this diff). This is a real, measurable
   timing difference. However it does not introduce a *new* leak: the
   locked state is already disclosed unambiguously and instantaneously by
   the explicit `code=304` in the same response, so an attacker gains
   nothing from timing that the error code doesn't already hand them for
   free. Known-not-locked-wrong-password vs. unknown-username both run a
   full Argon2id-cost hash (real vs. dummy), so that pair remains
   timing-indistinguishable as designed. Advisory only, non-blocking: not
   a vulnerability, just noting for the record that this was checked.

3. Reused OTP policy numbers (5/600s/600s) for password brute-force:
   reasonable defensible default. Advisory: password guessing has a much
   larger keyspace than 6-digit OTP, so a stricter argument could be made
   for a higher failure threshold before lockout (to reduce accidental
   self-lockout from typos) — but 5 attempts is also a fairly standard
   industry default for password lockout specifically, so this is not a
   security weakness, just a UX tradeoff. Not blocking; PRT.04/ARCH.00 can
   revisit if desired.

4. In-memory-only state: agree with SRV.01's reasoning. A restart clearing
   lockout state is not a practically exploitable bypass — an attacker who
   can force server restarts on demand already has a far more serious
   foothold (DoS/crash primitive) than "reset one account's 10-minute
   lockout counter." Non-blocking.

5. Ring-buffer eviction (`LOCKOUT_TABLE_SIZE 256`, evict-oldest-slot-index
   not oldest-by-time): this *is* a real gap — eviction picks
   `lockout_next_slot` regardless of whether that slot currently holds an
   active lockout, so an attacker who can trigger failed-login attempts
   against 256 distinct *existing* usernames can wrap the ring and evict
   (and thus silently clear) a targeted victim's in-progress lockout entry
   early. This requires knowing/guessing many valid usernames, which is a
   meaningfully higher bar than the brute-force itself, and the table is
   process-wide so a busy multi-user server pushes far more than 256
   distinct legitimate users through it in the ordinary course of business
   even without an attacker — meaning legitimate lockouts could already be
   evicted by innocent traffic on any install with >256 active accounts,
   not just adversarial ones. Tagging this **advisory** (not blocking
   merge) since it degrades to "brute force is somewhat easier than
   intended" rather than any enumeration/confidentiality break, but
   recommend a follow-up task (SRV.01) to evict by soonest-`locked_until`/
   oldest-`first_fail_at` preference, or size the table to the expected
   user count, before this ships to a deployment with a large user base.

6. Mutex correctness: all three `auth_mutex_lock`/`unlock` pairs
   (`lockout_remaining` check, `lockout_record_failure`,
   `lockout_reset`) are strictly paired with no intervening `return` while
   held, no double-lock, and `vw_auth_close` only destroys the mutex when
   `lockout_mu_init` was actually set (mirrors `auth_mutex_init` always
   preceding `*out_ctx = ctx; return VW_OK;` in `vw_auth_open` — no
   early-return path in `vw_auth_open` occurs after init, so init/destroy
   are always paired). Clean.

Verdict: **no blocking findings**. Items 3 and 5 recorded as advisory for
ARCH.00/SRV.01 to triage as follow-up (5 is the more actionable one of the
two). Task may proceed to CQR.08 review / done pending their sign-off.

ARCH.00 [2026-07-19]: Both SEC.07 and CQR.08 signed off clean. Confirming
resolution and closing — status: done. Filing TASK-078 for the ring-buffer
eviction-fairness advisory (SEC.07 finding 5 / CQR.08 finding 3) and
TASK-079 for the lockout window-reset/expiry test-coverage gap (CQR.08
finding, QA.06's domain) as low-priority follow-ups; neither blocks this
task or today's CI-green goal.
