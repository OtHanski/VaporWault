---
id:          TASK-097
title:       Integration tests for sharing (grants, links, permission enforcement, quota)
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-07-29
priority:    high
depends_on:  [TASK-094, TASK-095]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [testing, security-sensitive]
---

Write regression tests for the sharing feature (`TASK-088`,
`docs/PROTOCOL.md` §7.5/§7.10). This is a security-sensitive feature per
routing rule 1, and every SEC.07 finding resolved against `TASK-094`/
`TASK-095` needs a corresponding regression test per the standing QA.06
responsibility in `CLAUDE.md`.

Scope (minimum, expand based on SEC.07 findings from TASK-094/095):

- User-to-user grant: create, use (read + edit), revoke, confirm access is
  denied post-revoke.
- Public link: create, redeem anonymously (no account), use within
  permission bounds, confirm denied outside bounds (e.g. a read-only link
  attempting a write), revoke, confirm an *already-issued* scoped session
  loses access on its next request after revocation (not just new
  redemptions) — this is the specific "live revocation" property flagged in
  `TASK-088`'s design notes as easy to get wrong.
- Quota: confirm uploads through an EDIT grant or a public edit link debit
  the file owner's quota, not the acting user's.
- Cross-user isolation: confirm a user cannot access another user's file
  through any path (direct, forged share_id, wrong link_token) without an
  active grant/link.
- Rate limiting: confirm repeated invalid `LINK_ACCESS` attempts from one
  source trigger the same silent-drop behavior as `NODE_HELLO`.
- **Scoped-session privilege escalation (SEC.07 finding, added
  2026-07-29)**: confirm an anonymous scoped session (from `LINK_ACCESS`)
  is rejected with `VW_ERR_PERMISSION` when attempting `SHARE_GRANT`,
  `SHARE_REVOKE`, `LINK_CREATE`, or `LINK_REVOKE` — this is the regression
  test for the "leaked link mints an independent, revocation-surviving
  grant" gap.
- **Write-count rate limiting (SEC.07 finding, added 2026-07-29)**: confirm
  a scoped session is blocked after exceeding the configured write-count
  threshold, independent of remaining byte quota (e.g. many near-zero-byte
  `FILE_COMMIT`s in rapid succession).
- **FILE_MOVE ownership/cycle rules (SEC.07 finding, added 2026-07-29)**:
  confirm moving a shared file into a folder owned by someone other than
  the file's actual owner fails, and confirm moving a directory into its
  own descendant fails.

## Acceptance criteria

- All scenarios above pass.
- Sign-off note added to `TASK-094`/`TASK-095` before ARCH.00 closes the
  sharing milestone.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-088`.

QA.06 [2026-07-31]: Corrected `review_by` to `[SEC.07, CQR.08]` — this task
is tagged `security-sensitive` but was filed with only `CQR.08` listed,
violating `CLAUDE.md` routing rule 1 (both are required together). Fixing
the oversight while closing the task out rather than leaving it for a
future pass.

Reviewed `tests/integration/test_sharing.py` (the existing TASK-094
suite, 12 tests) against this task's scenario checklist and found five
concrete gaps; added five new tests rather than rewriting what already
passed:

1. `test_public_link_edit_quota_charges_owner` — the existing quota test
   only covered a named user-to-user EDIT grant; the public-EDIT-link path
   through the same quota-resolution code (scope_share_id vs. a real
   user_id grant lookup) was untested.
2. `test_no_grant_or_link_means_no_access` — baseline cross-user isolation
   (a stranger with *zero* relationship to a file) was never actually
   exercised; every existing test involved some grant/link, if only to
   prove restriction *within* it. Confirms `VW_ERR_NOT_FOUND` (not
   `VW_ERR_PERMISSION`) per `require_permission`'s existence-hiding
   convention.
3. Extended `test_scoped_session_cannot_grant_or_create_link` to also
   attempt `SHARE_REVOKE`/`LINK_REVOKE` from a scoped session against a
   real share/link the owner created — the existing test only covered
   `SHARE_GRANT`/`LINK_CREATE`, leaving half the checklist's named message
   list untested.
4. `test_scoped_session_write_count_rate_limited` — the write-count limiter
   (`SHARE_WRITE_MAX_PER_WINDOW=30`) had unit coverage
   (`test_vw_share.c`) but no integration-level confirmation that a real
   wire-level `FILE_COMMIT` sequence through a public EDIT link actually
   gets `VW_ERR_RATE_LIMITED` on the 31st call. Uses zero-chunk commits so
   it's fast and isolated from quota entirely. Rate-limiter state here is
   keyed by the scoped session's own token (freshly random per test), so
   this test has no cross-test pollution risk.
5. `test_link_access_repeated_failures_trigger_silent_drop` — same gap for
   the `LINK_ACCESS` IP-based limiter (`LINK_ACCESS_MAX_FAILURES=5`). This
   one *is* a cross-test pollution risk since it's keyed by source IP and
   every test in this file shares one IP against one server instance —
   placed deliberately as the last test in the file (with a comment
   explaining why) so a successful trip doesn't poison any test that runs
   after it. Confirmed the module's `server` fixture is module-scoped (one
   server subprocess per test *file*), so this can't bleed into other
   integration test files.

Not added, and explicitly out of scope for this pass:
`FILE_MOVE`'s cross-owner-destination and directory-cycle rules — both
need a real directory to exist server-side as the move destination, and
there is still no wire message that creates one (`TASK-104`, filed
2026-07-30, still `todo`). `test_sharing.py`'s own module docstring already
disclosed this gap when `TASK-094` was written; the cycle-detection logic
itself is exercised at the unit level only (per `vw_file_handlers.c`'s
`bfs_subtree_has_chunk`-shaped ancestor walk, same pattern
`handle_file_list` already uses, per that function's own review note).
Revisit once `TASK-104` lands — do not consider this task's FILE_MOVE
coverage complete until then.

Validation: full extended `test_sharing.py` (16 tests, up from 12) run
three consecutive times with no flakes (GCC/WSL, real server). Full pytest
integration suite (37 tests across all six files) passes with no
regressions.

SEC.07 [2026-07-31]: Reviewed the five new tests against the SEC.07
findings they claim to regress-test. Confirmed each asserts the specific
error code the finding's fix produces (`VW_ERR_NOT_FOUND` for isolation,
`VW_ERR_RATE_LIMITED` for both rate limiters), not just "raises some
error" — a test that only checks "an exception occurred" would silently
stop catching a regression to the *wrong* error code (e.g. a future change
that returns `VW_ERR_PERMISSION` instead of `VW_ERR_NOT_FOUND` for the
isolation case, quietly reintroducing an enumeration leak). Confirmed the
`LINK_ACCESS` rate-limit test's broad `except Exception` is deliberate and
justified (documented in the test itself) given the silently-dropped
connection can surface as different transport-level exception types across
platforms/OpenSSL versions — the alternative (asserting one specific
exception class) would itself be a source of environment-dependent
flakiness. No blocking findings.

CQR.08 [2026-07-31]: Reviewed for consistency with this file's established
conventions (per-test user isolation, try/finally connection cleanup, the
small-worker-pool sequential-connection pattern for tests needing more than
two simultaneous connections). All five new tests follow them. The
cross-test-pollution risk in the `LINK_ACCESS` rate-limit test is unusual
for this file but well-contained and clearly documented — the "must remain
last" constraint is stated both in a section comment above the test and in
the test's own docstring, so a future contributor adding a test below it
(easy mistake, since Python doesn't enforce file-position dependencies) has
two chances to notice. No blocking findings.

ARCH.00 [2026-07-31]: SEC.07 and CQR.08 sign-off received, no blocking
findings. Closing as done. `TASK-088`'s sharing milestone
(`TASK-094`/`TASK-095`/`TASK-097`) is now fully closed; `TASK-096` (GUI)
remains open, and `TASK-104`/`TASK-106` remain as disclosed, filed
follow-up gaps (no wire `mkdir`; sync-engine tree integration for shared
folders).

QA.06 [2026-07-31]: `TASK-104` closed shortly after this task, unblocking
real wire-created folders. Added four tests this file couldn't have had
before: two folder-sharing scenarios
(`test_folder_share_view_grant_blocks_creating_children`/
`test_folder_share_edit_grant_allows_creating_children`) and — closing the
FILE_MOVE gap this task's own checklist flagged as untestable — the
cross-owner-destination and directory-cycle scenarios
(`test_file_move_rejects_destination_owned_by_someone_else`/
`test_file_move_directory_into_own_descendant_rejected`). This task's
FILE_MOVE coverage is now complete.
