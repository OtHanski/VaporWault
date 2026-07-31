---
id:          TASK-110
title:       Fix flaky IT-7 quota-enforcement legacy integration test
status:      todo
assignee:    QA.06
created_by:  CLI.02
created:     2026-07-31
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [testing, flaky]
---

Discovered while verifying TASK-106 (Task #18, FILE_LIST dir_file_id wire
extension): the legacy TAP integration harness (`tests/integration/run_integration.py`,
run via `ctest -R '^integration$'`) fails IT-7 ("quota enforcement — upload
rejected when quota exceeded") consistently, including in complete isolation
and against a clean pre-TASK-106 baseline (commit `7d882f8`). This is a
pre-existing issue, not a regression from TASK-106's changes — confirmed by
stashing all TASK-106 working-tree changes, rebuilding, and reproducing the
identical failure.

IT-7 sets the test user's quota to 1024 bytes (already exceeded by prior
test steps), writes a 64 KiB file, triggers a sync, sleeps 3 seconds, then
checks the daemon's `status` output for a nonzero error count. It
consistently reports `0 uploads, 0 downloads, 0 errors` instead of a
recorded upload error — i.e. either the client daemon isn't attempting the
over-quota upload within the 3s window, isn't surfacing the resulting
server-side rejection as a status error count, or the server isn't
rejecting the upload as expected. All other 14 sub-tests in this harness
pass reliably.

## Acceptance criteria

- Root-caused: determine whether this is a timing issue (3s window too
  short), a daemon status-reporting gap (errors not counted for this
  rejection path), or an actual server/client quota-enforcement gap.
- `tests/integration/test_quota.py` (the pytest-based quota suite, which
  currently passes) may need a comparison read to confirm whether it
  exercises the same code path — if it does and passes, that narrows the
  bug to the daemon's `status` error-counting or this harness's timing
  assumption rather than server-side enforcement itself.
- IT-7 passes reliably (run at least 3x back-to-back with no failures).
- No regression in the other 14 IT-* sub-tests in this harness.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-07-31]: Filed as an out-of-domain discovery per CLAUDE.md §4
while verifying TASK-106. Not blocking TASK-106's closure — this flake
predates TASK-106 and is unrelated to the FILE_LIST/dir_file_id changes
(verified via `git stash` + rebuild + rerun against baseline `7d882f8`,
same failure reproduced identically). Left assigned to QA.06 since this is
squarely test-harness/QA territory, not a sync-engine or protocol concern.
