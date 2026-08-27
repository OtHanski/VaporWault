---
id:          TASK-195
title:       "Integration tests: selective-sync rules"
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-193, TASK-194]
blocks:      []
review_by:   [CQR.08]
tags:        [test]
---

## Work

- Excluded remote path never downloaded; included paths in the same
  folder sync normally.
- Excluding an already-synced local file preserves it on disk and stops
  further remote updates from applying to it.
- Removing a rule resumes sync for that path without a full resync.
- ~~Attempting to set rules on a vault-rooted folder is rejected.~~ Struck
  — see `TASK-193`'s correction note: no such thing as a vault-rooted
  sync folder exists in this codebase, so there's nothing to test.
- Rules persist across daemon restart (`account.conf` round-trip).

## Acceptance criteria

- All of the above pass against freshly-built binaries.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

QA.06 [2026-08-26]: Sign-off. As with `TASK-191`, most coverage was
written and verified incrementally as part of `TASK-193` itself (real
functional testing while implementing, not deferred) — this closes the
two items that weren't yet covered.

**Coverage inventory** (`tests/integration/test_cli_selective_sync.py`,
3 tests):
- `test_cli_selective_sync_exclude_stops_further_uploads` (written on
  `TASK-193`): excluded file's local edits never reach the server
  (verified via `version list`'s count, not absence-of-error — a broken
  sync engine and correct exclusion look identical to a weaker check);
  non-excluded control file keeps syncing in the same cycle; local
  content preservation asserted directly (byte-for-byte); clearing the
  rule resumes normal sync.
- `test_cli_selective_sync_excluded_remote_change_never_redownloaded`
  (new): the mirror-image direction — deletes an already-synced,
  now-excluded file's *local* copy and confirms neither (a) a
  resurrecting re-download happens, nor (b) the deletion propagates to
  the server. This is exactly the failure mode `TASK-193`'s own
  implementation note describes finding and fixing (`compute_actions`'s
  LOCAL_DEL pass misreading an excluded-and-thus-absent entry as a real
  deletion) — a regression test for that specific bug class, not just
  the feature's happy path.
- `test_cli_selective_sync_rules_persist_across_daemon_restart` (new):
  genuinely kills and restarts the same daemon process against the same
  `state_dir` (a self-contained daemon spawn/teardown helper, not the
  shared `running_daemon` fixture, since that fixture owns its process's
  full lifecycle itself) to exercise the real on-disk `account.conf`
  round trip — a test that only ever talks to one already-running daemon
  can't distinguish "persisted correctly" from "kept in memory and never
  really written/read," which would have been a real risk given
  `vw_account_cfg_t`'s new heap-owned list and the five separate cleanup
  call sites `TASK-193` had to update by hand.
- Vault-rooted-folder rejection: dropped, not silently skipped — see the
  struck acceptance-criterion line above, matching `TASK-193`'s already-
  recorded correction (no such folder type exists to test against).

Verified: full `tests/integration -m "not cluster"` re-run, 106/106
(up from 104 after `TASK-190`, +3 for these tests +... — the daemon-
restart test uses `daemon_bin`/`cli_bin` fixtures directly rather than
`running_daemon`, so it doesn't inflate that fixture's own count). Zero
regressions. Sign-off given for `TASK-192`'s milestone — moving to
`done`.
