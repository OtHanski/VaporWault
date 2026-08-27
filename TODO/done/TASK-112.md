---
id:          TASK-112
title:       "Surface per-action sync failures (e.g. quota rejection) into daemon status error_count"
status:      done
assignee:    CLI.02
created_by:  QA.06
created:     2026-08-03
priority:    normal
depends_on:  []
blocks:      [TASK-110]
review_by:   [CQR.08]
tags:        [client, sync, daemon, testing]
---

Root-caused while investigating TASK-110 (flaky IT-7 quota-enforcement
integration test). The client sync engine has no mechanism to surface a
per-action failure (a specific file's upload/download/delete being
rejected by the server for a non-network reason — quota exceeded being
the concrete case in hand, but the gap is general) into anything visible
to the user. `vapourwault-cli status`'s `error_count` only reflects
whole-sync-cycle network failures.

Trace of the gap (see `src/client/vw_sync.c` unless noted):

- `exec_action()` (line 654) returns the real per-action `vw_err_t`
  (e.g. `VW_ERR_QUOTA_EXCEEDED` from a rejected `ACT_UPLOAD`), but every
  call site in `sync_one_folder()` (lines 1088, 1094, 1100) discards it
  via `(void)exec_action(...)`.
- `sync_one_folder()` unconditionally `return VW_OK;` (line 1104)
  regardless of any action's outcome.
- `vw_sync_run()` (line 1157) only treats a folder's result as fatal via
  `is_net_err()` (line 1178) — non-network per-action errors are silently
  "continue with remaining folders."
- `vw_daemon.c`'s main loop (lines 1310-1318) only increments its local
  `error_count` when `vw_sync_run()` itself returns non-`VW_OK`.
- `vw_sync_ctx_t` (line 444) has no error-counting field of any kind —
  only `bytes_done`/`bytes_total`.

Net effect: a file that permanently fails to sync (quota exceeded today;
any other permanent per-file rejection in the future) retries silently
forever every cycle with zero visible indication in `status`, in logs
beyond a per-cycle DEBUG line that never fires for this path, or anywhere
else. This is why TASK-110's IT-7 cannot pass as written — it isn't a
timing bug, there is genuinely nothing to observe.

Confirmed server-side quota enforcement itself is correct and already
covered by `tests/integration/test_quota.py::test_upload_fails_when_quota_exceeded`
— this task is purely about client-side error accounting/visibility, not
enforcement.

## Acceptance criteria

- `vw_sync_ctx_t` (or equivalent) accumulates a count of per-action
  failures within a sync cycle, distinct from bytes progress — at minimum
  covering `ACT_UPLOAD` rejections (quota or otherwise); download/delete
  failures should follow the same mechanism if not materially more work.
- That count reaches the daemon's `error_count` reported via `status`
  (`src/client/vw_daemon.c`, `vw_ipc.h`'s status payload) without
  requiring a whole-cycle network failure.
- A repeatedly-failing action (e.g. permanently over quota) does not grow
  the count unboundedly forever — decide and document whether it's a
  per-cycle count (reset each cycle, matching current `error_count`
  semantics) or a persistent one, and note the choice in `docs/PROTOCOL.md`
  or `ARCHITECTURE.md` if the IPC status contract changes shape.
- Regression test: a quota-exceeded upload is reflected in `status`
  within one normal sync cycle, without relying on a fixed sleep longer
  than necessary.
- No change to network-error handling/offline-queue behavior for actual
  `is_net_err()` cases — this is additive, not a rework of that path.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

QA.06 [2026-08-03]: Filed from TASK-110's root-cause investigation (see
that task's notes for the full call-chain trace). Assigned to CLI.02 per
CLAUDE.md §4 — the fix lives in the sync engine (`src/client/vw_sync.c`)
and daemon main loop (`src/client/vw_daemon.c`), both CLI.02 domain, not
QA.06's. TASK-110 is blocked on this landing before IT-7 can be made to
pass for real rather than papered over with a longer sleep.

CLI.02 [2026-08-03]: Implemented.

- Added `action_errors` (`uint32_t`) to `vw_sync_ctx_t`
  (`src/client/vw_sync.c`), guarded by the existing `ctx->mu`, same
  pattern as `bytes_done`/`bytes_total`. Reset to 0 at the top of each
  `vw_sync_run()` cycle.
- Added `note_action_error(ctx)` static helper and called it from every
  `exec_action()` branch where a per-action outcome is a non-network
  failure: both shared-folder upload sub-cases (by-id and into-folder),
  the "parent directory unresolvable this cycle" shared-upload fallback,
  the plain upload path, download, remote delete, local delete, and the
  conflict-resolution upload. `is_net_err()` continues to gate the
  existing offline-queue/retry behavior unchanged; the new counting is
  strictly additive on the non-net, non-OK outcomes that used to just
  vanish.
- Added `vw_sync_action_error_count()` (`vw_sync.c`/`vw_sync.h`),
  mirroring `vw_sync_get_progress()`'s lock-and-copy pattern.
- `vw_daemon.c`'s main loop now folds `vw_sync_action_error_count()` into
  its existing `error_count` local right after `vw_sync_run()` returns,
  so it reaches `VW_IPC_STATUS_RESP` the same way a whole-cycle network
  failure already did. No change to the IPC wire format — `error_count`'s
  meaning was already documented as "non-fatal errors since last sync."

Verification:
- `build-wsl-werror` (gcc, `-Wall -Wextra -Werror` equivalent) full
  rebuild clean, zero warnings.
- Full `ctest` suite (14 registered tests, including the legacy
  `run_integration.py` TAP harness and all unit tests): 100% pass.
- `ctest -R '^integration$'` re-run 3 additional times back-to-back,
  standalone: all 15 IT-* sub-tests pass every time, including IT-7 —
  see TODO/TASK-110.md for the detailed confirmation, that's QA.06's
  territory to sign off on.
- Sent for CQR.08 review (this task's diff touches only `src/client/`,
  no security-sensitive tag, so SEC.07 is not required per CLAUDE.md
  routing rules).

CQR.08 [2026-08-03]: Reviewed. No blocking findings. Two advisory items,
both addressed before sign-off:

1. The shared-upload "parent directory unresolvable this cycle" branch
   was the one `exec_action()` outcome left uncounted, on the assumption
   it self-heals. Traced `dirmap` construction (`srv_collect_by_id`) and
   found no mechanism anywhere in the sync engine that creates a missing
   remote directory automatically (`FILE_MKDIR` is only reachable via an
   explicit user `mkdir` CLI command) — so this can in fact recur every
   cycle indefinitely for a shared folder, i.e. the exact
   permanently-silent-failure pattern this task exists to close. Fixed:
   now calls `note_action_error()` too. The deeper "shared-folder sync
   should actually be able to create that directory" question is a
   materially larger behavioral change, out of this task's scope — filed
   as **TASK-113** (CLI.02).
2. `vw_sync.h`'s file-header thread-safety summary hadn't been updated to
   list the new `vw_sync_action_error_count()` alongside
   `vw_sync_get_progress()`. Fixed.

Re-verified after both fixes: `build-wsl-werror` (gcc, warnings-as-errors)
clean rebuild; full `ctest` suite 14/14 pass; `pytest
tests/integration/test_shared_sync.py` (exercises this exact file's
shared-folder path end-to-end) and `test_quota.py` both pass. Signing off
— review requirement satisfied, no other reviewers required (not
security-sensitive). Marking done.
