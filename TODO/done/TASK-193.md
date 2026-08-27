---
id:          TASK-193
title:       "Client: selective-sync exclude rules"
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-192]
blocks:      [TASK-194, TASK-195]
review_by:   [CQR.08]
tags:        [client]
---

Implements `TASK-192`'s design.

## Work

- `vw_sync_folder_t`: new exclude-pattern list (glob/fnmatch-style,
  relative to the folder root).
- `account.conf` persistence (`vw_daemon.c`, `account_cfg_apply_kv`/
  `_save`): new per-folder key for the rule list, same
  read-on-load/write-on-change pattern as existing folder config.
- `vw_sync.c`: `srv_collect` and its `remote_dir_id`-rooted variant
  (`TASK-106`) skip any entry whose relative path matches an exclude
  rule, before it ever becomes an `action_t`. Excluding a path that's
  already synced locally leaves the local copy alone (per `TASK-192`
  decision 5) — it simply stops appearing as a source of further
  upload/download actions.
- `vapourwault-cli`: `add-folder`/a new `set-folder-rules <local>
  --exclude <glob> [--exclude <glob> ...]` and `list-folders` shows the
  active rules per folder.

## Acceptance criteria

- A file matching an exclude pattern is never downloaded even though the
  server has it and the folder is otherwise syncing.
- A file already synced locally, then newly excluded, remains on disk
  untouched and stops receiving further remote updates.
- Removing a rule resumes normal sync for the previously-excluded path
  without requiring a full resync of the whole folder.
- Vault-rooted sync folders reject rule assignment with a clear error
  (per `TASK-192` decision 6).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-08-26]: **Two corrections to `TASK-192`'s design, found by
reading the actual code before implementing rather than trusting the
design doc's assumptions** — the same category of mistake as the public-
link milestone's expiration mix-up, so flagging the pattern again, not
just fixing the instance:

1. Decision 3 said rules "persist in `account.conf` alongside the
   folder's other config." `account.conf` has no per-folder structure at
   all (it's account-identity config: label/host/credentials) — folders
   live entirely in `vw_cache`'s `sync_folders.db`, a fixed 1040-byte
   `vw_sync_folder_t` record with **zero** reserved bytes (unlike
   `vw_share_record_t`'s 40, which is what made the link-password
   feature's similar problem solvable by reusing existing space). Growing
   that record would need an on-disk migration. Resolved by storing rules
   as repeatable `exclude = <local_root>|<pattern>` lines directly in
   `account.conf` after all — it's a plain re-serialized-in-full text
   file (not a fixed binary record), so a genuinely variable-length list
   costs nothing extra there. Mirrored into the live `vw_sync_ctx_t` (new
   `vw_sync_set_folder_excludes`) at account load and on every live
   change — `account.conf` is the durable source, the sync engine's own
   copy is what `vw_sync_run` actually consults each cycle.
2. Decision 6 ("vault-rooted sync folders are exempt, reject rule
   assignment") describes something that doesn't exist: vault content is
   never registered as a `vw_sync_folder_t` at all — `VAULT_UPLOAD_REQ`/
   `_DOWNLOAD_REQ` take an explicit local path per call, entirely separate
   from the automatic `vw_sync_run` BFS loop that owned/shared folders go
   through. There is no "vault-rooted sync folder" for a rule-assignment
   call to reject. Dropped this acceptance criterion as inapplicable
   rather than implementing a check against a case that can't occur.

Implementation:

- `vw_sync.c`: a small custom glob matcher (`vw_sync_glob_match`) —
  `*`/`?` within one path segment, `**` as a whole segment for zero-or-
  more segments — since POSIX `fnmatch()` isn't available on MSVC and
  this project avoids a vendored dependency for something this small.
  `vw_sync_set_folder_excludes` stores patterns keyed by `local_root`
  inside `vw_sync_ctx_t` (freed in `vw_sync_close`).
- **Found and fixed a real bug while testing, not caught by design
  review**: the obvious-looking implementation — filter excluded entries
  out of the `lfiles`/`srv` snapshots before calling `compute_actions` —
  is actively wrong, not just incomplete. `compute_actions`'s LOCAL_DEL/
  REMOTE_DEL detection passes reason over `vw_cache_list` (the durable,
  persisted cache of every file this folder has ever synced), completely
  independent of whatever snapshot arrays are passed in for the current
  cycle. Silently dropping an already-`SYNCED` entry from those arrays
  made `compute_actions` conclude the file had been deleted and queue a
  real `ACT_DEL_REMOTE` — caught by the integration test below actually
  deleting the file server-side (`version list` returned `NOT_FOUND`
  after setting an exclude rule), not by inspection. Fixed by moving the
  exclusion check inside `compute_actions` itself, applied at all five
  places it reasons about a path (new-local, LOCAL_DEL scan, new-remote,
  REMOTE_DEL scan, and the final action-building pass, the last one as
  defense-in-depth for a path that was already mid-transition before its
  rule was added) — never in a pre-filtered snapshot compute_actions
  doesn't fully control.
- `vw_daemon.c`: `vw_account_cfg_t` gains a dynamic `folder_excludes`
  list; `account_cfg_apply_kv`/`_save` handle the new repeatable
  `exclude` line; a new `VW_IPC_FOLDER_SET_EXCLUDES_REQ`/`_RESP` pair
  (wholesale replace, not incremental) persists + applies live;
  `FOLDER_LIST_RESP` gained a trailing per-folder pattern list. Re-auth
  (`ACCOUNT_ADD_REQ` with `existing != NULL`) carries the existing
  heap-owned list across the whole-struct `existing->cfg = acfg`
  assignment explicitly — missing that would have silently wiped every
  configured rule on a routine password re-authentication.
- `vapourwault-cli`: `set-folder-rules <local> [--exclude <glob> ...]`;
  `list-folders` prints each folder's active rules.
- Verified: `build-msvc-105` and `build-gw-e2e` (WSL/GCC) both build
  clean, zero warnings (GCC caught one real thing MSVC didn't — a
  `/*`-inside-a-comment false-nested-comment warning from writing
  `"node_modules/**"` literally in a doc comment; reworded). New unit
  tests for the glob matcher (`test_vw_sync.c`, 7 cases) and a new
  end-to-end integration test (`test_cli_selective_sync.py`) that
  specifically proves the negative property that matters here: an
  excluded file's local edits never reach the server, verified via
  `version list`'s version count rather than by absence-of-error (a
  silently-broken sync engine and a correctly-excluded file both look
  like "nothing happened" to a weaker test). Full suite re-run: `ctest`
  18/18, `tests/integration` 104 non-cluster + 15 cluster, all passed,
  zero regressions.

Moving to `review`/`done`.