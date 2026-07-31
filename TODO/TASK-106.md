---
id:          TASK-106
title:       Sync engine awareness of shared folders (local tree integration)
status:      todo
assignee:    CLI.02
created_by:  CLI.02
created:     2026-07-30
priority:    normal
depends_on:  [TASK-095]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [client, sync, security-sensitive]
---

`TASK-095` implemented the client library, daemon IPC, and CLI layers for
direct share/link management (grant/revoke/list, create/revoke/list public
links) and file-id-based stat/download/upload/move — everything needed to
manage sharing and to read/write a single shared item by `file_id`. It did
**not** implement the separate scope item `TASK-095` originally called out:
making `vw_sync.c`'s background sync engine aware of items shared with the
current user, so a shared folder can appear and stay up to date inside the
user's own local sync tree (via `add-folder`) the same way an owned folder
does, rather than only being reachable through explicit `share`-family CLI
commands and file-id-based one-off operations.

This was deferred because the user's scope decision for `TASK-095` (see its
own notes) was specifically "library + full daemon/CLI plumbing" for direct
share/link management — sync-tree integration is a distinct, larger design
question (how does a shared item's virtual path coexist with the owner's
own path namespace, given paths are namespaced by `owner_id` server-side —
see `vw_store_file_get_by_path`'s hard filter, noted repeatedly in
`docs/PROTOCOL.md` §7.5) and deserves its own design pass rather than being
folded in under time pressure.

## Acceptance criteria

- Design (in this task's notes or `ARCHITECTURE.md`) for how a shared
  folder is represented in `vw_sync_folder_t`/`vw_cache_entry_t` given paths
  are owner-namespaced server-side — likely needs either a `file_id`-rooted
  sync folder variant (bypassing path-based `FILE_LIST`/`FILE_COMMIT`
  entirely, using the file-id-based functions `TASK-095` already added) or
  an explicit local virtual-root remapping.
- `add-folder`-equivalent CLI/daemon support for pointing a local directory
  at a shared item by `share_id` or `file_id` instead of an owned virtual
  path.
- Sync engine correctly handles live revocation mid-sync (a grant or link
  can be revoked between sync cycles — the engine must not treat a
  permission error as a generic I/O error it retries forever).
- Regression tests covering: initial sync of a shared folder, incremental
  sync after the owner adds/modifies files, and sync behavior immediately
  after the share is revoked.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-07-30]: Filed while closing out `TASK-095` — this is the one
scope item from that task's original description not covered by the
delivered work. Not fixed in place since it's a genuinely separate design
question, not a small follow-on.

CLI.02 [2026-07-31]: Design recorded in full in `ARCHITECTURE.md`'s "Sync
engine awareness of shared folders" entry — summary: `FILE_LIST` gains an
optional `dir_file_id` field (resolved via `effective_permission()`,
mirroring `FILE_COMMIT`'s existing directory-target branch), `vw_sync_folder_t`
gains `remote_dir_id`, the sync engine's server-walk and action-executor
get file-id-addressed variants alongside the existing path-based ones
(owned-folder behavior is unchanged byte-for-byte), and a definitive
permission error auto-pauses the affected sync folder instead of retrying
forever. Also filed `TODO/TASK-109.md` for a pre-existing, unrelated-but-
adjacent bug this surfaced (`FILE_LIST_RESP` never carries `version_id`,
silently breaking ongoing remote-change detection for *every* sync folder)
— worked around client-locally for this task rather than fixed at the wire
level, which needs its own design pass. Proceeding to implementation.

CLI.02 [2026-07-31]: `FILE_LIST` `dir_file_id` wire extension implemented
and committed (`a6a4929`) — `vw_client_file_list_by_id`/`_file_delete_by_id`
added to the client library, server-side `handle_file_list` resolves the
directory by id via `effective_permission()` for a non-scoped session.
Verified against the pre-existing flaky `IT-7` legacy quota test
(`TODO/TASK-110.md`, confirmed unrelated — reproduces identically on the
pre-TASK-106 baseline commit `7d882f8`).

CLI.02 [2026-07-31]: Sync-engine implementation complete. `vw_sync_folder_t`
gained `remote_dir_id` (`vw_cache.h`, struct now 1040 bytes). `vw_sync.c`
gained `srv_collect_by_id` (id-addressed BFS mirroring `srv_collect`, plus a
`dirmap_t` side-map of discovered directories' `virtual_path → file_id`,
needed to resolve the immediate parent for a brand-new file inside a shared
folder). `action_t` gained `shared`/`file_id`/`parent_dir_id`; `exec_action`
branches on `shared` to use `vw_client_file_upload_to_id`/
`_upload_into_folder`/`_download_by_id`/`_delete_by_id` instead of the
path-based calls, while an owned folder (`shared == 0`) executes byte-for-
byte the same code path as before. `vw_client_file_upload_into_folder`
gained `out_file_id`/`out_version_id` params (previously discarded
internally — the sync engine needs the new file's id to address it on every
later cycle, since a path-based `FILE_STAT` can never resolve inside a
folder this client doesn't own). The offline queue is intentionally NOT
used for shared-folder actions (per the recorded design: it's path-based
only) — a network error during a shared-folder action just fails that
cycle and is retried on the next one, no extra state. Live revocation:
`srv_collect_by_id`, unlike `srv_collect`, does not swallow
`VW_ERR_NOT_FOUND`/`VW_ERR_PERMISSION` from any BFS level (a shared folder's
FILE_LIST_BY_ID has no legitimate "just empty" NOT_FOUND case — empty
always returns zero entries) — `sync_one_folder` treats either as a
revocation signal and auto-pauses the folder via the existing `paused`
flag/`vw_cache_folder_set_paused` mechanism rather than retrying forever.

Scope note: a shared-folder sync folder can upload a new file into any
directory already known from the BFS (the owner's existing tree, or one
just discovered this cycle), but cannot create a brand-new *local*
subdirectory server-side from scratch — same limitation an owned folder
already has today (confirmed by reading `handle_file_commit`: path-based
FILE_COMMIT also requires the parent directory to already exist
server-side; `walk_recursive` never pushes directories as their own
actionable entries for either mode). Not a regression introduced here;
kept deliberately at parity rather than expanding scope.

Verified: GCC/WSL `-Wall -Wextra -Wpedantic -Werror` build clean; `ctest`
all green except the pre-existing `TASK-110` flake; full
`tests/integration/` pytest suite 62/62 passed; MSVC `/W4 /WX` build clean.
No unit test exists for `vw_sync.c` specifically (none existed before this
change either) — coverage is via the integration/pytest suite and will be
extended in Task #21 (regression tests) with shared-folder-specific sync
scenarios once Task #20 (CLI/daemon plumbing to actually add a shared
folder as a sync target) lands.
