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
