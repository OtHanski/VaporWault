---
id:          TASK-223
title:       "Client-side file_id-based version history for shared files"
status:      todo
assignee:    CLI.02
created_by:  PRT.04
created:     2026-08-27
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [client]
---

`TASK-214` corrected a wrong assumption from `TASK-182`: the server's
`VERSION_LIST`/`VERSION_RESTORE` handlers were already fully file_id-based
and already permission-safe via `effective_permission()` — `VERSION_LIST`
needed no server change at all, and `VERSION_RESTORE` needed only one
small relaxation (`docs/PROTOCOL.md` §7.3, revision 25): its
`virtual_path` field may now be an empty string, meaning "resolve by
`version_id`/`file_id` alone," with no other behavior change and no wire
version bump.

That means the **only** remaining blocker for a grantee to use version
history on a file shared with them is client-side:

- `vw_client_version_list` (`src/client/vw_client_core.c`) always resolves
  `file_id` via `vw_client_file_stat(sess, virtual_path, ...)` first — an
  owner-namespaced path lookup a grantee cannot perform for a file that
  isn't in their own namespace.
- `vw_client_version_restore` requires a non-empty `virtual_path` and
  validates it with `path_validate_client()` (rejects anything not
  starting with `/`), so it cannot send the now-permitted empty string
  today even though the server would accept it.
- Neither the daemon IPC layer (`vw_ipc.h`/`vw_daemon.c`), the CLI
  (`vapourwault-cli`), nor the GUI have any surface for obtaining a
  shared file's `file_id` without going through a path (e.g. via a
  `share list` / "shared with me" view that already returns file
  identifiers) and passing it straight into version history.

## Work

- Add `vw_client_version_list_by_id`/`vw_client_version_restore_by_id`
  (or extend the existing functions to accept `file_id` directly,
  whichever keeps the API surface cleaner — CLI.02's call) that skip
  `vw_client_file_stat` and send `VERSION_RESTORE` with an empty
  `virtual_path`, per `docs/PROTOCOL.md` §7.3 rev 25.
- Wire the new client-core function(s) through daemon IPC
  (`vw_ipc.h`/`vw_daemon.c`), following the existing one-request-per-
  connection pattern (see `TASK-209`'s note on this — each IPC request
  needs its own connection unless it's the same request/response pair).
- Surface it in `vapourwault-cli` (e.g. `version list --file-id <id>` /
  `version restore --file-id <id> <version_id>`, alongside the existing
  path-based subcommands) and in the GUI's shared-files view.
- Update `tests/integration/test_cli_version_history.py`'s
  `test_cli_version_restore_not_available_for_a_shared_file` once this
  ships — the "known limitation" it locks in will no longer be true, and
  should be replaced with a real by-file_id round-trip test for a
  grantee, covering both a VIEW grant (must fail at `VW_PERM_EDIT` check,
  not at path resolution) and an EDIT grant (must succeed).

## Acceptance criteria

- A grantee with an EDIT share on a file can list and restore that
  file's versions using only identifiers obtained from the share (never
  an owner-namespaced path), via the CLI (and GUI, if in scope for the
  same pass).
- A grantee with only a VIEW share gets a permission error (not a
  not-found error) when attempting to restore — proving the
  `effective_permission()`/`VW_PERM_EDIT` check is actually being
  reached, unlike today.
- Existing path-based version history behavior is unchanged for callers
  that still supply a real path.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

PRT.04 [2026-08-27]: Filed as `TASK-214`'s promised follow-up after
determining the server side needed only a one-line permissive relaxation
(landed directly in `TASK-214`, not deferred here) — see
`docs/PROTOCOL.md` §7.3 revision 25 for the corrected understanding of
why `VERSION_LIST`/`VERSION_RESTORE` were never actually broken
server-side. All remaining work is client-side plumbing and UI.
