---
id:          TASK-223
title:       "Client-side file_id-based version history for shared files"
status:      done
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

CLI.02 [2026-08-27]: Implemented.

- **Client core** (`vw_client_core.h`/`.c`): refactored
  `vw_client_version_list`/`vw_client_version_restore` to share their
  wire-send/response-parse bodies (`version_list_by_file_id`/
  `version_restore_send`) with two new public entry points,
  `vw_client_version_list_by_id`/`vw_client_version_restore_by_id`,
  following this codebase's existing `_by_id` naming convention
  (`vw_client_file_stat_by_id`/`_delete_by_id`/`_download_by_id`,
  `TASK-095`/`106`). The `_by_id` restore sends `virtual_path=""` per
  `TASK-214`'s relaxation; no wire change needed, exactly as `TASK-214`
  predicted.
- **Daemon IPC** (`vw_ipc.h` `0x8047`-`0x804A`, `vw_daemon.c`): thin
  passthrough, `VERSION_RESTORE_BY_ID` gated on `account_is_read_only`
  like the existing path-based `VERSION_RESTORE_REQ`.
- **CLI**: `version list --file-id <id>` / `version restore --file-id
  <id> <version_id>`, alongside the existing path-based subcommands. The
  `file_id` argument to `restore --file-id` is accepted but unused
  server-side (restore resolves entirely by `version_id`) — kept on the
  command line anyway so the two `--file-id` subcommands read
  symmetrically and a caller doesn't need to know that asymmetry exists.
- **Tests**: replaced
  `test_cli_version_history.py::test_cli_version_restore_not_available_for_a_shared_file`
  (which only proved "fails cleanly regardless of permission level," the
  old, now-obsolete limitation) with
  `test_cli_version_history_by_file_id_for_a_shared_file` — a real
  three-account (owner/viewer/editor) round trip: a VIEW grantee lists
  versions successfully (`VW_PERM_VIEW`) but cannot restore one; an EDIT
  grantee does both, producing exactly one new version record, same as
  an owner's own restore. Re-ran 3× with no flakiness. Needed
  `max_workers=4` on this test's `ServerInstance` — three concurrently-
  connected daemon accounts exceed the default of 2, the same
  worker-pool-exhaustion class `test_cli_search.py`/`test_notify_alerts.py`
  already hit and fixed identically.
- **Acceptance-criterion wording correction**: the criterion as written
  said a VIEW grantee's restore attempt should get "a permission error
  (not a not-found error)." Verified against the actual server code
  (`handle_version_restore`) that this was never literally true and
  isn't something to fix here: insufficient permission there returns
  `VW_ERR_VERSION_NOT_FOUND`, a deliberate pre-existing "don't leak a
  version's existence below EDIT" posture, not a bug this task
  introduced or should change (changing it would be a SRV.01/PRT.04
  design decision affecting error-code semantics generally, out of
  this client-side task's scope). The test instead verifies the
  behavior that actually matters: VIEW can list but not restore, EDIT
  can do both — proving the permission boundary is real and
  level-dependent, which is the criterion's actual intent.
- **Deliberately out of scope, disclosed rather than silently
  skipped**: GUI and web-gateway/frontend surfacing. The acceptance
  criteria mark GUI as conditional ("if in scope for the same pass");
  given the CLI path is fully implemented, tested, and is what the
  acceptance criteria require unconditionally, GUI/web surfacing is left
  as a small, mechanical follow-up (all the underlying client-core/IPC
  plumbing already exists — a GUI "shared with me" panel or a web
  version-history-by-id endpoint would be a thin UI addition, not new
  infrastructure) rather than expanding this task's scope further.

Verified on both toolchains: WSL/GCC (`build-gw-e2e`) and MSVC
(`build-msvc-105`) build clean, including the GUI and web gateway
(unaffected by this task's client-core/CLI-only changes, confirmed
still linking correctly). `ctest` 20/20 on WSL. Full regression sweep
across every touched Python suite (`test_gateway.py`,
`test_cli_account_email.py`, `test_cli_version_history.py`,
`test_cli_notify_prefs.py`): 42/42 passing.

CQR.08 [2026-08-27]: Reviewed the diff line by line, not just the notes
above.

- The `vw_client_version_list`/`_restore` refactor into shared
  `version_list_by_file_id`/`version_restore_send` bodies is a clean
  extraction — verified byte-for-byte that the wire-send/response-parse
  logic moved unchanged (no accidental behavior drift for the existing
  path-based callers), and that both original public functions still
  perform exactly the same up-front validation
  (`sess_check_valid`/`path_validate_client`) before ever calling into
  the shared body, so `_by_id` skipping that validation is a deliberate,
  correct difference, not an accidentally-dropped check.
- All new CLI argument-parsing branches (`version list --file-id`,
  `version restore --file-id`) bounds-check `argi` against `argc` before
  every `argv[]` dereference, including the nested `--file-id` sub-case;
  no out-of-bounds read possible on a truncated command line.
  `version_restore_send`'s `if (path_len > 0) memcpy(...)` correctly
  avoids a zero-length memcpy from a merely-empty (not NULL) string —
  harmless either way, but the guard is honest about the size-0 case
  being intentional (the `_by_id` restore path), not accidental.
- IPC daemon handlers (`VW_IPC_VERSION_LIST_BY_ID_REQ`/
  `VERSION_RESTORE_BY_ID_REQ`) correctly mirror the existing path-based
  handlers' error-priority order (`!a` → `VW_ERR_INVALID_ARG`, `!a->sess`
  → `VW_ERR_AUTH_REQUIRED`) and the restore variant's
  `account_is_read_only` gate — consistent with every other write-shaped
  IPC request in this file, nothing missed.
- The acceptance-criterion wording correction above is exactly the kind
  of thing this project's review process exists to catch — verified
  independently by reading `handle_version_restore`
  (`src/server/vw_file_handlers.c`) myself rather than taking the note's
  word for it: confirmed `perm < VW_PERM_EDIT` does return
  `VW_ERR_VERSION_NOT_FOUND`, not a distinct permission code, and that
  this is pre-existing behavior (present before this task, unrelated to
  any code this task touched). Agree this is out of scope to change here.
- Test file changes: the removed test's function name is gone from the
  file entirely (not left as a dead/skipped stub), and the replacement
  covers strictly more ground (three accounts, both permission levels,
  a real restore with version-count verification) than what it
  replaced. No `blocking` findings. `status: done` approved.

ARCH.00 [2026-08-27]: Closing. Both acceptance criteria that matter are
met (by-file_id list/restore works for a real grantee via the CLI;
existing path-based behavior unchanged), with the third criterion's
literal wording corrected against verified reality rather than blindly
chased. GUI/web surfacing left as a disclosed, small follow-up rather
than expanding scope — not filed as a separate task since it's optional
per this task's own acceptance criteria and small enough to pick up
opportunistically whenever GUI.03/WEB.09 next touch their respective
shared-content views.
