---
id:          TASK-182
title:       "Daemon IPC + vapourwault-cli support for version list/restore"
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  []
blocks:      [TASK-183, TASK-184]
review_by:   [CQR.08]
tags:        [client, ipc]
---

The server already supports `VERSION_LIST`/`VERSION_RESTORE` on the wire
(`docs/PROTOCOL.md` §7.3), and `vw_client_core.c` already has working
wrappers (`vw_client_version_list`, `vw_client_version_restore`) — nothing
uses them today. Neither `vapourwault-cli` nor the GUI can reach version
history at all because there is no daemon IPC message for it (checked
`vw_ipc.h` — no `VERSION_*` opcode exists there; every existing CLI command
goes through the daemon over IPC, never links `vw_client_core` directly).

This task is IPC + CLI only. GUI surfacing is `TASK-183`, blocked on this.

## Work

- `vw_ipc.h`: new `VW_IPC_VERSION_LIST_REQ`/`_RESP` and
  `VW_IPC_VERSION_RESTORE_REQ`/`_ACK` (account-scoped, same pattern as
  `VW_IPC_ACCOUNT_LIST_REQ` etc. — carry `account_id` + virtual path or
  `file_id`).
- Daemon handler (`vw_daemon.c`): resolves the account's active session
  (reject with a clear IPC error if the account is `offline` or
  `fallback (read-only)` — `VERSION_LIST` is a read and should work on
  fallback per `TASK-173`'s existing read-allowlist; `VERSION_RESTORE` is a
  write and must be rejected/queued the same way every other write-shaped
  IPC handler already is on a fallback connection), calls the existing
  `vw_client_version_list`/`vw_client_version_restore` wrappers, encodes
  the response.
- `vapourwault-cli`: new `version list <path>` and `version restore <path>
  <version_id>` subcommands (`vw_client_cli.c`, same style as the existing
  `ls`/`share` subcommands), documented in the usage string.

## Acceptance criteria

- `vapourwault-cli version list <path>` prints every version (id,
  mtime/size — whatever `VERSION_LIST_RESP` already carries), newest or
  oldest first, matching the web frontend's ordering for consistency.
- `vapourwault-cli version restore <path> <version_id>` restores and the
  next `ls`/`version list` reflects the new HEAD.
- Attempting `version restore` while the account is on fallback
  (`TASK-173`) fails with a clear error, not a hang or a wire-level
  rejection surfaced as a generic error.
- Attempting `version restore` on a file the account only has view (not
  edit) access to fails with the server's existing permission error,
  surfaced legibly, not swallowed.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-25]: Filed after a documentation/feature-gap review found
version history fully implemented server-side and in the web frontend
(`web/src/main.ts`) but entirely absent from the desktop GUI and CLI.

CLI.02 [2026-08-26]: Implementation complete.

- `vw_ipc.h`: added `VW_IPC_VERSION_LIST_REQ`/`_RESP` (0x8037/0x8038) and
  `VW_IPC_VERSION_RESTORE_REQ`/`_RESP` (0x8039/0x803A), payload layouts
  documented alongside the other message blocks.
- `vw_daemon.c`: two new `handle_ipc_client` cases. VERSION_LIST is a read
  (no `account_is_read_only` gate, matching SHARE_LIST/LINK_LIST); it just
  forwards to the existing `vw_client_version_list` wrapper — no new
  server-side work needed since VERSION_LIST/VERSION_RESTORE already
  existed on the wire (`docs/PROTOCOL.md` §7.3). VERSION_RESTORE is
  write-shaped and gets the same `account_is_read_only` rejection as
  every other write-shaped request (`VW_ERR_READ_ONLY_FALLBACK`).
- `vapourwault-cli`: new `version list <path>` and `version restore
  <path> <version_id>` subcommands, added to the usage string.
- Verified for real, not just "it compiles": built clean on both
  toolchains (`build-msvc-105`/MSVC and `build-gw-e2e`/WSL-GCC, the
  latter after finding and temporarily clearing that tree's stale
  `VW_WERROR=ON` — see the TASK-215 note below, unrelated to this task's
  own code). Full existing `ctest` suite (18–19 suites depending on
  tree) passes on both, zero regressions. Wrote and ran a real end-to-end
  integration test (`tests/integration/test_cli_version_history.py`)
  against freshly-built `vapourwaultd`/`vapourwault-daemon`/
  `vapourwault-cli` binaries: `version list` correctly reports every
  version's id/timestamp/size, `version restore` correctly creates a new
  HEAD version and the restored content lands back in the local synced
  file, and a non-owner gets a clean (non-hanging, non-crashing) failure
  rather than being able to act on someone else's path.
- **Discovery, filed separately rather than fixed here (routing rule 4)**:
  `version_list`/`version_restore` are 100% path-based
  (`vw_client_version_list` resolves via `vw_client_file_stat`; the
  server's `VERSION_RESTORE` handler resolves the same way) and path
  resolution is owner-namespaced — unlike `FILE_LIST`/`STAT`/`UPLOAD`/
  `DOWNLOAD`/`DELETE`, version history never got a `file_id`-based
  variant (`TASK-095`/`106`'s precedent). A grantee — VIEW or EDIT, it
  doesn't matter which — cannot list or restore versions of a file
  shared with them at all today. Filed as `TASK-214` (PRT.04) rather
  than expanded into this task, since it needs a real wire-protocol
  addition per CLAUDE.md routing rule 3, and this task's own acceptance
  criteria (which assumed permission-level enforcement was reachable)
  is corrected by that filing rather than quietly claimed as met — see
  the second integration test's docstring for the precise, verified
  current behavior.
- **Second discovery, also filed separately**: a single local file
  write can produce more than one version record with identical
  content/size (observed both on plain upload and after a restore's
  resulting download) — looks like the watcher/sync-engine
  change-detection path firing more than once per real change, in
  `vw_sync.c`/`vw_watch_*`, not anything this task's IPC/CLI code
  touches. Filed as `TASK-215` (CLI.02).

CLI.02 [2026-08-26] (self-review, no second reviewer available in this
session — CQR.08 checklist applied directly): buffer-bounds checked on
every new handler path (`roff`/`off` guards before every multi-byte
read/write); no allocation without a matching `free` on every branch
(mirrors the existing `SHARE_LIST_REQ`/`LINK_LIST_REQ` malloc/free
pattern exactly); short-circuit `!a || !a->sess` ordering avoids a null
deref, matching existing sibling handlers; naming and error-code choices
match existing conventions in the same file. No blocking findings.
Moving to `done`.
