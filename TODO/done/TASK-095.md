---
id:          TASK-095
title:       Implement client library support for sharing (grants + links)
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-29
priority:    high
depends_on:  [TASK-088, TASK-094]
blocks:      [TASK-096, TASK-097]
review_by:   [SEC.07, CQR.08]
tags:        [client, protocol, security-sensitive]
---

Implement the client-side API for the sharing design published in
`docs/PROTOCOL.md` §7.5 (`TASK-088`). GUI.03 blocks on this per the existing
CLAUDE.md constraint that the GUI consumes the client library API only.

Scope:

- `vw_client_core.c` gains share/link API functions: create/revoke/list
  grants, create/revoke/list public links, and redeem a public link
  (unauthenticated connect path — needs its own connect-then-`LINK_ACCESS`
  flow distinct from the normal `AUTH_REQUEST` login path, since no
  username/password is involved).
- Sync engine awareness: items shared-with-me should be visible to the
  local sync engine as effectively read-only or read-write per the grant's
  permission, without conflating them with the user's own owned-file
  namespace. Define exactly how a shared folder appears in the local
  virtual path tree (this is the "GUI integration point definition" this
  task should write, per CLI.02's TODO-interaction responsibilities in
  `CLAUDE.md`).
- Client-side path validation for share/link targets should mirror the
  server-side rules in §7.8.2 for UX (fail fast locally) but the server
  check remains authoritative — do not skip server-side validation on the
  assumption the client already checked.
- `vw_client_cli.c`: add commands for share/link management (share, unshare,
  list-shares, create-link, revoke-link, list-links), following the
  existing CLI conventions (stdin-based input for anything sensitive,
  matching the `login`/admin CLI precedent).

## Acceptance criteria

- Client library functions for every message in §7.5 exist and are
  exercised by at least a manual WSL round-trip against the real server
  (once TASK-094 lands).
- CLI commands work end-to-end.
- Integration point definition for GUI.03 is written down (in this task's
  notes or a doc) before GUI.03 starts `TASK-096`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-088`. Depends on
`TASK-094` for the real wire handlers to test against, but the client-side
message encode/decode work can start in parallel once the protocol spec is
published (it already is, in `docs/PROTOCOL.md` §7.5).

CLI.02 [2026-07-30]: Implemented all three layers per the user's explicit
scope decision (library + full daemon/CLI plumbing), deferring only the
sync-engine tree-integration item — filed separately as `TASK-106` (see its
notes for why that's a distinct design question, not a small follow-on).

**Layer 1 — `vw_client_core.c`/`.h`:**
- File-id-based operations: `vw_client_file_stat_by_id`,
  `vw_client_file_download_by_id`, `vw_client_file_upload_to_id` (update an
  existing file by id), `vw_client_file_upload_into_folder` (create a new
  file inside a shared folder by id — server resolves `path` as a bare leaf
  name in this case per `handle_file_commit`'s file_id-names-a-DIR branch),
  and `vw_client_file_move`.
- Sharing CRUD: `vw_client_share_grant/_revoke/_list`,
  `vw_client_link_create/_revoke/_list`, and `vw_client_link_access` (a
  separate connect-then-`LINK_ACCESS` flow distinct from
  `vw_client_connect`, since no username/password is involved — mirrors
  `vw_client_resume`'s shape but decodes `LINK_ACCESS_ACK`, which reuses
  `AUTH_OK`'s wire shape per §7.5).
- Refactored `vw_client_file_upload`/`_download`/`_stat` into shared
  `upload_chunks`/`send_file_commit`/`stat_common`/`download_by_entry`
  helpers so the file-id and path-based entry points share one code path
  rather than duplicating the chunk/version wire logic.
- `link_token` is `secure_zero`'d after being copied out in both
  `vw_client_link_create` and its stack buffer, matching this codebase's
  existing "never let a raw secret linger" convention for session tokens.

**Layer 2 — `vw_ipc.h`/`vw_daemon.c`:** 12 new IPC message types
(`VW_IPC_SHARE_GRANT_REQ`/`_RESP` … `VW_IPC_LINK_LIST_REQ`/`_RESP`,
0x8015–0x8020). Every `_RESP` is prefixed with `error_code(u32)` (unlike
the local-cache-only `FOLDER_LIST`/`FILE_LIST` responses) since these are
genuine network round-trips through `dc->sess` that can fail —
`VW_ERR_AUTH_REQUIRED` if there's no active session. `SHARE_GRANT_REQ` and
`LINK_CREATE_REQ` take a `virtual_path` string (not a `file_id`) since the
CLI/GUI only knows paths; the daemon resolves it via
`vw_client_file_stat` before calling through. `LINK_LIST_REQ` carries a
`file_id_filter` (matching the library API) but the CLI always sends 0 —
per-file filtering isn't exposed as a CLI feature yet.

**Layer 3 — `vw_client_cli.c`:** `share`, `unshare`, `list-shares`
(`--to-me` flag for mode=1), `create-link`, `revoke-link`, `list-links`.
`create-link` prints the raw token as hex exactly once, with the same
"save this now" framing as the server's own never-re-disclose convention.

**Bug found and fixed while verifying (in-domain, not filed separately —
see rationale in `TASK-105`'s notes for when out-of-domain filing applies
vs. fixing in place; this is squarely `vw_sync.c`, CLI.02's own module):**
Any file synced at the root of a `virtual_root == "/"` sync folder got a
doubled leading slash (`"//name"`) wherever a virtual path was built by
naively concatenating `dir_virtual + "/" + name` — three sites in
`vw_sync.c` (`walk_cb`'s local-tree walk, `srv_collect`'s server-tree BFS,
and `vw_sync_mark_local_modified`). `vw_client_file_upload`'s
`path_validate_client` rejects a leading `"//"` outright, so **every
upload of a root-level file in a `"/"`-rooted sync folder silently failed**
— the file stayed in `local_mod`/`new_local` forever, invisible in `status`
error counts, while `ls` still displayed it (from the local cache scan,
independent of upload success), masking the bug entirely. Confirmed via a
standalone repro (add-folder to `"/"`, sync a file, `ls` showed
`sync_state=local_mod` and `NAME=//diag_test.bin` forever). This blocked
verifying `share`/`create-link` against a real root-level synced file
(`vw_client_file_stat` on the clean `/name` path returned `NOT_FOUND` since
the file never actually reached the server). Fixed with a shared
`vpath_child()` helper (root-dir special case: skip the redundant
separator) applied at all three sites, plus a matching inline fix in
`vw_sync_mark_local_modified`. Confirmed fixed via the same repro
(`sync_state=synced`, `NAME=/diag_test.bin`, then via
`run_integration.py`'s new IT-9…IT-15 sharing tests, which need a real
server-side file to share/link).

**Also fixed while wiring up `run_integration.py`'s new tests (test-harness
bugs, not sharing-related, but blocking verification of this task in that
harness):**
- `PROTO_VERSION` was hardcoded to `4`; `VW_PROTO_VERSION_CURRENT` is now
  `6` (bumped for the cluster feature, unrelated to this task) — the
  server's `vw_proto_negotiate` rejects a client offering a lower max
  version outright (`VERSION_REJECT`), so every login in this harness was
  failing before even reaching the auth phase. Bumped the constant.
- The `ls`-polling loop after `sync` used a 5s `subprocess` timeout against
  a daemon whose main loop only dequeues pending IPC connections once per
  outer iteration, gated by `vw_watcher_wait(sync_interval_ms=5000)` — an
  occasional but real race that crashed the whole suite with an uncaught
  `TimeoutExpired`. Bumped to 8s and now catches the timeout as "not yet
  synced, retry" instead of propagating.

**New tests added:** `run_integration.py` IT-9 through IT-15 — create a
second user, `share`/`list-shares`/`unshare` a real synced file, then
`create-link`/`list-links`/`revoke-link` on it. These are CLI/daemon
plumbing smoke tests (rc + stdout substrings), not a re-verification of
wire-level protocol details — that depth already exists in
`tests/integration/test_sharing.py` (`TASK-094`).

**Validation:**
- GCC/WSL Ubuntu (`-Wall -Wextra -Wpedantic -Werror`): full build clean.
  All 13 CTest suites pass except the pre-existing `integration` suite's
  IT-7 (quota enforcement) sub-test, which fails identically with and
  without this task's changes (confirmed by re-running twice) — a
  pre-existing timing issue unrelated to sharing, out of this task's scope.
  IT-1 through IT-6, IT-8 through IT-15 all pass, including the six new
  sharing tests.
- Full pytest integration suite (33 tests across
  `test_auth.py`/`test_dedup.py`/`test_file_ops.py`/`test_gc.py`/
  `test_quota.py`/`test_sharing.py`): all pass, no regressions from the
  `vw_sync.c` fix (none of those tests exercise `vw_sync.c` — they drive
  the wire protocol directly via the Python reference client).
- MSVC (`/W4 /WX`, Ninja + `cl.exe` via `vcvars64.bat`, reusing
  `build/_deps` as `FETCHCONTENT_BASE_DIR`): `vapourwaultd`,
  `vapourwault-daemon`, `vapourwault-cli`, `vapourwault-server-cli`,
  `test_vw_ipc`, and `test_vw_share` all build and pass clean. Did not
  attempt a full MSVC build of the GUI targets — `imgui.h`/`SDL.h` aren't
  vendored on this machine (pre-existing environment gap, unrelated to
  this task) — scoped the MSVC check to the targets this task touches.

Status set to `review` per `review_by: [SEC.07, CQR.08]` (security-sensitive
tag: this task adds new secret-bearing wire traffic — link tokens — and new
unauthenticated-connect code path `vw_client_link_access`).

SEC.07 [2026-07-30]: Reviewed the new secret-handling paths.
`vw_client_link_create` and the daemon's `VW_IPC_LINK_CREATE_REQ` handler
both `secure_zero` the raw token after use; confirmed no other code path
logs, persists, or otherwise retains it beyond the caller-supplied
`out_link_token`/CLI hex-print-once. `vw_client_link_access` correctly
treats "unknown token" and "revoked token" identically (both surface as
whatever `VW_ERR_AUTH_BAD_CREDS`-equivalent the server sends) — no new
client-side enumeration surface introduced, since the client is a pure
relay for the server's already-reviewed (`TASK-094`) anti-enumeration
behavior. The daemon's IPC handlers for `SHARE_GRANT_REQ`/`LINK_CREATE_REQ`
correctly gate on `dc->sess` before touching the network (no
use-after-free/NULL-deref risk if a CLI command arrives before the daemon
has ever logged in). Local IPC payload parsing (`vw_ipc_read_str` /
manual offset bounds checks in the new `vw_daemon.c` cases) rejects
truncated input rather than reading past the receive buffer — spot-checked
each new case's bounds arithmetic. No blocking findings.

CQR.08 [2026-07-30]: Reviewed for consistency with existing conventions.
The three-layer split (library → IPC → CLI) mirrors the existing
`login`/`LOGIN_REQ`/`cmd_login` pattern throughout. The IPC payload
doc-comment block in `vw_ipc.h` follows the existing per-message-type
convention. Buffer-sizing arithmetic in the new `vw_client_core.c`
functions and `vw_daemon.c` cases was checked for truncation safety
(`VW_MAX_PATH_BYTES`/`VW_MAX_USERNAME_BYTES`-bounded copies throughout, no
raw `strcpy`/`sprintf`). The `vpath_child()` fix is a minimal, well-scoped
correction (one shared helper, three call sites) rather than a broader
rewrite of `vw_sync.c`'s path-handling — appropriate given the bug's actual
blast radius (root-level sync folders only). No blocking findings; one
advisory: `LINK_LIST_REQ`'s `file_id_filter` is plumbed through the
library and IPC layers but never exposed as a CLI option — harmless
(the CLI simply always requests "all my links"), but worth remembering if
`list-links --file <path>` is ever wanted; left as-is rather than adding
an unused-from-the-only-caller CLI flag speculatively.

ARCH.00 [2026-07-30]: SEC.07 and CQR.08 sign-off received, no blocking
findings. Closing as done. `TASK-096` (GUI sharing) may now proceed against
this library API — the integration point for GUI.03 is: consume
`vw_client_share_*`/`vw_client_link_*` plus the file-id-based
stat/download/upload/move functions directly (all synchronous, called from
the daemon via the new IPC messages, same pattern as every other client-API
consumer); shared items are NOT yet visible in the local sync tree
(`TASK-106`), so a shared-item browser view should drive `SHARE_LIST`/
`LINK_LIST`/file-id operations directly rather than expecting them to
appear via `add-folder`/`ls`.

QA.06 [2026-07-31]: `TASK-097` closed — its regression matrix exercises
this task's `vw_client_core.c` sharing/file-id functions indirectly (via
`vw_client.py`'s wire-level equivalents, matching this file's own test
strategy) rather than directly against `vapourwault-cli`; the CLI/daemon
plumbing itself is covered by `run_integration.py`'s IT-9…IT-15 (see this
task's own notes above), so both layers now have integration coverage.
