---
id:          TASK-104
title:       No wire message to create a directory (VW_ENTRY_DIR) — folders can only exist via ancestor auto-creation gaps
status:      done
assignee:    PRT.04
created_by:  SRV.01
created:     2026-07-30
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [protocol, server, client, bug]
---

Discovered while writing `tests/integration/test_sharing.py` for `TASK-094`:
there is no wire message, in the current protocol, that creates a directory
(`VW_ENTRY_DIR`) record on the server. Confirmed by grepping the whole
codebase for `VW_ENTRY_DIR` — the only place it is ever *assigned* to a
record is directly through `vw_store_file_create` (bypassing the wire), or
in test-only helpers that call that same store API directly. `vw_sync.c`'s
sync engine explicitly skips directories (`if (se->entry_type ==
VW_ENTRY_DIR) continue;`) rather than creating them remotely.

`handle_file_commit` (`vw_file_handlers.c`) is the only message that
creates new file-table records at all, and:
- Its path-based branch always creates `entry_type = VW_ENTRY_FILE`, never
  `VW_ENTRY_DIR`.
- It does not auto-create missing ancestor directories ("mkdir -p"
  semantics) — if the parent path component doesn't already exist as a
  directory record, it fails with `VW_ERR_NOT_FOUND`.

Net effect: a real client has no way to create a folder on the server at
all, before or after `TASK-094`. This is why `TASK-094`'s own integration
tests (`test_sharing.py`) are written root-level-file-only — folder-sharing
scenarios (a link/grant on a folder, walk-up permission inheritance to its
children) could only be exercised at the unit level
(`tests/unit/test_vw_share.c`, which builds folder records directly via
`vw_store_file_create`).

This is a general Phase 2 file-model gap, not sharing-specific — it would
block any real folder-based workflow (sync clients mirroring local folder
structure, GUI "New Folder" actions, `TASK-096`'s sharing UI needing to let
a user share an actual folder they created through the app) regardless of
sharing.

## Acceptance criteria

- A wire mechanism exists for the client to create a directory record
  (either a new dedicated message, or `FILE_COMMIT`/an equivalent gaining
  "mkdir -p" semantics for intermediate path components — PRT.04's call on
  which fits the existing protocol shape better).
- `docs/PROTOCOL.md` documents the new/changed message.
- A regression test creates a nested directory structure over the wire (not
  via direct store API calls) and confirms `FILE_LIST`/`FILE_STAT` see it.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-07-30]: Filed per CLAUDE.md's out-of-domain discovery rule —
this is a protocol design gap (PRT.04's domain), discovered while
integration-testing TASK-094, not something TASK-094 itself should fix
(sharing doesn't need to invent directory creation; it just needs
directories to exist, which they currently can't via the wire at all).

PRT.04 [2026-07-31]: Chose a new dedicated message pair,
`FILE_MKDIR`/`FILE_MKDIR_ACK` (0x0211/0x0212 — the two opcodes immediately
following `FILE_MOVE`/`FILE_MOVE_ACK`), over giving `FILE_COMMIT` "mkdir -p"
ancestor auto-creation semantics. Reasons:
- This protocol consistently favors explicit single-record operations over
  implicit multi-record side effects — `FILE_MOVE` never silently creates
  its destination either; "mkdir -p" would be the first operation to break
  that pattern.
- Auto-creating ancestors on `FILE_COMMIT` would require a permission
  check per implicitly-created intermediate directory (each could sit
  under a different owner in a shared-folder chain), multiplying
  `handle_file_commit`'s already-substantial branching for a case a
  dedicated message sidesteps entirely — one explicit `FILE_MKDIR` per
  path component is simpler to reason about and to permission-check.
- `new_parent_dir_id` + bare leaf `name` mirrors `FILE_MOVE`'s existing
  `new_parent_dir_id`/`new_name` shape, and the permission rule reuses
  `FILE_COMMIT`'s already-specified "creating a new file under a shared
  folder needs EDIT on the parent" rule (§7.5) verbatim — no new
  permission concept introduced.

Payload, permission rule, and rate-limiting behavior documented in
`docs/PROTOCOL.md` §7.2 (see `FILE_MKDIR payload` there). Version history
row 11 added; purely additive, no protocol version bump (same reasoning as
`TASK-094`'s row 10).

SRV.01 [2026-07-31]: Implemented `handle_file_mkdir` in
`vw_file_handlers.c`, reusing `permission_on_dir_or_root`/
`require_permission` (both already existed for `FILE_MOVE`) rather than
introducing new helpers. Applies the same per-scoped-session write-count
rate limit as every other write op, per PRT.04's spec note.

**Bug found and fixed while writing the regression test (in-domain —
`vw_file_handlers.c` is SRV.01's own module, same "fix in place, don't file
separately" reasoning as `TASK-105`'s note on that distinction):**
`handle_file_commit`'s "creating a new file under a shared folder" branch
(added in `TASK-094`, for a `file_id` that names a directory) has been
**unreachable in every real scenario since it was written** — before this
task, there was no way to get a real directory record to target at all, so
nothing ever exercised it end-to-end. The bug: the general path-validation
block earlier in the same handler runs `vw_path_validate()` (which requires
a leading `/`, since it's meant for absolute virtual paths) unconditionally
whenever `path_len > 0` — but for the folder-target branch, `path` is a
*bare leaf name* with no leading `/` by design, so every such call was
rejected with `VW_ERR_PATH_INVALID` before ever reaching the branch that
would have accepted it. Fixed by gating the absolute-path check on
`file_id == 0` (path-based addressing only) — the folder-target branch's
own bare-leaf-name validation (already correct, checking for `/`/NUL and
length, just never reached) now actually runs. Confirmed via
`test_folder_share_edit_grant_allows_creating_children` (new,
`test_sharing.py`), which reproduced the bug against the pre-fix binary
first, then passed after the fix.

QA.06 [2026-07-31]: Regression tests added:
- `tests/integration/test_file_ops.py`:
  `test_mkdir_creates_nested_directory_structure` (two-level nested
  structure created purely over the wire, confirmed via both file-id- and
  path-based `FILE_LIST`/`FILE_STAT`, including a file uploaded inside the
  deepest directory) and `test_mkdir_duplicate_name_rejected`.
- `tests/integration/test_sharing.py`: `test_folder_share_view_grant_
  blocks_creating_children` and `test_folder_share_edit_grant_allows_
  creating_children` — the folder-sharing scenarios `test_sharing.py`'s own
  module docstring had disclosed as unit-test-only until now; updated that
  docstring accordingly rather than leaving it stale. Also closed
  `TASK-097`'s own disclosed gap while here: `test_file_move_rejects_
  destination_owned_by_someone_else` and `test_file_move_directory_into_
  own_descendant_rejected` — both needed a real cross-owner folder to move
  into/around, which is exactly what this task unblocks. See `TASK-097`'s
  notes for the cross-reference.

Validation: full pytest integration suite (43 tests across all six files,
up from 37 before this task's 6 new tests — 2 in `test_file_ops.py`, 4 in
`test_sharing.py`) passes. GCC/WSL full build clean (`-Werror`). MSVC
(`vapourwaultd`/`vapourwault-daemon`/`vapourwault-cli`/
`vapourwault-server-cli`) builds clean.

CQR.08 [2026-07-31]: Reviewed `handle_file_mkdir` against `handle_file_move`
and `handle_file_commit`'s folder-target branch, which it deliberately
mirrors. Confirmed the `path_len == 0` guard's fix (`file_id == 0 &&
path_len > 0`) doesn't change behavior for either pre-existing case it
touches: file_id==0/path_len==0 was already handled by a separate
`VW_ERR_INVALID_ARG` branch further down, and file_id!=0-targeting-a-file
never reads `path_buf` at all in that branch, so skipping validation for it
is inert, not a new gap. No blocking findings.

ARCH.00 [2026-07-31]: CQR.08 sign-off received, no blocking findings.
Closing as done. `TASK-096` (GUI sharing) can now offer a real "share a
folder you created" flow, and `TASK-106` (sync-engine folder awareness)
is no longer blocked on folder creation existing at all — both still have
their own open scope beyond this.
