---
id:          TASK-104
title:       No wire message to create a directory (VW_ENTRY_DIR) — folders can only exist via ancestor auto-creation gaps
status:      todo
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
