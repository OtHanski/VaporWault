---
id:          TASK-199
title:       "Client: daemon IPC + vapourwault-cli search"
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-198]
blocks:      [TASK-200]
review_by:   [CQR.08]
tags:        [client]
---

**Correction (2026-08-26)**: `TASK-197`'s published wire spec (§7.12) has
no cursor/pagination — `SEARCH_RESP` is one response, capped at 200
entries, with a `truncated` flag. This Work section originally assumed
a cursor existed to expose or hide from the caller; there is none.
Replaced below.

## Work

- `vw_client_core.c`/`.h`: `vw_client_search()` wrapper over the new
  `SEARCH`/`SEARCH_RESP` messages — one request, one response, returns a
  malloc'd array of entries + count + a `truncated` out-flag (same
  "malloc'd array; caller frees" convention as `vw_client_share_list`/
  `vw_client_link_list`). No cursor to manage on either side.
- Daemon IPC: new `VW_IPC_SEARCH_REQ`/`_RESP` (account-scoped, next free
  opcode pair after the existing highest `0x80xx` messages).
- `vapourwault-cli search <query>` prints matches (path or name, size,
  mtime) and, if `truncated` came back set, a trailing note that results
  were capped and to narrow the query — no pagination UX to build since
  there's no cursor to page through.

## Acceptance criteria

- `vapourwault-cli search <query>` returns matches across the whole
  account's visible tree, not just the current directory.
- Works while on fallback (read-only) since this is a read.
- A truncated result set (>200 matches) is surfaced to the user as a
  hint to narrow the query, not silently presented as complete.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-08-26]: Implemented per the corrected Work section above.

- `vw_client_core.h`/`.c`: new `vw_search_entry_t` + `vw_client_search()`,
  modeled directly on `vw_client_link_list`'s malloc'd-array convention.
  One request, one response — no cursor state to hold anywhere in this
  layer, matching `TASK-197`'s actual wire shape.
- `vw_ipc.h`: new `VW_IPC_SEARCH_REQ`/`_RESP` (0x803D/0x803E, next free
  pair after `FOLDER_SET_EXCLUDES`). Documented payload mirrors
  `VERSION_LIST_REQ`'s `u32 account_id + string` shape exactly.
- `vw_daemon.c`: new `VW_IPC_SEARCH_REQ` case, modeled on
  `VW_IPC_VERSION_LIST_REQ`'s handler (a **read** — deliberately NOT
  modeled on `VERSION_RESTORE_REQ`'s `account_is_read_only()`-gated
  write pattern). This is what satisfies "works while on fallback": the
  handler simply never checks read-only status, the same as every other
  read-shaped IPC case in this switch.
- `vw_client_cli.c`: `search <query>` subcommand + usage text, printing
  file_id/type/shared/mtime/name columns and a trailing note when
  `truncated` comes back set.
- Built clean on both toolchains after every change (WSL/GCC
  `build-gw-e2e`, MSVC `build-msvc-105`, Release).

**Testing**:

- New `tests/integration/test_cli_search.py`, driving the real compiled
  `vapourwault-cli` against a real daemon + server (three accounts:
  owner/grantee/stranger). Confirms end-to-end through the whole new
  stack (server → `vw_client_search` → daemon IPC → CLI output), not
  just that each layer compiles: owner sees both of their files;
  grantee sees only the one shared with them; stranger's search
  succeeds with zero results; a case-differing query still matches.
  The server-side permission-safety properties themselves (invisible
  matches genuinely invisible, the 200-entry cap boundary) are already
  proven once at the wire level by `TASK-198`'s `test_search.c` — this
  test isn't re-proving those, just that the daemon/CLI plumbing carries
  them through intact.
- **Found and fixed a real test-infra issue while first running this**:
  the shared `server` fixture's default `max_workers=2` isn't enough
  once three accounts are added to one daemon (each account holds a
  persistent connection for its own background sync cycle, unlike
  `TASK-198`'s short-lived test-harness sessions that could just be
  closed between steps) — the daemon's third `ACCOUNT_ADD_REQ` blocked
  forever waiting for a free server worker. Fixed by instantiating this
  test's own `ServerInstance` with `max_workers=4` rather than using the
  shared fixture.
- **Found and filed a real, separate product gap while first writing
  this test**: creating a new local subdirectory and putting a file in
  it never syncs up through the ordinary background watcher at all —
  traced to `vw_sync.c`'s local walk never representing a directory as
  a syncable entity (no `ACT_MKDIR` for a *local-only* new directory
  exists anywhere in that file — grepped, zero matches; the only
  existing directory-creation path is the reverse, `TASK-113`'s
  remote-directory-appears-locally case) combined with the server's
  `FILE_COMMIT` handler requiring the parent directory to already exist
  (`VW_ERR_NOT_FOUND` otherwise, by design — it's documented as a
  leaf-level operation, not a recursive-create). Filed as `TASK-218`
  (CLI.02/sync-engine) rather than fixed here — out of this task's
  scope, and this test was rewritten to avoid the nested-directory
  scenario entirely (both test files placed at top level; a folder
  share became a single-file share) rather than block on that fix.
- Full regression check green on both toolchains after this change:
  `ctest` (WSL: 19/19, MSVC: 18/18 — the one difference is a pre-existing
  `NOT WIN32`-guarded `integration` ctest entry, `run_integration.py`,
  `tests/integration/CMakeLists.txt:333`; unrelated to this task) and the
  non-cluster pytest integration suite.

Moving to `review`.

CLI.02 [2026-08-26]: Full regression confirmed green after finalizing —
non-cluster pytest integration suite: `108 passed, 15 deselected`
(includes both `test_cli_search.py` and `TASK-198`'s `test_search.py`).

CQR.08 [2026-08-26]: Reviewed for code quality and consistency.

- `vw_client_search()` follows `vw_client_link_list`'s exact
  malloc'd-array/`recv_expect` convention — no new pattern introduced.
- Daemon `VW_IPC_SEARCH_REQ` case correctly modeled on the *read*
  handler (`VERSION_LIST_REQ`), not the write-gated one — verified this
  is what actually makes "works on fallback" true, not just an assertion
  in the notes.
- IPC opcode numbering, payload doc block, and CLI usage text all follow
  this file's existing conventions (`account_id` first, string second;
  usage line format matches `version`/`list-links` neighbors).
- The two discoveries during implementation (test-server
  `max_workers` headroom; `TASK-218`'s new-local-subdirectory sync gap)
  were each handled correctly per `CLAUDE.md`'s protocol: the former
  fixed locally (test's own `ServerInstance` config, not a shared
  fixture), the latter filed as a separate task rather than silently
  worked around or fixed out-of-scope.
- No blocking findings. Approved.
