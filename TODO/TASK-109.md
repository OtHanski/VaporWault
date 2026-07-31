---
id:          TASK-109
title:       FILE_LIST_RESP never carries version_id — remote-change detection silently relies on it anyway
status:      todo
assignee:    CLI.02
created_by:  CLI.02
created:     2026-07-31
priority:    normal
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [client, server, sync, protocol]
---

Discovered while implementing `TASK-106` (sync engine awareness of shared
folders): `FILE_LIST_RESP`'s per-entry wire layout (`docs/PROTOCOL.md` §7.2,
`handle_file_list` in `src/server/vw_file_handlers.c`) never includes
`version_id` — only `name`, `file_id`, `size_bytes`, `mtime_unix`,
`entry_type`, `perm`. `vw_client_file_list()`'s decode
(`src/client/vw_client_core.c`) correspondingly never sets
`vw_file_entry_t.version_id`, so it is always `0` (from `calloc`).

`vw_sync.c`'s `srv_push` copies `e->version_id` into `srv_entry_t`
regardless (always `0`), and `compute_actions`'s remote-change detection
compares `ce.server_version_id != se->version_id` to decide whether the
server has a newer version than what was last synced. Since both sides of
that comparison are `0` for every file discovered via `FILE_LIST` (as
opposed to `FILE_STAT`, which *does* return a real `version_id`), **this
comparison can never be true** — a file uploaded once, then modified by a
different client, is never redetected as changed by an ongoing sync cycle
that relies on `FILE_LIST` to enumerate a folder. Only the "not yet in
local cache at all" path (a brand-new remote file) downloads correctly,
since that path doesn't depend on the version_id comparison.

**Not fixed here**: `TASK-106` worked around this with a client-local,
wire-format-safe fix (`compute_actions` also compares `mtime_unix`/
`size_bytes`, which *are* correctly populated by `FILE_LIST_RESP`, catching
the same real-world change-detection cases without needing a wire change)
— see `TASK-106`'s notes for why that's an adequate practical fix, not a
full resolution. A *proper* fix means adding `version_id` to
`FILE_LIST_RESP`'s per-entry layout, which is a repeated fixed-shape
structure (unlike every other "optional trailing field at the end of one
message" extension elsewhere in this codebase) — safely extending a
*repeated* structure without breaking old-client decode needs its own
design pass (e.g. making each entry self-length-prefixed so an old client
can skip trailing bytes per-entry, the way length-prefixed strings already
allow skipping unknown trailing content within one field) rather than
being folded into `TASK-106` under time pressure.

## Acceptance criteria

- Design and implement a backward-compatible way to extend `FILE_LIST_RESP`
  per-entry data (starting with `version_id`, but ideally general enough
  for future per-entry fields too).
- `compute_actions`'s remote-change detection uses the real `version_id`
  once available; the `mtime`/`size` fallback from `TASK-106` may stay as
  defense-in-depth (a version bump race is still worth catching by proxy)
  but should no longer be the *only* signal.
- Regression test: a file modified by one client is redetected as changed
  by a second client's *ongoing* sync cycle (not just a first-time sync),
  which is the exact scenario this bug silently breaks today.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-07-31]: Filed while implementing `TASK-106`. Own domain, but
deliberately not fixed in place — a safe wire-level fix to a *repeated*
structure's per-entry layout is a bigger, riskier change than anything
else touched this session, and deserves the same "own design pass"
treatment `TASK-106` itself got, not a rushed tangent.
