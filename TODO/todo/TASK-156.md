---
id:          TASK-156
title:       FILE_LIST_RESP never populates vault_id per entry (only FILE_STAT/VERSION_CHUNKS do)
status:      todo
assignee:    PRT.04
created_by:  WEB.09
created:     2026-08-12
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [protocol, client, web]
---

Discovered while implementing the web gateway's vault UI (`TASK-141`) —
out-of-domain for `WEB.09` (wire protocol / native client), filed per
`CLAUDE.md`'s routing rule rather than fixed in place.

## The gap

`vw_client_file_entry_t.vault_id` (`vw_client_core.h`) is a real field with
real intent — the type's own comment says it exists so a caller "can show
a lock icon" for encrypted content in a listing. But `vw_client_file_list`
(`src/client/vw_client_core.c`, `recv_file_list_resp`) never actually sets
`entries[i].vault_id` from the wire response at all; it's left at its
`calloc`-zeroed default (0) for every entry, always, regardless of whether
the underlying file is vault-encrypted.

Confirmed by reading the server's own `FILE_LIST_RESP` wire-format comment
(`src/server/vw_file_handlers.c` around line 382) and the actual
`resp[]`-writing code around it (lines ~403-420): the per-entry fields
written are `file_id`, `size_bytes`, `mtime_unix`, `entry_type`, `perm`,
and (TASK-109's later addition) `version_id` — no `vault_id` field exists
in this response's wire format at all. Only `FILE_STAT_RESP`
(`handle_file_stat`, ~line 481-518) and `VERSION_CHUNKS_RESP`
(~line 1491-1519) actually carry it.

## Impact

Nothing that reads `vw_client_file_list`'s output can tell which files in
a listing are vault-encrypted without an extra `FILE_STAT` call per entry
— this affects **every** consumer, not just the new web gateway:

- The native GUI (`src/gui/`) presumably wants a lock icon on encrypted
  files in its file browser (matching the "can show a lock icon" comment's
  own stated purpose) and has the identical limitation.
- The web gateway's frontend (`TASK-141`) worked around this by keying
  off "is the *containing folder* a registered vault" instead of the
  per-file field (correct for anything the web client itself uploads,
  since every file it commits into a vault folder carries that vault's
  id) — but this only works because of that upload-time invariant, not
  because the underlying gap is actually closed. A file uploaded by some
  other means into a vault folder, or a vault situation this project
  hasn't built yet, could break that assumption.

## Suggested fix (PRT.04 to decide, not prescribed here)

Add a per-entry `vault_id(u64)` field to `FILE_LIST_RESP`'s wire format
(files only, `0` for directories — matching `FILE_STAT_RESP`'s existing
convention) and have `recv_file_list_resp` actually populate
`entries[i].vault_id` from it. A wire format change needs a version bump
per `docs/PROTOCOL.md`'s own versioning discipline; not this task's call
to make.

## Acceptance criteria

- `FILE_LIST_RESP` carries a real per-entry `vault_id`, and
  `vw_client_file_list`/`vw_client_file_list_by_id` populate it correctly.
- A regression test confirming a vault-encrypted file shows its real
  `vault_id` from a plain listing, not just from `FILE_STAT`.
- `docs/PROTOCOL.md` updated with the new field and any version bump.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-12]: Filed while implementing `TASK-141`'s vault UI —
confirmed by reading `recv_file_list_resp` and the server's
`FILE_LIST_RESP`-writing code, not just suspected from a test result.
Worked around it in the web frontend rather than blocked on it; see
`TASK-141`'s own implementation note for the workaround's reasoning and
its limits.
