---
id:          TASK-157
title:       FILE_MOVE never updates the path_ht index — renamed/moved files become permanently unresolvable by path
status:      todo
assignee:    SRV.01
created_by:  WEB.09
created:     2026-08-12
priority:    critical
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, storage, security-sensitive]
---

Discovered while writing `TASK-143`'s integration tests for the web
gateway — out-of-domain for `WEB.09` (server storage internals), filed
per `CLAUDE.md`'s routing rule rather than fixed in place. Reproduced via
the raw wire protocol directly (`vw_client.py`, zero gateway involvement)
as well as through the gateway, confirming this is a server bug, not
something the gateway introduces.

## The bug

`src/server/vw_store_files.c` maintains `path_ht`, a hash table keyed by
`(owner_id, fnv1a(leaf_name))` mapping a name to its record slot, used by
`vw_store_file_get_by_path` (and therefore `FILE_STAT`, and anything else
that resolves a virtual path). This index is only ever populated in two
places:

- Store-open (`vw_store_files.c` ~line 349-368): a full scan of `meta.dat`
  rebuilds it from scratch.
- `vw_store_file_create` (~line 516): inserts the new record's name.

**`handle_file_move` (`src/server/vw_file_handlers.c:2021-2110`) updates
the file record's `name`/`parent_dir_id` fields via
`vw_store_file_update` (line ~2103) but never touches `path_ht` at
all** — no removal of the old `(old_name, old_parent)` entry, no
insertion of the new one. `vw_store_file_update` itself doesn't touch
`path_ht` either (confirmed by reading its full body — no `path_ht_*`
call anywhere in it).

`path_ht_find_in_dir` (`vw_store_files.c:250-278`) does cross-verify a
hash hit against the record currently on disk
(`strncmp(rec.name, name, 63) == 0`, line 276) before trusting it — this
is what turns a stale index into "not found" rather than "found the
wrong file," but the practical effect is that **both the old and the new
name become unresolvable by path**, permanently, until the server
restarts (which rebuilds `path_ht` from scratch and fixes it — this is
why the corruption doesn't compound across restarts, but does affect
every renamed/moved item until the next one).

## Reproduction (real, not hypothetical; both paths tested independently)

Via the web gateway:
```
POST /api/files/mkdir {"name":"repro_dir"}          -> {"dir_id":21}
POST /api/files/move {"file_id":21,"new_name":"repro_renamed","new_parent_dir_id":0}
                                                      -> {"status":"ok"}
POST /api/files/stat {"path":"/repro_renamed"}       -> {"status":"not_found"}   <- BUG
POST /api/files/stat {"path":"/repro_dir"}           -> {"status":"not_found"}   <- BUG (old name too)
POST /api/files/list {"path":"/","recursive":false}  -> shows "repro_renamed", file_id 21, correctly  <- proves the record itself is fine
```

Via the raw wire protocol directly (`vw_client.py`, no gateway at all —
confirms this isn't gateway-introduced):
```python
dir_id = c.file_mkdir(token, "direct_repro_dir")           # succeeds
c.file_stat(token, path="/direct_repro_dir")                # succeeds, file_id matches
c.file_move(token, dir_id, new_parent_dir_id=0, new_name="direct_repro_renamed")  # succeeds
c.file_stat(token, path="/direct_repro_renamed")             # VwProtocolError: server error code=5 (NOT_FOUND)
c.file_list(token, path="/")                                 # shows "direct_repro_renamed", file_id matches
```

## Impact

This affects **every** consumer of `FILE_STAT`/path-based lookups after
any `FILE_MOVE` (rename OR relocate), not just the gateway:

- The native CLI/GUI/sync engine's own path-based operations on a
  renamed/moved item break the same way (`vw_client_file_stat`,
  `vw_client_file_download`, `vw_client_file_upload`'s path-based
  create-new-version case, `vw_client_file_delete` when called by path)
  until the server restarts.
- File-id-based operations (`vw_client_file_stat_by_id`,
  `vw_client_file_download_by_id`, etc., TASK-095) are unaffected — they
  never go through `path_ht` at all — so the sync engine's own steady-
  state operation on already-known file_ids is likely fine; this
  specifically hits anything that re-resolves a path fresh after a move,
  which is common for a simple client (e.g. the web gateway's frontend,
  `TASK-138`, navigates and re-stats by path routinely) and for the
  first path lookup after any rename from any client.
- This is a **basic, ubiquitous operation** (any rename or move) breaking
  a **basic, ubiquitous follow-up** (stat/re-resolve that path) — not an
  edge case requiring unusual input.

Tagged `security-sensitive` because the failure mode is fail-closed
(`NOT_FOUND`, not e.g. resolving to the wrong file) as far as this
review found, but SEC.07 should confirm that independently rather than
take this filing's word for it — a stale index in a security-relevant
lookup path is exactly the kind of thing worth a second look.

## Suggested fix (SRV.01 to decide, not prescribed here)

`handle_file_move` (or `vw_store_file_update` itself, if every caller of
it that changes `name`/`parent_dir_id` should get this for free) needs to
remove the old `(old_name, old_parent_dir_id)` `path_ht` entry and insert
a new `(new_name, new_parent_dir_id)` one as part of the same operation
that updates the record — no `path_ht_remove` function exists yet
(only `path_ht_insert`/`path_ht_find_in_dir`/`path_ht_grow`), so this
likely needs a new removal primitive (open-addressed hash tables need
careful tombstone/backward-shift handling on delete — mishandling that
could reintroduce a different bug, so this isn't a trivial one-liner).

## Acceptance criteria

- After a `FILE_MOVE` (rename and/or relocate), `FILE_STAT` on the new
  path resolves correctly on the first call, no restart required.
- The old path correctly returns `NOT_FOUND` after the move (this part
  already works, just for the wrong reason).
- A regression test covering mkdir → move → stat-by-new-path, added to
  `tests/unit` (`test_vw_store_files.c`-equivalent) and/or
  `tests/integration` (`TASK-143`'s `test_gateway.py` has a version-list
  test that would have caught this if this gap didn't block it first —
  worth checking whether existing `tests/integration/test_*.py` files
  have equivalent path-based-after-move coverage that should have caught
  this earlier, or whether this is a real coverage gap across the whole
  suite, not just new `TASK-143` work).
- Server restart is no longer a workaround needed for this scenario.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-12]: Filed while writing `TASK-143`'s integration tests —
a `mkdir → move → stat` test sequence failed unexpectedly; root-caused by
reading `vw_store_files.c` in full (not just observed and guessed) before
filing this. Worked around in `TASK-143`'s own test suite by not
asserting path-based `stat` immediately after a `move` in the affected
test (see `test_gateway.py`'s own note at that test) — `FILE_LIST`-based
assertions are used instead where the test only needs to confirm the
rename itself took effect, which isn't affected by this bug.
