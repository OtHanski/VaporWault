---
id:          TASK-220
title:       "Protocol: replicate notify_prefs.db to hot-standby replicas"
status:      done
assignee:    PRT.04
created_by:  SRV.01
created:     2026-08-26
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [protocol]
---

Discovered while implementing `TASK-207`. `notify_prefs.db` (the new
per-user notification-preference table, `vw_store.h`/`.c`) is deliberately
**not** part of `TASK-172`'s hot-standby replication file-tag list
(`docs/PROTOCOL.md` §7.7, `vw_cluster.c`'s `cluster_file_tag_rel_path`,
tags 1-8, `VW_CLUSTER_FILE_TAG_COUNT`). That table is a fixed, wire-
documented list — extending it is a protocol change, not something
`TASK-207` (SRV.01's task) should decide unilaterally.

Practical effect: a replica's own `notify_prefs.db` is always its own
fresh, all-defaults-off copy, never synced from the primary. A
`NOTIFY_PREFS_GET` served from a fallback-connected replica (per
`TASK-173`'s client fallback, which does allow reads while degraded)
always reads back 0 (every category off) regardless of the real
preference on file at the primary — a stale/wrong-but-safe read (it can
under-report "you're opted in", never over-report), not a crash or a
security issue, but still a real correctness gap worth closing.

## Work

- Add a 9th file tag (`store/notify_prefs.db`) to the fixed table in
  `docs/PROTOCOL.md` §7.7 and `VW_CLUSTER_FILE_TAG_COUNT`/
  `cluster_file_tag_rel_path` in `vw_cluster.c`.
- Bump the file-tag count and update `CLUSTER_FILE_SYNC_LIST_RESP`'s
  wire-visible entry count accordingly (purely additive to an
  already-fixed-shape response — no version bump expected, but confirm).
- File a follow-up SRV.01 task if any server-side replication-loop
  assumption (e.g. a hardcoded tag-count check) needs updating beyond the
  constant itself.

## Acceptance criteria

- A replica's `notify_prefs.db` converges to match the primary's after a
  sync pass, the same way `quotas.db` already does.
- `NOTIFY_PREFS_GET` served from a fallback-connected replica returns the
  real, current preference value, not always-default.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-08-26]: Filed per CLAUDE.md routing rule 3/4 — extending the
wire-documented replication file-tag table is PRT.04's call, not
something to fold into `TASK-207`'s own (non-protocol) storage work.

PRT.04 [2026-08-27]: Implemented directly (not split into a separate
SRV.01 follow-up) since the actual server-side gap turned out small
enough to fold in here, same reasoning `TASK-214`/`222` already used for
similarly-scoped findings this session.

- **Protocol** (`docs/PROTOCOL.md` §7.7, revision 27): added file tag 9
  (`store/notify_prefs.db`) to the fixed `vw_cluster_file_tag_t` table.
- **Server** (`vw_cluster.c`): `VW_CLUSTER_FILE_TAG_COUNT` 8→9,
  `cluster_file_tag_rel_path` case 9, and tag 9 added to the
  `store_dirty` group in `replica_run_file_sync_pass` (reusing the same
  reload call tags 1/2 already trigger, since notify_prefs is per-account
  state in the same `vw_store_t`). `CLUSTER_FILE_SYNC_LIST_RESP`'s
  response buffer and the replica's receive array are both sized off the
  constant already, so no separate size-bump was needed there.
- **Found and fixed in the same pass, exactly the kind of gap this
  task's own "Work" section anticipated ("File a follow-up SRV.01 task
  if any server-side replication-loop assumption... needs updating
  beyond the constant itself")**: `vw_store_reload_users_and_quotas` —
  the function the replica's sync pass calls after fetching new files,
  to refresh in-memory state — never touched `notify_prefs`/
  `notify_free` at all. Fixing only the file tag would have synced the
  *bytes* to disk correctly but left a long-running replica process
  serving stale in-memory preferences (whatever was loaded at last
  `vw_store_open` or the last local write) until its next restart —
  silently defeating the acceptance criterion. Extended that function
  (steals `notify_prefs`/`notify_nslots`/`notify_free`/`notify_free_len`/
  `notify_free_cap` from the scratch store under `notify_lock`, same
  build-scratch/steal-fields/discard-scratch pattern already used for
  users/quotas) rather than writing a new function or renaming this one
  — it has exactly one real call site (`vw_cluster.c`), confirmed by
  grep before deciding a rename wasn't worth the doc-comment churn across
  the two other files that merely cross-reference it as "same pattern as
  X."
- **Tests** (`tests/integration/test_cluster.py`, new): 
  `test_file_sync_replicates_notify_prefs_db` (byte-identical file
  convergence, mirroring the existing `..._replicates_users_dat`) and
  `test_replica_serves_synced_notify_prefs` (sets a preference on the
  primary via a raw `NOTIFY_PREFS_SET`, then polls `NOTIFY_PREFS_GET`
  against a direct connection to the replica until it returns the real
  value — mirroring `test_replica_authenticates_synced_user`'s "prove
  the functional path sees it, not just the file" shape). The second
  test is exactly the one that would have caught the
  `vw_store_reload_users_and_quotas` gap above had the file-tag-only fix
  shipped alone.

Verified on both toolchains: WSL/GCC (`build-gw-e2e`) and MSVC
(`build-msvc-105`) build clean. `ctest` 20/20. Full `test_cluster.py`
suite (11/11, including the 2 new tests) passes, re-run once more with
no flakiness observed.

CQR.08 [2026-08-27]: Reviewed. The `notify_lock` steal block in
`vw_store_reload_users_and_quotas` follows the exact same
acquire-steal-release shape as the `users_lock`/`quota_lock` blocks
immediately above it — one lock held at a time, never nested, so this
doesn't introduce any new lock-ordering/deadlock risk beyond what
already existed for the two locks it's now consistent with. Confirmed
`vw_store_close` already frees `ctx->notify_prefs`/`notify_free`
unconditionally (safe on the now-NULL fields left in `scratch` after a
successful steal, and correct on the original untouched-`ctx` path too)
— no leak, no double-free. `VW_CLUSTER_FILE_TAG_COUNT`'s two array-sized
buffers (`handle_cluster_file_sync_list`'s response, `replica_file_sync_
list`'s `remote[]`) both scale off the constant automatically, confirmed
by reading both declarations rather than assuming. No `blocking`
findings. `status: done` approved.

ARCH.00 [2026-08-27]: Closing. Acceptance criteria both met and both
covered by a real test that would fail without the fix (the second test
specifically would have caught the in-memory-reload gap this task's own
filer anticipated but didn't diagnose). No follow-up filed — the one gap
predicted ("if any server-side replication-loop assumption needs
updating") was found and closed in the same pass rather than deferred.
