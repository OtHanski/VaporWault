---
id:          TASK-220
title:       "Protocol: replicate notify_prefs.db to hot-standby replicas"
status:      todo
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
