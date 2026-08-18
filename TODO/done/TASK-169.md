---
id:          TASK-169
title:       ARCH.00 design: opt-in automatic client fallback to a replica
status:      done
assignee:    ARCH.00
created_by:  ARCH.00
created:     2026-08-14
priority:    high
depends_on:  []
blocks:      [TASK-170, TASK-171, TASK-172, TASK-173, TASK-176]
review_by:   [CQR.08]
tags:        [design]
---

User request: an opt-in automatic fallback server for when the primary is
down, additive to the existing manual reconfiguration option.

Three decisions were needed before any implementation could start, all
resolved directly with the user (not assumed):

1. **Fallback writes**: read-only while degraded (writes queue locally and
   flush to the primary once it's back), not read-write. Read-write would
   have reopened exactly the split-brain risk `ARCHITECTURE.md`'s existing
   "Primary failover: None" decision was written to avoid.
2. **Fallback source**: must be an already-`vw_cluster`-paired replica
   (not an arbitrary second server with no data relationship to the
   primary).
3. **Scope**: both the client daemon (covers CLI + GUI) and the web
   gateway.

Implementing decision 2 as stated surfaced a real gap: a "replica" today
(`vw_cluster.c`) only ships the oplog *notification* stream to a second
node's own oplog file — it never applies those notifications to that
node's live, queryable store (`vw_store.c`/`vw_storage.c`). Confirmed by
reading every op type's actual `vw_oplog_append` call site
(`vw_store_files.c`/`vw_vault.c` etc.): payloads are bare IDs (e.g.
`VW_OPLOG_FILE_CREATE`'s payload is literally just `owner_id`), never the
full record. So "must be a configured replica" as it exists today would
have meant failing over to a server with no actual data. Asked the user
directly rather than silently scoping down or silently building more than
asked: build real record+chunk replication so a replica is a genuine hot
standby. Confirmed (recommended option accepted).

This also surfaced a second, independent latent bug while researching the
above: `vw_gc.c`'s chunk deletion has zero regard for replica lag (only
oplog *segment truncation* is gated on `vw_cluster_min_sync_watermark()`
today) — a lagging replica could have a chunk vanish from under it before
it ever syncs the content. Recorded as its own decision/task (`TASK-171`)
since it's an independently reviewable fix to a different subsystem
(`vw_gc.c`, not `vw_cluster.c`'s replication loop), even though the same
design pass found it.

## Decisions recorded (`ARCHITECTURE.md`, Decision Log table)

- `Primary failover` row amended (still no automatic *promotion*/consensus
  — that risk is unchanged and deliberately unsolved — but clients can now
  fail over themselves, read-only).
- New row: `Replica hot-standby data replication` (`CLUSTER_RECORD_FETCH`/
  `_DATA`, `CLUSTER_CHUNK_QUERY`/`_FETCH`/`_DATA`, `0x0708`+).
- New row: `GC replica-safety gating`.
- New row: `Client-side automatic fallback (read-only)`.

## Task breakdown

| Task | Assignee | Depends on | review_by | tags |
|------|----------|------------|-----------|------|
| `TASK-170` — Protocol: publish `CLUSTER_RECORD_*`/`CLUSTER_CHUNK_*` wire spec in `docs/PROTOCOL.md` | PRT.04 | 169 | CQR.08 | protocol |
| `TASK-171` — Server: GC replica-safety gating (`vw_gc.c` chunk deletion gated on `vw_cluster_min_sync_watermark()`) | SRV.01 | 169 | SEC.07, CQR.08 | security-sensitive, server |
| `TASK-172` — Server: replica hot-standby data replication (record fetch + chunk sync, extends `vw_cluster.c`'s replica pull loop) | SRV.01 | 170, 171 | SEC.07, CQR.08 | security-sensitive, server |
| `TASK-173` — Daemon: per-account fallback config + read-only failover connection logic + offline-queue integration | CLI.02 | 172 | SEC.07, CQR.08 | security-sensitive, client |
| `TASK-174` — `vapourwault-cli`: `--fallback-host`/`--fallback-port`/`--fallback-ca-cert` on `account add`, shown in `account list` | CLI.02 | 173 | CQR.08 | client |
| `TASK-175` — GUI: fallback fields in the "Add account" dialog, a visible "read-only (fallback)" indicator distinct from plain offline | GUI.03 | 173 | CQR.08 | gui |
| `TASK-176` — Gateway: `--fallback-server-host`/`--fallback-server-port`/`--fallback-ca-cert` + read-only failover connection logic | WEB.09 | 172 | SEC.07, CQR.08 | security-sensitive, gateway |
| `TASK-177` — Docs: `docs/DEPLOYMENT.md` end-to-end primary+replica+fallback setup walkthrough | BLD.05 | 172, 173, 176 | CQR.08 | docs |
| `TASK-178` — Integration tests: replica hot-standby correctness, GC-safety regression, daemon/gateway automatic fallback (read-only success + write-queue-and-flush), replica-lag chunk-safety | QA.06 | 170–177 | CQR.08 | test |

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-14]: Design complete, `ARCHITECTURE.md` updated, task
breakdown above created directly in `TODO/todo/`. Proceeding to `TASK-170`
next (protocol spec must land before `TASK-172`'s implementation, per
`CLAUDE.md`'s routing rule 3).
