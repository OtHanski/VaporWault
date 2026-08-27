---
id:          TASK-171
title:       "Server - GC replica-safety gating (chunk deletion vs replica lag)"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-08-14
priority:    high
depends_on:  [TASK-169]
blocks:      [TASK-172, TASK-178]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, server]
---

Found during `TASK-169`'s design research, independent of the replication
work itself: `vw_gc.c` calls `vw_storage_gc_run(ctx->chunk_store)`
unconditionally every GC cycle, deleting any chunk whose ref_count is
already zero. Unlike oplog *segment truncation* (already gated on
`vw_cluster_min_sync_watermark()` so a slow replica never loses oplog
entries it hasn't pulled yet), chunk deletion has no such gate. Once
`TASK-172` makes replicas genuinely fetch chunk content, a lagging replica
racing against the primary's own GC becomes a real, silent data-loss path:
the primary can physically unlink a chunk before a behind replica ever
copies it, with no error surfaced anywhere until a client later tries to
download that file from the failed-over replica and gets a permanent gap.

Fix this BEFORE `TASK-172` lands (it's `TASK-172`'s own dependency,
deliberately), so the new replication path is never exercised against an
unsafe GC.

## Work

- `vw_gc.c`: before calling `vw_storage_gc_run`, check
  `vw_cluster_min_sync_watermark()` (same primitive segment truncation
  already uses) against the oplog watermark that existed at the START of
  this GC cycle. If any active replica's acked watermark is behind that
  snapshot, skip chunk deletion for this cycle entirely (same conservative
  all-or-nothing granularity as the existing segment-truncation gate —
  no per-chunk bookkeeping of "which eid last touched this chunk's
  refcount," which would be a much bigger change for marginal benefit at
  this project's scale).
- A server with `cluster_port == 0`/no replicas configured must behave
  exactly as today (GC gating must degrade to a no-op check, not a hang
  or a permanent block, when there's nothing to wait for).
- Log a clear, rate-limited message when a GC cycle is skipped for this
  reason (an operator needs to know "GC is being held back by a lagging
  replica," not just silently see chunk storage grow).

## Acceptance criteria

- With no replicas configured: chunk GC behavior is bit-for-bit unchanged
  from before this task (regression test: existing `vw_gc`/GC-related
  tests still pass unmodified).
- With a replica configured and caught up: chunk GC still runs normally.
- With a replica configured and deliberately lagging (test harness pulls
  oplog slower than the primary produces it, or is paused): a
  zero-refcount chunk that a lagging replica would still need is NOT
  deleted while that replica remains behind, and IS deleted once the
  replica catches up past the relevant watermark — verified by an actual
  test (`TASK-178`), not just code inspection.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**SRV.01 [2026-08-14]:** Implemented as designed — `vw_gc.c`'s phase 3
(file/version/chunk GC) now checks `vw_cluster_has_active_replicas`/
`vw_cluster_min_sync_watermark` the same way phase 2 (oplog truncation)
already did, and skips the WHOLE phase (not just the final
`vw_storage_gc_run` call) when any active replica hasn't caught up to
the current oplog tail — deliberately the coarser, whole-phase grain
rather than tracking "which specific chunk needs which specific
watermark," matching this task's own acceptance-criteria wording and the
existing segment-truncation gate's own precedent. Degrades to a no-op
check (zero behavior change) when `vw_cluster_has_active_replicas`
returns false — confirmed by the pre-existing
`run_once: cluster with no active replicas behaves like single-node`
test still passing unmodified.

Reused `tests/unit/test_vw_gc.c`'s existing `vw_cluster_t` stub
(`has_active_replicas`/`min_sync_watermark` fields, fully test-controlled,
`vw_cluster.c` deliberately not linked into this test binary) rather than
adding a new one — it already supports exactly the scenario `TASK-178`
will need (a controllable "replica is lagging" watermark), confirmed by
reading `gc_stack_open`'s existing signature before writing any code.

Build: both trees clean. `ctest`: 18/18 (MSVC), 19/19 (WSL, with
`VW_BUILD_TESTS` flipped ON→verified→OFF per this session's established
discipline) — `unit_vw_gc`'s existing 464 assertions all still pass
unmodified. The actual positive regression test (a genuinely lagging
replica, chunk NOT deleted while behind, IS deleted once caught up) is
`TASK-178`'s job per this task's own acceptance criteria, since it needs
`TASK-172` to exist first to be a meaningful end-to-end test rather than
just re-exercising this stub.

CQR.08 self-review: confirmed the gate reads `ctx->cluster`/`ctx->oplog`
— both pre-existing fields, no new plumbing added; confirmed the new
`replica_lag_blocks_gc` local is scoped to this one function and doesn't
leak into `vw_gc_ctx_t`'s persistent state (each cycle re-evaluates fresh,
consistent with the primary's watermark changing between cycles). No
blocking findings.

**QA.06, 2026-08-17 — TASK-178 sign-off.**
`tests/integration/test_cluster.py::test_gc_does_not_delete_chunk_while_replica_lags`
is the real end-to-end regression test this task's own acceptance
criteria deferred to `TASK-178`: real primary + real replica, a real
upload, the replica deliberately stopped (frozen watermark), a real
delete, and a confirmed-not-deleted chunk across multiple real GC
cycles while the replica lags. The gating logic itself is confirmed
correct by this test. **It also surfaced a separate, pre-existing bug
this task's own gating logic does not cause and is not responsible for**:
once the replica catches up, the chunk still never reaches `ref_count ==
0` because of an unrelated double-count between `chunk_put_impl` and
`handle_file_commit`'s `addref` (filed as `TASK-180`, SRV.01) — the test
is marked `xfail(strict=True)` pending that fix, specifically so it
starts failing loudly (forcing the marker's removal) the moment
`TASK-180` lands, rather than silently staying green either way.
