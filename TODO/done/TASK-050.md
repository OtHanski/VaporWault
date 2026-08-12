---
id:          TASK-050
title:       GC cluster integration and CLUSTER_STATUS admin handler
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-13
priority:    normal
depends_on:  [TASK-049]
blocks:      [TASK-053]
review_by:   [CQR.08]
tags:        [server, cluster, gc, admin, phase-7]
---

Wire the cluster sync watermark into the GC oplog truncation pass, and
implement the `CLUSTER_STATUS` / `CLUSTER_STATUS_RESP` admin handler.

## Acceptance criteria

### 1. GC oplog truncation — cluster-aware

`vw_gc_run_once` pass 2 currently uses `vw_oplog_last_entry_id` to compute the
safe truncation point. This is correct for single-node mode but causes data
loss in a cluster: the primary may truncate oplog segments that lagging replicas
still need.

Replace:
```c
last_eid = vw_oplog_last_entry_id(ctx->oplog);
if (last_eid > 0)
    rc = vw_oplog_truncate_before(ctx->oplog, last_eid);
```

With:
```c
uint64_t safe_eid;
if (ctx->cluster && vw_cluster_has_active_replicas(ctx->cluster)) {
    /* Truncate only up to the minimum replica sync watermark. */
    safe_eid = vw_cluster_min_sync_watermark(ctx->cluster);
} else {
    safe_eid = vw_oplog_last_entry_id(ctx->oplog);
}
if (safe_eid > 0)
    rc = vw_oplog_truncate_before(ctx->oplog, safe_eid);
```

Add a `vw_cluster_t *cluster` field to `struct vw_gc_ctx` (nullable; NULL =
single-node mode). Update `vw_gc_create` to accept a nullable
`vw_cluster_t *cluster` parameter. Wire in `vw_server_main.c` after
`vw_cluster_open`.

Add:
- `vw_cluster_has_active_replicas(ctx)` — returns 1 if any node with
  `is_active == 1 && role == 0` exists.
- These are already in the API sketch in TASK-048; implement them as part of
  this task if not yet present.

### 2. CLUSTER_STATUS handler in `vw_admin`

Add handling for `VW_MSG_CLUSTER_STATUS` (0x0706) in `vw_admin.c`:

1. Verify the session is admin (`is_admin == 1`).
2. Call `vw_cluster_node_list(cluster_ctx, *out_recs, *out_count)` — returns
   all node records (with `auth_token` zeroed in each copy).
3. Compute `lag_entries = primary_last_entry_id − sync_watermark` for each node.
4. Serialize and send `CLUSTER_STATUS_RESP` per the §7.7 spec.

`vw_cluster_node_list` (new helper in `vw_cluster.c`):
```c
vw_err_t vw_cluster_node_list(vw_cluster_t      *ctx,
                               vw_node_record_t **out_recs,
                               uint32_t          *out_count);
```
Returns a heap-allocated array of all node records with `auth_token` zeroed.
Caller frees.

### 3. CMake / wiring

- Update `vw_gc_create` call in `vw_server_main.c` to pass the cluster
  context.
- Wire `CLUSTER_STATUS` dispatch into `vw_admin.c` message handler switch.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: The GC change is safety-critical: without it, a slow
replica can have its unread oplog segments deleted, causing it to fall
permanently out of sync and requiring a full re-seed. The fix must be applied
before the cluster is considered production-ready. The `safe_eid` fallback to
`last_eid` when no active replicas exist preserves the existing single-node GC
behaviour with no regression.

SRV.01 [2026-07-13]: Implementation complete.

Files modified:
- `src/server/vw_gc.h` — Added `#include "vw_cluster.h"`, added nullable
  `vw_cluster_t *cluster` parameter to `vw_gc_create`. Updated comment to
  describe cluster-aware oplog truncation.
- `src/server/vw_gc.c` — Added `#include "vw_cluster.h"`, added `vw_cluster_t
  *cluster` field to `struct vw_gc_ctx`. Updated `vw_gc_create` to accept and
  store cluster. Replaced pass 2 with cluster-aware block: if cluster is set and
  has active replicas, uses `vw_cluster_min_sync_watermark` as safe_eid;
  otherwise uses `vw_oplog_last_entry_id`. Removed now-redundant `last_eid`
  local variable.
- `src/server/vw_server_core.h` — Added `#include "vw_cluster.h"`, added
  `vw_server_ctx_set_cluster` and `vw_server_ctx_cluster` declarations.
- `src/server/vw_server_core.c` — Added `vw_cluster_t *cluster` field to
  `struct vw_server_ctx`. Implemented `vw_server_ctx_set_cluster` and
  `vw_server_ctx_cluster`.
- `src/server/vw_file_handlers.c` — Added `#include "vw_cluster.h"`.
  Implemented `handle_cluster_status`: validates admin session, calls
  `vw_cluster_node_list`, serializes CLUSTER_STATUS_RESP (role u8 + count u32 +
  per-node: node_id u64 + is_active u8 + sync_watermark u64 + lag_entries u64
  + hostname 128 bytes). auth_token never included. Single-node NULL cluster
  returns role=1, count=0. Added `VW_MSG_CLUSTER_STATUS` case to the
  admin-only dispatch switch.
- `src/server/vw_server_main.c` — Moved cluster open+start BEFORE GC create so
  the cluster pointer is non-NULL when passed to `vw_gc_create`. Added
  `vw_server_ctx_set_cluster(sctx, cluster)` after cluster init to expose
  cluster to TLS handlers.

CQR.08 review requested.

CQR.08 [2026-07-13]: Review complete. No blocking findings.

GC changes:
- `vw_gc_create` signature change: new `cluster` parameter is nullable and
  documented; callsite in `vw_server_main.c` updated correctly. ✓
- `vw_gc_run_once` pass 2: cluster-aware logic correct — `vw_cluster_has_active_replicas`
  guards before `vw_cluster_min_sync_watermark`. If no active replicas, falls
  back to `last_entry_id` (single-node behaviour preserved). Block scope for
  `safe_eid` avoids the now-removed function-level `last_eid` variable. ✓
- Initialization ordering fixed: `vw_cluster_open` now precedes `vw_gc_create`
  so GC receives the live cluster pointer, not NULL. ✓

CLUSTER_STATUS handler:
- `validate_session` called before any other payload parsing (SEC.07-A-2). ✓
- `vw_store_user_get_by_id` admin check; `urec` zeroed with `secure_zero` after
  use (contains password_hash / password_salt fields). ✓
- `vw_cluster_node_list` returns auth_token-zeroed copies (enforced inside
  vw_cluster); CLUSTER_STATUS_RESP serialization confirmed: node_id at p+0,
  is_active at p+8, sync_watermark at p+9, lag_entries at p+17, hostname at
  p+25. auth_token field from vw_node_record_t intentionally skipped. ✓
- lag_entries computed only for role==0 (replica) nodes; primary node gets
  lag=0 by default (correct — primary is always current). ✓
- malloc+free for resp; nodes heap-allocated by vw_cluster_node_list and freed
  before resp is sent. No double-free path. ✓
- single-node NULL cluster path returns fixed 5-byte response, no heap. ✓
- `VW_MSG_CLUSTER_STATUS` wired into admin-only dispatch before the file-store
  gate (consistent with USER_LIST, AUDIT_QUERY pattern). ✓

Advisory: `resp_len = 5u + count * CLUSTER_NODE_ENTRY_SIZE` — if count is
very large (e.g. adversarially controlled node DB), this could allocate up to
~153 × 2^32 bytes. In practice, the node store has a fixed-size file and count
is bounded by the number of registered nodes (a small operator-controlled set),
so this is not exploitable. A max-node-count cap (e.g. 256) would be defensive
hardening for a future Phase 8 pass.

**CQR.08 sign-off granted.**

ARCH.00 [2026-07-13]: CQR.08 signed off. No blocking findings. TASK-050 done.
TASK-053 (cluster status GUI view) is unblocked.
