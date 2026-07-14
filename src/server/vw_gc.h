#ifndef VW_GC_H
#define VW_GC_H

/*
 * vw_gc — Background garbage-collection thread.
 *
 * Runs periodically (default: every 1800 s) to:
 *   1. Expire stale sessions (is_active && expires_at <= now).
 *   2. Truncate completed oplog segments (single-node mode; Phase 7 will
 *      replace this with cluster min-replica-sync-offset truncation).
 *   3. Collect soft-deleted files and their chunk refs; run chunk GC.
 *
 * Usage:
 *   vw_gc_create(&cfg, store, file_store, chunk_store, oplog, &gc);
 *   vw_gc_start(gc);
 *   ...server runs...
 *   vw_gc_stop(gc);
 *   vw_gc_destroy(gc);
 */

#include "../core/vw_proto.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_oplog.h"
#include "vw_cluster.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Configuration ───────────────────────────────────────────────────────── */

#define VW_GC_DEFAULT_INTERVAL_SECS 1800u

typedef struct {
    uint32_t interval_secs; /* GC cycle period; 0 = disabled */
} vw_gc_cfg_t;

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_gc_ctx vw_gc_ctx_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Create a GC context. Does not start the background thread.
 * All borrowed pointers are valid until after vw_gc_destroy returns.
 * file_store and chunk_store may be NULL to skip file/chunk GC (pass 3).
 * cluster may be NULL (single-node mode); when set, pass 2 uses the minimum
 * replica sync watermark instead of last_entry_id to avoid truncating oplog
 * segments that lagging replicas still need.
 * Returns VW_OK and sets *out on success; VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_gc_create(const vw_gc_cfg_t *cfg,
                       vw_store_t       *store,
                       vw_file_store_t  *file_store,
                       vw_storage_t     *chunk_store,
                       vw_oplog_t       *oplog,
                       vw_cluster_t     *cluster,
                       vw_gc_ctx_t     **out);

/*
 * Free all resources held by the GC context.
 * MUST be called only after vw_gc_stop has returned. Safe to call with NULL.
 */
void vw_gc_destroy(vw_gc_ctx_t *ctx);

/*
 * Spawn the background GC thread.
 * If cfg.interval_secs == 0, returns VW_OK immediately (disabled).
 * Returns VW_ERR_IO if thread creation fails.
 */
vw_err_t vw_gc_start(vw_gc_ctx_t *ctx);

/*
 * Signal the GC thread to stop and block until it exits.
 * Safe to call when the thread was never started (no-op).
 */
void vw_gc_stop(vw_gc_ctx_t *ctx);

/*
 * Run one full GC pass synchronously on the calling thread.
 * Safe to call at any time (e.g. from an admin command); uses the same
 * store/oplog locks as the background thread.
 * Returns VW_OK (GC errors are logged internally but not propagated).
 */
vw_err_t vw_gc_run_once(vw_gc_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VW_GC_H */
