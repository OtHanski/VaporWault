#ifndef VW_SCRUB_H
#define VW_SCRUB_H

/*
 * vw_scrub — Background chunk-store integrity scan thread.
 *
 * Phase 22 (corruption detection & repair), TASK-255 detection foundation
 * plus TASK-260's repair wiring. See ARCHITECTURE.md's Phase 22 row for
 * the full design.
 *
 * Runs periodically (default: every 6 hours) to walk the entire chunk
 * store (vw_storage_scrub_run) re-hashing every chunk on disk against its
 * own filename, logging any genuine corruption found (a chunk still
 * referenced — ref_count > 0 — whose bytes no longer match). This is
 * deliberately a much slower cadence than vw_gc's (every 30 min by
 * default): a full chunk-store walk re-reads every byte of every chunk on
 * disk, unlike GC's in-memory ref-count sweep.
 *
 * TASK-260: each corrupt chunk found also drives vw_repair.c's repair
 * pipeline (local Reed-Solomon reconstruction, then cluster replica-fetch
 * if that's not enough) inline within the scrub pass — see
 * log_corrupt_chunk in vw_scrub.c. A repair failure is logged, not
 * treated as a scrub-pass failure; TASK-261 will add an admin alert for
 * the still-corrupt case.
 *
 * Usage:
 *   vw_scrub_create(&cfg, chunk_store, cluster, notify, &scrub);  // cluster/notify may be NULL
 *   vw_scrub_start(scrub);
 *   ...server runs...
 *   vw_scrub_stop(scrub);
 *   vw_scrub_destroy(scrub);
 */

#include "../core/vw_proto.h"
#include "vw_storage.h"
#include "vw_cluster.h"
#include "vw_notify.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Configuration ───────────────────────────────────────────────────────── */

#define VW_SCRUB_DEFAULT_INTERVAL_SECS (6u * 3600u)  /* 6 hours */

typedef struct {
    uint32_t interval_secs;  /* scrub cycle period; 0 = disabled */
} vw_scrub_cfg_t;

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_scrub_ctx vw_scrub_ctx_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Create a scrub context. Does not start the background thread.
 * chunk_store must remain valid for the lifetime of the context.
 * cluster (TASK-260) may be NULL — clustering disabled/single-node
 * deployment; the repair pipeline then only ever tries local Reed-Solomon
 * reconstruction, never replica-fetch, matching vw_repair_chunk's own
 * NULL-cluster behavior.
 * notify (TASK-261) may be NULL — admin alerts disabled; a chunk that
 * exhausts both repair paths is then only logged, never emailed. When
 * non-NULL, vw_notify_chunk_unrepairable is called for every chunk that
 * fails both local RS reconstruction and every reachable replica.
 * Returns VW_OK and sets *out on success; VW_ERR_OOM on allocation failure;
 * VW_ERR_INVALID_ARG if chunk_store is NULL.
 */
vw_err_t vw_scrub_create(const vw_scrub_cfg_t *cfg,
                          vw_storage_t *chunk_store,
                          vw_cluster_t *cluster,
                          vw_notify_ctx_t *notify,
                          vw_scrub_ctx_t **out);

/*
 * Free all resources held by the scrub context.
 * MUST be called only after vw_scrub_stop has returned. Safe with NULL.
 */
void vw_scrub_destroy(vw_scrub_ctx_t *ctx);

/*
 * Spawn the background scrub thread.
 * If cfg.interval_secs == 0, returns VW_OK immediately (disabled).
 * Returns VW_ERR_IO if thread creation fails.
 */
vw_err_t vw_scrub_start(vw_scrub_ctx_t *ctx);

/*
 * Signal the scrub thread to stop and block until it exits.
 * Safe to call when the thread was never started (no-op).
 */
void vw_scrub_stop(vw_scrub_ctx_t *ctx);

/*
 * Run one full scrub pass synchronously on the calling thread (e.g. from
 * an admin command — see vw_admin's VW_ADMIN_SCRUB_RUN_REQ, TASK-256).
 * Safe to call at any time; uses the same chunk-store lock as the
 * background thread. Returns VW_OK (per-chunk errors are logged
 * internally, never fatal to the pass).
 */
vw_err_t vw_scrub_run_once(vw_scrub_ctx_t *ctx);

/*
 * Report the results of the most recently completed pass (TASK-256's
 * VW_ADMIN_SCRUB_STATUS_REQ). *out_last_run_unix is 0 if no pass has ever
 * completed yet. Thread-safe.
 */
void vw_scrub_get_last_stats(vw_scrub_ctx_t *ctx,
                              vw_storage_scrub_stats_t *out_stats,
                              int64_t *out_last_run_unix);

#ifdef __cplusplus
}
#endif

#endif /* VW_SCRUB_H */
