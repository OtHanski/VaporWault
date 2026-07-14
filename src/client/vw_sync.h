#ifndef VW_SYNC_H
#define VW_SYNC_H

/*
 * vw_sync — client sync engine.
 *
 * Reconciles local filesystem state with the server using a 5-step cycle:
 *   1. Walk local tree; update cache dirty bits.
 *   2. Fetch server FILE_LIST for each virtual root (client-side BFS).
 *   3. Compute required action per file (upload/download/conflict/delete).
 *   4. Execute actions (uploads first, then downloads, then deletes).
 *   5. Update cache with results.
 *
 * Network failures queue pending ops into an offline queue persisted at
 * {state_dir}/offline_queue.db. The queue is drained at the start of the
 * next sync cycle when the session reconnects.
 *
 * Security:
 *   VW_SYNC_REMOTE_DEL local deletions are verified to be under a registered
 *   sync folder's local_root before any call to vw_fs_delete (§SEC.07).
 *
 * Thread safety: vw_sync_set_session and vw_sync_get_progress are safe to
 * call concurrently with vw_sync_run. Other functions are not concurrent-safe.
 */

#include "vw_client_core.h"
#include "vw_cache.h"
#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vw_sync_ctx vw_sync_ctx_t;

typedef struct {
    vw_client_sess_t *sess;      /* authenticated session; may be NULL (offline) */
    vw_cache_t       *cache;     /* local metadata cache (TASK-026)              */
    const char       *state_dir; /* directory for offline_queue.db               */
} vw_sync_cfg_t;

vw_err_t vw_sync_open(const vw_sync_cfg_t *cfg, vw_sync_ctx_t **out);
void     vw_sync_close(vw_sync_ctx_t *ctx);

/*
 * Update the server session (e.g. after reconnect). Thread-safe.
 */
void vw_sync_set_session(vw_sync_ctx_t *ctx, vw_client_sess_t *sess);

/*
 * Run one complete sync cycle. Blocks until complete. See module header for
 * the cycle algorithm.
 *
 * Returns VW_OK on full or partial success (network failures queue ops).
 * Returns VW_ERR_IO for unrecoverable local filesystem failures.
 */
vw_err_t vw_sync_run(vw_sync_ctx_t *ctx);

/*
 * Mark a specific local file as modified. Called by the daemon on watch events.
 * Updates (or creates) the cache entry with sync_state = VW_SYNC_LOCAL_MOD /
 * VW_SYNC_NEW_LOCAL. Thread-safe relative to vw_sync_set_session.
 */
vw_err_t vw_sync_mark_local_modified(vw_sync_ctx_t *ctx, const char *local_path);

/*
 * Return the number of operations pending in the offline queue.
 */
uint32_t vw_sync_pending_count(const vw_sync_ctx_t *ctx);

/*
 * Read the byte-transfer progress of the current (or most recent) sync cycle.
 * Thread-safe; may be called while vw_sync_run is running.
 */
void vw_sync_get_progress(const vw_sync_ctx_t *ctx,
                           uint64_t *out_done, uint64_t *out_total);

#ifdef __cplusplus
}
#endif

#endif /* VW_SYNC_H */
