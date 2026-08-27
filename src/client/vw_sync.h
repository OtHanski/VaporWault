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
 * Thread safety: vw_sync_set_session, vw_sync_set_read_only,
 * vw_sync_get_progress, vw_sync_action_error_count, and
 * vw_sync_permission_denied_count are safe to call concurrently with
 * vw_sync_run. Other functions are not concurrent-safe.
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
 * TASK-173: mark the current session as a read-only fallback connection
 * (or clear the mark once back on the primary). While set, vw_sync_run
 * never attempts a write against `sess` — every upload/delete/mkdir/
 * conflict-resolution action that would otherwise be attempted is instead
 * queued into the existing offline queue (or, for shared-folder actions,
 * silently deferred to next cycle — the queue is path-based only, same as
 * its existing net-error handling) exactly as if the connection were down
 * for writes specifically, while reads (file list, download) still go
 * through normally. Does not itself change `sess` — call
 * vw_sync_set_session separately. Thread-safe.
 */
void vw_sync_set_read_only(vw_sync_ctx_t *ctx, int read_only);

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

/*
 * Return the number of non-network action failures (e.g. a quota-rejected
 * upload) recorded during the current (or most recent) sync cycle. Reset to
 * zero at the start of each vw_sync_run. Network errors are not counted here
 * — they are already handled via the offline queue / per-cycle retry.
 * Thread-safe; may be called while vw_sync_run is running.
 */
uint32_t vw_sync_action_error_count(const vw_sync_ctx_t *ctx);

/*
 * Selective sync (TASK-192/193): set (replacing any previous set) the
 * exclude patterns for one sync folder, identified by its local_root
 * (must match a folder already registered via the cache — this function
 * does not itself add/remove folders). Patterns are glob-style, matched
 * against each entry's path relative to the folder's root: '*' matches
 * any run of characters within one path segment, '?' matches exactly one
 * character, and '**' as a whole path segment matches zero or more whole
 * segments (so a pattern of "node_modules" followed by a trailing "**"
 * segment excludes the node_modules directory itself and everything
 * under it). No character classes, no negation —
 * deliberately not full .gitignore semantics (TASK-192's design note).
 * Matching is case-sensitive. Takes effect starting with the next
 * vw_sync_run cycle. A path already synced locally when a rule newly
 * excludes it is left on disk untouched — it simply stops being a
 * source of further upload/download/delete actions in either direction.
 * count == 0 clears any exclude rules for that folder. Not thread-safe
 * relative to vw_sync_run (call it from the same thread that drives the
 * sync loop, same as vw_sync_mark_local_modified).
 */
vw_err_t vw_sync_set_folder_excludes(vw_sync_ctx_t *ctx, const char *local_root,
                                      const char *const *patterns, uint32_t count);

/*
 * Return the number of permission-denied auto-mkdir attempts (TASK-113: a
 * shared folder's new local subdirectory has no server-side counterpart,
 * and the grantee lacks EDIT permission to create one) recorded during the
 * current (or most recent) sync cycle. Reset to zero at the start of each
 * vw_sync_run. Counted separately from vw_sync_action_error_count so a
 * permission problem is distinguishable from any other action failure.
 * Thread-safe; may be called while vw_sync_run is running.
 */
uint32_t vw_sync_permission_denied_count(const vw_sync_ctx_t *ctx);

#ifdef VW_SYNC_TEST_HOOKS
/*
 * Test-only instrumentation (TASK-111). Only declared/defined when the
 * compiling target defines VW_SYNC_TEST_HOOKS — never part of a production
 * build. Set to a callback to have it invoked synchronously immediately
 * before the shared-folder BFS lists a given directory, letting a
 * regression test deterministically inject a delete/permission change
 * exactly in the window a real TOCTOU race would occur in.
 */
extern void (*vw_sync_test_before_list_dir)(const char *vpath, uint64_t dir_id);
#endif

#ifdef __cplusplus
}
#endif

#endif /* VW_SYNC_H */
