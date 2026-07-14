#ifndef VW_WATCH_H
#define VW_WATCH_H

/*
 * vw_watch — cross-platform filesystem event watcher.
 *
 * Pull model: caller calls vw_watcher_wait() to block until events are
 * available, then vw_watcher_drain() to consume them. No background thread.
 * Ring buffer is mutex-protected for thread-safety.
 *
 * Backends:
 *   Linux   — vw_watch_linux.c   (inotify, #ifdef __linux__)
 *   Windows — vw_watch_windows.c (ReadDirectoryChangesW, #ifdef _WIN32)
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VW_WATCH_CREATED  = 1,
    VW_WATCH_MODIFIED = 2,
    VW_WATCH_DELETED  = 3,
    VW_WATCH_MOVED    = 4,  /* rename within the watched tree */
} vw_watch_event_type_t;

typedef struct {
    vw_watch_event_type_t type;
    char path[1024];     /* absolute local path, NUL-terminated */
    char old_path[1024]; /* populated for VW_WATCH_MOVED; else empty string */
} vw_watch_event_t;

typedef struct vw_watcher vw_watcher_t;

/*
 * Create a watcher. max_events is the internal ring buffer capacity (clamped
 * to at least 256). Returns VW_ERR_OOM or VW_ERR_IO on failure.
 */
vw_err_t vw_watcher_open(uint32_t max_events, vw_watcher_t **out);

/*
 * Recursively add a directory to the watch set. Returns VW_ERR_NOT_FOUND if
 * the path does not exist.
 */
vw_err_t vw_watcher_add(vw_watcher_t *w, const char *path);

/*
 * Remove a directory (and its subtree) from the watch set. Returns
 * VW_ERR_NOT_FOUND if the path was not watched.
 */
vw_err_t vw_watcher_remove(vw_watcher_t *w, const char *path);

/*
 * Block until at least one event is available or timeout_ms elapses.
 * timeout_ms == 0 means block indefinitely.
 * Returns VW_OK if events are available; VW_ERR_TIMEOUT on timeout.
 */
vw_err_t vw_watcher_wait(vw_watcher_t *w, uint32_t timeout_ms);

/*
 * Drain up to *count events from the ring buffer into out_events.
 * Updates *count to the actual number of events written. Non-blocking.
 * Also reads any pending OS events before returning.
 */
vw_err_t vw_watcher_drain(vw_watcher_t *w,
                            vw_watch_event_t *out_events, uint32_t *count);

/*
 * Returns 1 if events were dropped (ring overflow) since the last drain;
 * clears the flag. The sync engine must do a full-scan reconcile on overflow.
 */
int vw_watcher_overflowed(vw_watcher_t *w);

/* Close watcher and release all resources. Safe to call with NULL. */
void vw_watcher_close(vw_watcher_t *w);

#ifdef __cplusplus
}
#endif

#endif /* VW_WATCH_H */
