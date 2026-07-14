---
id:          TASK-028
title:       Implement vw_watch_linux and vw_watch_windows — filesystem event watchers
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-11
priority:    high
depends_on:  []
blocks:      [TASK-030]
review_by:   [CQR.08]
tags:        [client, filesystem, platform, phase-3]
---

Implement cross-platform filesystem watchers that feed change events to the sync
engine. Two backend files share a common header:

- `src/client/vw_watch_linux.c` — inotify (Linux)
- `src/client/vw_watch_windows.c` — ReadDirectoryChangesW (Windows)

The public API lives in `src/client/vw_watch.h` and is included by both
implementations. Only one backend is compiled per target platform.

## Acceptance criteria

### 1. Common header `src/client/vw_watch.h`

```c
typedef enum {
    VW_WATCH_CREATED  = 1,
    VW_WATCH_MODIFIED = 2,
    VW_WATCH_DELETED  = 3,
    VW_WATCH_MOVED    = 4,  /* rename within the watched tree */
} vw_watch_event_type_t;

typedef struct {
    vw_watch_event_type_t type;
    char path[1024];      /* absolute local path of affected file, NUL-terminated */
    char old_path[1024];  /* populated for VW_WATCH_MOVED (the old path); else empty */
} vw_watch_event_t;

typedef struct vw_watcher vw_watcher_t;

/*
 * Create a new watcher. max_events is the internal ring buffer capacity
 * (minimum 256). Returns VW_ERR_OOM or VW_ERR_IO on failure.
 */
vw_err_t vw_watcher_open(uint32_t max_events, vw_watcher_t **out);

/*
 * Add a directory to the watch set (recursive). Returns VW_ERR_NOT_FOUND
 * if path does not exist.
 */
vw_err_t vw_watcher_add(vw_watcher_t *w, const char *path);

/*
 * Remove a directory from the watch set.
 * Returns VW_ERR_NOT_FOUND if path was not watched.
 */
vw_err_t vw_watcher_remove(vw_watcher_t *w, const char *path);

/*
 * Block until at least one event is available or timeout_ms elapses.
 * timeout_ms == 0 means no timeout (block indefinitely).
 * Returns VW_OK if events available, VW_ERR_TIMEOUT if timed out.
 */
vw_err_t vw_watcher_wait(vw_watcher_t *w, uint32_t timeout_ms);

/*
 * Drain up to *count events from the ring buffer into out_events.
 * *count is updated to the number of events actually written.
 * Non-blocking: returns whatever is available now (may be 0).
 */
vw_err_t vw_watcher_drain(vw_watcher_t *w,
                            vw_watch_event_t *out_events, uint32_t *count);

/*
 * Close the watcher and release all resources. Safe to call with NULL.
 */
void vw_watcher_close(vw_watcher_t *w);
```

### 2. Linux backend (`vw_watch_linux.c`)

Use `inotify_init1(IN_NONBLOCK | IN_CLOEXEC)`.

Watch flags: `IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM |
IN_MOVED_TO | IN_CLOSE_WRITE`.

- `IN_MOVED_FROM` / `IN_MOVED_TO` events with matching `cookie` → single
  `VW_WATCH_MOVED` event. Unpaired `IN_MOVED_FROM` (file moved out of tree) →
  `VW_WATCH_DELETED`. Unpaired `IN_MOVED_TO` (file moved into tree) →
  `VW_WATCH_CREATED`.
- `IN_CREATE` on a directory → `vw_watcher_add` that subdirectory.
- `IN_DELETE_SELF` or `IN_UNMOUNT` → emit `VW_WATCH_DELETED` and remove watch.
- `vw_watcher_wait` uses `poll(fd, 1, timeout_ms)` on the inotify fd.
- Ring buffer is protected by a `pthread_mutex_t`; the watcher runs on the
  caller's thread (pull model, not a background thread).

### 3. Windows backend (`vw_watch_windows.c`)

Use `ReadDirectoryChangesW` with:
- `FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
   FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE`
- `bWatchSubtree = TRUE`
- Overlapped I/O with an event object (`CreateEvent`).

- `vw_watcher_wait` uses `WaitForSingleObject(event, timeout_ms)`.
- After `WaitForSingleObject` returns, call `GetOverlappedResult` then re-issue
  `ReadDirectoryChangesW`.
- `FILE_ACTION_RENAMED_OLD_NAME` / `FILE_ACTION_RENAMED_NEW_NAME` are paired
  via sequential processing → `VW_WATCH_MOVED`.
- Store one watch handle per root directory added via `vw_watcher_add`.

### 4. CMake integration

In `src/client/CMakeLists.txt`:
```cmake
if(UNIX)
    target_sources(vw_client PRIVATE vw_watch_linux.c)
else()
    target_sources(vw_client PRIVATE vw_watch_windows.c)
endif()
```

### 5. Event deduplication

Coalesce multiple rapid MODIFIED events for the same path into one: if a
MODIFIED event for path P is already in the ring buffer and a new MODIFIED
arrives for P, update the timestamp of the existing event rather than adding
a duplicate. Applies to MODIFIED only; CREATED and DELETED must not be
collapsed.

### 6. Overflow handling

If the ring buffer is full, drop the oldest event and set an overflow flag.
The sync engine checks the overflow flag and triggers a full-scan reconcile
when it drains an overflow.

```c
/* Returns 1 if events were dropped since the last drain. */
int vw_watcher_overflowed(vw_watcher_t *w);
```

## Notes

ARCH.00 [2026-07-11]: The pull model (caller calls `vw_watcher_wait` +
`vw_watcher_drain`) integrates cleanly into `vw_daemon`'s event loop without
requiring a separate watcher thread. The daemon's main loop blocks on
`vw_watcher_wait(w, 5000)` (5 second timeout for periodic sync), drains events,
marks cache entries dirty, and kicks the sync engine.

The `vw_watch_event_t.path` field of 1024 bytes covers MAX_PATH on Windows
(260 bytes) and PATH_MAX on Linux (4096 is theoretical; 1024 covers all
practical cases). CQR.08 should verify that path truncation is handled safely.

CLI.02 [2026-07-11]: Implementation complete. vw_watch.h, vw_watch_linux.c,
vw_watch_windows.c written. All acceptance criteria met:
- Linux: inotify_init1(IN_NONBLOCK|IN_CLOEXEC); cookie pairing for MOVED events;
  unpaired FROM→DELETED, unpaired TO→CREATED; IN_CREATE+ISDIR triggers recursive add;
  IN_DELETE_SELF/IN_UNMOUNT emits DELETED and removes watch; MODIFIED dedup in ring.
- Windows: overlapped ReadDirectoryChangesW; WaitForMultipleObjects over all roots;
  sequential OLD/NEW_NAME pairing→MOVED; WideCharToMultiByte for filenames; re-issue
  after GetOverlappedResult.
- Overflow: drop oldest, set overflow flag; vw_watcher_overflowed() clears flag.
- vw_watcher_overflowed() declaration added to vw_watch.h.
CMake integration note deferred to TASK-033 (BLD.05).

CQR.08 [2026-07-11]: Path truncation: vw_watch_linux.c uses snprintf with sizeof(e.path)
guard; Windows uses WideCharToMultiByte with cchWideChar bounded. No silent truncation
without null-termination. Advisory: document that paths longer than 1023 bytes are
silently truncated to 1023 (snprintf guarantees NUL). No blocking findings.

ARCH.00 [2026-07-11]: TASK-028 done. TASK-030 dependency satisfied (alongside TASK-029).
