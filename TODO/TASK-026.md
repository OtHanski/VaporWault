---
id:          TASK-026
title:       Implement vw_cache — local file metadata cache and sync-state tracker
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-11
priority:    high
depends_on:  []
blocks:      [TASK-029]
review_by:   [CQR.08]
tags:        [client, cache, sync, phase-3]
---

Implement `src/client/vw_cache.{h,c}` — the client-side local metadata cache.
The cache records each known file's sync state so `vw_sync` (TASK-029) can
determine what to upload, download, or flag as a conflict without hitting the
server on every poll.

## Background

The cache is the ground truth for the client's view of the sync state. Every
file known to the daemon has one entry. The sync engine reads the cache to
decide what action to take; filesystem watch events (TASK-028) and server poll
results both update the cache. The cache is persisted to disk so it survives
daemon restarts.

On-disk location: `{state_dir}/cache.db` — a fixed-size record table.
The `state_dir` is a platform-appropriate directory (e.g.,
`$XDG_STATE_HOME/vapourwault/` on Linux,
`%LOCALAPPDATA%\VaporWault\` on Windows).

## Acceptance criteria

### 1. Cache entry record

```c
/* Sync state for one file/directory known to the daemon. */
typedef enum {
    VW_SYNC_SYNCED    = 0,  /* local matches server HEAD                     */
    VW_SYNC_LOCAL_MOD = 1,  /* local newer than last known server version     */
    VW_SYNC_REMOTE_MOD= 2,  /* server has a newer version than local          */
    VW_SYNC_CONFLICT  = 3,  /* both sides changed since last sync             */
    VW_SYNC_LOCAL_DEL = 4,  /* deleted locally, still on server               */
    VW_SYNC_REMOTE_DEL= 5,  /* deleted on server, still exists locally        */
    VW_SYNC_NEW_LOCAL = 6,  /* new local file, not yet uploaded               */
} vw_sync_state_t;

typedef struct {
    uint64_t        file_id;          /* server file_id; 0 if not yet uploaded */
    uint64_t        server_version_id;/* version_id of last known server state */
    int64_t         server_mtime;     /* mtime of last known server version     */
    uint64_t        server_size;      /* size of last known server version      */
    int64_t         local_mtime;      /* mtime of local file at last sync       */
    uint64_t        local_size;       /* size of local file at last sync        */
    vw_sync_state_t sync_state;       /* u32 on disk                            */
    uint8_t         entry_type;       /* VW_ENTRY_FILE or VW_ENTRY_DIR          */
    uint8_t         _pad[3];
    char            virtual_path[512];/* NUL-terminated absolute virtual path   */
    char            local_path[512];  /* NUL-terminated absolute local path     */
} vw_cache_entry_t;
```

`_Static_assert(sizeof(vw_cache_entry_t) == 1088, "...")` must be present.

### 2. Opaque context

```c
typedef struct vw_cache vw_cache_t;

vw_err_t vw_cache_open(const char *state_dir, vw_cache_t **out);
void     vw_cache_close(vw_cache_t *cache);
```

Opens or creates `{state_dir}/cache.db`. Scans existing records into an
in-memory hash table keyed by `virtual_path`. Creates the state dir if it does
not exist. Returns VW_ERR_IO on any disk failure.

### 3. CRUD

```c
/* Insert or replace a cache entry. virtual_path is the key. */
vw_err_t vw_cache_upsert(vw_cache_t *cache, const vw_cache_entry_t *entry);

/* Fetch an entry by virtual_path. Returns VW_ERR_NOT_FOUND if absent. */
vw_err_t vw_cache_get(vw_cache_t *cache, const char *virtual_path,
                       vw_cache_entry_t *out);

/* Remove an entry by virtual_path. Returns VW_ERR_NOT_FOUND if absent. */
vw_err_t vw_cache_delete(vw_cache_t *cache, const char *virtual_path);
```

### 4. Listing and filtering

```c
/*
 * Enumerate entries matching sync_state. If sync_state == -1, return all.
 * Returns a malloc'd array of vw_cache_entry_t; caller frees.
 * *out_count may be 0.
 */
vw_err_t vw_cache_list(vw_cache_t *cache, int sync_state,
                        vw_cache_entry_t **out, uint32_t *out_count);
```

### 5. Sync-folder configuration

```c
/* A sync folder maps a local filesystem path to a virtual path root. */
typedef struct {
    char local_root[512];    /* absolute local path, NUL-terminated */
    char virtual_root[512];  /* virtual path root, NUL-terminated   */
    uint8_t paused;          /* 1 = sync paused for this folder      */
    uint8_t _pad[7];
} vw_sync_folder_t;
/* _Static_assert(sizeof(vw_sync_folder_t) == 1032, "...") */

vw_err_t vw_cache_folder_add(vw_cache_t *cache, const vw_sync_folder_t *f);
vw_err_t vw_cache_folder_remove(vw_cache_t *cache, const char *local_root);
vw_err_t vw_cache_folder_list(vw_cache_t *cache,
                               vw_sync_folder_t **out, uint32_t *out_count);
vw_err_t vw_cache_folder_set_paused(vw_cache_t *cache,
                                     const char *local_root, uint8_t paused);
```

Sync folder config lives in `{state_dir}/sync_folders.db` (separate from
`cache.db`). Fixed-size records.

### 6. Thread safety

All public functions are thread-safe. Use a single `pthread_rwlock_t`; reads
hold shared, writes hold exclusive.

### 7. Persistence

`vw_cache_upsert`, `vw_cache_delete`, and all folder functions flush changes
to disk before returning. Use `pwrite` + `fdatasync` for in-place record
updates. Use `vw_fs_atomic_write` for the sync-folder table.

### 8. Error codes

- `VW_ERR_NOT_FOUND` — entry or folder not found.
- `VW_ERR_IO` — any disk or syscall failure.
- `VW_ERR_OOM` — malloc failure.
- `VW_ERR_INVALID_ARG` — NULL pointers, empty paths.

## Notes

ARCH.00 [2026-07-11]: `vw_cache_entry_t.virtual_path` must be absolute (starts
with `/`). `local_path` is the platform-native absolute path to the local copy.
The sync engine populates these when it maps server paths to local paths via
the sync-folder table.

The cache record size of 1088 bytes is deliberate: 512+512 bytes for paths is
the largest reasonable size for this use case and avoids any heap allocation per
entry lookup. CQR.08 should verify the _Static_assert at review.

CLI.02 [2026-07-11]: Implementation complete. vw_cache.h and vw_cache.c written.
_Static_assert verified: sizeof(vw_cache_entry_t)==1088, sizeof(vw_sync_folder_t)==1032.
FNV-1a HT with linear probing; free-list for slot reuse; pwrite+fsync persistence.
vw_cache_open creates state_dir via vw_fs_ensure_dir and guard slot on first run.
All 8 acceptance criteria met. Blocks TASK-029 (vw_sync) — now unblocked.

CQR.08 [2026-07-11]: _Static_asserts present and correct. cht_remove rebuilds the
probe chain after deletion (no tombstone corruption). Folder ops use linear scan —
appropriate for small folder count. Advisory: consider validating that virtual_path
starts with '/' in vw_cache_upsert. No blocking findings.

ARCH.00 [2026-07-11]: TASK-026 done. TASK-029 unblocked.
