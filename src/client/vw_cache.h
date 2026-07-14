#ifndef VW_CACHE_H
#define VW_CACHE_H

/*
 * vw_cache — client-side file metadata cache and sync-state tracker.
 *
 * Persists two files in {state_dir}:
 *   cache.db        — fixed-size vw_cache_entry_t records (1088 bytes each)
 *   sync_folders.db — fixed-size vw_sync_folder_t records (1032 bytes each)
 *
 * Thread-safe; all functions hold a rwlock internally.
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Entry type constants (parallel to server-side VW_ENTRY_FILE / VW_ENTRY_DIR). */
#ifndef VW_ENTRY_FILE
#define VW_ENTRY_FILE ((uint8_t)0)
#define VW_ENTRY_DIR  ((uint8_t)1)
#endif

/* ── Sync state ──────────────────────────────────────────────────────────── */

typedef enum {
    VW_SYNC_SYNCED     = 0,  /* local matches server HEAD                   */
    VW_SYNC_LOCAL_MOD  = 1,  /* local newer than last known server version   */
    VW_SYNC_REMOTE_MOD = 2,  /* server has a newer version than local        */
    VW_SYNC_CONFLICT   = 3,  /* both sides changed since last sync           */
    VW_SYNC_LOCAL_DEL  = 4,  /* deleted locally, still on server             */
    VW_SYNC_REMOTE_DEL = 5,  /* deleted on server, still exists locally      */
    VW_SYNC_NEW_LOCAL  = 6,  /* new local file, not yet uploaded             */
} vw_sync_state_t;

/* ── Cache entry record ──────────────────────────────────────────────────── */

/*
 * One cache entry per known file / directory. 1088 bytes on disk:
 *   64 bytes of scalar fields (including 11-byte alignment pad)
 *   512 bytes for virtual_path
 *   512 bytes for local_path
 *
 * A slot with virtual_path[0] == '\0' is free.
 */
typedef struct {
    uint64_t        file_id;           /* server file_id; 0 = not yet uploaded  */
    uint64_t        server_version_id; /* version_id of last known server state  */
    int64_t         server_mtime;      /* mtime of last known server version      */
    uint64_t        server_size;       /* size of last known server version       */
    int64_t         local_mtime;       /* mtime of local file at last sync        */
    uint64_t        local_size;        /* size of local file at last sync         */
    vw_sync_state_t sync_state;        /* u32 on disk                             */
    uint8_t         entry_type;        /* VW_ENTRY_FILE or VW_ENTRY_DIR           */
    uint8_t         _pad[11];          /* pad to align paths at offset 64         */
    char            virtual_path[512]; /* NUL-terminated absolute virtual path    */
    char            local_path[512];   /* NUL-terminated absolute local path      */
} vw_cache_entry_t;
_Static_assert(sizeof(vw_cache_entry_t) == 1088,
               "vw_cache_entry_t must be 1088 bytes");

/* ── Sync-folder record ──────────────────────────────────────────────────── */

typedef struct {
    char    local_root[512];   /* absolute local path, NUL-terminated  */
    char    virtual_root[512]; /* virtual path root, NUL-terminated    */
    uint8_t paused;            /* 1 = sync paused for this folder      */
    uint8_t _pad[7];
} vw_sync_folder_t;
_Static_assert(sizeof(vw_sync_folder_t) == 1032,
               "vw_sync_folder_t must be 1032 bytes");

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_cache vw_cache_t;

/*
 * Open or create the cache at state_dir.
 * Builds in-memory indexes from cache.db and sync_folders.db.
 * Creates state_dir and database files if they do not exist.
 */
vw_err_t vw_cache_open(const char *state_dir, vw_cache_t **out);
void     vw_cache_close(vw_cache_t *cache);

/* ── CRUD ────────────────────────────────────────────────────────────────── */

/* Insert or replace by virtual_path; flushes to disk before returning. */
vw_err_t vw_cache_upsert(vw_cache_t *cache, const vw_cache_entry_t *entry);

/* Returns VW_ERR_NOT_FOUND if the path is not in the cache. */
vw_err_t vw_cache_get(vw_cache_t *cache, const char *virtual_path,
                      vw_cache_entry_t *out);

/* Remove entry; flushes zeroed slot to disk. Returns VW_ERR_NOT_FOUND if absent. */
vw_err_t vw_cache_delete(vw_cache_t *cache, const char *virtual_path);

/* ── Listing ─────────────────────────────────────────────────────────────── */

/*
 * Return a malloc'd array of matching entries.
 * sync_state == -1 returns all entries.
 * *out_count may be 0; *out is NULL in that case.
 * Caller must free(*out).
 */
vw_err_t vw_cache_list(vw_cache_t *cache, int sync_state,
                       vw_cache_entry_t **out, uint32_t *out_count);

/* ── Sync-folder management ──────────────────────────────────────────────── */

/* Add a sync folder. Returns VW_ERR_ALREADY_EXISTS if local_root is duplicate. */
vw_err_t vw_cache_folder_add(vw_cache_t *cache, const vw_sync_folder_t *f);

/* Remove by local_root. Returns VW_ERR_NOT_FOUND if absent. */
vw_err_t vw_cache_folder_remove(vw_cache_t *cache, const char *local_root);

/*
 * Return a malloc'd copy of all sync folders.
 * Caller must free(*out). *out_count may be 0.
 */
vw_err_t vw_cache_folder_list(vw_cache_t *cache,
                               vw_sync_folder_t **out, uint32_t *out_count);

/* Set the paused flag for a folder by local_root. Returns VW_ERR_NOT_FOUND if absent. */
vw_err_t vw_cache_folder_set_paused(vw_cache_t *cache,
                                    const char *local_root, uint8_t paused);

#ifdef __cplusplus
}
#endif

#endif /* VW_CACHE_H */
