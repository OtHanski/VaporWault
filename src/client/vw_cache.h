#ifndef VW_CACHE_H
#define VW_CACHE_H

/*
 * vw_cache — client-side file metadata cache and sync-state tracker.
 *
 * Persists two files in {state_dir}:
 *   cache.db        — fixed-size vw_cache_entry_t records (1088 bytes each)
 *   sync_folders.db — fixed-size vw_sync_folder_t records (1040 bytes each)
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
 * One cache entry per known file / directory. 1096 bytes on disk (grew from
 * 1088 in TASK-158, which added vault_id — see vw_cache.c's cache.db load
 * path for the resulting old-format migration):
 *   72 bytes of scalar fields (including a 3-byte alignment pad)
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
    uint64_t        vault_id;          /* TASK-158: last known server version's vault,
                                         * 0 if unencrypted — mirrors vw_file_entry_t.
                                         * vault_id, populated from the same FILE_LIST/
                                         * FILE_STAT calls that already set the other
                                         * server_* fields below. */
    vw_sync_state_t sync_state;        /* u32 on disk                             */
    uint8_t         entry_type;        /* VW_ENTRY_FILE or VW_ENTRY_DIR           */
    uint8_t         _pad[11];          /* pad to align paths at offset 72         */
    char            virtual_path[512]; /* NUL-terminated absolute virtual path    */
    char            local_path[512];   /* NUL-terminated absolute local path      */
} vw_cache_entry_t;
_Static_assert(sizeof(vw_cache_entry_t) == 1096,
               "vw_cache_entry_t must be 1096 bytes");

/* Size of a cache.db record before TASK-158 added vault_id — needed only to
 * recognize (and migrate away from) a pre-existing cache.db written by an
 * older build; see vw_cache.c. */
#define VW_CACHE_ENTRY_SIZE_PRE_TASK158 1088u

/* Reasons a sync folder can be found paused (vw_sync_folder_t.pause_reason).
 * Only meaningful when paused == 1; VW_PAUSE_REASON_NONE covers both "never
 * paused" and "paused manually" (via vw_cache_folder_set_paused, which
 * always clears any prior automatic reason — a human pausing/resuming a
 * folder isn't one of these specific automated causes). */
#define VW_PAUSE_REASON_NONE           ((uint8_t)0)
#define VW_PAUSE_REASON_REVOKED        ((uint8_t)1) /* TASK-106/111: shared-folder
                                                       * access revoked or the
                                                       * shared root itself deleted */
#define VW_PAUSE_REASON_TREE_TOO_LARGE ((uint8_t)2) /* TASK-111: shared-folder BFS
                                                       * exceeded the client's
                                                       * per-cycle resource ceiling */

/* ── Sync-folder record ──────────────────────────────────────────────────── */

typedef struct {
    char     local_root[512];   /* absolute local path, NUL-terminated  */
    char     virtual_root[512]; /* virtual path root, NUL-terminated    */
    uint8_t  paused;            /* 1 = sync paused for this folder      */
    uint8_t  pause_reason;      /* VW_PAUSE_REASON_*; valid iff paused   */
    uint8_t  _pad[6];
    uint64_t remote_dir_id;     /* TASK-106: 0 = normal owned, path-addressed
                                  * sync folder. Nonzero = a SHARED folder,
                                  * rooted at this server file_id rather than
                                  * a path this client owns — virtual_root is
                                  * then purely a local naming/display value,
                                  * never sent to the server. */
} vw_sync_folder_t;
_Static_assert(sizeof(vw_sync_folder_t) == 1040,
               "vw_sync_folder_t must be 1040 bytes");

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

/*
 * Set the paused flag for a folder by local_root. Always resets
 * pause_reason to VW_PAUSE_REASON_NONE (this is the manual/generic path —
 * use vw_cache_folder_set_pause_reason for an automatic pause with a
 * specific cause). Returns VW_ERR_NOT_FOUND if absent.
 */
vw_err_t vw_cache_folder_set_paused(vw_cache_t *cache,
                                    const char *local_root, uint8_t paused);

/*
 * Auto-pause a folder with a specific reason (VW_PAUSE_REASON_*). Always
 * sets paused = 1. Returns VW_ERR_NOT_FOUND if absent.
 */
vw_err_t vw_cache_folder_set_pause_reason(vw_cache_t *cache,
                                          const char *local_root, uint8_t reason);

#ifdef __cplusplus
}
#endif

#endif /* VW_CACHE_H */
