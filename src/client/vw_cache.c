/*
 * vw_cache.c — client-side metadata cache and sync-folder registry.
 *
 * Two flat-file databases in {state_dir}/:
 *   cache.db        — array of vw_cache_entry_t (1088 bytes/slot)
 *   sync_folders.db — array of vw_sync_folder_t (1032 bytes/slot)
 *
 * Slot 0 is a reserved guard (all-zero). Free slots have virtual_path[0]=='\0'
 * (cache) or local_root[0]=='\0' (folders). In-memory indexes are rebuilt on
 * open. Writes use vw_fs_pwrite + vw_fs_sync_file for durability.
 */

#include "vw_cache.h"
#include "../core/vw_fs.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef SRWLOCK vw_rwlock_t;
#   define rwlock_init(l)     ((void)InitializeSRWLock(l), 0)
#   define rwlock_rdlock(l)   AcquireSRWLockShared(l)
#   define rwlock_rdunlock(l) ReleaseSRWLockShared(l)
#   define rwlock_wrlock(l)   AcquireSRWLockExclusive(l)
#   define rwlock_wrunlock(l) ReleaseSRWLockExclusive(l)
#   define rwlock_destroy(l)  ((void)(l))
#else
#   include <pthread.h>
typedef pthread_rwlock_t vw_rwlock_t;
#   define rwlock_init(l)     pthread_rwlock_init((l), NULL)
#   define rwlock_rdlock(l)   pthread_rwlock_rdlock(l)
#   define rwlock_rdunlock(l) pthread_rwlock_unlock(l)
#   define rwlock_wrlock(l)   pthread_rwlock_wrlock(l)
#   define rwlock_wrunlock(l) pthread_rwlock_unlock(l)
#   define rwlock_destroy(l)  pthread_rwlock_destroy(l)
#endif

/* ── FNV-1a hash ─────────────────────────────────────────────────────────── */

static uint64_t fnv1a_str(const char *s)
{
    uint64_t h = 14695981039346656037ULL;
    while (*s) h = (h ^ (uint8_t)*s++) * 1099511628211ULL;
    return h;
}

/* ── In-memory path → slot HT ────────────────────────────────────────────── */

typedef struct {
    char     path[512]; /* [0] == '\0' means empty */
    uint64_t slot;      /* 0-based slot in cache.db */
} cht_entry_t;

#define CHT_INITIAL_CAP 128u
#define CHT_NOT_FOUND   UINT64_MAX

/* Returns CHT_NOT_FOUND if path is absent. */
static uint64_t cht_find(const cht_entry_t *ht, size_t cap, const char *path)
{
    size_t i;
    uint64_t h;

    if (!cap || !path || !path[0]) return CHT_NOT_FOUND;
    h = fnv1a_str(path) % (uint64_t)cap;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].path[0] == '\0') return CHT_NOT_FOUND;
        if (strncmp(ht[idx].path, path, 511) == 0) return ht[idx].slot;
    }
    return CHT_NOT_FOUND;
}

static int cht_insert_raw(cht_entry_t *ht, size_t cap,
                           const char *path, uint64_t slot)
{
    size_t i;
    uint64_t h = fnv1a_str(path) % (uint64_t)cap;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].path[0] == '\0') {
            strncpy(ht[idx].path, path, 511);
            ht[idx].path[511] = '\0';
            ht[idx].slot = slot;
            return 0;
        }
        if (strncmp(ht[idx].path, path, 511) == 0) {
            ht[idx].slot = slot;
            return 0;
        }
    }
    return -1;
}

/* Forward declaration */
struct vw_cache;
static int cht_grow(struct vw_cache *c);

/* ── Internal context ────────────────────────────────────────────────────── */

struct vw_cache {
    char        cache_path[512];
    char        folders_path[512];
    vw_rwlock_t lock;

    /* cache.db — guarded by lock */
    vw_cache_entry_t *entries;   /* in-memory copy of all slots (slot 0 = guard) */
    uint64_t          nslots;    /* total slots on disk */
    cht_entry_t      *ht;
    size_t            ht_cap;
    size_t            ht_len;
    uint64_t         *free_slots;
    size_t            free_len;
    size_t            free_cap;

    /* sync_folders.db — guarded by lock */
    vw_sync_folder_t *folders;   /* in-memory copy of all slots */
    uint64_t          nfolders;  /* total folder slots on disk */
};

static int cht_grow(struct vw_cache *c)
{
    size_t new_cap = c->ht_cap * 2;
    cht_entry_t *nh;
    size_t i;

    nh = (cht_entry_t *)calloc(new_cap, sizeof(*nh));
    if (!nh) return -1;
    for (i = 0; i < c->ht_cap; i++) {
        if (c->ht[i].path[0] != '\0')
            cht_insert_raw(nh, new_cap, c->ht[i].path, c->ht[i].slot);
    }
    free(c->ht);
    c->ht = nh;
    c->ht_cap = new_cap;
    return 0;
}

static int cht_insert(struct vw_cache *c, const char *path, uint64_t slot)
{
    if (c->ht_len * 4 >= c->ht_cap * 3) {
        if (cht_grow(c) != 0) return -1;
    }
    if (cht_insert_raw(c->ht, c->ht_cap, path, slot) != 0) return -1;
    c->ht_len++;
    return 0;
}

/* Tombstone removed by rebuilding the HT (called rarely). */
static void cht_remove(struct vw_cache *c, const char *path)
{
    size_t i;
    uint64_t h;

    if (!c->ht_cap || !path || !path[0]) return;
    h = fnv1a_str(path) % (uint64_t)c->ht_cap;
    for (i = 0; i < c->ht_cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)c->ht_cap);
        if (c->ht[idx].path[0] == '\0') return;
        if (strncmp(c->ht[idx].path, path, 511) == 0) {
            /* Rebuild to avoid breaking linear-probe chains. */
            memset(&c->ht[idx], 0, sizeof(c->ht[idx]));
            c->ht_len--;
            /* Re-insert entries that probe through this slot. */
            i++;
            for (; i < c->ht_cap; i++) {
                size_t j = (size_t)((h + (uint64_t)i) % (uint64_t)c->ht_cap);
                if (c->ht[j].path[0] == '\0') break;
                cht_entry_t tmp = c->ht[j];
                memset(&c->ht[j], 0, sizeof(c->ht[j]));
                c->ht_len--;
                cht_insert(c, tmp.path, tmp.slot);
            }
            return;
        }
    }
}

/* Push a slot onto the free list. */
static int free_push(struct vw_cache *c, uint64_t slot)
{
    uint64_t *p;
    size_t new_cap;

    if (c->free_len >= c->free_cap) {
        new_cap = c->free_cap ? c->free_cap * 2 : 16;
        p = (uint64_t *)realloc(c->free_slots, new_cap * sizeof(uint64_t));
        if (!p) return -1;
        c->free_slots = p;
        c->free_cap = new_cap;
    }
    c->free_slots[c->free_len++] = slot;
    return 0;
}

/* Persist in-memory entry at slot to cache.db. */
static vw_err_t cache_write_slot(struct vw_cache *c, uint64_t slot)
{
    uint64_t off = slot * (uint64_t)sizeof(vw_cache_entry_t);
    vw_err_t err = vw_fs_pwrite(c->cache_path, off,
                                  &c->entries[slot], sizeof(vw_cache_entry_t));
    if (err != VW_OK) return err;
    return vw_fs_sync_file(c->cache_path);
}

/* Persist in-memory folder at slot to sync_folders.db. */
static vw_err_t folder_write_slot(struct vw_cache *c, uint64_t slot)
{
    uint64_t off = slot * (uint64_t)sizeof(vw_sync_folder_t);
    vw_err_t err = vw_fs_pwrite(c->folders_path, off,
                                  &c->folders[slot], sizeof(vw_sync_folder_t));
    if (err != VW_OK) return err;
    return vw_fs_sync_file(c->folders_path);
}

/* ── vw_cache_open ───────────────────────────────────────────────────────── */

vw_err_t vw_cache_open(const char *state_dir, vw_cache_t **out)
{
    struct vw_cache *c = NULL;
    vw_err_t err;
    void *buf = NULL;
    size_t buf_len = 0;
    uint64_t i;
    int lock_init = 0;
    int sn;
    vw_cache_entry_t guard_e;
    vw_sync_folder_t guard_f;

    if (!state_dir || !out) return VW_ERR_INVALID_ARG;

    err = vw_fs_ensure_dir(state_dir);
    if (err != VW_OK) return err;

    c = (struct vw_cache *)calloc(1, sizeof(*c));
    if (!c) return VW_ERR_OOM;

    sn = snprintf(c->cache_path, sizeof(c->cache_path),
                  "%s/cache.db", state_dir);
    if (sn < 0 || sn >= (int)sizeof(c->cache_path)) { err = VW_ERR_INVALID_ARG; goto fail; }

    sn = snprintf(c->folders_path, sizeof(c->folders_path),
                  "%s/sync_folders.db", state_dir);
    if (sn < 0 || sn >= (int)sizeof(c->folders_path)) { err = VW_ERR_INVALID_ARG; goto fail; }

    if (rwlock_init(&c->lock) != 0) { err = VW_ERR_IO; goto fail; }
    lock_init = 1;

    /* ── cache.db ── */

    if (!vw_fs_exists(c->cache_path)) {
        memset(&guard_e, 0, sizeof(guard_e));
        err = vw_fs_atomic_write(c->cache_path, &guard_e, sizeof(guard_e));
        if (err != VW_OK) goto fail;
    }

    err = vw_fs_read_file(c->cache_path, &buf, &buf_len);
    if (err != VW_OK) goto fail;

    c->nslots = buf_len / sizeof(vw_cache_entry_t);
    c->entries = (vw_cache_entry_t *)calloc(c->nslots ? c->nslots : 1,
                                              sizeof(vw_cache_entry_t));
    if (!c->entries) { err = VW_ERR_OOM; free(buf); goto fail; }
    if (c->nslots)
        memcpy(c->entries, buf, c->nslots * sizeof(vw_cache_entry_t));
    free(buf); buf = NULL;

    c->ht = (cht_entry_t *)calloc(CHT_INITIAL_CAP, sizeof(cht_entry_t));
    if (!c->ht) { err = VW_ERR_OOM; goto fail; }
    c->ht_cap = CHT_INITIAL_CAP;

    for (i = 1; i < c->nslots; i++) { /* slot 0 is guard */
        if (c->entries[i].virtual_path[0] == '\0') {
            (void)free_push(c, i);
        } else {
            if (cht_insert(c, c->entries[i].virtual_path, i) != 0) {
                err = VW_ERR_OOM; goto fail;
            }
        }
    }

    /* ── sync_folders.db ── */

    if (!vw_fs_exists(c->folders_path)) {
        memset(&guard_f, 0, sizeof(guard_f));
        err = vw_fs_atomic_write(c->folders_path, &guard_f, sizeof(guard_f));
        if (err != VW_OK) goto fail;
    }

    err = vw_fs_read_file(c->folders_path, &buf, &buf_len);
    if (err != VW_OK) goto fail;

    c->nfolders = buf_len / sizeof(vw_sync_folder_t);
    c->folders = (vw_sync_folder_t *)calloc(c->nfolders ? c->nfolders : 1,
                                              sizeof(vw_sync_folder_t));
    if (!c->folders) { err = VW_ERR_OOM; free(buf); goto fail; }
    if (c->nfolders)
        memcpy(c->folders, buf, c->nfolders * sizeof(vw_sync_folder_t));
    free(buf); buf = NULL;

    *out = c;
    return VW_OK;

fail:
    if (buf) free(buf);
    if (c) {
        if (lock_init) rwlock_destroy(&c->lock);
        free(c->entries);
        free(c->ht);
        free(c->free_slots);
        free(c->folders);
        free(c);
    }
    return err;
}

/* ── vw_cache_close ──────────────────────────────────────────────────────── */

void vw_cache_close(vw_cache_t *cache)
{
    if (!cache) return;
    rwlock_destroy(&cache->lock);
    free(cache->entries);
    free(cache->ht);
    free(cache->free_slots);
    free(cache->folders);
    free(cache);
}

/* ── vw_cache_upsert ─────────────────────────────────────────────────────── */

vw_err_t vw_cache_upsert(vw_cache_t *cache, const vw_cache_entry_t *entry)
{
    vw_err_t err;
    uint64_t slot;
    uint64_t new_cap;
    vw_cache_entry_t *p;

    if (!cache || !entry || entry->virtual_path[0] == '\0')
        return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&cache->lock);

    slot = cht_find(cache->ht, cache->ht_cap, entry->virtual_path);

    if (slot == CHT_NOT_FOUND) {
        /* Allocate new slot. */
        if (cache->free_len > 0) {
            slot = cache->free_slots[--cache->free_len];
        } else {
            /* Append new slot. */
            uint64_t new_nslots = cache->nslots + 1;
            p = (vw_cache_entry_t *)realloc(cache->entries,
                    new_nslots * sizeof(vw_cache_entry_t));
            if (!p) { err = VW_ERR_OOM; goto unlock; }
            cache->entries = p;
            memset(&cache->entries[cache->nslots], 0, sizeof(vw_cache_entry_t));
            /* Extend on-disk file: write the empty slot first. */
            new_cap = cache->nslots; /* the new slot index */
            err = vw_fs_pwrite(cache->cache_path,
                               new_cap * sizeof(vw_cache_entry_t),
                               &cache->entries[new_cap], sizeof(vw_cache_entry_t));
            if (err != VW_OK) goto unlock;
            slot = cache->nslots;
            cache->nslots = new_nslots;
        }
        if (cht_insert(cache, entry->virtual_path, slot) != 0) {
            err = VW_ERR_OOM; goto unlock;
        }
    }

    cache->entries[slot] = *entry;
    err = cache_write_slot(cache, slot);

unlock:
    rwlock_wrunlock(&cache->lock);
    return err;
}

/* ── vw_cache_get ────────────────────────────────────────────────────────── */

vw_err_t vw_cache_get(vw_cache_t *cache, const char *virtual_path,
                       vw_cache_entry_t *out)
{
    uint64_t slot;

    if (!cache || !virtual_path || !out) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&cache->lock);
    slot = cht_find(cache->ht, cache->ht_cap, virtual_path);
    if (slot != CHT_NOT_FOUND && slot < cache->nslots)
        *out = cache->entries[slot];
    rwlock_rdunlock(&cache->lock);

    return (slot == CHT_NOT_FOUND) ? VW_ERR_NOT_FOUND : VW_OK;
}

/* ── vw_cache_delete ─────────────────────────────────────────────────────── */

vw_err_t vw_cache_delete(vw_cache_t *cache, const char *virtual_path)
{
    vw_err_t err = VW_OK;
    uint64_t slot;

    if (!cache || !virtual_path) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&cache->lock);

    slot = cht_find(cache->ht, cache->ht_cap, virtual_path);
    if (slot == CHT_NOT_FOUND) {
        err = VW_ERR_NOT_FOUND;
        goto unlock;
    }

    cht_remove(cache, virtual_path);
    memset(&cache->entries[slot], 0, sizeof(vw_cache_entry_t));
    err = cache_write_slot(cache, slot);
    if (err == VW_OK)
        (void)free_push(cache, slot);

unlock:
    rwlock_wrunlock(&cache->lock);
    return err;
}

/* ── vw_cache_list ───────────────────────────────────────────────────────── */

vw_err_t vw_cache_list(vw_cache_t *cache, int sync_state,
                        vw_cache_entry_t **out, uint32_t *out_count)
{
    vw_cache_entry_t *arr = NULL;
    uint32_t count = 0;
    uint32_t cap = 0;
    uint64_t i;

    if (!cache || !out || !out_count) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&cache->lock);

    for (i = 1; i < cache->nslots; i++) {
        vw_cache_entry_t *e = &cache->entries[i];
        if (e->virtual_path[0] == '\0') continue;
        if (sync_state != -1 && (int)e->sync_state != sync_state) continue;

        if (count >= cap) {
            uint32_t new_cap = cap ? cap * 2 : 16;
            vw_cache_entry_t *p = (vw_cache_entry_t *)realloc(arr,
                                     new_cap * sizeof(*p));
            if (!p) {
                free(arr);
                rwlock_rdunlock(&cache->lock);
                return VW_ERR_OOM;
            }
            arr = p;
            cap = new_cap;
        }
        arr[count++] = *e;
    }

    rwlock_rdunlock(&cache->lock);

    *out = arr;
    *out_count = count;
    return VW_OK;
}

/* ── Sync-folder management ──────────────────────────────────────────────── */

vw_err_t vw_cache_folder_add(vw_cache_t *cache, const vw_sync_folder_t *f)
{
    vw_err_t err;
    uint64_t i;
    uint64_t free_slot = 0;
    int found_free = 0;
    vw_sync_folder_t *p;

    if (!cache || !f || f->local_root[0] == '\0') return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&cache->lock);

    for (i = 1; i < cache->nfolders; i++) {
        if (cache->folders[i].local_root[0] == '\0') {
            if (!found_free) { free_slot = i; found_free = 1; }
        } else if (strncmp(cache->folders[i].local_root, f->local_root, 511) == 0) {
            err = VW_ERR_ALREADY_EXISTS;
            goto unlock;
        }
    }

    if (!found_free) {
        uint64_t ns = cache->nfolders + 1;
        p = (vw_sync_folder_t *)realloc(cache->folders, ns * sizeof(*p));
        if (!p) { err = VW_ERR_OOM; goto unlock; }
        cache->folders = p;
        memset(&cache->folders[cache->nfolders], 0, sizeof(vw_sync_folder_t));
        free_slot = cache->nfolders;
        cache->nfolders = ns;
    }

    cache->folders[free_slot] = *f;
    err = folder_write_slot(cache, free_slot);

unlock:
    rwlock_wrunlock(&cache->lock);
    return err;
}

vw_err_t vw_cache_folder_remove(vw_cache_t *cache, const char *local_root)
{
    vw_err_t err = VW_ERR_NOT_FOUND;
    uint64_t i;

    if (!cache || !local_root) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&cache->lock);

    for (i = 1; i < cache->nfolders; i++) {
        if (cache->folders[i].local_root[0] != '\0' &&
            strncmp(cache->folders[i].local_root, local_root, 511) == 0)
        {
            memset(&cache->folders[i], 0, sizeof(vw_sync_folder_t));
            err = folder_write_slot(cache, i);
            break;
        }
    }

    rwlock_wrunlock(&cache->lock);
    return err;
}

vw_err_t vw_cache_folder_list(vw_cache_t *cache,
                               vw_sync_folder_t **out, uint32_t *out_count)
{
    vw_sync_folder_t *arr = NULL;
    uint32_t count = 0;
    uint64_t i;

    if (!cache || !out || !out_count) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&cache->lock);

    for (i = 1; i < cache->nfolders; i++) {
        if (cache->folders[i].local_root[0] != '\0') count++;
    }

    if (count > 0) {
        arr = (vw_sync_folder_t *)malloc(count * sizeof(*arr));
        if (!arr) {
            rwlock_rdunlock(&cache->lock);
            return VW_ERR_OOM;
        }
        uint32_t j = 0;
        for (i = 1; i < cache->nfolders; i++) {
            if (cache->folders[i].local_root[0] != '\0')
                arr[j++] = cache->folders[i];
        }
    }

    rwlock_rdunlock(&cache->lock);

    *out = arr;
    *out_count = count;
    return VW_OK;
}

vw_err_t vw_cache_folder_set_paused(vw_cache_t *cache,
                                     const char *local_root, uint8_t paused)
{
    vw_err_t err = VW_ERR_NOT_FOUND;
    uint64_t i;

    if (!cache || !local_root) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&cache->lock);

    for (i = 1; i < cache->nfolders; i++) {
        if (cache->folders[i].local_root[0] != '\0' &&
            strncmp(cache->folders[i].local_root, local_root, 511) == 0)
        {
            cache->folders[i].paused = paused;
            err = folder_write_slot(cache, i);
            break;
        }
    }

    rwlock_wrunlock(&cache->lock);
    return err;
}
