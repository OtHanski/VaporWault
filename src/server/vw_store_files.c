/*
 * vw_store_files.c — file and version metadata tables (Phase 2).
 *
 * Storage layout under {data_dir}/files/:
 *   meta.dat       — array of vw_file_record_t (128 bytes/slot)
 *   versions.dat   — array of vw_version_record_t (80 bytes/slot)
 *   versions.blob  — chunk hash arrays (chunk_count * 32 bytes per version)
 *
 * Slot 0 of meta.dat is a guard (file_id == 0 == free).
 * Real file records occupy slots >= 1.
 * Version slot 0 is likewise a guard (version_id == 0 == free).
 *
 * In-memory structures:
 *   path_ht    — open-addressed HT keyed by (owner_id, fnv1a(leaf_name))
 *                Used for fast duplicate detection on create and for path walking.
 *                On hash collision (same owner + same name-hash but different
 *                parent_dir or actual name), the lookup reads from disk to verify.
 *   fid_to_slot — array indexed by file_id; value = 0-based slot in meta.dat.
 *                 Index 0 is unused (file_id 0 = free).
 *   vid_to_slot — array indexed by version_id; same convention.
 *
 * All write operations use oplog two-phase commit (same pattern as vw_store.c):
 *   vw_oplog_append → write to .dat → sync → update indexes → vw_oplog_confirm
 *   On any failure before confirm: vw_oplog_abort.
 *
 * Path walk (get_by_path):
 *   Split absolute path into components; for each component look up in path_ht
 *   by (owner_id, fnv1a(component)). On candidate found, read the record from
 *   disk and verify owner_id + parent_dir_id + name. Walk to next component.
 *   O(components * avg_probe_length) — acceptable for Phase 2.
 */

#include "vw_store.h"
#include "vw_oplog.h"
#include "../core/vw_fs.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
#   include <fcntl.h>
#   include <unistd.h>
typedef pthread_rwlock_t vw_rwlock_t;
#   define rwlock_init(l)     pthread_rwlock_init((l), NULL)
#   define rwlock_rdlock(l)   pthread_rwlock_rdlock(l)
#   define rwlock_rdunlock(l) pthread_rwlock_unlock(l)
#   define rwlock_wrlock(l)   pthread_rwlock_wrlock(l)
#   define rwlock_wrunlock(l) pthread_rwlock_unlock(l)
#   define rwlock_destroy(l)  pthread_rwlock_destroy(l)
#endif

/* ── pread helper — atomic read at offset, no seek state ─────────────────── */

#ifdef _WIN32
static int fs_pread(const char *path, void *buf, size_t len, uint64_t off)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;

    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.Offset     = (DWORD)(off & 0xFFFFFFFFu);
    ov.OffsetHigh = (DWORD)(off >> 32);

    DWORD nread = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)len, &nread, &ov);
    CloseHandle(h);
    return (ok && nread == (DWORD)len) ? 0 : -1;
}
#else
static int fs_pread(const char *path, void *buf, size_t len, uint64_t off)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)off);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}
#endif

/* ── FNV-1a 64-bit hash ───────────────────────────────────────────────────── */

static uint64_t fnv1a(const void *data, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    const uint8_t *p = (const uint8_t *)data;
    size_t i;
    for (i = 0; i < len; i++)
        h = (h ^ (uint64_t)p[i]) * 1099511628211ULL;
    return h;
}

/* ── Path hash table ─────────────────────────────────────────────────────── */
/*
 * Key: (owner_id, name_hash) where name_hash = fnv1a(leaf_name_component).
 * Empty entry: owner_id == 0. Multiple entries with same key allowed; the
 * lookup reads from disk to distinguish by parent_dir_id + actual name.
 */

#define PATH_HT_INITIAL_CAP 64u

typedef struct {
    uint64_t owner_id;   /* 0 = empty slot */
    uint64_t name_hash;  /* fnv1a of the leaf name component */
    uint64_t slot;       /* 0-based slot in meta.dat */
} path_ht_entry_t;

static uint64_t path_ht_probe_start(uint64_t owner_id, uint64_t name_hash,
                                     size_t cap)
{
    /* Mix both key fields for the initial probe position. */
    uint64_t h = owner_id * 6364136223846793005ULL + name_hash;
    return h % (uint64_t)cap;
}

static int path_ht_insert_raw(path_ht_entry_t *ht, size_t cap,
                               uint64_t owner_id, uint64_t nh, uint64_t slot)
{
    uint64_t h = path_ht_probe_start(owner_id, nh, cap);
    size_t i;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].owner_id == 0) {
            ht[idx].owner_id  = owner_id;
            ht[idx].name_hash = nh;
            ht[idx].slot      = slot;
            return 0;
        }
    }
    return -1; /* full — caller must grow first */
}

/* ── Internal context ─────────────────────────────────────────────────────── */

struct vw_file_store {
    char files_dir[512];     /* {data_dir}/files */
    char meta_path[512];     /* .../files/meta.dat */
    char versions_path[512]; /* .../files/versions.dat */
    char blob_path[512];     /* .../files/versions.blob */
    vw_oplog_t *oplog;       /* borrowed */

    /* File records — guarded by files_lock */
    vw_rwlock_t      files_lock;
    uint64_t         next_file_id;
    uint64_t         file_slots;      /* total slot count in meta.dat */
    path_ht_entry_t *path_ht;
    size_t           path_ht_cap;
    size_t           path_ht_len;
    uint64_t        *fid_to_slot;     /* fid_to_slot[file_id] = 0-based slot; 0 = absent */
    size_t           fid_to_slot_cap;

    /* Version records — guarded by versions_lock */
    vw_rwlock_t  versions_lock;
    uint64_t     next_version_id;
    uint64_t     version_slots;       /* total slot count in versions.dat */
    uint64_t     blob_size;           /* current EOF of versions.blob (bytes) */
    uint64_t    *vid_to_slot;         /* vid_to_slot[version_id] = 0-based slot; 0 = absent */
    size_t       vid_to_slot_cap;
};

/* ── Dynamic array helpers ───────────────────────────────────────────────── */

static int fid_to_slot_ensure(struct vw_file_store *fs, uint64_t file_id)
{
    if (file_id >= (uint64_t)fs->fid_to_slot_cap) {
        size_t new_cap = fs->fid_to_slot_cap ? fs->fid_to_slot_cap * 2 : 64;
        while ((uint64_t)new_cap <= file_id) new_cap *= 2;
        uint64_t *p = (uint64_t *)realloc(fs->fid_to_slot,
                                           new_cap * sizeof(uint64_t));
        if (!p) return -1;
        memset(p + fs->fid_to_slot_cap, 0,
               (new_cap - fs->fid_to_slot_cap) * sizeof(uint64_t));
        fs->fid_to_slot     = p;
        fs->fid_to_slot_cap = new_cap;
    }
    return 0;
}

static int vid_to_slot_ensure(struct vw_file_store *fs, uint64_t version_id)
{
    if (version_id >= (uint64_t)fs->vid_to_slot_cap) {
        size_t new_cap = fs->vid_to_slot_cap ? fs->vid_to_slot_cap * 2 : 64;
        while ((uint64_t)new_cap <= version_id) new_cap *= 2;
        uint64_t *p = (uint64_t *)realloc(fs->vid_to_slot,
                                           new_cap * sizeof(uint64_t));
        if (!p) return -1;
        memset(p + fs->vid_to_slot_cap, 0,
               (new_cap - fs->vid_to_slot_cap) * sizeof(uint64_t));
        fs->vid_to_slot     = p;
        fs->vid_to_slot_cap = new_cap;
    }
    return 0;
}

/* ── Path hash table operations ─────────────────────────────────────────── */

static int path_ht_grow(struct vw_file_store *fs)
{
    size_t new_cap = fs->path_ht_cap * 2;
    path_ht_entry_t *new_ht = (path_ht_entry_t *)calloc(new_cap,
                                                          sizeof(*new_ht));
    if (!new_ht) return -1;
    size_t i;
    for (i = 0; i < fs->path_ht_cap; i++) {
        if (fs->path_ht[i].owner_id != 0)
            path_ht_insert_raw(new_ht, new_cap,
                               fs->path_ht[i].owner_id,
                               fs->path_ht[i].name_hash,
                               fs->path_ht[i].slot);
    }
    free(fs->path_ht);
    fs->path_ht     = new_ht;
    fs->path_ht_cap = new_cap;
    return 0;
}

/* Insert (owner_id, name_hash → slot) into path_ht, growing as needed. */
static int path_ht_insert(struct vw_file_store *fs,
                           uint64_t owner_id, uint64_t name_hash, uint64_t slot)
{
    if (fs->path_ht_len * 4 >= fs->path_ht_cap * 3)
        if (path_ht_grow(fs) != 0) return -1;
    if (path_ht_insert_raw(fs->path_ht, fs->path_ht_cap,
                            owner_id, name_hash, slot) != 0) return -1;
    fs->path_ht_len++;
    return 0;
}

/*
 * Find a file by (owner_id, name_component, parent_dir_id) using the path HT.
 * Reads candidates from disk to resolve hash collisions.
 * Returns UINT64_MAX on miss; slot index on hit.
 */
static uint64_t path_ht_find_in_dir(const struct vw_file_store *fs,
                                     uint64_t owner_id,
                                     const char *name,
                                     uint64_t parent_dir_id)
{
    if (!fs->path_ht_cap) return UINT64_MAX;
    uint64_t nh = fnv1a(name, strlen(name));
    uint64_t h = path_ht_probe_start(owner_id, nh, fs->path_ht_cap);
    size_t i;

    for (i = 0; i < fs->path_ht_cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)fs->path_ht_cap);
        const path_ht_entry_t *e = &fs->path_ht[idx];

        if (e->owner_id == 0) break; /* empty slot — end of probe chain */

        if (e->owner_id != owner_id || e->name_hash != nh) continue;

        /* Candidate — read the record from disk to verify. */
        vw_file_record_t rec;
        uint64_t off = e->slot * (uint64_t)sizeof(vw_file_record_t);
        if (fs_pread(fs->meta_path, &rec, sizeof(rec), off) != 0) continue;

        if (rec.owner_id     == owner_id &&
            rec.parent_dir_id == parent_dir_id &&
            !rec.deleted &&
            strncmp(rec.name, name, 63) == 0)
            return e->slot;
    }
    return UINT64_MAX;
}

/* ── File guard-slot writer (slot 0) ──────────────────────────────────────── */

static vw_err_t write_file_guard(const char *path)
{
    vw_file_record_t guard;
    memset(&guard, 0, sizeof(guard));
    return vw_fs_append(path, &guard, sizeof(guard));
}

static vw_err_t write_version_guard(const char *path)
{
    vw_version_record_t guard;
    memset(&guard, 0, sizeof(guard));
    return vw_fs_append(path, &guard, sizeof(guard));
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_file_store_open(const char *data_dir, vw_oplog_t *oplog,
                             vw_file_store_t **out)
{
    vw_err_t rc;
    struct vw_file_store *fs;
    uint64_t file_size;

    if (!data_dir || !oplog || !out) return VW_ERR_INVALID_ARG;

    fs = (struct vw_file_store *)calloc(1, sizeof(*fs));
    if (!fs) return VW_ERR_OOM;
    fs->oplog = oplog;

    /* Build paths */
    if (vw_fs_path_join(fs->files_dir, sizeof(fs->files_dir),
                        data_dir, "files") != VW_OK ||
        vw_fs_path_join(fs->meta_path, sizeof(fs->meta_path),
                        fs->files_dir, "meta.dat") != VW_OK ||
        vw_fs_path_join(fs->versions_path, sizeof(fs->versions_path),
                        fs->files_dir, "versions.dat") != VW_OK ||
        vw_fs_path_join(fs->blob_path, sizeof(fs->blob_path),
                        fs->files_dir, "versions.blob") != VW_OK) {
        free(fs);
        return VW_ERR_INVALID_ARG;
    }

    rc = vw_fs_ensure_dir(fs->files_dir);
    if (rc != VW_OK) { free(fs); return rc; }

    rwlock_init(&fs->files_lock);
    rwlock_init(&fs->versions_lock);

    /* Allocate initial path HT */
    fs->path_ht = (path_ht_entry_t *)calloc(PATH_HT_INITIAL_CAP,
                                              sizeof(*fs->path_ht));
    if (!fs->path_ht) { free(fs); return VW_ERR_OOM; }
    fs->path_ht_cap = PATH_HT_INITIAL_CAP;

    /* ── meta.dat ── */
    if (!vw_fs_exists(fs->meta_path)) {
        rc = write_file_guard(fs->meta_path);
        if (rc != VW_OK) { vw_file_store_close(fs); return rc; }
    }

    rc = vw_fs_file_size(fs->meta_path, &file_size);
    if (rc != VW_OK) { vw_file_store_close(fs); return rc; }
    fs->file_slots = file_size / sizeof(vw_file_record_t);
    fs->next_file_id = 1;

    /* Scan meta.dat to build fid_to_slot and path_ht */
    {
        uint64_t s;
        for (s = 1; s < fs->file_slots; s++) {
            vw_file_record_t rec;
            uint64_t off = s * (uint64_t)sizeof(vw_file_record_t);
            if (fs_pread(fs->meta_path, &rec, sizeof(rec), off) != 0) continue;
            if (rec.file_id == 0) continue; /* free slot */

            if (fid_to_slot_ensure(fs, rec.file_id) != 0) {
                vw_file_store_close(fs);
                return VW_ERR_OOM;
            }
            fs->fid_to_slot[rec.file_id] = s;
            if (rec.file_id >= fs->next_file_id)
                fs->next_file_id = rec.file_id + 1;

            if (!rec.deleted) {
                uint64_t nh = fnv1a(rec.name, strlen(rec.name));
                if (path_ht_insert(fs, rec.owner_id, nh, s) != 0) {
                    vw_file_store_close(fs);
                    return VW_ERR_OOM;
                }
            }
        }
    }

    /* ── versions.dat ── */
    if (!vw_fs_exists(fs->versions_path)) {
        rc = write_version_guard(fs->versions_path);
        if (rc != VW_OK) { vw_file_store_close(fs); return rc; }
    }

    rc = vw_fs_file_size(fs->versions_path, &file_size);
    if (rc != VW_OK) { vw_file_store_close(fs); return rc; }
    fs->version_slots = file_size / sizeof(vw_version_record_t);
    fs->next_version_id = 1;
    fs->blob_size = 0;

    /* Scan versions.dat to build vid_to_slot and compute blob_size */
    {
        uint64_t s;
        for (s = 1; s < fs->version_slots; s++) {
            vw_version_record_t rec;
            uint64_t off = s * (uint64_t)sizeof(vw_version_record_t);
            if (fs_pread(fs->versions_path, &rec, sizeof(rec), off) != 0) continue;
            if (rec.version_id == 0) continue;

            if (vid_to_slot_ensure(fs, rec.version_id) != 0) {
                vw_file_store_close(fs);
                return VW_ERR_OOM;
            }
            fs->vid_to_slot[rec.version_id] = s;
            if (rec.version_id >= fs->next_version_id)
                fs->next_version_id = rec.version_id + 1;

            uint64_t end = rec.blob_offset +
                           (uint64_t)rec.chunk_count * VW_HASH_BYTES;
            if (end > fs->blob_size)
                fs->blob_size = end;
        }
    }

    /* ── versions.blob ── */
    if (!vw_fs_exists(fs->blob_path)) {
        /* create empty blob file */
        rc = vw_fs_append(fs->blob_path, "", 0);
        if (rc != VW_OK) { vw_file_store_close(fs); return rc; }
    }

    *out = fs;
    return VW_OK;
}

void vw_file_store_close(vw_file_store_t *fs)
{
    if (!fs) return;
    rwlock_destroy(&fs->files_lock);
    rwlock_destroy(&fs->versions_lock);
    free(fs->path_ht);
    free(fs->fid_to_slot);
    free(fs->vid_to_slot);
    free(fs);
}

/* ── File CRUD ───────────────────────────────────────────────────────────── */

vw_err_t vw_store_file_create(vw_file_store_t *fs,
                               const vw_file_record_t *rec,
                               uint64_t *out_file_id)
{
    vw_err_t rc;
    vw_err_t abort_rc;
    uint64_t eid;
    uint64_t file_id;
    uint64_t slot;
    vw_file_record_t w;

    if (!fs || !rec || !out_file_id)        return VW_ERR_INVALID_ARG;
    if (rec->owner_id == 0)                  return VW_ERR_INVALID_ARG;
    if (rec->name[0] == '\0')                return VW_ERR_INVALID_ARG;
    if (strnlen(rec->name, 64) >= 64)        return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&fs->files_lock);

    /* Duplicate check: same owner + same parent + same name */
    uint64_t nh = fnv1a(rec->name, strlen(rec->name));
    if (path_ht_find_in_dir(fs, rec->owner_id, rec->name,
                              rec->parent_dir_id) != UINT64_MAX) {
        rwlock_wrunlock(&fs->files_lock);
        return VW_ERR_ALREADY_EXISTS;
    }

    /* Pre-grow path_ht before any disk writes so the post-commit insert below
     * cannot fail with OOM after the record is already durable on disk. */
    if (fs->path_ht_len * 4 >= fs->path_ht_cap * 3) {
        if (path_ht_grow(fs) != 0) {
            rwlock_wrunlock(&fs->files_lock);
            return VW_ERR_OOM;
        }
    }

    rc = vw_oplog_append(fs->oplog, VW_OPLOG_FILE_WRITE,
                         &rec->owner_id, (uint32_t)sizeof(rec->owner_id), &eid);
    if (rc != VW_OK) { rwlock_wrunlock(&fs->files_lock); return rc; }

    file_id = fs->next_file_id;
    slot    = fs->file_slots; /* append at end */

    w = *rec;
    w.file_id = file_id;
    memset(w._pad, 0, sizeof(w._pad));
    memset(w._reserved, 0, sizeof(w._reserved));

    rc = vw_fs_append(fs->meta_path, &w, sizeof(w));
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(fs->oplog, eid);
        (void)abort_rc;
        rwlock_wrunlock(&fs->files_lock);
        return rc;
    }

    rc = vw_fs_sync_file(fs->meta_path);
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(fs->oplog, eid);
        (void)abort_rc;
        rwlock_wrunlock(&fs->files_lock);
        return rc;
    }

    /*
     * Disk write committed: advance counters before touching indexes.
     * If index OOM occurs below, the record is on disk but unreachable
     * in-memory this session. next_file_id is advanced so a subsequent
     * create does not overwrite this slot; fid_to_slot is set where
     * possible. The oplog entry is confirmed so the next-open scan can
     * rebuild the index from disk.
     */
    fs->file_slots++;
    fs->next_file_id++;

    if (fid_to_slot_ensure(fs, file_id) == 0)
        fs->fid_to_slot[file_id] = slot;

    rc = vw_oplog_confirm(fs->oplog, eid);
    (void)rc;

    if (path_ht_insert(fs, rec->owner_id, nh, slot) != 0) {
        rwlock_wrunlock(&fs->files_lock);
        return VW_ERR_OOM;
    }

    *out_file_id = file_id;
    rwlock_wrunlock(&fs->files_lock);
    return VW_OK;
}

vw_err_t vw_store_file_get_by_id(vw_file_store_t *fs,
                                  uint64_t file_id,
                                  vw_file_record_t *out)
{
    if (!fs || !out || file_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&fs->files_lock);

    if (file_id >= (uint64_t)fs->fid_to_slot_cap ||
        fs->fid_to_slot[file_id] == 0) {
        rwlock_rdunlock(&fs->files_lock);
        return VW_ERR_NOT_FOUND;
    }

    uint64_t slot = fs->fid_to_slot[file_id];
    uint64_t off  = slot * (uint64_t)sizeof(vw_file_record_t);

    vw_file_record_t rec;
    if (fs_pread(fs->meta_path, &rec, sizeof(rec), off) != 0) {
        rwlock_rdunlock(&fs->files_lock);
        return VW_ERR_IO;
    }

    rwlock_rdunlock(&fs->files_lock);

    if (rec.file_id == 0 || rec.deleted)
        return VW_ERR_NOT_FOUND;

    *out = rec;
    return VW_OK;
}

vw_err_t vw_store_file_get_by_path(vw_file_store_t *fs,
                                    uint64_t owner_id,
                                    const char *path,
                                    vw_file_record_t *out)
{
    if (!fs || !path || !out || owner_id == 0) return VW_ERR_INVALID_ARG;
    if (path[0] != '/') return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&fs->files_lock);

    uint64_t parent_dir_id = 0;
    const char *p = path + 1; /* skip leading '/' */
    vw_file_record_t found;
    memset(&found, 0, sizeof(found));
    int found_something = 0;

    while (*p) {
        /* Extract next component */
        const char *slash = strchr(p, '/');
        size_t complen = slash ? (size_t)(slash - p) : strlen(p);
        if (complen == 0 || complen > 63) {
            rwlock_rdunlock(&fs->files_lock);
            return VW_ERR_NOT_FOUND;
        }

        char comp[64];
        memcpy(comp, p, complen);
        comp[complen] = '\0';

        uint64_t slot = path_ht_find_in_dir(fs, owner_id, comp, parent_dir_id);
        if (slot == UINT64_MAX) {
            rwlock_rdunlock(&fs->files_lock);
            return VW_ERR_NOT_FOUND;
        }

        uint64_t off = slot * (uint64_t)sizeof(vw_file_record_t);
        if (fs_pread(fs->meta_path, &found, sizeof(found), off) != 0) {
            rwlock_rdunlock(&fs->files_lock);
            return VW_ERR_IO;
        }
        found_something = 1;
        parent_dir_id = found.file_id;

        p = slash ? slash + 1 : p + complen;
    }

    rwlock_rdunlock(&fs->files_lock);

    if (!found_something || found.deleted)
        return VW_ERR_NOT_FOUND;

    *out = found;
    return VW_OK;
}

vw_err_t vw_store_file_update(vw_file_store_t *fs,
                               uint64_t file_id,
                               const vw_file_record_t *new_rec)
{
    vw_err_t rc;
    vw_err_t abort_rc;
    uint64_t eid;

    if (!fs || !new_rec || file_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&fs->files_lock);

    if (file_id >= (uint64_t)fs->fid_to_slot_cap ||
        fs->fid_to_slot[file_id] == 0) {
        rwlock_wrunlock(&fs->files_lock);
        return VW_ERR_NOT_FOUND;
    }

    uint64_t slot = fs->fid_to_slot[file_id];
    uint64_t off  = slot * (uint64_t)sizeof(vw_file_record_t);

    rc = vw_oplog_append(fs->oplog, VW_OPLOG_FILE_WRITE,
                         &file_id, (uint32_t)sizeof(file_id), &eid);
    if (rc != VW_OK) { rwlock_wrunlock(&fs->files_lock); return rc; }

    vw_file_record_t w = *new_rec;
    w.file_id = file_id; /* preserve canonical ID */
    memset(w._pad, 0, sizeof(w._pad));
    memset(w._reserved, 0, sizeof(w._reserved));

    rc = vw_fs_pwrite(fs->meta_path, off, &w, sizeof(w));
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(fs->oplog, eid);
        (void)abort_rc;
        rwlock_wrunlock(&fs->files_lock);
        return rc;
    }

    rc = vw_fs_sync_file(fs->meta_path);
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(fs->oplog, eid);
        (void)abort_rc;
        rwlock_wrunlock(&fs->files_lock);
        return rc;
    }

    rc = vw_oplog_confirm(fs->oplog, eid);
    (void)rc;

    rwlock_wrunlock(&fs->files_lock);
    return VW_OK;
}

vw_err_t vw_store_file_soft_delete(vw_file_store_t *fs, uint64_t file_id)
{
    vw_file_record_t rec;
    vw_err_t rc = vw_store_file_get_by_id(fs, file_id, &rec);
    if (rc != VW_OK) return rc;

    rec.deleted = 1;
    return vw_store_file_update(fs, file_id, &rec);
}

vw_err_t vw_store_file_list(vw_file_store_t *fs,
                             uint64_t owner_id,
                             uint64_t parent_dir_id,
                             vw_file_record_t **out_records,
                             uint32_t *out_count)
{
    if (!fs || !out_records || !out_count) return VW_ERR_INVALID_ARG;

    *out_records = NULL;
    *out_count   = 0;

    rwlock_rdlock(&fs->files_lock);

    /* Two-pass: count then collect. */
    uint32_t count = 0;
    uint64_t s;
    for (s = 1; s < fs->file_slots; s++) {
        vw_file_record_t rec;
        uint64_t off = s * (uint64_t)sizeof(vw_file_record_t);
        if (fs_pread(fs->meta_path, &rec, sizeof(rec), off) != 0) continue;
        if (rec.file_id  == 0)           continue;
        if (rec.deleted)                  continue;
        if (rec.owner_id != owner_id)    continue;
        if (rec.parent_dir_id != parent_dir_id) continue;
        count++;
    }

    if (count == 0) {
        rwlock_rdunlock(&fs->files_lock);
        return VW_OK;
    }

    vw_file_record_t *arr = (vw_file_record_t *)malloc(
                                count * sizeof(vw_file_record_t));
    if (!arr) {
        rwlock_rdunlock(&fs->files_lock);
        return VW_ERR_OOM;
    }

    uint32_t n = 0;
    for (s = 1; s < fs->file_slots && n < count; s++) {
        vw_file_record_t rec;
        uint64_t off = s * (uint64_t)sizeof(vw_file_record_t);
        if (fs_pread(fs->meta_path, &rec, sizeof(rec), off) != 0) continue;
        if (rec.file_id  == 0)           continue;
        if (rec.deleted)                  continue;
        if (rec.owner_id != owner_id)    continue;
        if (rec.parent_dir_id != parent_dir_id) continue;
        arr[n++] = rec;
    }

    rwlock_rdunlock(&fs->files_lock);

    *out_records = arr;
    *out_count   = n;
    return VW_OK;
}

/* ── Version CRUD ────────────────────────────────────────────────────────── */

vw_err_t vw_store_version_create(vw_file_store_t *fs,
                                  const vw_version_record_t *rec,
                                  const uint8_t *chunk_hashes,
                                  uint64_t *out_version_id)
{
    vw_err_t rc;
    vw_err_t abort_rc;
    uint64_t eid;

    if (!fs || !rec || !out_version_id) return VW_ERR_INVALID_ARG;
    if (rec->file_id == 0)              return VW_ERR_INVALID_ARG;
    if (rec->chunk_count > 0 && !chunk_hashes) return VW_ERR_INVALID_ARG;
    /* Protocol limits chunk_count to uint16 range; guard the storage layer too
     * to prevent blob_bytes overflow when passed chunk_count is unvalidated. */
    if (rec->chunk_count > UINT16_MAX) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&fs->versions_lock);

    uint64_t version_id = fs->next_version_id;
    uint64_t blob_off   = fs->blob_size;
    uint64_t blob_bytes = (uint64_t)rec->chunk_count * VW_HASH_BYTES;

    /* Oplog append for the version write. */
    rc = vw_oplog_append(fs->oplog, VW_OPLOG_FILE_WRITE,
                         &rec->file_id, (uint32_t)sizeof(rec->file_id), &eid);
    if (rc != VW_OK) { rwlock_wrunlock(&fs->versions_lock); return rc; }

    /* 1. Append chunk hashes to versions.blob. */
    if (blob_bytes > 0) {
        rc = vw_fs_append(fs->blob_path, chunk_hashes, (size_t)blob_bytes);
        if (rc != VW_OK) {
            abort_rc = vw_oplog_abort(fs->oplog, eid);
            (void)abort_rc;
            rwlock_wrunlock(&fs->versions_lock);
            return rc;
        }
        rc = vw_fs_sync_file(fs->blob_path);
        if (rc != VW_OK) {
            abort_rc = vw_oplog_abort(fs->oplog, eid);
            (void)abort_rc;
            rwlock_wrunlock(&fs->versions_lock);
            return rc;
        }
    }

    /* 2. Append version record to versions.dat. */
    vw_version_record_t w = *rec;
    w.version_id  = version_id;
    w.blob_offset = blob_off;
    memset(w._reserved, 0, sizeof(w._reserved));
    w._pad = 0;

    rc = vw_fs_append(fs->versions_path, &w, sizeof(w));
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(fs->oplog, eid);
        (void)abort_rc;
        rwlock_wrunlock(&fs->versions_lock);
        return rc;
    }
    rc = vw_fs_sync_file(fs->versions_path);
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(fs->oplog, eid);
        (void)abort_rc;
        rwlock_wrunlock(&fs->versions_lock);
        return rc;
    }

    /* 3. Update indexes — advance counters first so a subsequent create
     *    never reuses this slot or this blob region if vid_to_slot OOMs. */
    uint64_t slot = fs->version_slots;
    fs->version_slots++;
    fs->blob_size += blob_bytes;
    fs->next_version_id++;

    rc = vw_oplog_confirm(fs->oplog, eid);
    (void)rc;

    if (vid_to_slot_ensure(fs, version_id) == 0)
        fs->vid_to_slot[version_id] = slot;
    /* OOM here: version is on disk and counters correct; index rebuilt on restart. */

    *out_version_id = version_id;
    rwlock_wrunlock(&fs->versions_lock);
    return VW_OK;
}

vw_err_t vw_store_version_get(vw_file_store_t *fs,
                               uint64_t version_id,
                               vw_version_record_t *out)
{
    if (!fs || !out || version_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&fs->versions_lock);

    if (version_id >= (uint64_t)fs->vid_to_slot_cap ||
        fs->vid_to_slot[version_id] == 0) {
        rwlock_rdunlock(&fs->versions_lock);
        return VW_ERR_NOT_FOUND;
    }

    uint64_t slot = fs->vid_to_slot[version_id];
    uint64_t off  = slot * (uint64_t)sizeof(vw_version_record_t);

    vw_version_record_t rec;
    if (fs_pread(fs->versions_path, &rec, sizeof(rec), off) != 0) {
        rwlock_rdunlock(&fs->versions_lock);
        return VW_ERR_IO;
    }

    rwlock_rdunlock(&fs->versions_lock);

    if (rec.version_id == 0) return VW_ERR_NOT_FOUND;
    *out = rec;
    return VW_OK;
}

vw_err_t vw_store_version_get_chunks(vw_file_store_t *fs,
                                      const vw_version_record_t *ver,
                                      uint8_t **out_hashes)
{
    if (!fs || !ver || !out_hashes) return VW_ERR_INVALID_ARG;
    if (ver->chunk_count == 0) {
        *out_hashes = NULL;
        return VW_OK;
    }

    size_t bytes = (size_t)ver->chunk_count * VW_HASH_BYTES;
    uint8_t *buf = (uint8_t *)malloc(bytes);
    if (!buf) return VW_ERR_OOM;

    rwlock_rdlock(&fs->versions_lock);
    int r = fs_pread(fs->blob_path, buf, bytes, ver->blob_offset);
    rwlock_rdunlock(&fs->versions_lock);

    if (r != 0) {
        free(buf);
        return VW_ERR_IO;
    }

    *out_hashes = buf;
    return VW_OK;
}

vw_err_t vw_store_version_list(vw_file_store_t *fs,
                                uint64_t file_id,
                                vw_version_record_t **out_records,
                                uint32_t *out_count)
{
    if (!fs || !out_records || !out_count || file_id == 0)
        return VW_ERR_INVALID_ARG;

    *out_records = NULL;
    *out_count   = 0;

    rwlock_rdlock(&fs->versions_lock);

    uint32_t count = 0;
    uint64_t s;
    for (s = 1; s < fs->version_slots; s++) {
        vw_version_record_t rec;
        uint64_t off = s * (uint64_t)sizeof(vw_version_record_t);
        if (fs_pread(fs->versions_path, &rec, sizeof(rec), off) != 0) continue;
        if (rec.version_id == 0) continue;
        if (rec.file_id != file_id) continue;
        count++;
    }

    if (count == 0) {
        rwlock_rdunlock(&fs->versions_lock);
        return VW_OK;
    }

    vw_version_record_t *arr = (vw_version_record_t *)malloc(
                                    count * sizeof(vw_version_record_t));
    if (!arr) {
        rwlock_rdunlock(&fs->versions_lock);
        return VW_ERR_OOM;
    }

    uint32_t n = 0;
    for (s = 1; s < fs->version_slots && n < count; s++) {
        vw_version_record_t rec;
        uint64_t off = s * (uint64_t)sizeof(vw_version_record_t);
        if (fs_pread(fs->versions_path, &rec, sizeof(rec), off) != 0) continue;
        if (rec.version_id == 0) continue;
        if (rec.file_id != file_id) continue;
        arr[n++] = rec;
    }

    rwlock_rdunlock(&fs->versions_lock);

    /* Sort by version_id ascending (insertion sort — n is small in Phase 2). */
    uint32_t i, j;
    for (i = 1; i < n; i++) {
        vw_version_record_t key = arr[i];
        j = i;
        while (j > 0 && arr[j-1].version_id > key.version_id) {
            arr[j] = arr[j-1];
            j--;
        }
        arr[j] = key;
    }

    *out_records = arr;
    *out_count   = n;
    return VW_OK;
}

/* ── File GC helpers ─────────────────────────────────────────────────────── */

vw_err_t vw_store_file_scan_deleted(vw_file_store_t *fs,
                                     int (*cb)(const vw_file_record_t *, void *),
                                     void *userdata)
{
    if (!fs || !cb) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&fs->files_lock);

    uint64_t s;
    for (s = 1; s < fs->file_slots; s++) {
        vw_file_record_t rec;
        uint64_t off = s * (uint64_t)sizeof(vw_file_record_t);
        if (fs_pread(fs->meta_path, &rec, sizeof(rec), off) != 0) continue;
        if (rec.file_id == 0 || !rec.deleted) continue;

        if (cb(&rec, userdata) != 0) break;
    }

    rwlock_rdunlock(&fs->files_lock);
    return VW_OK;
}

vw_err_t vw_store_file_hard_delete(vw_file_store_t *fs, uint64_t file_id)
{
    if (!fs || file_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&fs->files_lock);

    if (file_id >= (uint64_t)fs->fid_to_slot_cap ||
        fs->fid_to_slot[file_id] == 0) {
        rwlock_wrunlock(&fs->files_lock);
        return VW_ERR_NOT_FOUND;
    }

    uint64_t slot = fs->fid_to_slot[file_id];
    uint64_t off  = slot * (uint64_t)sizeof(vw_file_record_t);

    vw_file_record_t zero;
    memset(&zero, 0, sizeof(zero));

    vw_err_t rc = vw_fs_pwrite(fs->meta_path, off, &zero, sizeof(zero));
    if (rc != VW_OK) {
        rwlock_wrunlock(&fs->files_lock);
        return rc;
    }

    rc = vw_fs_sync_file(fs->meta_path);
    if (rc != VW_OK) {
        rwlock_wrunlock(&fs->files_lock);
        return rc;
    }

    fs->fid_to_slot[file_id] = 0;

    rwlock_wrunlock(&fs->files_lock);
    return VW_OK;
}

vw_err_t vw_store_version_hard_delete(vw_file_store_t *fs, uint64_t version_id)
{
    if (!fs || version_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&fs->versions_lock);

    if (version_id >= (uint64_t)fs->vid_to_slot_cap ||
        fs->vid_to_slot[version_id] == 0) {
        rwlock_wrunlock(&fs->versions_lock);
        return VW_ERR_NOT_FOUND;
    }

    uint64_t slot = fs->vid_to_slot[version_id];
    uint64_t off  = slot * (uint64_t)sizeof(vw_version_record_t);

    vw_version_record_t zero;
    memset(&zero, 0, sizeof(zero));

    vw_err_t rc = vw_fs_pwrite(fs->versions_path, off, &zero, sizeof(zero));
    if (rc != VW_OK) {
        rwlock_wrunlock(&fs->versions_lock);
        return rc;
    }

    rc = vw_fs_sync_file(fs->versions_path);
    if (rc != VW_OK) {
        rwlock_wrunlock(&fs->versions_lock);
        return rc;
    }

    fs->vid_to_slot[version_id] = 0;

    rwlock_wrunlock(&fs->versions_lock);
    return VW_OK;
}
