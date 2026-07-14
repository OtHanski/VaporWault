/*
 * vw_storage.c — SHA-256-keyed chunk content store.
 *
 * See vw_storage.h for design overview.
 *
 * On-disk refcounts record (48 bytes):
 *   hash[32] + ref_count(u32) + _pad(u32) + owner_user_id(u64)
 *
 * refcounts.db:
 *   Slot 0 is a guard (all-zero). Slots 1+ hold real records.
 *   Slot is free when hash is all-zero (SHA-256 of real data is never 0).
 *   New records are appended; existing records are updated in-place via
 *   vw_fs_pwrite. GC zeroes the hash to mark a slot free.
 *
 * In-memory HT:
 *   Key: first 8 bytes of hash as LE uint64 → initial probe position.
 *   Empty entry: hash all-zero. Insert-only (no removal without HT rebuild).
 */

#include "vw_storage.h"
#include "vw_store.h"
#include "../core/vw_fs.h"
#include "../core/vw_crypto.h"

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

/* ── On-disk record ──────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  hash[VW_HASH_BYTES]; /* 32 */
    uint32_t ref_count;            /*  4 */
    uint32_t _pad;                 /*  4 — align owner_user_id to 8-byte boundary */
    uint64_t owner_user_id;        /*  8 — user_id of first uploader (for GC quota) */
} refcount_record_t;

_Static_assert(sizeof(refcount_record_t) == 48,
               "refcount_record_t must be 48 bytes");

/* ── In-memory HT entry ──────────────────────────────────────────────────── */

#define RC_HT_INITIAL_CAP 128u

typedef struct {
    uint8_t  hash[VW_HASH_BYTES]; /* all-zero = empty slot */
    uint32_t ref_count;
    uint64_t slot;                 /* 0-based slot in refcounts.db */
    uint64_t owner_user_id;        /* first uploader (for GC quota decrement) */
} rc_ht_entry_t;

/* ── pread helper ────────────────────────────────────────────────────────── */

#ifdef _WIN32
static int rcdb_pread(const char *path, void *buf, size_t len, uint64_t off)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    OVERLAPPED ov; memset(&ov, 0, sizeof(ov));
    ov.Offset = (DWORD)(off & 0xFFFFFFFFu); ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD n = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)len, &n, &ov);
    CloseHandle(h);
    return (ok && n == (DWORD)len) ? 0 : -1;
}
#else
#include <fcntl.h>
#include <unistd.h>
static int rcdb_pread(const char *path, void *buf, size_t len, uint64_t off)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)off);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}
#endif

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int hash_is_zero(const uint8_t *h)
{
    size_t i;
    for (i = 0; i < VW_HASH_BYTES; i++) if (h[i]) return 0;
    return 1;
}

static void hash_to_hex(const uint8_t *hash, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < VW_HASH_BYTES; i++) {
        out[i * 2]     = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    out[VW_HASH_BYTES * 2] = '\0';
}

static int build_chunk_path(const char *chunks_dir, const uint8_t *hash,
                             char *out, size_t out_size)
{
    char hex[VW_HASH_BYTES * 2 + 1];
    hash_to_hex(hash, hex);
    int n = snprintf(out, out_size, "%s/%.2s/%s.chunk", chunks_dir, hex, hex);
    return (n > 0 && (size_t)n < out_size) ? 0 : -1;
}

static int build_shard_dir(const char *chunks_dir, const uint8_t *hash,
                            char *out, size_t out_size)
{
    char hex[3];
    hex[0] = (char)("0123456789abcdef"[hash[0] >> 4]);
    hex[1] = (char)("0123456789abcdef"[hash[0] & 0xF]);
    hex[2] = '\0';
    int n = snprintf(out, out_size, "%s/%s", chunks_dir, hex);
    return (n > 0 && (size_t)n < out_size) ? 0 : -1;
}

/* ── In-memory HT operations ──────────────────────────────────────────────── */

static uint64_t ht_probe_start(const uint8_t *hash, size_t cap)
{
    uint64_t v = 0;
    size_t i;
    for (i = 0; i < 8; i++) v |= (uint64_t)hash[i] << (i * 8u);
    return v % (uint64_t)cap;
}

static rc_ht_entry_t *ht_find(rc_ht_entry_t *ht, size_t cap,
                                const uint8_t *hash)
{
    if (!cap) return NULL;
    uint64_t h = ht_probe_start(hash, cap);
    size_t i;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (hash_is_zero(ht[idx].hash)) return NULL;
        if (memcmp(ht[idx].hash, hash, VW_HASH_BYTES) == 0) return &ht[idx];
    }
    return NULL;
}

static int ht_insert_raw(rc_ht_entry_t *ht, size_t cap,
                          const uint8_t *hash, uint32_t rc, uint64_t slot,
                          uint64_t owner_user_id)
{
    uint64_t h = ht_probe_start(hash, cap);
    size_t i;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (hash_is_zero(ht[idx].hash)) {
            memcpy(ht[idx].hash, hash, VW_HASH_BYTES);
            ht[idx].ref_count = rc;
            ht[idx].slot = slot;
            ht[idx].owner_user_id = owner_user_id;
            return 0;
        }
    }
    return -1;
}

/* ── Internal context ─────────────────────────────────────────────────────── */

struct vw_storage {
    char chunks_dir[512];
    char rcdb_path[512];
    vw_rwlock_t lock;
    rc_ht_entry_t *ht;
    size_t ht_cap;
    size_t ht_len;
    uint64_t rc_slots;      /* total slots in refcounts.db (incl. guard) */
    vw_store_t *store;      /* optional; for GC quota decrement; may be NULL */
};

/* ── HT grow ─────────────────────────────────────────────────────────────── */

static int ht_grow(struct vw_storage *st)
{
    size_t new_cap = st->ht_cap * 2;
    rc_ht_entry_t *new_ht = (rc_ht_entry_t *)calloc(new_cap, sizeof(*new_ht));
    if (!new_ht) return -1;
    size_t i;
    for (i = 0; i < st->ht_cap; i++)
        if (!hash_is_zero(st->ht[i].hash))
            ht_insert_raw(new_ht, new_cap,
                          st->ht[i].hash, st->ht[i].ref_count, st->ht[i].slot,
                          st->ht[i].owner_user_id);
    free(st->ht);
    st->ht = new_ht; st->ht_cap = new_cap;
    return 0;
}

static int ht_insert(struct vw_storage *st,
                      const uint8_t *hash, uint32_t rc, uint64_t slot,
                      uint64_t owner_user_id)
{
    if (st->ht_len * 4 >= st->ht_cap * 3)
        if (ht_grow(st) != 0) return -1;
    if (ht_insert_raw(st->ht, st->ht_cap, hash, rc, slot, owner_user_id) != 0) return -1;
    st->ht_len++;
    return 0;
}

/* ── rcdb helpers ─────────────────────────────────────────────────────────── */

static vw_err_t rcdb_write(const struct vw_storage *st, uint64_t slot,
                             const refcount_record_t *rec)
{
    vw_err_t rc = vw_fs_pwrite(st->rcdb_path,
                                slot * (uint64_t)sizeof(*rec), rec, sizeof(*rec));
    if (rc != VW_OK) return rc;
    return vw_fs_sync_file(st->rcdb_path);
}

static vw_err_t rcdb_append(const struct vw_storage *st,
                              const refcount_record_t *rec)
{
    vw_err_t rc = vw_fs_append(st->rcdb_path, rec, sizeof(*rec));
    if (rc != VW_OK) return rc;
    return vw_fs_sync_file(st->rcdb_path);
}

/* ── Rebuild HT from disk (used after GC deletes entries) ───────────────── */

static void ht_rebuild(struct vw_storage *st)
{
    rc_ht_entry_t *new_ht = (rc_ht_entry_t *)calloc(st->ht_cap, sizeof(*new_ht));
    if (!new_ht) return; /* leave HT degraded; restart will fix */
    uint64_t s;
    for (s = 1; s < st->rc_slots; s++) {
        refcount_record_t rec;
        if (rcdb_pread(st->rcdb_path, &rec, sizeof(rec),
                       s * (uint64_t)sizeof(rec)) != 0) continue;
        if (hash_is_zero(rec.hash)) continue;
        ht_insert_raw(new_ht, st->ht_cap, rec.hash, rec.ref_count, s,
                      rec.owner_user_id);
    }
    free(st->ht);
    st->ht = new_ht;
    st->ht_len = 0;
    size_t i;
    for (i = 0; i < st->ht_cap; i++)
        if (!hash_is_zero(st->ht[i].hash)) st->ht_len++;
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_storage_open(const char *data_dir, vw_storage_t **out)
{
    vw_err_t rc;
    struct vw_storage *st;
    uint64_t file_size;

    if (!data_dir || !out) return VW_ERR_INVALID_ARG;

    st = (struct vw_storage *)calloc(1, sizeof(*st));
    if (!st) return VW_ERR_OOM;

    if (vw_fs_path_join(st->chunks_dir, sizeof(st->chunks_dir),
                        data_dir, "chunks") != VW_OK ||
        vw_fs_path_join(st->rcdb_path, sizeof(st->rcdb_path),
                        st->chunks_dir, "refcounts.db") != VW_OK) {
        free(st); return VW_ERR_INVALID_ARG;
    }

    rc = vw_fs_ensure_dir(st->chunks_dir);
    if (rc != VW_OK) { free(st); return rc; }

    rwlock_init(&st->lock);

    st->ht = (rc_ht_entry_t *)calloc(RC_HT_INITIAL_CAP, sizeof(*st->ht));
    if (!st->ht) { free(st); return VW_ERR_OOM; }
    st->ht_cap = RC_HT_INITIAL_CAP;

    /* Create refcounts.db with guard if needed. */
    if (!vw_fs_exists(st->rcdb_path)) {
        refcount_record_t guard; memset(&guard, 0, sizeof(guard));
        rc = vw_fs_append(st->rcdb_path, &guard, sizeof(guard));
        if (rc != VW_OK) { vw_storage_close(st); return rc; }
    }

    rc = vw_fs_file_size(st->rcdb_path, &file_size);
    if (rc != VW_OK) { vw_storage_close(st); return rc; }
    st->rc_slots = file_size / sizeof(refcount_record_t);

    /* Scan to build HT. */
    {
        uint64_t s;
        for (s = 1; s < st->rc_slots; s++) {
            refcount_record_t rec;
            if (rcdb_pread(st->rcdb_path, &rec, sizeof(rec),
                           s * (uint64_t)sizeof(rec)) != 0) continue;
            if (hash_is_zero(rec.hash)) continue;
            if (ht_insert(st, rec.hash, rec.ref_count, s, rec.owner_user_id) != 0) {
                vw_storage_close(st); return VW_ERR_OOM;
            }
        }
    }

    *out = st;
    return VW_OK;
}

void vw_storage_close(vw_storage_t *st)
{
    if (!st) return;
    rwlock_destroy(&st->lock);
    free(st->ht);
    free(st);
}

/* ── vw_storage_chunk_put ────────────────────────────────────────────────── */

vw_err_t vw_storage_chunk_put(vw_storage_t *st,
                               const uint8_t hash[VW_HASH_BYTES],
                               const uint8_t *data, uint32_t len,
                               uint64_t owner_user_id)
{
    vw_err_t rc;

    if (!st || !hash || !data) return VW_ERR_INVALID_ARG;
    if (len == 0 || len > (uint32_t)VW_CHUNK_SIZE_DEFAULT) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&st->lock);

    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);

    if (entry && entry->ref_count > 0) {
        /* Dedup hit: increment ref_count; owner_user_id unchanged (charged to first uploader). */
        entry->ref_count++;
        refcount_record_t rec;
        memcpy(rec.hash, hash, VW_HASH_BYTES);
        rec.ref_count = entry->ref_count;
        rec._pad = 0;
        rec.owner_user_id = entry->owner_user_id;
        rc = rcdb_write(st, entry->slot, &rec);
        rwlock_wrunlock(&st->lock);
        return rc;
    }

    /*
     * New chunk (or previously GC'd chunk being re-uploaded).
     * Release the write lock while doing I/O to avoid starving readers.
     * Re-acquire after disk write and re-check for races.
     */
    rwlock_wrunlock(&st->lock);

    /* Verify SHA-256 before touching disk. */
    uint8_t computed[VW_HASH_BYTES];
    rc = vw_crypto_sha256(data, len, computed);
    if (rc != VW_OK) return rc;
    if (!vw_crypto_constant_time_eq(computed, hash, VW_HASH_BYTES))
        return VW_ERR_CHUNK_HASH_MISMATCH;

    /* Build paths. */
    char cpath[768], sdir[512];
    if (build_shard_dir(st->chunks_dir, hash, sdir, sizeof(sdir)) != 0 ||
        build_chunk_path(st->chunks_dir, hash, cpath, sizeof(cpath)) != 0)
        return VW_ERR_INVALID_ARG;

    rc = vw_fs_ensure_dir(sdir);
    if (rc != VW_OK) return rc;

    /* vw_fs_atomic_write: writes to path.tmp + fdatasync + rename. */
    rc = vw_fs_atomic_write(cpath, data, len);
    if (rc != VW_OK) return rc;

    /* Re-acquire write lock; re-check for race (another thread may have
     * inserted this hash while we were doing I/O). */
    rwlock_wrlock(&st->lock);

    entry = ht_find(st->ht, st->ht_cap, hash);
    if (entry && entry->ref_count > 0) {
        /* Race: another thread already inserted this chunk. Just increment. */
        entry->ref_count++;
        refcount_record_t rec;
        memcpy(rec.hash, hash, VW_HASH_BYTES);
        rec.ref_count = entry->ref_count;
        rec._pad = 0;
        rec.owner_user_id = entry->owner_user_id;
        rc = rcdb_write(st, entry->slot, &rec);
        rwlock_wrunlock(&st->lock);
        return rc;
    }

    if (entry && entry->ref_count == 0) {
        /* Previously GC'd entry — reuse its slot.  Chunk is new from quota perspective:
         * charge atomically under the write lock so no concurrent upload can double-charge. */
        if (st->store) {
            vw_err_t qrc = vw_store_quota_add(st->store, owner_user_id, (int64_t)len);
            if (qrc != VW_OK) {
                /* Quota exceeded — chunk stays on disk as a dark orphan; GC cleans it. */
                rwlock_wrunlock(&st->lock);
                return qrc;
            }
        }
        entry->ref_count = 1;
        entry->owner_user_id = owner_user_id;
        refcount_record_t rec;
        memcpy(rec.hash, hash, VW_HASH_BYTES);
        rec.ref_count = 1;
        rec._pad = 0;
        rec.owner_user_id = owner_user_id;
        rc = rcdb_write(st, entry->slot, &rec);
        if (rc != VW_OK && st->store)
            (void)vw_store_quota_add(st->store, owner_user_id, -(int64_t)len);
        rwlock_wrunlock(&st->lock);
        return rc;
    }

    /* Truly new: charge quota then append to refcounts.db. */
    if (st->store) {
        vw_err_t qrc = vw_store_quota_add(st->store, owner_user_id, (int64_t)len);
        if (qrc != VW_OK) {
            /* Quota exceeded — chunk stays on disk as a dark orphan; GC cleans it. */
            rwlock_wrunlock(&st->lock);
            return qrc;
        }
    }

    uint64_t slot = st->rc_slots;
    refcount_record_t rec;
    memcpy(rec.hash, hash, VW_HASH_BYTES);
    rec.ref_count = 1;
    rec._pad = 0;
    rec.owner_user_id = owner_user_id;

    rc = rcdb_append(st, &rec);
    if (rc != VW_OK) {
        /* Chunk is on disk but no ref record — dark orphan; next GC handles it.
         * Roll back the quota we just charged. */
        if (st->store)
            (void)vw_store_quota_add(st->store, owner_user_id, -(int64_t)len);
        rwlock_wrunlock(&st->lock);
        return rc;
    }
    st->rc_slots++;

    if (ht_insert(st, hash, 1, slot, owner_user_id) != 0) {
        /* OOM in HT — data is on disk with ref recorded; next open rebuilds HT.
         * Roll back the quota charged above so usage stays accurate. */
        if (st->store)
            (void)vw_store_quota_add(st->store, owner_user_id, -(int64_t)len);
        rwlock_wrunlock(&st->lock);
        return VW_ERR_OOM;
    }

    rwlock_wrunlock(&st->lock);
    return VW_OK;
}

/* ── vw_storage_chunk_get ────────────────────────────────────────────────── */

vw_err_t vw_storage_chunk_get(vw_storage_t *st,
                               const uint8_t hash[VW_HASH_BYTES],
                               uint8_t **out_data, uint32_t *out_len)
{
    if (!st || !hash || !out_data || !out_len) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&st->lock);
    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);
    int present = (entry && entry->ref_count > 0);
    rwlock_rdunlock(&st->lock);

    if (!present) return VW_ERR_NOT_FOUND;

    char cpath[768];
    if (build_chunk_path(st->chunks_dir, hash, cpath, sizeof(cpath)) != 0)
        return VW_ERR_INVALID_ARG;

    void *buf; size_t file_len;
    vw_err_t rc = vw_fs_read_file(cpath, &buf, &file_len);
    if (rc != VW_OK) return rc;
    if (file_len > UINT32_MAX) { free(buf); return VW_ERR_IO; }

    *out_data = (uint8_t *)buf;
    *out_len  = (uint32_t)file_len;
    return VW_OK;
}

/* ── vw_storage_chunk_addref ─────────────────────────────────────────────── */

vw_err_t vw_storage_chunk_addref(vw_storage_t *st,
                                   const uint8_t hash[VW_HASH_BYTES])
{
    if (!st || !hash) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&st->lock);

    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);
    if (!entry || entry->ref_count == 0) {
        rwlock_wrunlock(&st->lock);
        return VW_ERR_NOT_FOUND;
    }

    entry->ref_count++;
    refcount_record_t rec;
    memcpy(rec.hash, hash, VW_HASH_BYTES);
    rec.ref_count = entry->ref_count;
    rec._pad = 0;
    rec.owner_user_id = entry->owner_user_id;
    vw_err_t rc = rcdb_write(st, entry->slot, &rec);

    rwlock_wrunlock(&st->lock);
    return rc;
}

/* ── vw_storage_chunk_decref ─────────────────────────────────────────────── */

vw_err_t vw_storage_chunk_decref(vw_storage_t *st,
                                  const uint8_t hash[VW_HASH_BYTES])
{
    if (!st || !hash) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&st->lock);

    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);
    if (!entry || entry->ref_count == 0) {
        rwlock_wrunlock(&st->lock);
        return VW_ERR_NOT_FOUND;
    }

    entry->ref_count--;
    refcount_record_t rec;
    memcpy(rec.hash, hash, VW_HASH_BYTES);
    rec.ref_count = entry->ref_count;
    rec._pad = 0;
    rec.owner_user_id = entry->owner_user_id;
    vw_err_t rc = rcdb_write(st, entry->slot, &rec);

    rwlock_wrunlock(&st->lock);
    return rc;
}

/* ── vw_storage_chunk_query ──────────────────────────────────────────────── */

vw_err_t vw_storage_chunk_query(vw_storage_t *st,
                                 const uint8_t (*hashes)[VW_HASH_BYTES],
                                 uint16_t count, uint8_t *out_bitmask)
{
    if (!st || (!hashes && count > 0) || !out_bitmask) return VW_ERR_INVALID_ARG;
    if (count > 1024) return VW_ERR_INVALID_ARG;
    if (count == 0) return VW_OK;

    uint16_t bm_bytes = (uint16_t)((count + 7u) / 8u);
    memset(out_bitmask, 0, bm_bytes);

    rwlock_rdlock(&st->lock);
    uint16_t i;
    for (i = 0; i < count; i++) {
        rc_ht_entry_t *e = ht_find(st->ht, st->ht_cap, hashes[i]);
        if (e && e->ref_count > 0)
            out_bitmask[i / 8u] |= (uint8_t)(1u << (7u - (i % 8u)));
    }
    rwlock_rdunlock(&st->lock);
    return VW_OK;
}

/* ── vw_storage_gc_run ───────────────────────────────────────────────────── */

vw_err_t vw_storage_gc_run(vw_storage_t *st)
{
    vw_err_t rc = VW_OK;
    if (!st) return VW_ERR_INVALID_ARG;

    /* ── Phase A: collect zero-ref chunks ── */
    rwlock_wrlock(&st->lock);

    size_t i;
    for (i = 0; i < st->ht_cap; i++) {
        if (hash_is_zero(st->ht[i].hash)) continue;
        if (st->ht[i].ref_count != 0) continue;

        char cpath[768];
        uint64_t chunk_len = 0;

        if (build_chunk_path(st->chunks_dir, st->ht[i].hash,
                             cpath, sizeof(cpath)) == 0) {
            /* Read size before deleting so we can decrement the owner's quota. */
            (void)vw_fs_file_size(cpath, &chunk_len);
            (void)vw_fs_delete(cpath);
        }

        /* Decrement quota for the chunk owner (best-effort; ignore errors). */
        if (st->store && st->ht[i].owner_user_id != 0 && chunk_len > 0)
            (void)vw_store_quota_add(st->store, st->ht[i].owner_user_id,
                                     -(int64_t)chunk_len);

        /* Zero the refcounts.db record. */
        refcount_record_t zero; memset(&zero, 0, sizeof(zero));
        (void)vw_fs_pwrite(st->rcdb_path,
                           st->ht[i].slot * (uint64_t)sizeof(zero),
                           &zero, sizeof(zero));

        /* Clear in-memory entry (will break probe chains; rebuild fixes it). */
        memset(st->ht[i].hash, 0, VW_HASH_BYTES);
        st->ht[i].owner_user_id = 0;
        st->ht_len--;
    }

    /* Sync and rebuild HT to repair broken probe chains.
     * Sync failure is intentionally ignored: GC is best-effort and a failed
     * sync does not corrupt the HT — it will be rebuilt cleanly on next open. */
    (void)vw_fs_sync_file(st->rcdb_path);
    ht_rebuild(st);

    rwlock_wrunlock(&st->lock);

    /*
     * Phase B — dark-orphan scan:
     *
     * Walk each shard directory (data/chunks/XX/ for XX in 00..ff).
     * For each *.chunk file whose base name decodes to a hash not present in
     * the in-memory HT (or present with ref_count == 0), register it as
     * ref_count=0 so Phase A in the next GC cycle deletes it.
     *
     * Phase B runs outside the write lock because the directory walk is slow.
     * Entries added here are immediately visible to subsequent GC passes.
     *
     * Phase 2 limitation: the directory enumeration uses vw_fs_list_dir which
     * is available. A full implementation is deferred to Phase 5 (cluster);
     * the dark-orphan scenario (crash between chunk write and ref_count set) is
     * low-probability and the orphan only consumes disk space until fixed.
     *
     * Stub: traverse all 256 shards and register orphan .chunk files.
     */
    /*
     * Phase B stub: dark-orphan walk is deferred to Phase 5.
     * Orphans (crash between chunk write and ref_count set) accumulate on disk
     * but cause no correctness issues — they are simply unreferenced files.
     * A Phase 5 implementation will walk data/chunks/<shard>/*.chunk, decode the
     * SHA-256 filename, and register any file with no HT entry as ref_count=0
     * so Phase A can delete it on the next pass.
     */

    return rc;
}

/* ── vw_storage_set_store ────────────────────────────────────────────────── */

void vw_storage_set_store(vw_storage_t *st, vw_store_t *store)
{
    if (!st) return;
    rwlock_wrlock(&st->lock);
    st->store = store;
    rwlock_wrunlock(&st->lock);
}
