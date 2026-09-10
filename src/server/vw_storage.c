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
#include "vw_ecc.h"
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

/* ── Parity group member record (Phase 22, TASK-258) ─────────────────────── */

/*
 * On-disk record in parity_groups.db (48 -> padded to 64 bytes, same
 * append-only/HT-rebuilt-on-open shape as refcounts.db above). Unlike
 * refcounts.db, a member record is never rewritten in place once written
 * — group membership is permanent even after the chunk itself is later
 * GC'd (a stale member record for a since-deleted chunk is harmless: the
 * repair path always checks the chunk's live ref_count in refcounts.db,
 * never this file, to tell a tombstone from real corruption).
 */
typedef struct {
    uint8_t  hash[VW_HASH_BYTES]; /* 32; all-zero = free/guard slot */
    uint64_t group_id;             /*  8 */
    uint32_t slot_index;           /*  4 — 0..VW_ECC_MAX_DATA_SHARDS-1 */
    uint32_t chunk_len;            /*  4 — real on-disk length of this member */
    uint8_t  _pad[16];             /* 16 — reserved */
} pg_member_record_t;

_Static_assert(sizeof(pg_member_record_t) == 64,
               "pg_member_record_t must be 64 bytes");

#define PG_HT_INITIAL_CAP 128u

typedef struct {
    uint8_t  hash[VW_HASH_BYTES]; /* all-zero = empty slot */
    uint64_t group_id;
    uint32_t slot_index;
    uint32_t chunk_len;
} pg_ht_entry_t;

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

/* ── Parity-group in-memory HT (Phase 22, TASK-258) ───────────────────────── */
/*
 * Same probe scheme as ht_find/ht_insert_raw above (ht_probe_start and
 * hash_is_zero are already hash-generic, reused as-is) — a parallel, small
 * set of functions rather than templating the rc_ht_entry_t ones, since
 * this entry shape has no ref_count/owner_user_id fields and this
 * codebase's own convention is a dedicated small module/helper set over a
 * forced shared abstraction (see vw_scrub.c's own logging macros for the
 * same reasoning, applied to a different pair of near-identical modules).
 */

static pg_ht_entry_t *pg_ht_find(pg_ht_entry_t *ht, size_t cap,
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

static int pg_ht_insert_raw(pg_ht_entry_t *ht, size_t cap,
                             const uint8_t *hash, uint64_t group_id,
                             uint32_t slot_index, uint32_t chunk_len)
{
    uint64_t h = ht_probe_start(hash, cap);
    size_t i;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (hash_is_zero(ht[idx].hash)) {
            memcpy(ht[idx].hash, hash, VW_HASH_BYTES);
            ht[idx].group_id   = group_id;
            ht[idx].slot_index = slot_index;
            ht[idx].chunk_len  = chunk_len;
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

    /* Phase 22 (TASK-258): parity groups. */
    char parity_dir[512];   /* {chunks_dir}/parity */
    char pgdb_path[512];    /* {chunks_dir}/parity_groups.db */
    pg_ht_entry_t *pg_ht;
    size_t pg_ht_cap;
    size_t pg_ht_len;
    uint64_t pg_slots;          /* total record slots in parity_groups.db (incl. guard) */
    uint64_t open_group_id;     /* group currently accumulating members; starts at 1 */
    uint32_t open_group_count;  /* members added to open_group_id so far, 0..VW_ECC_MAX_DATA_SHARDS */
    uint8_t  open_group_hashes[VW_ECC_MAX_DATA_SHARDS][VW_HASH_BYTES]; /* fast path for seal_group — avoids an O(n) scan on every group fill */
    uint32_t open_group_lens[VW_ECC_MAX_DATA_SHARDS];
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

static int pg_ht_grow(struct vw_storage *st)
{
    size_t new_cap = st->pg_ht_cap * 2;
    pg_ht_entry_t *new_ht = (pg_ht_entry_t *)calloc(new_cap, sizeof(*new_ht));
    if (!new_ht) return -1;
    size_t i;
    for (i = 0; i < st->pg_ht_cap; i++)
        if (!hash_is_zero(st->pg_ht[i].hash))
            pg_ht_insert_raw(new_ht, new_cap, st->pg_ht[i].hash,
                              st->pg_ht[i].group_id, st->pg_ht[i].slot_index,
                              st->pg_ht[i].chunk_len);
    free(st->pg_ht);
    st->pg_ht = new_ht; st->pg_ht_cap = new_cap;
    return 0;
}

static int pg_ht_insert(struct vw_storage *st, const uint8_t *hash,
                         uint64_t group_id, uint32_t slot_index, uint32_t chunk_len)
{
    if (st->pg_ht_len * 4 >= st->pg_ht_cap * 3)
        if (pg_ht_grow(st) != 0) return -1;
    if (pg_ht_insert_raw(st->pg_ht, st->pg_ht_cap, hash, group_id, slot_index,
                          chunk_len) != 0)
        return -1;
    st->pg_ht_len++;
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

/* ── pgdb helper (Phase 22, TASK-258) ─────────────────────────────────────── */
/* Append-only — a member record, once written, is never rewritten in
 * place, so unlike refcounts.db there is no pgdb_write counterpart. */

static vw_err_t pgdb_append(const struct vw_storage *st,
                             const pg_member_record_t *rec)
{
    vw_err_t rc = vw_fs_append(st->pgdb_path, rec, sizeof(*rec));
    if (rc != VW_OK) return rc;
    return vw_fs_sync_file(st->pgdb_path);
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

/* ── Parity groups (Phase 22, TASK-258) ───────────────────────────────────── */

#define VW_PARITY_FORMAT_VERSION 0u

static int build_parity_path(const char *parity_dir, uint64_t group_id,
                              char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "%s/%016llx.parity", parity_dir,
                      (unsigned long long)group_id);
    return (n > 0 && (size_t)n < out_size) ? 0 : -1;
}

vw_err_t vw_storage_parity_lookup(vw_storage_t *st,
                                   const uint8_t hash[VW_HASH_BYTES],
                                   vw_parity_membership_t *out)
{
    if (!st || !hash || !out) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&st->lock);
    pg_ht_entry_t *e = pg_ht_find(st->pg_ht, st->pg_ht_cap, hash);
    if (e) {
        out->group_id   = e->group_id;
        out->slot_index = e->slot_index;
        out->chunk_len  = e->chunk_len;
    }
    rwlock_rdunlock(&st->lock);

    return e ? VW_OK : VW_ERR_NOT_FOUND;
}

int vw_storage_parity_group_is_sealed(vw_storage_t *st, uint64_t group_id)
{
    if (!st) return 0;
    char ppath[768];
    if (build_parity_path(st->parity_dir, group_id, ppath, sizeof(ppath)) != 0)
        return 0;
    return vw_fs_exists(ppath);
}

vw_err_t vw_storage_parity_group_members(vw_storage_t *st, uint64_t group_id,
                                          uint8_t out_hashes[][VW_HASH_BYTES],
                                          vw_parity_membership_t *out_memberships,
                                          uint32_t *out_count)
{
    if (!st || !out_hashes || !out_memberships || !out_count)
        return VW_ERR_INVALID_ARG;

    uint32_t count = 0;
    rwlock_rdlock(&st->lock);
    size_t i;
    for (i = 0; i < st->pg_ht_cap; i++) {
        pg_ht_entry_t *e = &st->pg_ht[i];
        if (hash_is_zero(e->hash)) continue;
        if (e->group_id != group_id) continue;
        if (e->slot_index >= VW_ECC_MAX_DATA_SHARDS) continue; /* defensive; can't happen */
        memcpy(out_hashes[e->slot_index], e->hash, VW_HASH_BYTES);
        out_memberships[e->slot_index].group_id   = e->group_id;
        out_memberships[e->slot_index].slot_index = e->slot_index;
        out_memberships[e->slot_index].chunk_len  = e->chunk_len;
        count++;
    }
    rwlock_rdunlock(&st->lock);

    *out_count = count;
    return VW_OK;
}

vw_err_t vw_storage_parity_stuck_groups(vw_storage_t *st,
                                         uint64_t *out_group_ids,
                                         uint32_t max_count,
                                         uint32_t *out_count)
{
    if (!st || !out_group_ids || max_count == 0 || !out_count)
        return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&st->lock);
    uint64_t highest_group_id = st->open_group_id;

    /* Tally member counts per group_id in one pass over the in-memory
     * parity index. group_ids are assigned sequentially starting at 1,
     * so a plain array indexed by group_id is simpler and cheaper here
     * than a second hash table just for this rare, non-hot-path scan. */
    uint32_t *counts = (uint32_t *)calloc((size_t)highest_group_id + 1, sizeof(uint32_t));
    if (!counts) { rwlock_rdunlock(&st->lock); return VW_ERR_OOM; }

    size_t i;
    for (i = 0; i < st->pg_ht_cap; i++) {
        pg_ht_entry_t *e = &st->pg_ht[i];
        if (hash_is_zero(e->hash)) continue;
        if (e->group_id == 0 || e->group_id > highest_group_id) continue; /* defensive */
        counts[e->group_id]++;
    }
    rwlock_rdunlock(&st->lock);

    /* is_sealed does its own file-exists check below, outside the lock —
     * same "runs unlocked" posture seal_group's own doc comment
     * establishes for filesystem I/O in this module. */
    uint32_t found = 0;
    uint64_t gid;
    for (gid = 1; gid < highest_group_id && found < max_count; gid++) {
        if (counts[gid] != VW_ECC_MAX_DATA_SHARDS) continue;
        if (vw_storage_parity_group_is_sealed(st, gid)) continue;
        out_group_ids[found++] = gid;
    }

    free(counts);
    *out_count = found;
    return VW_OK;
}

vw_err_t vw_storage_parity_shard_read(vw_storage_t *st, uint64_t group_id,
                                       uint8_t **out_data, uint32_t *out_len)
{
    if (!st || !out_data || !out_len) return VW_ERR_INVALID_ARG;

    char ppath[768];
    if (build_parity_path(st->parity_dir, group_id, ppath, sizeof(ppath)) != 0)
        return VW_ERR_INVALID_ARG;
    if (!vw_fs_exists(ppath)) return VW_ERR_NOT_FOUND;

    void *buf; size_t flen;
    vw_err_t rc = vw_fs_read_file(ppath, &buf, &flen);
    if (rc != VW_OK) return rc;

    if (flen != 1u + (size_t)VW_CHUNK_SIZE_DEFAULT) {
        free(buf);
        return VW_ERR_STORE_CORRUPT;
    }
    uint8_t *bytes = (uint8_t *)buf;
    if (bytes[0] != VW_PARITY_FORMAT_VERSION) {
        free(buf);
        return VW_ERR_STORE_CORRUPT;
    }

    uint8_t *payload = (uint8_t *)malloc(VW_CHUNK_SIZE_DEFAULT);
    if (!payload) { free(buf); return VW_ERR_OOM; }
    memcpy(payload, bytes + 1, VW_CHUNK_SIZE_DEFAULT);
    free(buf);

    *out_data = payload;
    *out_len  = (uint32_t)VW_CHUNK_SIZE_DEFAULT;
    return VW_OK;
}

/* ── vw_storage_repair_local (Phase 22, TASK-260) ─────────────────────────── */

vw_err_t vw_storage_repair_local(vw_storage_t *st,
                                  const uint8_t hash[VW_HASH_BYTES],
                                  uint8_t **out_data, uint32_t *out_len)
{
    if (!st || !hash || !out_data || !out_len) return VW_ERR_INVALID_ARG;

    vw_parity_membership_t my_membership;
    vw_err_t rc = vw_storage_parity_lookup(st, hash, &my_membership);
    if (rc != VW_OK) return rc; /* VW_ERR_NOT_FOUND */

    if (!vw_storage_parity_group_is_sealed(st, my_membership.group_id))
        return VW_ERR_NOT_FOUND; /* nothing to reconstruct from yet */

    uint8_t                  member_hashes[VW_ECC_MAX_DATA_SHARDS][VW_HASH_BYTES];
    vw_parity_membership_t   members[VW_ECC_MAX_DATA_SHARDS];
    uint32_t                 member_count = 0;
    rc = vw_storage_parity_group_members(st, my_membership.group_id,
                                          member_hashes, members, &member_count);
    if (rc != VW_OK) return rc;
    if (member_count != VW_ECC_MAX_DATA_SHARDS) return VW_ERR_NOT_FOUND; /* defensive */

    uint8_t *parity = NULL;
    uint32_t parity_len = 0;
    rc = vw_storage_parity_shard_read(st, my_membership.group_id, &parity, &parity_len);
    if (rc != VW_OK) return rc;

    uint8_t *padded[VW_ECC_MAX_DATA_SHARDS];
    const uint8_t *shard_ptrs[VW_ECC_MAX_DATA_SHARDS];
    uint32_t i;
    for (i = 0; i < member_count; i++) padded[i] = NULL;

    vw_err_t result = VW_OK;
    for (i = 0; i < member_count; i++) {
        if (members[i].slot_index == my_membership.slot_index) {
            /* This is the chunk we're trying to reconstruct — the one
             * allowed gap. Never read its own (known-bad) file. */
            shard_ptrs[i] = NULL;
            continue;
        }

        padded[i] = (uint8_t *)calloc(1, VW_CHUNK_SIZE_DEFAULT);
        if (!padded[i]) { result = VW_ERR_OOM; break; }

        uint8_t *sib_data = NULL;
        uint32_t sib_len  = 0;
        vw_err_t grc = vw_storage_chunk_get(st, member_hashes[i], &sib_data, &sib_len);
        int sib_ok = 0;
        if (grc == VW_OK) {
            uint8_t actual[VW_HASH_BYTES];
            if (sib_len == members[i].chunk_len &&
                vw_crypto_sha256(sib_data, sib_len, actual) == VW_OK &&
                memcmp(actual, member_hashes[i], VW_HASH_BYTES) == 0) {
                memcpy(padded[i], sib_data, sib_len);
                sib_ok = 1;
            }
        }
        free(sib_data);

        /* A sibling that fails this check — whether genuinely corrupt,
         * unreadable, or a legitimate GC tombstone (see this function's
         * own header comment on the "one gap already spent" limitation)
         * — is simply unusable for this reconstruction; vw_ecc_decode_
         * single below correctly rejects a second gap on its own, no
         * need to distinguish why here. */
        shard_ptrs[i] = sib_ok ? padded[i] : NULL;
    }

    if (result == VW_OK) {
        uint8_t *reconstructed = (uint8_t *)malloc(VW_CHUNK_SIZE_DEFAULT);
        if (!reconstructed) {
            result = VW_ERR_OOM;
        } else {
            result = vw_ecc_decode_single(shard_ptrs, member_count, parity,
                                           my_membership.slot_index,
                                           VW_CHUNK_SIZE_DEFAULT, reconstructed);
            if (result == VW_OK) {
                /* Defense in depth: the reconstructed bytes, trimmed to
                 * this member's own recorded length, must actually hash
                 * to the hash we were asked to repair. */
                uint8_t actual[VW_HASH_BYTES];
                if (my_membership.chunk_len > (uint32_t)VW_CHUNK_SIZE_DEFAULT ||
                    vw_crypto_sha256(reconstructed, my_membership.chunk_len, actual) != VW_OK ||
                    memcmp(actual, hash, VW_HASH_BYTES) != 0) {
                    result = VW_ERR_CHUNK_CORRUPT;
                } else {
                    uint8_t *trimmed = (uint8_t *)malloc(my_membership.chunk_len);
                    if (!trimmed) {
                        result = VW_ERR_OOM;
                    } else {
                        memcpy(trimmed, reconstructed, my_membership.chunk_len);
                        *out_data = trimmed;
                        *out_len  = my_membership.chunk_len;
                    }
                }
            }
            free(reconstructed);
        }
    }

    free(parity);
    for (i = 0; i < member_count; i++) free(padded[i]);
    return result;
}

/*
 * Compute and durably write group_id's parity shard from exactly
 * VW_ECC_MAX_DATA_SHARDS members (hashes[i]/lens[i]). Called two ways:
 *   - Live sealing (chunk_put_impl): hashes/lens come straight from this
 *     store's fast in-memory open-group accumulator — no scan needed.
 *   - Startup crash recovery (vw_storage_open): hashes/lens come from
 *     vw_storage_parity_group_members's scan of the group left at exactly
 *     VW_ECC_MAX_DATA_SHARDS members with no parity file on disk yet.
 *
 * Runs unlocked (reads chunk files by hash, same as vw_storage_chunk_get)
 * — callers must not hold st->lock across this call, both to avoid
 * blocking concurrent uploads/downloads for a potentially slow multi-MB
 * operation and because vw_fs_read_file below needs none of st's locked
 * state anyway.
 *
 * Best-effort: on any failure (OOM, a member's file unreadable, disk
 * full), returns the error but changes nothing that would prevent a
 * retry — no partial/corrupt parity file is ever left behind
 * (vw_fs_atomic_write is temp+rename), so an interrupted or failed seal
 * simply looks identical to "not sealed yet" and is retried at the next
 * vw_storage_open. Callers (chunk_put_impl) must NOT propagate this
 * failure to their own caller — a client's chunk upload must never fail
 * merely because this purely-additive reliability feature had a
 * transient hiccup.
 */
/*
 * hashes/lens intentionally non-const: both call sites pass a non-const
 * local array, and pre-C2X ISO C (pedantic mode) rejects an implicit
 * uint8_t(*)[N] -> const uint8_t(*)[N] conversion on a multi-dimensional
 * array parameter (unlike a plain T* -> const T*) — seal_group doesn't
 * modify either array, but the const qualifier isn't worth the cast this
 * would otherwise force at every call site.
 */
static vw_err_t seal_group(vw_storage_t *st, uint64_t group_id,
                            uint8_t hashes[][VW_HASH_BYTES],
                            uint32_t *lens, uint32_t count)
{
    if (count != VW_ECC_MAX_DATA_SHARDS) return VW_ERR_INVALID_ARG;

    uint8_t *bufs[VW_ECC_MAX_DATA_SHARDS];
    uint32_t i;
    vw_err_t result = VW_OK;
    for (i = 0; i < count; i++) bufs[i] = NULL;

    for (i = 0; i < count; i++) {
        bufs[i] = (uint8_t *)calloc(1, VW_CHUNK_SIZE_DEFAULT);
        if (!bufs[i]) { result = VW_ERR_OOM; break; }

        char cpath[768];
        if (build_chunk_path(st->chunks_dir, hashes[i], cpath, sizeof(cpath)) != 0) {
            result = VW_ERR_INVALID_ARG; break;
        }

        void *filebuf; size_t filelen;
        vw_err_t rrc = vw_fs_read_file(cpath, &filebuf, &filelen);
        if (rrc != VW_OK) { result = rrc; break; }
        if (filelen != (size_t)lens[i] || filelen > (size_t)VW_CHUNK_SIZE_DEFAULT) {
            free(filebuf);
            result = VW_ERR_STORE_CORRUPT;
            break;
        }
        memcpy(bufs[i], filebuf, filelen);
        free(filebuf);
        /* bufs[i][filelen .. VW_CHUNK_SIZE_DEFAULT) is already zero (calloc) —
         * this member's zero-padding for the GF(256) arithmetic. */
    }

    uint8_t *parity = NULL;
    if (result == VW_OK) {
        parity = (uint8_t *)malloc(VW_CHUNK_SIZE_DEFAULT);
        if (!parity) result = VW_ERR_OOM;
    }
    if (result == VW_OK) {
        const uint8_t *shard_ptrs[VW_ECC_MAX_DATA_SHARDS];
        for (i = 0; i < count; i++) shard_ptrs[i] = bufs[i];
        result = vw_ecc_encode(shard_ptrs, count, VW_CHUNK_SIZE_DEFAULT, parity);
    }
    if (result == VW_OK) {
        size_t out_len = 1u + (size_t)VW_CHUNK_SIZE_DEFAULT;
        uint8_t *out_buf = (uint8_t *)malloc(out_len);
        if (!out_buf) {
            result = VW_ERR_OOM;
        } else {
            out_buf[0] = VW_PARITY_FORMAT_VERSION;
            memcpy(out_buf + 1, parity, VW_CHUNK_SIZE_DEFAULT);

            char ppath[768];
            if (build_parity_path(st->parity_dir, group_id, ppath, sizeof(ppath)) != 0)
                result = VW_ERR_INVALID_ARG;
            else
                result = vw_fs_atomic_write(ppath, out_buf, out_len);
            free(out_buf);
        }
    }

    free(parity);
    for (i = 0; i < count; i++) free(bufs[i]);
    return result;
}

vw_err_t vw_storage_parity_group_reseal(vw_storage_t *st, uint64_t group_id)
{
    if (!st) return VW_ERR_INVALID_ARG;

    if (vw_storage_parity_group_is_sealed(st, group_id)) return VW_OK;

    uint8_t                 hashes[VW_ECC_MAX_DATA_SHARDS][VW_HASH_BYTES];
    vw_parity_membership_t  memberships[VW_ECC_MAX_DATA_SHARDS];
    uint32_t                count = 0;
    vw_err_t rc = vw_storage_parity_group_members(st, group_id, hashes, memberships, &count);
    if (rc != VW_OK) return rc;
    if (count != VW_ECC_MAX_DATA_SHARDS) return VW_ERR_INVALID_ARG;

    uint32_t lens[VW_ECC_MAX_DATA_SHARDS];
    uint32_t i;
    for (i = 0; i < count; i++) lens[i] = memberships[i].chunk_len;

    return seal_group(st, group_id, hashes, lens, count);
}

/*
 * Record chunk `hash` (length `chunk_len`) as the next member of the
 * currently-open parity group, and seal that group if this fills it.
 * Self-guarding: a no-op if `hash` already has a membership (checked via
 * pg_ht), so every call site can call this unconditionally without its
 * own "have I already registered this?" bookkeeping.
 *
 * Two call sites, deliberately at different points in a chunk's
 * lifecycle (found necessary after TASK-258 shipped — see that task's
 * "disclosed limitations" note and ARCHITECTURE.md's "Corruption
 * detection & repair data layout" decision for the incident this fixes):
 *   - vw_storage_chunk_addref, the first time a hash's ref_count goes
 *     0 -> 1: covers real client uploads. Registering only once a chunk
 *     has a genuine, permanent reference (rather than at upload time,
 *     before FILE_COMMIT) means vw_storage_gc_run's Phase A can never
 *     delete a group member out from under an unsealed group over an
 *     abandoned (never-committed) upload — the exact race that motivated
 *     this change. A residual, much narrower window remains: a chunk
 *     committed and then deleted again (ref_count back to 0) while its
 *     group is still open can still be GC'd before the group seals;
 *     accepted as a disclosed, low-probability edge case rather than
 *     also gating vw_storage_gc_run on parity-group state (the
 *     alternative fix — more coupling for a narrower problem).
 *   - chunk_put_impl's "truly new chunk" path, but ONLY for the
 *     replicated write path (establish_own_ref — see that function's own
 *     doc comment): a replica never calls addref for content it
 *     receives via CLUSTER_CHUNK_DATA, and a replicated write always
 *     establishes ref_count >= 1 immediately at write time (no
 *     abandoned-pre-commit state exists for it), so there is no GC race
 *     to avoid there — registering at write time is correct and is the
 *     only place that ever happens for a replica.
 *
 * Must be called with st->lock held (write lock) for the bookkeeping
 * (pg_ht_find, pgdb_append, pg_ht_insert, open_group_* update) — mirrors
 * exactly how refcounts.db's own writes happen under the same lock in
 * both callers. If this call fills the group, the write lock is released
 * internally before the (potentially slow, multi-MB) seal_group work
 * runs, and re-acquired before returning, so each caller's own
 * subsequent unlock remains correct either way.
 */
static void register_parity_member(vw_storage_t *st,
                                    const uint8_t hash[VW_HASH_BYTES],
                                    uint32_t chunk_len)
{
    if (pg_ht_find(st->pg_ht, st->pg_ht_cap, hash) != NULL) return; /* already registered */

    uint64_t group_id   = st->open_group_id;
    uint32_t slot_index = st->open_group_count;

    pg_member_record_t rec;
    memcpy(rec.hash, hash, VW_HASH_BYTES);
    rec.group_id   = group_id;
    rec.slot_index = slot_index;
    rec.chunk_len  = chunk_len;
    memset(rec._pad, 0, sizeof(rec._pad));

    /* Best-effort, same posture as the rest of this feature (see
     * seal_group's doc comment) — a failure here just means this hash
     * never gets parity coverage; it does not fail the chunk write. */
    if (pgdb_append(st, &rec) != VW_OK) return;
    if (pg_ht_insert(st, hash, group_id, slot_index, chunk_len) != 0) return;

    memcpy(st->open_group_hashes[slot_index], hash, VW_HASH_BYTES);
    st->open_group_lens[slot_index] = chunk_len;
    st->open_group_count++;

    if (st->open_group_count < VW_ECC_MAX_DATA_SHARDS) return;

    /* Group just filled. Snapshot it, advance to a fresh open group
     * immediately (so concurrent uploads aren't blocked on this group's
     * seal), then do the actual I/O unlocked. */
    uint8_t  seal_hashes[VW_ECC_MAX_DATA_SHARDS][VW_HASH_BYTES];
    uint32_t seal_lens[VW_ECC_MAX_DATA_SHARDS];
    memcpy(seal_hashes, st->open_group_hashes, sizeof(seal_hashes));
    memcpy(seal_lens, st->open_group_lens, sizeof(seal_lens));

    st->open_group_id++;
    st->open_group_count = 0;

    rwlock_wrunlock(&st->lock);
    (void)seal_group(st, group_id, seal_hashes, seal_lens, VW_ECC_MAX_DATA_SHARDS);
    rwlock_wrlock(&st->lock);
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
                        st->chunks_dir, "refcounts.db") != VW_OK ||
        vw_fs_path_join(st->parity_dir, sizeof(st->parity_dir),
                        st->chunks_dir, "parity") != VW_OK ||
        vw_fs_path_join(st->pgdb_path, sizeof(st->pgdb_path),
                        st->chunks_dir, "parity_groups.db") != VW_OK) {
        free(st); return VW_ERR_INVALID_ARG;
    }

    rc = vw_fs_ensure_dir(st->chunks_dir);
    if (rc != VW_OK) { free(st); return rc; }
    rc = vw_fs_ensure_dir(st->parity_dir);
    if (rc != VW_OK) { free(st); return rc; }

    rwlock_init(&st->lock);

    st->ht = (rc_ht_entry_t *)calloc(RC_HT_INITIAL_CAP, sizeof(*st->ht));
    if (!st->ht) { free(st); return VW_ERR_OOM; }
    st->ht_cap = RC_HT_INITIAL_CAP;

    st->pg_ht = (pg_ht_entry_t *)calloc(PG_HT_INITIAL_CAP, sizeof(*st->pg_ht));
    if (!st->pg_ht) { vw_storage_close(st); return VW_ERR_OOM; }
    st->pg_ht_cap = PG_HT_INITIAL_CAP;
    st->open_group_id = 1; /* group_id 0 reserved/unused, mirrors refcounts.db's guard-slot-0 convention */

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

    /* Create parity_groups.db with guard if needed. */
    if (!vw_fs_exists(st->pgdb_path)) {
        pg_member_record_t guard; memset(&guard, 0, sizeof(guard));
        rc = vw_fs_append(st->pgdb_path, &guard, sizeof(guard));
        if (rc != VW_OK) { vw_storage_close(st); return rc; }
    }

    rc = vw_fs_file_size(st->pgdb_path, &file_size);
    if (rc != VW_OK) { vw_storage_close(st); return rc; }
    st->pg_slots = file_size / sizeof(pg_member_record_t);

    /* Scan to build the parity HT and recover open-group state: track the
     * highest group_id seen and its members (by slot_index, in case scan
     * order and slot order ever diverge) — that's the currently-open (or,
     * if a crash landed exactly on the boundary, crashed-mid-seal) group. */
    {
        uint64_t s;
        for (s = 1; s < st->pg_slots; s++) {
            pg_member_record_t rec;
            if (rcdb_pread(st->pgdb_path, &rec, sizeof(rec),
                           s * (uint64_t)sizeof(rec)) != 0) continue;
            if (hash_is_zero(rec.hash)) continue;
            if (pg_ht_insert(st, rec.hash, rec.group_id, rec.slot_index,
                              rec.chunk_len) != 0) {
                vw_storage_close(st); return VW_ERR_OOM;
            }

            if (rec.group_id > st->open_group_id) {
                st->open_group_id = rec.group_id;
                st->open_group_count = 0;
            }
            if (rec.group_id == st->open_group_id &&
                rec.slot_index < VW_ECC_MAX_DATA_SHARDS) {
                memcpy(st->open_group_hashes[rec.slot_index], rec.hash, VW_HASH_BYTES);
                st->open_group_lens[rec.slot_index] = rec.chunk_len;
                st->open_group_count++;
            }
        }
    }

    /* Finish sealing a group a prior crash landed on exactly
     * VW_ECC_MAX_DATA_SHARDS members with no parity file written yet —
     * see seal_group's own doc comment. Best-effort: on failure, leave it
     * exactly as found (still retryable at the next open) rather than
     * fail the whole vw_storage_open call over a purely-additive
     * reliability feature. */
    if (st->open_group_count == VW_ECC_MAX_DATA_SHARDS &&
        !vw_storage_parity_group_is_sealed(st, st->open_group_id)) {
        (void)seal_group(st, st->open_group_id, st->open_group_hashes,
                          st->open_group_lens, VW_ECC_MAX_DATA_SHARDS);
        st->open_group_id++;
        st->open_group_count = 0;
    }

    *out = st;
    return VW_OK;
}

void vw_storage_close(vw_storage_t *st)
{
    if (!st) return;
    rwlock_destroy(&st->lock);
    free(st->ht);
    free(st->pg_ht);
    free(st);
}

/* ── vw_storage_chunk_put ────────────────────────────────────────────────── */

/*
 * Shared implementation of vw_storage_chunk_put/vw_storage_chunk_put_replicated
 * (TASK-172) — identical hash-verify + atomic-write logic; charge_quota
 * controls whether a new/reused chunk debits owner_user_id's quota.
 * Replicated chunk writes (a replica applying content the primary already
 * accepted and charged) must never fail on the replica's own, possibly
 * not-yet-synced quota state — see vw_storage_chunk_put_replicated's own
 * doc comment.
 *
 * Ref-count semantics differ by caller (TASK-180 fix — see that task for
 * the full incident writeup):
 *
 *   - Real client uploads (vw_storage_chunk_put, charge_quota=1): this
 *     call establishes presence only. It must NOT itself add a reference
 *     — handle_file_commit's own vw_storage_chunk_addref (called exactly
 *     once per chunk hash in every FILE_COMMIT, whether the chunk was
 *     just uploaded or already present via dedup) is the sole source of
 *     real references for this path. Before this fix, chunk_put_impl
 *     ALSO added a reference here, so a chunk uploaded and committed in
 *     the same request permanently carried one extra, never-decremented
 *     reference — no chunk was ever fully garbage-collected via normal
 *     file deletion. A side effect worth knowing: a chunk sitting between
 *     CHUNK_UPLOAD and its FILE_COMMIT is now genuinely ref_count==0 and
 *     therefore GC-eligible — intentional (an uploaded-but-abandoned
 *     chunk must eventually be collectible, the flip side of this same
 *     fix), and bounded by gc_interval_secs (1800s default): a real
 *     client's FILE_COMMIT normally follows CHUNK_UPLOAD within the same
 *     round trip, well inside any reasonable interval.
 *   - Replicated writes (vw_storage_chunk_put_replicated, charge_quota=0):
 *     UNCHANGED by this fix. A replica has no FILE_COMMIT/addref call of
 *     its own — replicated content only ever arrives through this
 *     function — so it must keep establishing its own reference here.
 *     (This path's refcount accounting has a separate, pre-existing
 *     under-count for a chunk referenced by more than one synced version,
 *     since a hash already present locally is never re-passed through
 *     here on a later sync pass — flagged in TASK-180 as follow-up
 *     investigation, deliberately not touched by this fix to avoid
 *     changing replica behavior without its own dedicated review.)
 */
static vw_err_t chunk_put_impl(vw_storage_t *st,
                                const uint8_t hash[VW_HASH_BYTES],
                                const uint8_t *data, uint32_t len,
                                uint64_t owner_user_id, int charge_quota)
{
    vw_err_t rc;

    if (!st || !hash || !data) return VW_ERR_INVALID_ARG;
    if (len == 0 || len > (uint32_t)VW_CHUNK_SIZE_DEFAULT) return VW_ERR_INVALID_ARG;

    /* See the function-level comment above: only the replicated path
     * establishes its own reference here; the real-upload path leaves
     * ref-counting entirely to handle_file_commit's addref. */
    int establish_own_ref = !charge_quota;

    rwlock_wrlock(&st->lock);

    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);

    if (entry && entry->ref_count > 0) {
        /* Dedup hit: content already has at least one real reference.
         * Only bump it for the replicated path (see above) — the real
         * upload path is a pure presence-check here, no-op on ref_count. */
        if (!establish_own_ref) {
            rwlock_wrunlock(&st->lock);
            return VW_OK;
        }
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
        /* Race: another thread already inserted this chunk. Bump it only
         * for the replicated path — see the function-level comment. */
        if (!establish_own_ref) {
            rwlock_wrunlock(&st->lock);
            return VW_OK;
        }
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
        if (charge_quota && st->store) {
            vw_err_t qrc = vw_store_quota_add(st->store, owner_user_id, (int64_t)len);
            if (qrc != VW_OK) {
                /* Quota exceeded — chunk stays on disk as a dark orphan; GC cleans it. */
                rwlock_wrunlock(&st->lock);
                return qrc;
            }
        }
        entry->ref_count = establish_own_ref ? 1u : 0u;
        entry->owner_user_id = owner_user_id;
        refcount_record_t rec;
        memcpy(rec.hash, hash, VW_HASH_BYTES);
        rec.ref_count = entry->ref_count;
        rec._pad = 0;
        rec.owner_user_id = owner_user_id;
        rc = rcdb_write(st, entry->slot, &rec);
        if (rc != VW_OK && charge_quota && st->store)
            (void)vw_store_quota_add(st->store, owner_user_id, -(int64_t)len);
        rwlock_wrunlock(&st->lock);
        return rc;
    }

    /* Truly new: charge quota then append to refcounts.db. */
    if (charge_quota && st->store) {
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
    rec.ref_count = establish_own_ref ? 1u : 0u;
    rec._pad = 0;
    rec.owner_user_id = owner_user_id;

    rc = rcdb_append(st, &rec);
    if (rc != VW_OK) {
        /* Chunk is on disk but no ref record — dark orphan; next GC handles it.
         * Roll back the quota we just charged. */
        if (charge_quota && st->store)
            (void)vw_store_quota_add(st->store, owner_user_id, -(int64_t)len);
        rwlock_wrunlock(&st->lock);
        return rc;
    }
    st->rc_slots++;

    if (ht_insert(st, hash, rec.ref_count, slot, owner_user_id) != 0) {
        /* OOM in HT — data is on disk with ref recorded; next open rebuilds HT.
         * Roll back the quota charged above so usage stays accurate. */
        if (charge_quota && st->store)
            (void)vw_store_quota_add(st->store, owner_user_id, -(int64_t)len);
        rwlock_wrunlock(&st->lock);
        return VW_ERR_OOM;
    }

    /* Phase 22 (TASK-258, revised — see register_parity_member's own doc
     * comment for the incident this addresses): only the replicated write
     * path registers a parity-group slot here, at write time — a
     * replicated write always has ref_count >= 1 immediately, so there is
     * no abandoned-pre-commit window for vw_storage_gc_run to race with.
     * A real client upload (establish_own_ref == 0) is registered later,
     * from vw_storage_chunk_addref, once it has a genuine reference.
     * Best-effort; never fails this call. */
    if (establish_own_ref)
        register_parity_member(st, hash, len);

    rwlock_wrunlock(&st->lock);
    return VW_OK;
}

vw_err_t vw_storage_chunk_put(vw_storage_t *st,
                               const uint8_t hash[VW_HASH_BYTES],
                               const uint8_t *data, uint32_t len,
                               uint64_t owner_user_id)
{
    return chunk_put_impl(st, hash, data, len, owner_user_id, 1);
}

/*
 * TASK-172: apply a chunk fetched from a primary during replica hot-standby
 * sync. Identical to vw_storage_chunk_put except it never charges quota —
 * the primary already charged (and byte-accounted) this content when its
 * own client uploaded it; re-charging it against whatever this replica's
 * own (possibly not-yet-synced) quota record happens to say right now would
 * be both double-counting and a real correctness bug: replication must
 * never fail with VW_ERR_QUOTA_EXCEEDED. owner_user_id is not needed either
 * for the same reason — nothing on the replica bills against it.
 */
vw_err_t vw_storage_chunk_put_replicated(vw_storage_t *st,
                                          const uint8_t hash[VW_HASH_BYTES],
                                          const uint8_t *data, uint32_t len)
{
    return chunk_put_impl(st, hash, data, len, 0, 0);
}

/* ── vw_storage_chunk_get ────────────────────────────────────────────────── */

vw_err_t vw_storage_chunk_get(vw_storage_t *st,
                               const uint8_t hash[VW_HASH_BYTES],
                               uint8_t **out_data, uint32_t *out_len)
{
    if (!st || !hash || !out_data || !out_len) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&st->lock);
    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);
    /* TASK-180: presence means "physically on disk," independent of
     * ref_count — a chunk between CHUNK_UPLOAD and its FILE_COMMIT is
     * legitimately ref_count==0 now (see chunk_put_impl's own comment)
     * but its bytes are still there; ht_find already returns NULL for a
     * genuinely absent/GC'd-and-zeroed hash, so entry's mere existence is
     * the correct signal, not its ref_count. */
    int present = (entry != NULL);
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
    /* TASK-180: entry->ref_count == 0 is now the NORMAL state for a chunk
     * freshly uploaded and about to be committed for the first time
     * (chunk_put_impl no longer pre-establishes a reference for a real
     * client upload) — addref-ing it from 0 to 1 here is exactly the
     * intended, sole source of that first real reference. Only a
     * genuinely absent hash (never uploaded, or already fully GC'd and
     * zeroed) is an error. */
    if (!entry) {
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

    if (rc == VW_OK) {
        /* Phase 22 (TASK-258, revised): this is where a real client
         * upload's chunk first gets a genuine, permanent reference —
         * register its parity-group slot here rather than at upload
         * time (see register_parity_member's own doc comment for the
         * GC race this fixes). Self-guarded (a no-op on a dedup hit
         * against an already-registered hash — the common case, since
         * every chunk in every FILE_COMMIT goes through this addref,
         * not just newly-uploaded ones). Best-effort: a stat failure
         * here just means this hash never gets parity coverage, it does
         * not fail this addref. */
        char cpath[768];
        uint64_t chunk_len = 0;
        if (build_chunk_path(st->chunks_dir, hash, cpath, sizeof(cpath)) == 0 &&
            vw_fs_file_size(cpath, &chunk_len) == VW_OK &&
            chunk_len <= (uint64_t)VW_CHUNK_SIZE_DEFAULT) {
            register_parity_member(st, hash, (uint32_t)chunk_len);
        }
    }

    rwlock_wrunlock(&st->lock);
    return rc;
}

/* ── vw_storage_chunk_reattribute (TASK-094) ─────────────────────────────── */

vw_err_t vw_storage_chunk_reattribute(vw_storage_t *st,
                                       const uint8_t hash[VW_HASH_BYTES],
                                       uint64_t from_user_id,
                                       uint64_t to_user_id)
{
    if (!st || !hash) return VW_ERR_INVALID_ARG;
    if (from_user_id == to_user_id) return VW_OK;

    rwlock_wrlock(&st->lock);

    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);
    if (!entry || entry->ref_count == 0) {
        rwlock_wrunlock(&st->lock);
        return VW_ERR_NOT_FOUND;
    }

    if (entry->owner_user_id != from_user_id) {
        /* Not charged to from_user_id (e.g. a dedup hit against a chunk a
         * third party uploaded) — nothing to move. */
        rwlock_wrunlock(&st->lock);
        return VW_OK;
    }

    char cpath[768];
    uint64_t chunk_len = 0;
    if (build_chunk_path(st->chunks_dir, hash, cpath, sizeof(cpath)) != 0 ||
        vw_fs_file_size(cpath, &chunk_len) != VW_OK) {
        rwlock_wrunlock(&st->lock);
        return VW_ERR_IO;
    }

    if (st->store) {
        vw_err_t qrc = vw_store_quota_add(st->store, to_user_id, (int64_t)chunk_len);
        if (qrc != VW_OK) {
            /* Owner's quota can't absorb it — leave attribution unchanged
             * rather than debiting from_user_id for bytes the owner's
             * quota rejects. */
            rwlock_wrunlock(&st->lock);
            return qrc;
        }
        (void)vw_store_quota_add(st->store, from_user_id, -(int64_t)chunk_len);
    }

    entry->owner_user_id = to_user_id;
    refcount_record_t rec;
    memcpy(rec.hash, hash, VW_HASH_BYTES);
    rec.ref_count = entry->ref_count;
    rec._pad = 0;
    rec.owner_user_id = to_user_id;
    vw_err_t rc = rcdb_write(st, entry->slot, &rec);

    rwlock_wrunlock(&st->lock);
    return rc;
}

/* ── vw_storage_chunk_repair_write (Phase 22, TASK-260) ──────────────────── */

vw_err_t vw_storage_chunk_repair_write(vw_storage_t *st,
                                        const uint8_t hash[VW_HASH_BYTES],
                                        const uint8_t *data, uint32_t len)
{
    if (!st || !hash || !data) return VW_ERR_INVALID_ARG;
    if (len == 0 || len > (uint32_t)VW_CHUNK_SIZE_DEFAULT) return VW_ERR_INVALID_ARG;

    uint8_t computed[VW_HASH_BYTES];
    if (vw_crypto_sha256(data, len, computed) != VW_OK) return VW_ERR_CRYPTO;
    if (memcmp(computed, hash, VW_HASH_BYTES) != 0) return VW_ERR_CHUNK_HASH_MISMATCH;

    rwlock_rdlock(&st->lock);
    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);
    int live = (entry != NULL && entry->ref_count > 0);
    rwlock_rdunlock(&st->lock);
    if (!live) return VW_ERR_NOT_FOUND;

    char cpath[768];
    if (build_chunk_path(st->chunks_dir, hash, cpath, sizeof(cpath)) != 0)
        return VW_ERR_INVALID_ARG;

    /* No lock held across this write: same reasoning as chunk_put_impl's
     * own new-chunk write — this only touches the chunk's on-disk bytes,
     * not any of st's own locked in-memory state (ref-counting, parity
     * membership, quota — repair never changes any of those). */
    return vw_fs_atomic_write(cpath, data, len);
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

/* ── vw_storage_chunk_set_refcount (TASK-181) ────────────────────────────── */

vw_err_t vw_storage_chunk_set_refcount(vw_storage_t *st,
                                        const uint8_t hash[VW_HASH_BYTES],
                                        uint32_t refcount)
{
    if (!st || !hash) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&st->lock);

    rc_ht_entry_t *entry = ht_find(st->ht, st->ht_cap, hash);
    if (!entry) {
        rwlock_wrunlock(&st->lock);
        return VW_ERR_NOT_FOUND;
    }

    /* CQR.08 (TASK-181 review): the replica's chunk-sync pass calls this
     * once per referenced hash on every pass, most of which leave the
     * count unchanged from the previous pass — skip the disk write (and
     * rcdb_write's fsync) rather than re-persisting an identical value
     * every few seconds for every live chunk a replica holds. */
    if (entry->ref_count == refcount) {
        rwlock_wrunlock(&st->lock);
        return VW_OK;
    }

    entry->ref_count = refcount;
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
        /* TASK-180: presence is "physically on disk" (e != NULL), not
         * "has a live reference" — see vw_storage_chunk_get's identical
         * fix for why ref_count==0 no longer means absent. This function
         * backs both the client-facing CHUNK_QUERY dedup check and
         * handle_file_commit's own upfront "do all these chunks exist"
         * validation, both of which must see a just-uploaded,
         * not-yet-committed chunk as present. */
        if (e != NULL)
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
     * A Phase 5 implementation will walk data/chunks shard-by-shard, decode the
     * SHA-256 filename, and register any file with no HT entry as ref_count=0
     * so Phase A can delete it on the next pass.
     */

    return rc;
}

/* ── vw_storage_scrub_run (TASK-255) ─────────────────────────────────────── */

typedef struct {
    vw_storage_t              *st;
    const char                 *shard_dir;
    vw_storage_scrub_cb         cb;
    void                       *ud;
    vw_storage_scrub_stats_t   *stats;
} scrub_walk_ctx_t;

static int scrub_file_cb(const char *name, void *userdata)
{
    scrub_walk_ctx_t *wc = (scrub_walk_ctx_t *)userdata;
    size_t nlen = strlen(name);

    /* Expect exactly "{64 hex}.chunk"; anything else is a stray file, not
     * ours to scrub (silently skipped). */
    if (nlen != VW_HASH_BYTES * 2 + 6 ||
        strcmp(name + VW_HASH_BYTES * 2, ".chunk") != 0)
        return 0;

    uint8_t hash[VW_HASH_BYTES];
    if (vw_crypto_hex_decode(name, VW_HASH_BYTES * 2, hash) != VW_OK)
        return 0;

    char path[768];
    int n = snprintf(path, sizeof(path), "%s/%s", wc->shard_dir, name);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 0;

    if (wc->stats) wc->stats->scanned++;

    void  *buf = NULL;
    size_t flen = 0;
    int    ok = 0;
    if (vw_fs_read_file(path, &buf, &flen) == VW_OK) {
        uint8_t actual[VW_HASH_BYTES];
        if (flen <= UINT32_MAX &&
            vw_crypto_sha256(buf, flen, actual) == VW_OK &&
            memcmp(actual, hash, VW_HASH_BYTES) == 0)
            ok = 1;
        free(buf);
    }
    if (ok) return 0;

    /* Mismatch or unreadable — distinguish real corruption (still
     * referenced) from a legitimate tombstone (ref_count == 0: GC may be
     * mid-unlink, or this is a dark orphan from a crash between chunk
     * write and ref_count set) via the live ref_count, not the read
     * outcome alone. */
    rwlock_rdlock(&wc->st->lock);
    rc_ht_entry_t *entry = ht_find(wc->st->ht, wc->st->ht_cap, hash);
    uint32_t rc_val = entry ? entry->ref_count : 0;
    rwlock_rdunlock(&wc->st->lock);

    if (rc_val == 0) {
        if (wc->stats) wc->stats->tombstoned++;
    } else {
        if (wc->stats) wc->stats->corrupt++;
        if (wc->cb) wc->cb(hash, wc->ud);
    }
    return 0;
}

vw_err_t vw_storage_scrub_run(vw_storage_t *st,
                               vw_storage_scrub_cb cb, void *ud,
                               vw_storage_scrub_stats_t *out_stats)
{
    if (!st) return VW_ERR_INVALID_ARG;
    if (out_stats) memset(out_stats, 0, sizeof(*out_stats));

    static const char hexch[] = "0123456789abcdef";
    size_t hi, lo;
    for (hi = 0; hi < 16; hi++) {
        for (lo = 0; lo < 16; lo++) {
            char shard_dir[768];
            int n = snprintf(shard_dir, sizeof(shard_dir), "%s/%c%c",
                              st->chunks_dir, hexch[hi], hexch[lo]);
            if (n <= 0 || (size_t)n >= sizeof(shard_dir)) continue;

            scrub_walk_ctx_t wc = { st, shard_dir, cb, ud, out_stats };
            /* A shard that has never received a chunk doesn't exist yet
             * (shard dirs are created lazily on first put) — vw_fs_list_dir
             * returning VW_ERR_IO for it is normal, not reported. */
            (void)vw_fs_list_dir(shard_dir, scrub_file_cb, &wc);
        }
    }
    return VW_OK;
}

/* ── vw_storage_set_store ────────────────────────────────────────────────── */

void vw_storage_set_store(vw_storage_t *st, vw_store_t *store)
{
    if (!st) return;
    rwlock_wrlock(&st->lock);
    st->store = store;
    rwlock_wrunlock(&st->lock);
}
