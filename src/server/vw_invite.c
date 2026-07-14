/*
 * vw_invite.c — Invite token flat-file store.
 *
 * Storage: {data_dir}/store/invites.db
 * Record: 64 bytes (vw_invite_record_t), slot 0-based.
 * Slot is free when code[0] == '\0'.
 * Invites are appended on creation; is_used is updated in-place.
 *
 * In-memory code→slot FNV-1a hash table with 75% load-factor cap.
 * Single rwlock guards both the table and the file.
 *
 * Security notes:
 *   - 128-bit random code (CSPRNG), base32-encoded → 26 printable chars.
 *   - Expiry and used-check happen under the read lock in vw_invite_get,
 *     so callers do not observe time-of-check/time-of-use gaps.
 */

#include "vw_invite.h"
#include "../core/vw_crypto.h"
#include "../core/vw_fs.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef SRWLOCK            inv_rwlock_t;
#   define inv_rwlock_init(l)     InitializeSRWLock(l)
#   define inv_rwlock_rlock(l)    AcquireSRWLockShared(l)
#   define inv_rwlock_runlock(l)  ReleaseSRWLockShared(l)
#   define inv_rwlock_wlock(l)    AcquireSRWLockExclusive(l)
#   define inv_rwlock_wunlock(l)  ReleaseSRWLockExclusive(l)
#   define inv_rwlock_destroy(l)  ((void)(l))
#else
#   include <pthread.h>
typedef pthread_rwlock_t   inv_rwlock_t;
#   define inv_rwlock_init(l)     pthread_rwlock_init((l), NULL)
#   define inv_rwlock_rlock(l)    pthread_rwlock_rdlock(l)
#   define inv_rwlock_runlock(l)  pthread_rwlock_unlock(l)
#   define inv_rwlock_wlock(l)    pthread_rwlock_wrlock(l)
#   define inv_rwlock_wunlock(l)  pthread_rwlock_unlock(l)
#   define inv_rwlock_destroy(l)  pthread_rwlock_destroy(l)
#endif

/* ── Base32 ──────────────────────────────────────────────────────────────── */

static const char BASE32_ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/*
 * Encode 16 random bytes (128 bits) into exactly 26 base32 ASCII characters.
 * out32[32] is fully zeroed first; [26..31] remain NUL padding.
 */
static void base32_encode_16(const uint8_t in[16], uint8_t out32[32])
{
    memset(out32, 0, 32);
    char *q = (char *)out32;
    uint32_t acc = 0;
    int bits = 0;
    for (int i = 0; i < 16; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            *q++ = BASE32_ALPHA[(acc >> bits) & 0x1Fu];
        }
    }
    /* 128 mod 5 == 3 bits remaining */
    if (bits > 0)
        *q++ = BASE32_ALPHA[(acc << (5 - bits)) & 0x1Fu];
    /* out32 is now: 26 printable chars + 6 NUL bytes */
}

/* ── In-memory hash table ────────────────────────────────────────────────── */

typedef struct {
    uint8_t  code[32];  /* '\0' in [0] means empty slot */
    uint64_t slot;      /* 0-based index into invites.db */
} ht_entry_t;

static uint64_t code_fnv1a(const uint8_t code[32])
{
    uint64_t h = 14695981039346656037ULL;
    for (int i = 0; i < 32; i++)
        h = (h ^ (uint64_t)code[i]) * 1099511628211ULL;
    return h;
}

/* Insert code→slot into ht[0..cap).  Returns 0 on success, -1 if table is full. */
static int ht_insert_raw(ht_entry_t *ht, size_t cap,
                          const uint8_t code[32], uint64_t slot)
{
    if (!cap) return -1;
    uint64_t h = code_fnv1a(code) % (uint64_t)cap;
    for (size_t i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].code[0] == '\0' || memcmp(ht[idx].code, code, 32) == 0) {
            memcpy(ht[idx].code, code, 32);
            ht[idx].slot = slot;
            return 0;
        }
    }
    return -1;
}

/* Look up code; return slot on hit, UINT64_MAX on miss. */
static uint64_t ht_find(const ht_entry_t *ht, size_t cap, const uint8_t code[32])
{
    if (!cap || code[0] == '\0') return UINT64_MAX;
    uint64_t h = code_fnv1a(code) % (uint64_t)cap;
    for (size_t i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].code[0] == '\0') return UINT64_MAX;
        if (memcmp(ht[idx].code, code, 32) == 0) return ht[idx].slot;
    }
    return UINT64_MAX;
}

/* ── Internal context ────────────────────────────────────────────────────── */

struct vw_invite_store {
    char         path[512];
    inv_rwlock_t lock;
    uint64_t     nslots;   /* total on-disk slot count */
    ht_entry_t  *ht;
    size_t       ht_cap;
    size_t       ht_len;
};

/* Grow the hash table to accommodate one more entry (≤75% load factor). */
static int ht_grow(struct vw_invite_store *s)
{
    size_t new_cap = (s->ht_cap < 16u) ? 16u : s->ht_cap * 2u;
    ht_entry_t *new_ht = (ht_entry_t *)calloc(new_cap, sizeof(*new_ht));
    if (!new_ht) return -1;

    for (size_t i = 0; i < s->ht_cap; i++) {
        if (s->ht[i].code[0] != '\0')
            (void)ht_insert_raw(new_ht, new_cap, s->ht[i].code, s->ht[i].slot);
    }
    free(s->ht);
    s->ht     = new_ht;
    s->ht_cap = new_cap;
    return 0;
}

/* Insert code→slot, growing if needed. Returns 0 on success, -1 on OOM. */
static int ht_add(struct vw_invite_store *s, const uint8_t code[32], uint64_t slot)
{
    if (s->ht_len * 4u >= s->ht_cap * 3u) {
        if (ht_grow(s) != 0) return -1;
    }
    if (ht_insert_raw(s->ht, s->ht_cap, code, slot) != 0) return -1;
    s->ht_len++;
    return 0;
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_invite_store_open(const char *data_dir, vw_invite_store_t **out)
{
    if (!data_dir || !out) return VW_ERR_INVALID_ARG;

    struct vw_invite_store *s =
        (struct vw_invite_store *)calloc(1, sizeof(*s));
    if (!s) return VW_ERR_OOM;

    /* Ensure {data_dir}/store/ exists. */
    char store_dir[512];
    snprintf(store_dir, sizeof(store_dir), "%s/store", data_dir);
    vw_err_t err = vw_fs_ensure_dir(store_dir);
    if (err != VW_OK) { free(s); return err; }

    snprintf(s->path, sizeof(s->path), "%s/store/invites.db", data_dir);
    inv_rwlock_init(&s->lock);

    /* Read and index existing records. */
    if (vw_fs_exists(s->path)) {
        void  *buf  = NULL;
        size_t blen = 0;
        err = vw_fs_read_file(s->path, &buf, &blen);
        if (err != VW_OK) {
            inv_rwlock_destroy(&s->lock);
            free(s);
            return err;
        }

        s->nslots = blen / sizeof(vw_invite_record_t);
        for (uint64_t i = 0; i < s->nslots; i++) {
            vw_invite_record_t rec;
            memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
            if (rec.code[0] != '\0') {
                if (ht_add(s, rec.code, i) != 0) {
                    free(buf);
                    inv_rwlock_destroy(&s->lock);
                    free(s->ht);
                    free(s);
                    return VW_ERR_OOM;
                }
            }
        }
        free(buf);
    }

    *out = s;
    return VW_OK;
}

void vw_invite_store_close(vw_invite_store_t *s)
{
    if (!s) return;
    inv_rwlock_destroy(&s->lock);
    free(s->ht);
    free(s);
}

/* ── Operations ──────────────────────────────────────────────────────────── */

vw_err_t vw_invite_create(vw_invite_store_t *s,
                           uint64_t created_by,
                           uint64_t quota_bytes,
                           uint32_t ttl_secs,
                           uint8_t  out_code[32])
{
    if (!s || !out_code) return VW_ERR_INVALID_ARG;

    uint8_t rand_bytes[16];
    vw_err_t err = vw_crypto_random(rand_bytes, sizeof(rand_bytes));
    if (err != VW_OK) return err;

    vw_invite_record_t rec;
    memset(&rec, 0, sizeof(rec));
    base32_encode_16(rand_bytes, rec.code);
    rec.created_by  = created_by;
    rec.quota_bytes = quota_bytes;
    rec.expires_at  = ttl_secs ? ((uint64_t)time(NULL) + ttl_secs) : 0u;
    rec.is_used     = 0;

    inv_rwlock_wlock(&s->lock);

    uint64_t slot = s->nslots;

    err = vw_fs_append(s->path, &rec, sizeof(rec));
    if (err != VW_OK) {
        inv_rwlock_wunlock(&s->lock);
        return err;
    }

    err = vw_fs_sync_file(s->path);
    if (err != VW_OK) {
        /* Record landed on disk but may not be durable; still increment nslots
         * so the in-memory counter stays consistent with the file length. */
        s->nslots++;
        inv_rwlock_wunlock(&s->lock);
        return err;
    }

    if (ht_add(s, rec.code, slot) != 0) {
        /* OOM in the hash table; record is durable on disk.
         * Next open will rebuild the index and include this slot. */
        s->nslots++;
        inv_rwlock_wunlock(&s->lock);
        memcpy(out_code, rec.code, 32);
        return VW_ERR_OOM;
    }

    s->nslots++;
    memcpy(out_code, rec.code, 32);
    inv_rwlock_wunlock(&s->lock);
    return VW_OK;
}

vw_err_t vw_invite_get(vw_invite_store_t *s,
                        const uint8_t code[32],
                        vw_invite_record_t *out)
{
    if (!s || !code || !out) return VW_ERR_INVALID_ARG;

    inv_rwlock_rlock(&s->lock);

    uint64_t slot = ht_find(s->ht, s->ht_cap, code);
    if (slot == UINT64_MAX) {
        inv_rwlock_runlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    void  *buf  = NULL;
    size_t blen = 0;
    vw_err_t err = vw_fs_read_file(s->path, &buf, &blen);
    if (err != VW_OK) {
        inv_rwlock_runlock(&s->lock);
        return err;
    }

    uint64_t byte_off = slot * (uint64_t)sizeof(vw_invite_record_t);
    if (byte_off + sizeof(vw_invite_record_t) > blen) {
        free(buf);
        inv_rwlock_runlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    vw_invite_record_t rec;
    memcpy(&rec, (uint8_t *)buf + byte_off, sizeof(rec));
    free(buf);

    /* Check usability while still under the read lock. */
    if (rec.is_used ||
        (rec.expires_at != 0u && (uint64_t)time(NULL) > rec.expires_at)) {
        inv_rwlock_runlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    *out = rec;
    inv_rwlock_runlock(&s->lock);
    return VW_OK;
}

vw_err_t vw_invite_claim(vw_invite_store_t *s,
                          const uint8_t code[32],
                          vw_invite_record_t *out)
{
    if (!s || !code || !out) return VW_ERR_INVALID_ARG;

    inv_rwlock_wlock(&s->lock);

    uint64_t slot = ht_find(s->ht, s->ht_cap, code);
    if (slot == UINT64_MAX) {
        inv_rwlock_wunlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    void  *buf  = NULL;
    size_t blen = 0;
    vw_err_t err = vw_fs_read_file(s->path, &buf, &blen);
    if (err != VW_OK) {
        inv_rwlock_wunlock(&s->lock);
        return err;
    }

    uint64_t byte_off = slot * (uint64_t)sizeof(vw_invite_record_t);
    if (byte_off + sizeof(vw_invite_record_t) > blen) {
        free(buf);
        inv_rwlock_wunlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    vw_invite_record_t rec;
    memcpy(&rec, (uint8_t *)buf + byte_off, sizeof(rec));
    free(buf);

    /* Validate while holding write lock — no concurrent claim can pass this check. */
    if (rec.is_used ||
        (rec.expires_at != 0u && (uint64_t)time(NULL) > rec.expires_at)) {
        inv_rwlock_wunlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    /* Mark used on disk before releasing the lock. */
    uint64_t flag_off = slot * (uint64_t)sizeof(vw_invite_record_t)
                        + (uint64_t)offsetof(vw_invite_record_t, is_used);
    const uint8_t used = 1u;
    err = vw_fs_pwrite(s->path, flag_off, &used, sizeof(used));
    if (err == VW_OK)
        err = vw_fs_sync_file(s->path);

    inv_rwlock_wunlock(&s->lock);

    if (err != VW_OK) return err;

    *out = rec;
    return VW_OK;
}

vw_err_t vw_invite_mark_used(vw_invite_store_t *s, const uint8_t code[32])
{
    if (!s || !code) return VW_ERR_INVALID_ARG;

    inv_rwlock_wlock(&s->lock);

    uint64_t slot = ht_find(s->ht, s->ht_cap, code);
    if (slot == UINT64_MAX) {
        inv_rwlock_wunlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    uint64_t file_off = slot * (uint64_t)sizeof(vw_invite_record_t)
                        + (uint64_t)offsetof(vw_invite_record_t, is_used);
    const uint8_t used = 1u;
    vw_err_t err = vw_fs_pwrite(s->path, file_off, &used, sizeof(used));
    if (err == VW_OK)
        err = vw_fs_sync_file(s->path);

    inv_rwlock_wunlock(&s->lock);
    return err;
}
