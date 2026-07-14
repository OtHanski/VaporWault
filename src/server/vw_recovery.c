/*
 * vw_recovery.c — Password-recovery token flat-file store.
 *
 * Storage: {data_dir}/store/recovery.db
 * Record: 64 bytes (vw_recovery_record_t). user_id==0 is a free slot.
 * New records are appended; is_used is updated in-place.
 * Lookup is linear-scan by user_id (expected count is small).
 *
 * Security notes:
 *   - SHA-256 of the plaintext code is stored; plaintext never touches disk.
 *   - Code verification uses vw_crypto_constant_time_eq to prevent timing leaks.
 *   - TTL is 10 minutes (set by caller via ttl_secs).
 */

#include "vw_recovery.h"
#include "../core/vw_fs.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef SRWLOCK             rec_rwlock_t;
#   define rec_rwlock_init(l)     InitializeSRWLock(l)
#   define rec_rwlock_rlock(l)    AcquireSRWLockShared(l)
#   define rec_rwlock_runlock(l)  ReleaseSRWLockShared(l)
#   define rec_rwlock_wlock(l)    AcquireSRWLockExclusive(l)
#   define rec_rwlock_wunlock(l)  ReleaseSRWLockExclusive(l)
#   define rec_rwlock_destroy(l)  ((void)(l))
#else
#   include <pthread.h>
typedef pthread_rwlock_t    rec_rwlock_t;
#   define rec_rwlock_init(l)     pthread_rwlock_init((l), NULL)
#   define rec_rwlock_rlock(l)    pthread_rwlock_rdlock(l)
#   define rec_rwlock_runlock(l)  pthread_rwlock_unlock(l)
#   define rec_rwlock_wlock(l)    pthread_rwlock_wrlock(l)
#   define rec_rwlock_wunlock(l)  pthread_rwlock_unlock(l)
#   define rec_rwlock_destroy(l)  pthread_rwlock_destroy(l)
#endif

/* ── Internal context ────────────────────────────────────────────────────── */

struct vw_recovery_store {
    char         path[512];
    rec_rwlock_t lock;
    uint64_t     nslots;
};

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_recovery_store_open(const char *data_dir, vw_recovery_store_t **out)
{
    if (!data_dir || !out) return VW_ERR_INVALID_ARG;

    struct vw_recovery_store *s =
        (struct vw_recovery_store *)calloc(1, sizeof(*s));
    if (!s) return VW_ERR_OOM;

    char store_dir[512];
    snprintf(store_dir, sizeof(store_dir), "%s/store", data_dir);
    vw_err_t err = vw_fs_ensure_dir(store_dir);
    if (err != VW_OK) { free(s); return err; }

    snprintf(s->path, sizeof(s->path), "%s/store/recovery.db", data_dir);
    rec_rwlock_init(&s->lock);

    /* Count existing slots from file length (no need to read content). */
    if (vw_fs_exists(s->path)) {
        void  *buf  = NULL;
        size_t blen = 0;
        err = vw_fs_read_file(s->path, &buf, &blen);
        if (err != VW_OK) {
            rec_rwlock_destroy(&s->lock);
            free(s);
            return err;
        }
        s->nslots = blen / sizeof(vw_recovery_record_t);
        free(buf);
    }

    *out = s;
    return VW_OK;
}

void vw_recovery_store_close(vw_recovery_store_t *s)
{
    if (!s) return;
    rec_rwlock_destroy(&s->lock);
    free(s);
}

/* ── Operations ──────────────────────────────────────────────────────────── */

vw_err_t vw_recovery_write(vw_recovery_store_t *s,
                            uint64_t user_id,
                            const uint8_t code_hash[32],
                            uint32_t ttl_secs)
{
    if (!s || !user_id || !code_hash || !ttl_secs) return VW_ERR_INVALID_ARG;

    vw_recovery_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.user_id    = user_id;
    memcpy(rec.code_hash, code_hash, 32);
    rec.expires_at = (uint64_t)time(NULL) + ttl_secs;
    rec.is_used    = 0;

    rec_rwlock_wlock(&s->lock);

    vw_err_t err = vw_fs_append(s->path, &rec, sizeof(rec));
    if (err == VW_OK)
        err = vw_fs_sync_file(s->path);
    if (err == VW_OK)
        s->nslots++;

    rec_rwlock_wunlock(&s->lock);
    return err;
}

vw_err_t vw_recovery_count_unexpired(vw_recovery_store_t *s,
                                      uint64_t user_id,
                                      uint64_t now_unix,
                                      uint32_t *out_count)
{
    if (!s || !user_id || !out_count) return VW_ERR_INVALID_ARG;
    *out_count = 0;

    rec_rwlock_rlock(&s->lock);

    if (s->nslots == 0) {
        rec_rwlock_runlock(&s->lock);
        return VW_OK;
    }

    void  *buf  = NULL;
    size_t blen = 0;
    vw_err_t err = vw_fs_read_file(s->path, &buf, &blen);
    if (err != VW_OK) {
        rec_rwlock_runlock(&s->lock);
        return err;
    }

    uint64_t nslots = blen / sizeof(vw_recovery_record_t);
    uint32_t count  = 0;

    for (uint64_t i = 0; i < nslots; i++) {
        vw_recovery_record_t rec;
        memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
        if (rec.user_id == user_id &&
            !rec.is_used &&
            rec.expires_at > now_unix) {
            count++;
        }
    }

    free(buf);
    rec_rwlock_runlock(&s->lock);

    *out_count = count;
    return VW_OK;
}

vw_err_t vw_recovery_find_latest(vw_recovery_store_t *s,
                                  uint64_t user_id,
                                  uint64_t now_unix,
                                  vw_recovery_record_t *out,
                                  uint64_t *out_slot)
{
    if (!s || !user_id || !out || !out_slot) return VW_ERR_INVALID_ARG;

    rec_rwlock_rlock(&s->lock);

    if (s->nslots == 0) {
        rec_rwlock_runlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    void  *buf  = NULL;
    size_t blen = 0;
    vw_err_t err = vw_fs_read_file(s->path, &buf, &blen);
    if (err != VW_OK) {
        rec_rwlock_runlock(&s->lock);
        return err;
    }

    uint64_t nslots    = blen / sizeof(vw_recovery_record_t);
    int      found     = 0;
    uint64_t best_slot = 0;
    uint64_t best_exp  = 0;
    vw_recovery_record_t best_rec;

    for (uint64_t i = 0; i < nslots; i++) {
        vw_recovery_record_t rec;
        memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
        if (rec.user_id != user_id || rec.is_used) continue;
        if (rec.expires_at <= now_unix) continue;
        /* Take the record with the latest expiry (most recently issued). */
        if (!found || rec.expires_at > best_exp) {
            best_rec  = rec;
            best_slot = i;
            best_exp  = rec.expires_at;
            found     = 1;
        }
    }

    free(buf);
    rec_rwlock_runlock(&s->lock);

    if (!found) return VW_ERR_NOT_FOUND;

    *out      = best_rec;
    *out_slot = best_slot;
    return VW_OK;
}

vw_err_t vw_recovery_mark_used(vw_recovery_store_t *s, uint64_t slot)
{
    if (!s) return VW_ERR_INVALID_ARG;

    rec_rwlock_wlock(&s->lock);

    if (slot >= s->nslots) {
        rec_rwlock_wunlock(&s->lock);
        return VW_ERR_NOT_FOUND;
    }

    uint64_t file_off = slot * (uint64_t)sizeof(vw_recovery_record_t)
                        + (uint64_t)offsetof(vw_recovery_record_t, is_used);
    const uint8_t used = 1u;
    vw_err_t err = vw_fs_pwrite(s->path, file_off, &used, sizeof(used));
    if (err == VW_OK)
        err = vw_fs_sync_file(s->path);

    rec_rwlock_wunlock(&s->lock);
    return err;
}
