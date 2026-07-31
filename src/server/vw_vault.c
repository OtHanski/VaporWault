/*
 * vw_vault.c — E2EE vault storage (TASK-098).
 *
 * See vw_vault.h for design overview.
 */

#include "vw_vault.h"
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
typedef SRWLOCK           vlt_rwlock_t;
#   define vlt_rwlock_init(l)     InitializeSRWLock(l)
#   define vlt_rwlock_rlock(l)    AcquireSRWLockShared(l)
#   define vlt_rwlock_runlock(l)  ReleaseSRWLockShared(l)
#   define vlt_rwlock_wlock(l)    AcquireSRWLockExclusive(l)
#   define vlt_rwlock_wunlock(l)  ReleaseSRWLockExclusive(l)
#   define vlt_rwlock_destroy(l)  ((void)(l))
#else
#   include <pthread.h>
typedef pthread_rwlock_t   vlt_rwlock_t;
#   define vlt_rwlock_init(l)     pthread_rwlock_init((l), NULL)
#   define vlt_rwlock_rlock(l)    pthread_rwlock_rdlock(l)
#   define vlt_rwlock_runlock(l)  pthread_rwlock_unlock(l)
#   define vlt_rwlock_wlock(l)    pthread_rwlock_wrlock(l)
#   define vlt_rwlock_wunlock(l)  pthread_rwlock_unlock(l)
#   define vlt_rwlock_destroy(l)  pthread_rwlock_destroy(l)
#endif

/* ── pread-at-offset helper (same pattern as vw_share.c / vw_store_files.c) ── */

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
#include <fcntl.h>
#include <unistd.h>
static int fs_pread(const char *path, void *buf, size_t len, uint64_t off)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)off);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}
#endif

/* ── Store ───────────────────────────────────────────────────────────────── */

struct vw_vault_store {
    char         db_path[512];
    char         blob_path[512];
    vlt_rwlock_t lock;
    vw_oplog_t  *oplog;          /* borrowed */

    uint64_t     nslots;
    uint64_t     next_vault_id;
    uint64_t     blob_size;      /* current EOF of vaults.blob */

    uint64_t    *vid_to_slot;    /* dense array indexed by vault_id */
    uint64_t     vid_to_slot_cap;
};

static int vid_to_slot_ensure(struct vw_vault_store *s, uint64_t vault_id)
{
    if (vault_id < s->vid_to_slot_cap) return 0;
    uint64_t new_cap = s->vid_to_slot_cap ? s->vid_to_slot_cap * 2u : 64u;
    while (new_cap <= vault_id) new_cap *= 2u;
    uint64_t *tmp = (uint64_t *)realloc(s->vid_to_slot, new_cap * sizeof(uint64_t));
    if (!tmp) return -1;
    memset(tmp + s->vid_to_slot_cap, 0,
           (size_t)(new_cap - s->vid_to_slot_cap) * sizeof(uint64_t));
    s->vid_to_slot     = tmp;
    s->vid_to_slot_cap = new_cap;
    return 0;
}

vw_err_t vw_vault_store_open(const char *data_dir, vw_oplog_t *oplog,
                              vw_vault_store_t **out)
{
    if (!data_dir || !oplog || !out) return VW_ERR_INVALID_ARG;

    struct vw_vault_store *s = (struct vw_vault_store *)calloc(1, sizeof(*s));
    if (!s) return VW_ERR_OOM;
    s->oplog = oplog;

    char vaults_dir[500];
    snprintf(vaults_dir, sizeof(vaults_dir), "%s/vaults", data_dir);
    vw_err_t err = vw_fs_ensure_dir(vaults_dir);
    if (err != VW_OK) { free(s); return err; }

    snprintf(s->db_path, sizeof(s->db_path), "%s/vaults.db", vaults_dir);
    snprintf(s->blob_path, sizeof(s->blob_path), "%s/vaults.blob", vaults_dir);
    vlt_rwlock_init(&s->lock);
    s->next_vault_id = 1;

    if (!vw_fs_exists(s->db_path)) {
        /* Slot 0 guard, matching vw_store_files.c/vw_share.c's convention —
         * real records start at slot 1, so slot index == vault_id directly. */
        vw_vault_record_t guard;
        memset(&guard, 0, sizeof(guard));
        err = vw_fs_append(s->db_path, &guard, sizeof(guard));
        if (err != VW_OK) { vlt_rwlock_destroy(&s->lock); free(s); return err; }
    }
    if (!vw_fs_exists(s->blob_path)) {
        err = vw_fs_append(s->blob_path, "", 0);
        if (err != VW_OK) { vlt_rwlock_destroy(&s->lock); free(s); return err; }
    }

    void  *buf  = NULL;
    size_t blen = 0;
    err = vw_fs_read_file(s->db_path, &buf, &blen);
    if (err != VW_OK) { vlt_rwlock_destroy(&s->lock); free(s); return err; }

    s->nslots = blen / sizeof(vw_vault_record_t);
    for (uint64_t i = 0; i < s->nslots; i++) {
        vw_vault_record_t rec;
        memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
        if (rec.vault_id == 0) continue;
        if (rec.vault_id >= s->next_vault_id) s->next_vault_id = rec.vault_id + 1;
        if (vid_to_slot_ensure(s, rec.vault_id) != 0) {
            free(buf); free(s->vid_to_slot); vlt_rwlock_destroy(&s->lock); free(s);
            return VW_ERR_OOM;
        }
        s->vid_to_slot[rec.vault_id] = i;
    }
    free(buf);

    uint64_t blob_sz = 0;
    err = vw_fs_file_size(s->blob_path, &blob_sz);
    if (err != VW_OK) {
        free(s->vid_to_slot); vlt_rwlock_destroy(&s->lock); free(s);
        return err;
    }
    s->blob_size = blob_sz;

    *out = s;
    return VW_OK;
}

void vw_vault_store_close(vw_vault_store_t *s)
{
    if (!s) return;
    vlt_rwlock_destroy(&s->lock);
    free(s->vid_to_slot);
    free(s);
}

/* ── CRUD ────────────────────────────────────────────────────────────────── */

vw_err_t vw_vault_create(vw_vault_store_t *s,
                          uint64_t owner_id, uint64_t folder_file_id,
                          const uint8_t *wrapped_vk, uint32_t wrapped_vk_len,
                          const uint8_t kdf_salt[16],
                          const uint8_t *kdf_params, uint32_t kdf_params_len,
                          uint64_t *out_vault_id)
{
    if (!s || !out_vault_id || owner_id == 0 || folder_file_id == 0)
        return VW_ERR_INVALID_ARG;
    if (!wrapped_vk || wrapped_vk_len == 0 ||
        wrapped_vk_len > VW_VAULT_MAX_WRAPPED_VK_BYTES)
        return VW_ERR_INVALID_ARG;
    if (kdf_params_len > VW_VAULT_MAX_KDF_PARAMS_BYTES ||
        (kdf_params_len > 0 && !kdf_params))
        return VW_ERR_INVALID_ARG;
    if (!kdf_salt) return VW_ERR_INVALID_ARG;

    vlt_rwlock_wlock(&s->lock);

    uint64_t vault_id = s->next_vault_id;
    uint64_t blob_off  = s->blob_size;

    uint64_t eid = 0;
    vw_err_t rc = vw_oplog_append(s->oplog, VW_OPLOG_VAULT_WRITE,
                                   &owner_id, (uint32_t)sizeof(owner_id), &eid);
    if (rc != VW_OK) { vlt_rwlock_wunlock(&s->lock); return rc; }

    /* 1. Append blob: wrapped_vk then kdf_params. */
    rc = vw_fs_append(s->blob_path, wrapped_vk, wrapped_vk_len);
    if (rc != VW_OK) {
        (void)vw_oplog_abort(s->oplog, eid);
        vlt_rwlock_wunlock(&s->lock);
        return rc;
    }
    if (kdf_params_len > 0) {
        rc = vw_fs_append(s->blob_path, kdf_params, kdf_params_len);
        if (rc != VW_OK) {
            (void)vw_oplog_abort(s->oplog, eid);
            vlt_rwlock_wunlock(&s->lock);
            return rc;
        }
    }
    rc = vw_fs_sync_file(s->blob_path);
    if (rc != VW_OK) {
        (void)vw_oplog_abort(s->oplog, eid);
        vlt_rwlock_wunlock(&s->lock);
        return rc;
    }

    /* 2. Append the fixed record. */
    vw_vault_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.vault_id       = vault_id;
    rec.owner_id       = owner_id;
    rec.folder_file_id = folder_file_id;
    rec.created_at     = (int64_t)time(NULL);
    rec.blob_offset    = blob_off;
    rec.wrapped_vk_len = wrapped_vk_len;
    rec.kdf_params_len = kdf_params_len;
    memcpy(rec.kdf_salt, kdf_salt, 16);

    rc = vw_fs_append(s->db_path, &rec, sizeof(rec));
    if (rc != VW_OK) {
        (void)vw_oplog_abort(s->oplog, eid);
        vlt_rwlock_wunlock(&s->lock);
        return rc;
    }
    rc = vw_fs_sync_file(s->db_path);
    if (rc != VW_OK) {
        (void)vw_oplog_abort(s->oplog, eid);
        vlt_rwlock_wunlock(&s->lock);
        return rc;
    }

    /* 3. Update in-memory state — advance counters before touching the
     * index, matching vw_store_files.c/vw_share.c's crash-safety ordering:
     * the record is durable on disk even if the index update below OOMs;
     * a restart rebuilds the index from disk. */
    uint64_t slot = s->nslots;
    s->nslots++;
    s->blob_size += (uint64_t)wrapped_vk_len + kdf_params_len;
    s->next_vault_id++;

    (void)vw_oplog_confirm(s->oplog, eid);

    if (vid_to_slot_ensure(s, vault_id) == 0)
        s->vid_to_slot[vault_id] = slot;

    *out_vault_id = vault_id;
    vlt_rwlock_wunlock(&s->lock);
    return VW_OK;
}

vw_err_t vw_vault_get_by_id(vw_vault_store_t *s, uint64_t vault_id,
                             vw_vault_record_t *out_rec,
                             uint8_t **out_wrapped_vk, uint8_t **out_kdf_params)
{
    if (!s || !out_rec || !out_wrapped_vk || !out_kdf_params || vault_id == 0)
        return VW_ERR_INVALID_ARG;

    vlt_rwlock_rlock(&s->lock);

    if (vault_id >= s->vid_to_slot_cap) { vlt_rwlock_runlock(&s->lock); return VW_ERR_NOT_FOUND; }

    uint64_t slot = s->vid_to_slot[vault_id];
    if (slot == 0) { vlt_rwlock_runlock(&s->lock); return VW_ERR_NOT_FOUND; }

    vw_vault_record_t rec;
    uint64_t off = slot * (uint64_t)sizeof(rec);
    if (fs_pread(s->db_path, &rec, sizeof(rec), off) != 0) {
        vlt_rwlock_runlock(&s->lock);
        return VW_ERR_IO;
    }
    if (rec.vault_id != vault_id) { vlt_rwlock_runlock(&s->lock); return VW_ERR_NOT_FOUND; }

    uint8_t *vk = NULL, *params = NULL;
    if (rec.wrapped_vk_len > 0) {
        vk = (uint8_t *)malloc(rec.wrapped_vk_len);
        if (!vk || fs_pread(s->blob_path, vk, rec.wrapped_vk_len, rec.blob_offset) != 0) {
            free(vk);
            vlt_rwlock_runlock(&s->lock);
            return vk ? VW_ERR_IO : VW_ERR_OOM;
        }
    }
    if (rec.kdf_params_len > 0) {
        params = (uint8_t *)malloc(rec.kdf_params_len);
        if (!params || fs_pread(s->blob_path, params, rec.kdf_params_len,
                                 rec.blob_offset + rec.wrapped_vk_len) != 0) {
            free(vk); free(params);
            vlt_rwlock_runlock(&s->lock);
            return params ? VW_ERR_IO : VW_ERR_OOM;
        }
    }

    vlt_rwlock_runlock(&s->lock);

    *out_rec = rec;
    *out_wrapped_vk = vk;
    *out_kdf_params = params;
    return VW_OK;
}

vw_err_t vw_vault_scan(vw_vault_store_t *s,
                        int (*callback)(const vw_vault_record_t *rec, void *ud),
                        void *userdata)
{
    if (!s || !callback) return VW_ERR_INVALID_ARG;

    vlt_rwlock_rlock(&s->lock);

    void  *buf  = NULL;
    size_t blen = 0;
    vw_err_t err = vw_fs_read_file(s->db_path, &buf, &blen);
    if (err != VW_OK) { vlt_rwlock_runlock(&s->lock); return err; }

    uint64_t n = blen / sizeof(vw_vault_record_t);
    for (uint64_t i = 0; i < n; i++) {
        vw_vault_record_t rec;
        memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
        if (rec.vault_id == 0) continue;
        if (callback(&rec, userdata) != 0) break;
    }

    free(buf);
    vlt_rwlock_runlock(&s->lock);
    return VW_OK;
}
