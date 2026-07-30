/*
 * vw_share.c — file/folder sharing store (TASK-094).
 *
 * See vw_share.h for design overview.
 */

#include "vw_share.h"
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
typedef SRWLOCK           shr_rwlock_t;
#   define shr_rwlock_init(l)     InitializeSRWLock(l)
#   define shr_rwlock_rlock(l)    AcquireSRWLockShared(l)
#   define shr_rwlock_runlock(l)  ReleaseSRWLockShared(l)
#   define shr_rwlock_wlock(l)    AcquireSRWLockExclusive(l)
#   define shr_rwlock_wunlock(l)  ReleaseSRWLockExclusive(l)
#   define shr_rwlock_destroy(l)  ((void)(l))
#else
#   include <pthread.h>
typedef pthread_rwlock_t   shr_rwlock_t;
#   define shr_rwlock_init(l)     pthread_rwlock_init((l), NULL)
#   define shr_rwlock_rlock(l)    pthread_rwlock_rdlock(l)
#   define shr_rwlock_runlock(l)  pthread_rwlock_unlock(l)
#   define shr_rwlock_wlock(l)    pthread_rwlock_wrlock(l)
#   define shr_rwlock_wunlock(l)  pthread_rwlock_unlock(l)
#   define shr_rwlock_destroy(l)  pthread_rwlock_destroy(l)
#endif

/* ── pread/pwrite-at-offset helper (same pattern as vw_store_files.c) ────── */

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

/* ── link_token hash table (same shape as vw_invite.c's code index) ──────── */

typedef struct {
    uint8_t  token[32]; /* all-zero => empty slot (a real token is never all-zero:
                          * vw_crypto_random draws from a CSPRNG) */
    uint64_t share_id;
} token_ht_entry_t;

static uint64_t token_fnv1a(const uint8_t token[32])
{
    uint64_t h = 14695981039346656037ULL;
    for (int i = 0; i < 32; i++)
        h = (h ^ (uint64_t)token[i]) * 1099511628211ULL;
    return h;
}

static int token_is_zero(const uint8_t token[32])
{
    for (int i = 0; i < 32; i++) if (token[i] != 0) return 0;
    return 1;
}

static int token_ht_insert_raw(token_ht_entry_t *ht, size_t cap,
                                const uint8_t token[32], uint64_t share_id)
{
    if (!cap) return -1;
    uint64_t h = token_fnv1a(token) % (uint64_t)cap;
    for (size_t i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (token_is_zero(ht[idx].token) ||
            vw_crypto_constant_time_eq(ht[idx].token, token, 32)) {
            memcpy(ht[idx].token, token, 32);
            ht[idx].share_id = share_id;
            return 0;
        }
    }
    return -1;
}

static uint64_t token_ht_find(const token_ht_entry_t *ht, size_t cap,
                               const uint8_t token[32])
{
    if (!cap || token_is_zero(token)) return 0;
    uint64_t h = token_fnv1a(token) % (uint64_t)cap;
    for (size_t i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (token_is_zero(ht[idx].token)) return 0;
        if (vw_crypto_constant_time_eq(ht[idx].token, token, 32))
            return ht[idx].share_id;
    }
    return 0;
}

/* ── Scoped-session write rate limit + LINK_ACCESS IP rate limit ─────────
 * Same fixed-table shape as vw_cluster.c's rate_entry_t/RATE_TABLE_SIZE,
 * with the eviction-fairness fix from TASK-078 applied from the start
 * (prefer a free/unlocked slot, else the entry closest to its own window
 * reset, rather than blind ring-buffer order). */

#define SHARE_RATE_TABLE_SIZE 256
#define SHARE_WRITE_MAX_PER_WINDOW 30u   /* writes per window per scoped session */
#define SHARE_WRITE_WINDOW_SECS    60u
#define LINK_ACCESS_MAX_FAILURES   5u
#define LINK_ACCESS_WINDOW_SECS    60u

typedef struct {
    uint8_t  token[32];      /* all-zero = free slot */
    uint32_t count;
    time_t   window_start;
} write_rate_entry_t;

typedef struct {
    char     ip[48];         /* empty = free slot */
    uint32_t fail_count;
    time_t   first_fail_at;
} ip_rate_entry_t;

static write_rate_entry_t *write_rate_find_or_evict(write_rate_entry_t *table,
                                                     const uint8_t token[32],
                                                     time_t now)
{
    for (int i = 0; i < SHARE_RATE_TABLE_SIZE; i++) {
        if (memcmp(table[i].token, token, 32) == 0 && !token_is_zero(table[i].token))
            return &table[i];
    }
    write_rate_entry_t *victim = &table[0];
    for (int i = 0; i < SHARE_RATE_TABLE_SIZE; i++) {
        write_rate_entry_t *cand = &table[i];
        if (token_is_zero(cand->token)) { victim = cand; break; }
        int cand_stale   = difftime(now, cand->window_start)   >= (double)SHARE_WRITE_WINDOW_SECS;
        int victim_stale = difftime(now, victim->window_start) >= (double)SHARE_WRITE_WINDOW_SECS;
        if (cand_stale != victim_stale) {
            if (cand_stale) victim = cand;
        } else if (cand->window_start < victim->window_start) {
            victim = cand;
        }
    }
    memset(victim, 0, sizeof(*victim));
    memcpy(victim->token, token, 32);
    victim->window_start = now;
    return victim;
}

static ip_rate_entry_t *ip_rate_find_or_evict(ip_rate_entry_t *table, const char *ip)
{
    for (int i = 0; i < SHARE_RATE_TABLE_SIZE; i++) {
        if (table[i].ip[0] != '\0' && strcmp(table[i].ip, ip) == 0)
            return &table[i];
    }
    ip_rate_entry_t *victim = &table[0];
    for (int i = 0; i < SHARE_RATE_TABLE_SIZE; i++) {
        ip_rate_entry_t *cand = &table[i];
        if (cand->ip[0] == '\0') { victim = cand; break; }
        if (cand->fail_count == 0 && victim->fail_count != 0) victim = cand;
    }
    memset(victim, 0, sizeof(*victim));
    snprintf(victim->ip, sizeof(victim->ip), "%s", ip);
    return victim;
}

/* ── Internal context ────────────────────────────────────────────────────── */

struct vw_share_store {
    char         path[512];
    shr_rwlock_t lock;
    vw_oplog_t  *oplog;          /* borrowed */
    uint64_t     nslots;
    uint64_t     next_share_id;

    token_ht_entry_t *token_ht;
    size_t            token_ht_cap;
    size_t            token_ht_len;

    /* Rate-limit tables: separate lock, accessed far more often than the
     * main share table and never touches shares.db. */
    shr_rwlock_t         rate_lock;
    write_rate_entry_t   write_rate[SHARE_RATE_TABLE_SIZE];
    ip_rate_entry_t      ip_rate[SHARE_RATE_TABLE_SIZE];
};

static int token_ht_grow(struct vw_share_store *s)
{
    size_t new_cap = (s->token_ht_cap < 16u) ? 16u : s->token_ht_cap * 2u;
    token_ht_entry_t *new_ht = (token_ht_entry_t *)calloc(new_cap, sizeof(*new_ht));
    if (!new_ht) return -1;
    for (size_t i = 0; i < s->token_ht_cap; i++) {
        if (!token_is_zero(s->token_ht[i].token))
            (void)token_ht_insert_raw(new_ht, new_cap, s->token_ht[i].token,
                                       s->token_ht[i].share_id);
    }
    free(s->token_ht);
    s->token_ht     = new_ht;
    s->token_ht_cap = new_cap;
    return 0;
}

static int token_ht_add(struct vw_share_store *s, const uint8_t token[32],
                         uint64_t share_id)
{
    if (token_is_zero(token)) return 0; /* user grants: nothing to index */
    if (s->token_ht_len * 4u >= s->token_ht_cap * 3u) {
        if (token_ht_grow(s) != 0) return -1;
    }
    if (token_ht_insert_raw(s->token_ht, s->token_ht_cap, token, share_id) != 0)
        return -1;
    s->token_ht_len++;
    return 0;
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_share_store_open(const char *data_dir, vw_oplog_t *oplog,
                              vw_share_store_t **out)
{
    if (!data_dir || !oplog || !out) return VW_ERR_INVALID_ARG;

    struct vw_share_store *s = (struct vw_share_store *)calloc(1, sizeof(*s));
    if (!s) return VW_ERR_OOM;
    s->oplog = oplog;

    char shares_dir[500];
    snprintf(shares_dir, sizeof(shares_dir), "%s/shares", data_dir);
    vw_err_t err = vw_fs_ensure_dir(shares_dir);
    if (err != VW_OK) { free(s); return err; }

    /* shares_dir is at most 500 bytes; "/shares.db" (10 bytes) always fits
     * within s->path's 512-byte buffer. */
    snprintf(s->path, sizeof(s->path), "%s/shares.db", shares_dir);
    shr_rwlock_init(&s->lock);
    shr_rwlock_init(&s->rate_lock);
    s->next_share_id = 1;

    if (!vw_fs_exists(s->path)) {
        /* Slot 0 guard, matching vw_store_files.c's convention — real
         * records start at slot 1, so slot index == share_id directly
         * (vw_share_get_by_id/_by_token/_revoke rely on this). */
        vw_share_record_t guard;
        memset(&guard, 0, sizeof(guard));
        err = vw_fs_append(s->path, &guard, sizeof(guard));
        if (err != VW_OK) {
            shr_rwlock_destroy(&s->lock);
            shr_rwlock_destroy(&s->rate_lock);
            free(s);
            return err;
        }
    }

    if (vw_fs_exists(s->path)) {
        void  *buf  = NULL;
        size_t blen = 0;
        err = vw_fs_read_file(s->path, &buf, &blen);
        if (err != VW_OK) {
            shr_rwlock_destroy(&s->lock);
            shr_rwlock_destroy(&s->rate_lock);
            free(s);
            return err;
        }

        s->nslots = blen / sizeof(vw_share_record_t);
        for (uint64_t i = 0; i < s->nslots; i++) {
            vw_share_record_t rec;
            memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
            if (rec.share_id == 0) continue;
            if (rec.share_id >= s->next_share_id) s->next_share_id = rec.share_id + 1;
            if (rec.share_type == VW_SHARE_TYPE_LINK && !rec.revoked) {
                if (token_ht_add(s, rec.link_token, rec.share_id) != 0) {
                    free(buf);
                    free(s->token_ht);
                    shr_rwlock_destroy(&s->lock);
                    shr_rwlock_destroy(&s->rate_lock);
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

void vw_share_store_close(vw_share_store_t *s)
{
    if (!s) return;
    shr_rwlock_destroy(&s->lock);
    shr_rwlock_destroy(&s->rate_lock);
    free(s->token_ht);
    free(s);
}

/* ── CRUD ────────────────────────────────────────────────────────────────── */

static vw_err_t share_create_common(struct vw_share_store *s,
                                     const vw_share_record_t *in,
                                     uint64_t *out_share_id)
{
    vw_share_record_t rec = *in;

    shr_rwlock_wlock(&s->lock);

    rec.share_id = s->next_share_id;

    uint64_t eid = 0;
    vw_err_t rc = vw_oplog_append(s->oplog, VW_OPLOG_PERM_WRITE,
                                  &rec.owner_id, (uint32_t)sizeof(rec.owner_id), &eid);
    if (rc != VW_OK) { shr_rwlock_wunlock(&s->lock); return rc; }

    rc = vw_fs_append(s->path, &rec, sizeof(rec));
    if (rc != VW_OK) {
        (void)vw_oplog_abort(s->oplog, eid);
        shr_rwlock_wunlock(&s->lock);
        return rc;
    }
    rc = vw_fs_sync_file(s->path);
    if (rc != VW_OK) {
        (void)vw_oplog_abort(s->oplog, eid);
        shr_rwlock_wunlock(&s->lock);
        return rc;
    }

    s->nslots++;
    s->next_share_id++;
    (void)vw_oplog_confirm(s->oplog, eid);

    if (rec.share_type == VW_SHARE_TYPE_LINK) {
        if (token_ht_add(s, rec.link_token, rec.share_id) != 0) {
            /* Durable on disk; next open rebuilds the index. */
            shr_rwlock_wunlock(&s->lock);
            *out_share_id = rec.share_id;
            return VW_ERR_OOM;
        }
    }

    *out_share_id = rec.share_id;
    shr_rwlock_wunlock(&s->lock);
    return VW_OK;
}

vw_err_t vw_share_grant_create(vw_share_store_t *ss,
                                uint64_t file_id, uint64_t owner_id,
                                uint64_t target_user_id, vw_perm_t permission,
                                int64_t expires_at, uint64_t *out_share_id)
{
    if (!ss || !out_share_id || file_id == 0 || owner_id == 0 || target_user_id == 0)
        return VW_ERR_INVALID_ARG;
    if (permission != VW_PERM_VIEW && permission != VW_PERM_EDIT)
        return VW_ERR_INVALID_ARG;

    vw_share_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.file_id        = file_id;
    rec.owner_id        = owner_id;
    rec.target_user_id  = target_user_id;
    rec.share_type      = VW_SHARE_TYPE_GRANT;
    rec.permission      = (uint8_t)permission;
    rec.created_at      = (int64_t)time(NULL);
    rec.expires_at      = expires_at;

    return share_create_common(ss, &rec, out_share_id);
}

vw_err_t vw_share_link_create(vw_share_store_t *ss,
                               uint64_t file_id, uint64_t owner_id,
                               vw_perm_t permission, int64_t expires_at,
                               uint8_t out_link_token[32],
                               uint64_t *out_share_id)
{
    if (!ss || !out_link_token || !out_share_id || file_id == 0 || owner_id == 0)
        return VW_ERR_INVALID_ARG;
    if (permission != VW_PERM_VIEW && permission != VW_PERM_EDIT)
        return VW_ERR_INVALID_ARG;

    vw_share_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.file_id     = file_id;
    rec.owner_id     = owner_id;
    rec.share_type   = VW_SHARE_TYPE_LINK;
    rec.permission   = (uint8_t)permission;
    rec.created_at   = (int64_t)time(NULL);
    rec.expires_at   = expires_at;

    vw_err_t err = vw_crypto_random(rec.link_token, sizeof(rec.link_token));
    if (err != VW_OK) return err;
    /* CSPRNG output is never all-zero in practice, but guard the sentinel
     * anyway rather than assume — retry once. */
    if (token_is_zero(rec.link_token)) {
        err = vw_crypto_random(rec.link_token, sizeof(rec.link_token));
        if (err != VW_OK) return err;
        if (token_is_zero(rec.link_token)) return VW_ERR_CRYPTO;
    }

    err = share_create_common(ss, &rec, out_share_id);
    if (err != VW_OK) return err;

    memcpy(out_link_token, rec.link_token, 32);
    return VW_OK;
}

vw_err_t vw_share_get_by_id(vw_share_store_t *ss, uint64_t share_id,
                             vw_share_record_t *out)
{
    if (!ss || !out || share_id == 0) return VW_ERR_INVALID_ARG;

    shr_rwlock_rlock(&ss->lock);
    if (share_id >= ss->nslots) { shr_rwlock_runlock(&ss->lock); return VW_ERR_NOT_FOUND; }

    /* Slots are appended in share_id order starting at 1 with no gaps
     * (share_create_common never skips an id), so share_id IS the 0-based
     * slot index directly — no separate id->slot index needed. */
    vw_share_record_t rec;
    if (fs_pread(ss->path, &rec, sizeof(rec), share_id * (uint64_t)sizeof(rec)) != 0) {
        shr_rwlock_runlock(&ss->lock);
        return VW_ERR_NOT_FOUND;
    }
    shr_rwlock_runlock(&ss->lock);

    if (rec.share_id != share_id) return VW_ERR_NOT_FOUND;
    *out = rec;
    return VW_OK;
}

vw_err_t vw_share_get_by_token(vw_share_store_t *ss, const uint8_t token[32],
                                vw_share_record_t *out)
{
    if (!ss || !token || !out) return VW_ERR_INVALID_ARG;

    shr_rwlock_rlock(&ss->lock);
    uint64_t share_id = token_ht_find(ss->token_ht, ss->token_ht_cap, token);
    if (share_id == 0) { shr_rwlock_runlock(&ss->lock); return VW_ERR_NOT_FOUND; }

    vw_share_record_t rec;
    if (fs_pread(ss->path, &rec, sizeof(rec), share_id * (uint64_t)sizeof(rec)) != 0) {
        shr_rwlock_runlock(&ss->lock);
        return VW_ERR_NOT_FOUND;
    }
    shr_rwlock_runlock(&ss->lock);

    if (rec.share_id != share_id || rec.share_type != VW_SHARE_TYPE_LINK ||
        !vw_crypto_constant_time_eq(rec.link_token, token, 32))
        return VW_ERR_NOT_FOUND;

    int64_t now = (int64_t)time(NULL);
    if (rec.revoked || (rec.expires_at != 0 && now >= rec.expires_at))
        return VW_ERR_NOT_FOUND;

    *out = rec;
    return VW_OK;
}

vw_err_t vw_share_revoke(vw_share_store_t *ss, uint64_t share_id,
                          uint64_t caller_user_id)
{
    if (!ss || share_id == 0) return VW_ERR_INVALID_ARG;

    shr_rwlock_wlock(&ss->lock);

    if (share_id >= ss->nslots) { shr_rwlock_wunlock(&ss->lock); return VW_ERR_NOT_FOUND; }

    vw_share_record_t rec;
    if (fs_pread(ss->path, &rec, sizeof(rec), share_id * (uint64_t)sizeof(rec)) != 0 ||
        rec.share_id != share_id) {
        shr_rwlock_wunlock(&ss->lock);
        return VW_ERR_NOT_FOUND;
    }
    if (rec.revoked) { shr_rwlock_wunlock(&ss->lock); return VW_ERR_NOT_FOUND; }
    if (rec.owner_id != caller_user_id) {
        shr_rwlock_wunlock(&ss->lock);
        return VW_ERR_PERMISSION;
    }

    uint64_t off = share_id * (uint64_t)sizeof(rec) + (uint64_t)offsetof(vw_share_record_t, revoked);
    uint8_t one = 1u;
    vw_err_t err = vw_fs_pwrite(ss->path, off, &one, sizeof(one));
    if (err == VW_OK) err = vw_fs_sync_file(ss->path);

    shr_rwlock_wunlock(&ss->lock);
    return err;
}

vw_err_t vw_share_scan(vw_share_store_t *ss,
                        int (*callback)(const vw_share_record_t *rec, void *ud),
                        void *userdata)
{
    if (!ss || !callback) return VW_ERR_INVALID_ARG;

    shr_rwlock_rlock(&ss->lock);
    void  *buf  = NULL;
    size_t blen = 0;
    vw_err_t err = ss->nslots ? vw_fs_read_file(ss->path, &buf, &blen) : VW_OK;
    if (err != VW_OK) { shr_rwlock_runlock(&ss->lock); return err; }

    uint64_t n = blen / sizeof(vw_share_record_t);
    for (uint64_t i = 0; i < n; i++) {
        vw_share_record_t rec;
        memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
        if (rec.share_id == 0) continue;
        if (callback(&rec, userdata) != 0) break;
    }
    free(buf);
    shr_rwlock_runlock(&ss->lock);
    return VW_OK;
}

/* ── Permission resolution ───────────────────────────────────────────────── */

/* True if `ancestor_id` is `file_id` itself or one of its ancestors, per
 * fs's parent_dir_id chain (bounded walk — VW_MAX_PATH_BYTES/2 is a very
 * generous ceiling on real directory depth, guarding against a corrupt or
 * cyclic parent_dir_id chain hanging this walk forever). */
static int is_file_or_ancestor(vw_file_store_t *fs, uint64_t file_id,
                                uint64_t ancestor_id)
{
    uint64_t cur = file_id;
    for (uint32_t hops = 0; hops < 2048u && cur != 0; hops++) {
        if (cur == ancestor_id) return 1;
        vw_file_record_t rec;
        if (vw_store_file_get_by_id(fs, cur, &rec) != VW_OK) return 0;
        cur = rec.parent_dir_id;
    }
    return cur == ancestor_id; /* handles ancestor_id == 0 (root) */
}

vw_perm_t vw_share_resolve_permission(vw_share_store_t *ss, vw_file_store_t *fs,
                                       uint64_t file_id,
                                       uint64_t caller_user_id,
                                       uint64_t scope_share_id)
{
    if (!ss || !fs || file_id == 0) return VW_PERM_NONE;

    vw_perm_t best = VW_PERM_NONE;

    /* Rule 3: scoped-session access, re-checked against the LIVE share
     * record every call (live revocation). */
    if (scope_share_id != 0) {
        vw_share_record_t rec;
        if (vw_share_get_by_id(ss, scope_share_id, &rec) == VW_OK &&
            !rec.revoked &&
            (rec.expires_at == 0 || rec.expires_at > (int64_t)time(NULL)) &&
            is_file_or_ancestor(fs, file_id, rec.file_id)) {
            if ((vw_perm_t)rec.permission > best) best = (vw_perm_t)rec.permission;
        }
        return best; /* a scoped session never also carries a real grant */
    }

    /* Rule 2: user-to-user grants. Full scan (see vw_share.h's index-tradeoff
     * note) — for each active grant targeting this user, check whether
     * file_id is the granted item or a descendant of it. Inlined directly
     * (rather than via vw_share_scan's callback) since this scan needs `fs`,
     * which vw_share_scan's callback signature doesn't carry. */
    if (caller_user_id != 0) {
        shr_rwlock_rlock(&ss->lock);
        void  *buf  = NULL;
        size_t blen = 0;
        vw_err_t err = ss->nslots ? vw_fs_read_file(ss->path, &buf, &blen) : VW_OK;
        if (err == VW_OK) {
            uint64_t n = blen / sizeof(vw_share_record_t);
            for (uint64_t i = 0; i < n; i++) {
                vw_share_record_t rec;
                memcpy(&rec, (uint8_t *)buf + i * sizeof(rec), sizeof(rec));
                if (rec.share_id == 0 || rec.revoked) continue;
                if (rec.share_type != VW_SHARE_TYPE_GRANT) continue;
                if (rec.target_user_id != caller_user_id) continue;
                if (rec.expires_at != 0 && rec.expires_at <= (int64_t)time(NULL)) continue;
                if ((vw_perm_t)rec.permission <= best) continue;
                if (is_file_or_ancestor(fs, file_id, rec.file_id))
                    best = (vw_perm_t)rec.permission;
            }
        }
        free(buf);
        shr_rwlock_runlock(&ss->lock);
    }

    return best;
}

/* ── Scoped-session write-count rate limit ──────────────────────────────── */

vw_err_t vw_share_scoped_write_ratelimit_check(vw_share_store_t *ss,
                                                const uint8_t token[32])
{
    if (!ss || !token) return VW_ERR_INVALID_ARG;

    time_t now = time(NULL);
    shr_rwlock_wlock(&ss->rate_lock);

    write_rate_entry_t *e = write_rate_find_or_evict(ss->write_rate, token, now);
    if (difftime(now, e->window_start) >= (double)SHARE_WRITE_WINDOW_SECS) {
        e->window_start = now;
        e->count = 0;
    }
    if (e->count >= SHARE_WRITE_MAX_PER_WINDOW) {
        shr_rwlock_wunlock(&ss->rate_lock);
        return VW_ERR_RATE_LIMITED;
    }
    e->count++;
    shr_rwlock_wunlock(&ss->rate_lock);
    return VW_OK;
}

/* ── LINK_ACCESS IP rate limit ───────────────────────────────────────────── */

int vw_share_link_access_is_blocked(vw_share_store_t *ss, const char *ip)
{
    if (!ss || !ip || !ip[0]) return 0;
    time_t now = time(NULL);
    int blocked = 0;

    shr_rwlock_rlock(&ss->rate_lock);
    for (int i = 0; i < SHARE_RATE_TABLE_SIZE; i++) {
        if (ss->ip_rate[i].ip[0] != '\0' && strcmp(ss->ip_rate[i].ip, ip) == 0) {
            if (ss->ip_rate[i].fail_count >= LINK_ACCESS_MAX_FAILURES &&
                difftime(now, ss->ip_rate[i].first_fail_at) < (double)LINK_ACCESS_WINDOW_SECS)
                blocked = 1;
            break;
        }
    }
    shr_rwlock_runlock(&ss->rate_lock);
    return blocked;
}

void vw_share_link_access_record_failure(vw_share_store_t *ss, const char *ip)
{
    if (!ss || !ip || !ip[0]) return;
    time_t now = time(NULL);

    shr_rwlock_wlock(&ss->rate_lock);
    ip_rate_entry_t *e = ip_rate_find_or_evict(ss->ip_rate, ip);
    if (e->fail_count > 0 && difftime(now, e->first_fail_at) >= (double)LINK_ACCESS_WINDOW_SECS) {
        e->fail_count    = 0;
        e->first_fail_at = 0;
    }
    if (e->fail_count == 0) e->first_fail_at = now;
    e->fail_count++;
    shr_rwlock_wunlock(&ss->rate_lock);
}

void vw_share_link_access_reset_on_success(vw_share_store_t *ss, const char *ip)
{
    if (!ss || !ip || !ip[0]) return;
    shr_rwlock_wlock(&ss->rate_lock);
    for (int i = 0; i < SHARE_RATE_TABLE_SIZE; i++) {
        if (ss->ip_rate[i].ip[0] != '\0' && strcmp(ss->ip_rate[i].ip, ip) == 0) {
            ss->ip_rate[i].fail_count    = 0;
            ss->ip_rate[i].first_fail_at = 0;
            break;
        }
    }
    shr_rwlock_wunlock(&ss->rate_lock);
}
