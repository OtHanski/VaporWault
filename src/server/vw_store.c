/*
 * vw_store.c — flat-file storage engine for users and sessions.
 *
 * See vw_store.h for the full design description.
 *
 * Storage layout:
 *   {data_dir}/store/users.dat    — array of vw_user_record_t (256 bytes/slot)
 *   {data_dir}/store/sessions.dat — array of vw_session_record_t (128 bytes/slot)
 *
 * Slot 0 of users.dat is a reserved guard (user_id == 0 == free).
 * Real users occupy slots >= 1.
 * Sessions occupy slots >= 0; free = is_active == 0.
 *
 * All write operations use oplog two-phase commit:
 *   vw_oplog_append (confirmed=0) → write to .dat → sync → update indexes
 *   → vw_oplog_confirm
 * On any failure between append and confirm: vw_oplog_abort is called.
 */

/* Own headers first, then stdlib (STYLE.md §11). */
#include "vw_store.h"
#include "../core/vw_crypto.h"
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

/* ── Atomic slot read (no seek state, no full-file read) ─────────────────── */

#ifdef _WIN32
static int store_pread(const char *path, void *buf, size_t len, uint64_t off)
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
static int store_pread(const char *path, void *buf, size_t len, uint64_t off)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)off);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}
#endif

/*
 * secure_zero — zero memory in a way optimising compilers cannot eliminate.
 * Uses a volatile function pointer so the call cannot be dead-store-eliminated.
 * Required before free() on any buffer containing password hashes or tokens.
 */
static void *(* volatile g_memset_fn)(void *, int, size_t) = memset;
#define secure_zero(p, n) ((void)g_memset_fn((p), 0, (n)))

/* ── Hash table entry types ───────────────────────────────────────────────── */

/*
 * Username and email HTs: key[0] == '\0' means the slot is empty.
 * Since slot 0 in users.dat is the guard (user_id==0), we never store it in
 * these tables, so slot==0 safely marks an empty HT entry.
 */
typedef struct {
    char     key[65]; /* NUL-terminated username; [0]=='\0' means empty */
    uint64_t slot;    /* 0-based file slot; 0 == empty HT entry */
} uname_ht_entry_t;

typedef struct {
    char     key[129]; /* NUL-terminated email; [0]=='\0' means empty */
    uint64_t slot;
} email_ht_entry_t;

/*
 * Token HT uses explicit state because session slot 0 is a valid live session.
 * Tombstone (TOKEN_DELETED) keeps linear-probe chains intact after delete.
 */
#define TOKEN_EMPTY    0
#define TOKEN_OCCUPIED 1
#define TOKEN_DELETED  2

typedef struct {
    uint8_t  key[32];
    uint64_t slot;
    int      state; /* TOKEN_EMPTY / TOKEN_OCCUPIED / TOKEN_DELETED */
} token_ht_entry_t;

/* ── Internal context ─────────────────────────────────────────────────────── */

struct vw_store {
    char       users_path[512];
    char       sessions_path[512];
    vw_oplog_t *oplog; /* borrowed — not owned */

    /* Users table — guarded by users_lock */
    vw_rwlock_t      users_lock;
    uint64_t         next_user_id;    /* next monotonic id to assign (>= 1) */
    uint64_t         user_slots;      /* total slots in users.dat */
    uname_ht_entry_t *username_ht;
    size_t            username_ht_cap;
    size_t            username_ht_len;
    email_ht_entry_t *email_ht;
    size_t            email_ht_cap;
    size_t            email_ht_len;
    uint64_t         *uid_to_slot;    /* uid_to_slot[user_id] = 0-based file slot */
    size_t            uid_to_slot_cap;

    /* Sessions table — guarded by sessions_lock */
    vw_rwlock_t      sessions_lock;
    uint64_t         session_slots;   /* total allocated slots in sessions.dat */
    token_ht_entry_t *token_ht;
    size_t            token_ht_cap;
    size_t            token_ht_len;
    uint64_t         *session_free_slots; /* reusable inactive slot indices */
    size_t            session_free_len;
    size_t            session_free_cap;

    /* Quota table — guarded by quota_lock */
    vw_rwlock_t       quota_lock;
    char              quotas_path[512];
    vw_quota_record_t *quotas;        /* in-memory copy of all quota slots */
    uint64_t          quota_nslots;   /* total slots on disk (incl. guard) */
    uint64_t         *quota_free;     /* free-slot indices */
    size_t            quota_free_len;
    size_t            quota_free_cap;
};

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

/* ── Username hash table ──────────────────────────────────────────────────── */

static int uname_ht_insert_raw(uname_ht_entry_t *ht, size_t cap,
                                const char *username, uint64_t slot)
{
    uint64_t h = fnv1a(username, strlen(username)) % (uint64_t)cap;
    size_t i;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].key[0] == '\0') {
            strncpy(ht[idx].key, username, 64);
            ht[idx].key[64] = '\0';
            ht[idx].slot = slot;
            return 0;
        }
        if (strncmp(ht[idx].key, username, 64) == 0) {
            ht[idx].slot = slot;
            return 0;
        }
    }
    return -1;
}

static int uname_ht_grow(vw_store_t *ctx)
{
    size_t new_cap = ctx->username_ht_cap * 2;
    uname_ht_entry_t *new_ht;
    size_t i;

    new_ht = (uname_ht_entry_t *)calloc(new_cap, sizeof(*new_ht));
    if (!new_ht) return -1;
    for (i = 0; i < ctx->username_ht_cap; i++) {
        if (ctx->username_ht[i].key[0] != '\0') {
            uname_ht_insert_raw(new_ht, new_cap,
                                 ctx->username_ht[i].key,
                                 ctx->username_ht[i].slot);
        }
    }
    free(ctx->username_ht);
    ctx->username_ht = new_ht;
    ctx->username_ht_cap = new_cap;
    return 0;
}

static int uname_ht_insert(vw_store_t *ctx, const char *username, uint64_t slot)
{
    int is_new = (uname_ht_find(ctx, username) == 0); /* 0 = not found */
    /* Grow at 75% load only for new entries (updates reuse an existing bucket). */
    if (is_new && ctx->username_ht_len * 4 >= ctx->username_ht_cap * 3) {
        if (uname_ht_grow(ctx) != 0) return -1;
    }
    if (uname_ht_insert_raw(ctx->username_ht, ctx->username_ht_cap,
                             username, slot) != 0) return -1;
    if (is_new) ctx->username_ht_len++;
    return 0;
}

static uint64_t uname_ht_find(const vw_store_t *ctx, const char *username)
{
    size_t cap = ctx->username_ht_cap;
    uint64_t h;
    size_t i;

    if (!cap || !username || !username[0]) return 0;
    h = fnv1a(username, strlen(username)) % (uint64_t)cap;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ctx->username_ht[idx].key[0] == '\0') return 0;
        if (strncmp(ctx->username_ht[idx].key, username, 64) == 0)
            return ctx->username_ht[idx].slot;
    }
    return 0;
}

/* ── Email hash table ─────────────────────────────────────────────────────── */

static int email_ht_insert_raw(email_ht_entry_t *ht, size_t cap,
                                const char *email, uint64_t slot)
{
    uint64_t h = fnv1a(email, strlen(email)) % (uint64_t)cap;
    size_t i;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].key[0] == '\0') {
            strncpy(ht[idx].key, email, 128);
            ht[idx].key[128] = '\0';
            ht[idx].slot = slot;
            return 0;
        }
        if (strncmp(ht[idx].key, email, 128) == 0) {
            ht[idx].slot = slot;
            return 0;
        }
    }
    return -1;
}

static int email_ht_grow(vw_store_t *ctx)
{
    size_t new_cap = ctx->email_ht_cap * 2;
    email_ht_entry_t *new_ht;
    size_t i;

    new_ht = (email_ht_entry_t *)calloc(new_cap, sizeof(*new_ht));
    if (!new_ht) return -1;
    for (i = 0; i < ctx->email_ht_cap; i++) {
        if (ctx->email_ht[i].key[0] != '\0') {
            email_ht_insert_raw(new_ht, new_cap,
                                 ctx->email_ht[i].key,
                                 ctx->email_ht[i].slot);
        }
    }
    free(ctx->email_ht);
    ctx->email_ht = new_ht;
    ctx->email_ht_cap = new_cap;
    return 0;
}

static int email_ht_insert(vw_store_t *ctx, const char *email, uint64_t slot)
{
    int is_new = (email_ht_find(ctx, email) == 0); /* 0 = not found */
    /* Grow at 75% load only for new entries (updates reuse an existing bucket). */
    if (is_new && ctx->email_ht_len * 4 >= ctx->email_ht_cap * 3) {
        if (email_ht_grow(ctx) != 0) return -1;
    }
    if (email_ht_insert_raw(ctx->email_ht, ctx->email_ht_cap, email, slot) != 0)
        return -1;
    if (is_new) ctx->email_ht_len++;
    return 0;
}

static uint64_t email_ht_find(const vw_store_t *ctx, const char *email)
{
    size_t cap = ctx->email_ht_cap;
    uint64_t h;
    size_t i;

    if (!cap || !email || !email[0]) return 0;
    h = fnv1a(email, strlen(email)) % (uint64_t)cap;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ctx->email_ht[idx].key[0] == '\0') return 0;
        if (strncmp(ctx->email_ht[idx].key, email, 128) == 0)
            return ctx->email_ht[idx].slot;
    }
    return 0;
}

/* ── Token hash table ─────────────────────────────────────────────────────── */

static int token_ht_insert_raw(token_ht_entry_t *ht, size_t cap,
                                const uint8_t *token, uint64_t slot)
{
    uint64_t h = fnv1a(token, 32) % (uint64_t)cap;
    size_t i;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ht[idx].state == TOKEN_EMPTY || ht[idx].state == TOKEN_DELETED) {
            memcpy(ht[idx].key, token, 32);
            ht[idx].slot = slot;
            ht[idx].state = TOKEN_OCCUPIED;
            return 0;
        }
        if (vw_crypto_constant_time_eq(ht[idx].key, token, 32)) {
            ht[idx].slot = slot;
            return 0;
        }
    }
    return -1;
}

static int token_ht_grow(vw_store_t *ctx)
{
    size_t new_cap = ctx->token_ht_cap * 2;
    token_ht_entry_t *new_ht;
    size_t i;

    new_ht = (token_ht_entry_t *)calloc(new_cap, sizeof(*new_ht));
    if (!new_ht) return -1;
    for (i = 0; i < ctx->token_ht_cap; i++) {
        if (ctx->token_ht[i].state == TOKEN_OCCUPIED) {
            token_ht_insert_raw(new_ht, new_cap,
                                 ctx->token_ht[i].key,
                                 ctx->token_ht[i].slot);
        }
    }
    free(ctx->token_ht);
    ctx->token_ht = new_ht;
    ctx->token_ht_cap = new_cap;
    return 0;
}

static int token_ht_insert(vw_store_t *ctx, const uint8_t *token, uint64_t slot)
{
    if (ctx->token_ht_len * 4 >= ctx->token_ht_cap * 3) {
        if (token_ht_grow(ctx) != 0) return -1;
    }
    if (token_ht_insert_raw(ctx->token_ht, ctx->token_ht_cap, token, slot) != 0)
        return -1;
    ctx->token_ht_len++;
    return 0;
}

/*
 * Look up a token. Sets *found=1 and returns the slot on hit; *found=0 on miss.
 * Uses vw_crypto_constant_time_eq so the comparison never short-circuits.
 */
static uint64_t token_ht_find(const vw_store_t *ctx,
                               const uint8_t *token, int *found)
{
    size_t cap = ctx->token_ht_cap;
    uint64_t h;
    size_t i;

    *found = 0;
    if (!cap) return 0;
    h = fnv1a(token, 32) % (uint64_t)cap;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ctx->token_ht[idx].state == TOKEN_EMPTY) return 0;
        if (ctx->token_ht[idx].state == TOKEN_DELETED) continue;
        if (vw_crypto_constant_time_eq(ctx->token_ht[idx].key, token, 32)) {
            *found = 1;
            return ctx->token_ht[idx].slot;
        }
    }
    return 0;
}

/* Tombstone the entry for token. Callers hold sessions write lock. */
static void token_ht_remove(vw_store_t *ctx, const uint8_t *token)
{
    size_t cap = ctx->token_ht_cap;
    uint64_t h;
    size_t i;

    if (!cap) return;
    h = fnv1a(token, 32) % (uint64_t)cap;
    for (i = 0; i < cap; i++) {
        size_t idx = (size_t)((h + (uint64_t)i) % (uint64_t)cap);
        if (ctx->token_ht[idx].state == TOKEN_EMPTY) return;
        if (ctx->token_ht[idx].state == TOKEN_DELETED) continue;
        if (vw_crypto_constant_time_eq(ctx->token_ht[idx].key, token, 32)) {
            ctx->token_ht[idx].state = TOKEN_DELETED;
            /* Zero the sensitive key material from the deleted slot. */
            secure_zero(ctx->token_ht[idx].key, 32);
            ctx->token_ht_len--;
            return;
        }
    }
}

/* ── uid_to_slot growth ───────────────────────────────────────────────────── */

static int uid_to_slot_ensure(vw_store_t *ctx, uint64_t user_id)
{
    size_t new_cap;
    uint64_t *p;

    if (user_id < (uint64_t)ctx->uid_to_slot_cap) return 0;
    new_cap = ctx->uid_to_slot_cap ? ctx->uid_to_slot_cap : 16;
    while ((uint64_t)new_cap <= user_id) new_cap *= 2;
    p = (uint64_t *)realloc(ctx->uid_to_slot, new_cap * sizeof(uint64_t));
    if (!p) return -1;
    memset(p + ctx->uid_to_slot_cap, 0,
           (new_cap - ctx->uid_to_slot_cap) * sizeof(uint64_t));
    ctx->uid_to_slot = p;
    ctx->uid_to_slot_cap = new_cap;
    return 0;
}

/* ── Session free-list ────────────────────────────────────────────────────── */

/*
 * Push a slot index onto the session free list.
 * Called from vw_store_open (inactive slots) and vw_store_session_delete.
 * Caller must hold sessions_lock.
 */
static int session_free_push(vw_store_t *ctx, uint64_t slot)
{
    uint64_t *p;
    size_t new_cap;

    if (ctx->session_free_len >= ctx->session_free_cap) {
        new_cap = ctx->session_free_cap ? ctx->session_free_cap * 2 : 16;
        p = (uint64_t *)realloc(ctx->session_free_slots,
                                 new_cap * sizeof(uint64_t));
        if (!p) return -1;
        ctx->session_free_slots = p;
        ctx->session_free_cap = new_cap;
    }
    ctx->session_free_slots[ctx->session_free_len++] = slot;
    return 0;
}

/* ── vw_store_open ────────────────────────────────────────────────────────── */

vw_err_t vw_store_open(const char *data_dir, vw_oplog_t *oplog,
                        vw_store_t **out_ctx)
{
    vw_err_t    err = VW_ERR_IO;
    vw_store_t *ctx = NULL;
    void       *ubuf = NULL;
    void       *sbuf = NULL;
    void       *qbuf = NULL;
    size_t      ubuf_len = 0;
    size_t      sbuf_len = 0;
    size_t      qbuf_len = 0;
    int         users_lock_init = 0;
    int         sessions_lock_init = 0;
    int         quota_lock_init = 0;
    uint64_t    max_user_id = 0;
    uint64_t    now = 0;
    uint64_t    i = 0;
    int         sn = 0;
    char        store_dir[512];
    char        users_path[512];
    char        sessions_path[512];
    char        quotas_path[512];
    uint8_t     guard[256];

    if (!data_dir || !oplog || !out_ctx) return VW_ERR_INVALID_ARG;

    sn = snprintf(store_dir, sizeof(store_dir), "%s/store", data_dir);
    if (sn < 0 || sn >= (int)sizeof(store_dir)) return VW_ERR_INVALID_ARG;
    sn = snprintf(users_path, sizeof(users_path),
                  "%s/store/users.dat", data_dir);
    if (sn < 0 || sn >= (int)sizeof(users_path)) return VW_ERR_INVALID_ARG;
    sn = snprintf(sessions_path, sizeof(sessions_path),
                  "%s/store/sessions.dat", data_dir);
    if (sn < 0 || sn >= (int)sizeof(sessions_path)) return VW_ERR_INVALID_ARG;
    sn = snprintf(quotas_path, sizeof(quotas_path),
                  "%s/store/quotas.db", data_dir);
    if (sn < 0 || sn >= (int)sizeof(quotas_path)) return VW_ERR_INVALID_ARG;

    err = vw_fs_ensure_dir(store_dir);
    if (err != VW_OK) return err;

    /* Create users.dat with a single reserved zero-slot if absent. */
    if (!vw_fs_exists(users_path)) {
        memset(guard, 0, sizeof(guard));
        err = vw_fs_atomic_write(users_path, guard, sizeof(guard));
        if (err != VW_OK) return err;
    }

    /* sessions.dat is created on first vw_store_session_create; skip if absent. */

    ctx = (vw_store_t *)calloc(1, sizeof(*ctx));
    if (!ctx) { err = VW_ERR_OOM; goto fail; }

    memcpy(ctx->users_path, users_path, sizeof(users_path));
    memcpy(ctx->sessions_path, sessions_path, sizeof(sessions_path));
    ctx->oplog = oplog;

    if (rwlock_init(&ctx->users_lock) != 0) { err = VW_ERR_IO; goto fail; }
    users_lock_init = 1;

    if (rwlock_init(&ctx->sessions_lock) != 0) { err = VW_ERR_IO; goto fail; }
    sessions_lock_init = 1;

    if (rwlock_init(&ctx->quota_lock) != 0) { err = VW_ERR_IO; goto fail; }
    quota_lock_init = 1;
    memcpy(ctx->quotas_path, quotas_path, sizeof(quotas_path));

    ctx->username_ht = (uname_ht_entry_t *)calloc(64, sizeof(*ctx->username_ht));
    if (!ctx->username_ht) { err = VW_ERR_OOM; goto fail; }
    ctx->username_ht_cap = 64;

    ctx->email_ht = (email_ht_entry_t *)calloc(64, sizeof(*ctx->email_ht));
    if (!ctx->email_ht) { err = VW_ERR_OOM; goto fail; }
    ctx->email_ht_cap = 64;

    ctx->token_ht = (token_ht_entry_t *)calloc(64, sizeof(*ctx->token_ht));
    if (!ctx->token_ht) { err = VW_ERR_OOM; goto fail; }
    ctx->token_ht_cap = 64;

    ctx->uid_to_slot = (uint64_t *)calloc(16, sizeof(uint64_t));
    if (!ctx->uid_to_slot) { err = VW_ERR_OOM; goto fail; }
    ctx->uid_to_slot_cap = 16;

    /* Scan users.dat and build indexes. */
    err = vw_fs_read_file(ctx->users_path, &ubuf, &ubuf_len);
    if (err != VW_OK) goto fail;

    ctx->user_slots = ubuf_len / sizeof(vw_user_record_t);
    for (i = 0; i < ctx->user_slots; i++) {
        vw_user_record_t urec;
        char             uname[65];
        char             email_str[129];
        uint64_t         uid;

        memcpy(&urec, (uint8_t *)ubuf + i * sizeof(vw_user_record_t),
               sizeof(vw_user_record_t));
        if (urec.user_id == 0) continue; /* free slot */

        uid = urec.user_id;
        if (uid > max_user_id) max_user_id = uid;

        memcpy(uname, urec.username, 64);
        uname[64] = '\0';
        memcpy(email_str, urec.email, 128);
        email_str[128] = '\0';

        if (uname_ht_insert(ctx, uname, i) != 0)       { err = VW_ERR_OOM; goto fail; }
        if (email_ht_insert(ctx, email_str, i) != 0)    { err = VW_ERR_OOM; goto fail; }
        if (uid_to_slot_ensure(ctx, uid) != 0)           { err = VW_ERR_OOM; goto fail; }
        ctx->uid_to_slot[uid] = i;
    }

    /* Zero the entire users buffer before freeing — it contains password hashes. */
    secure_zero(ubuf, ubuf_len);
    free(ubuf);
    ubuf = NULL;
    ubuf_len = 0;

    ctx->next_user_id = (max_user_id == 0) ? 1 : (max_user_id + 1);

    /* Scan sessions.dat (optional — file may not exist yet). */
    err = vw_fs_read_file(ctx->sessions_path, &sbuf, &sbuf_len);
    if (err == VW_ERR_NOT_FOUND) {
        err = VW_OK;
        sbuf = NULL;
        sbuf_len = 0;
    } else if (err != VW_OK) {
        goto fail;
    }

    now = (uint64_t)time(NULL);
    ctx->session_slots = sbuf_len / sizeof(vw_session_record_t);
    for (i = 0; i < ctx->session_slots; i++) {
        vw_session_record_t srec;
        memcpy(&srec, (uint8_t *)sbuf + i * sizeof(vw_session_record_t),
               sizeof(vw_session_record_t));
        if (!srec.is_active || (srec.expires_at != 0 && srec.expires_at <= now)) {
            /* Inactive or expired slot is available for reuse. */
            if (session_free_push(ctx, i) != 0) { err = VW_ERR_OOM; goto fail; }
        } else {
            if (token_ht_insert(ctx, srec.token, i) != 0) {
                err = VW_ERR_OOM;
                goto fail;
            }
        }
    }

    /* Zero the entire sessions buffer before freeing — it contains tokens. */
    if (sbuf) {
        secure_zero(sbuf, sbuf_len);
        free(sbuf);
        sbuf = NULL;
        sbuf_len = 0;
    }

    /* ── quotas.db ── */
    {
        vw_quota_record_t qguard;
        memset(&qguard, 0, sizeof(qguard));
        if (!vw_fs_exists(ctx->quotas_path)) {
            err = vw_fs_atomic_write(ctx->quotas_path, &qguard, sizeof(qguard));
            if (err != VW_OK) goto fail;
        }
        err = vw_fs_read_file(ctx->quotas_path, &qbuf, &qbuf_len);
        if (err != VW_OK) goto fail;

        ctx->quota_nslots = qbuf_len / sizeof(vw_quota_record_t);
        ctx->quotas = (vw_quota_record_t *)calloc(
            ctx->quota_nslots ? ctx->quota_nslots : 1, sizeof(vw_quota_record_t));
        if (!ctx->quotas) { err = VW_ERR_OOM; free(qbuf); qbuf = NULL; goto fail; }
        if (ctx->quota_nslots)
            memcpy(ctx->quotas, qbuf, ctx->quota_nslots * sizeof(vw_quota_record_t));
        free(qbuf); qbuf = NULL;

        /* Build free-list. Slot 0 is the guard. */
        for (i = 1; i < ctx->quota_nslots; i++) {
            if (ctx->quotas[i].user_id == 0) {
                uint64_t *p;
                size_t nc;
                if (ctx->quota_free_len >= ctx->quota_free_cap) {
                    nc = ctx->quota_free_cap ? ctx->quota_free_cap * 2 : 8;
                    p = (uint64_t *)realloc(ctx->quota_free, nc * sizeof(uint64_t));
                    if (!p) { err = VW_ERR_OOM; goto fail; }
                    ctx->quota_free = p;
                    ctx->quota_free_cap = nc;
                }
                ctx->quota_free[ctx->quota_free_len++] = i;
            }
        }
    }

    err = VW_OK;
    *out_ctx = ctx;
    ctx = NULL; /* ownership transferred; suppress cleanup below */

fail:
    if (ubuf) {
        secure_zero(ubuf, ubuf_len);
        free(ubuf);
    }
    if (sbuf) {
        secure_zero(sbuf, sbuf_len);
        free(sbuf);
    }
    if (qbuf) free(qbuf);
    if (ctx) {
        if (quota_lock_init)    rwlock_destroy(&ctx->quota_lock);
        if (sessions_lock_init) rwlock_destroy(&ctx->sessions_lock);
        if (users_lock_init)    rwlock_destroy(&ctx->users_lock);
        /* Zero token keys before freeing. */
        if (ctx->token_ht) {
            size_t j;
            for (j = 0; j < ctx->token_ht_cap; j++) {
                if (ctx->token_ht[j].state == TOKEN_OCCUPIED)
                    secure_zero(ctx->token_ht[j].key, 32);
            }
        }
        free(ctx->token_ht);
        free(ctx->email_ht);
        free(ctx->username_ht);
        free(ctx->uid_to_slot);
        free(ctx->session_free_slots);
        free(ctx->quotas);
        free(ctx->quota_free);
        free(ctx);
    }
    return err;
}

/* ── vw_store_close ───────────────────────────────────────────────────────── */

void vw_store_close(vw_store_t *ctx)
{
    if (!ctx) return;
    rwlock_destroy(&ctx->sessions_lock);
    rwlock_destroy(&ctx->users_lock);
    /* Zero token keys before freeing — they are sensitive 32-byte secrets. */
    if (ctx->token_ht) {
        size_t i;
        for (i = 0; i < ctx->token_ht_cap; i++) {
            if (ctx->token_ht[i].state == TOKEN_OCCUPIED)
                secure_zero(ctx->token_ht[i].key, 32);
        }
        free(ctx->token_ht);
    }
    free(ctx->email_ht);
    free(ctx->username_ht);
    free(ctx->uid_to_slot);
    free(ctx->session_free_slots);
    rwlock_destroy(&ctx->quota_lock);
    free(ctx->quotas);
    free(ctx->quota_free);
    free(ctx);
}

/* ── vw_store_user_create ─────────────────────────────────────────────────── */

vw_err_t vw_store_user_create(vw_store_t *ctx,
                               const vw_user_record_t *record,
                               uint64_t *out_user_id)
{
    vw_err_t         rc = VW_OK;
    vw_err_t         confirm_rc = VW_OK;
    vw_err_t         abort_rc = VW_OK;
    vw_user_record_t rec;
    uint64_t         eid = 0;
    uint64_t         user_id = 0;
    uint64_t         new_slot = 0;
    char             uname[65];
    char             email_str[129];

    if (!ctx || !record || !out_user_id) return VW_ERR_INVALID_ARG;

    memcpy(uname, record->username, 64);
    uname[64] = '\0';
    memcpy(email_str, record->email, 128);
    email_str[128] = '\0';

    rwlock_wrlock(&ctx->users_lock);

    /* Duplicate check — username and email must be unique. */
    if (uname_ht_find(ctx, uname) != 0 ||
        email_ht_find(ctx, email_str) != 0) {
        rwlock_wrunlock(&ctx->users_lock);
        return VW_ERR_ALREADY_EXISTS;
    }

    user_id  = ctx->next_user_id;
    new_slot = ctx->user_slots;  /* record will be appended at this slot index */

    /* Build the on-disk record. */
    memcpy(&rec, record, sizeof(rec));
    rec.user_id = user_id;
    memset(rec._pad, 0, sizeof(rec._pad));

    /* Phase 1: append oplog entry (confirmed=0). */
    rc = vw_oplog_append(ctx->oplog, VW_OPLOG_USER_WRITE,
                         &user_id, sizeof(user_id), &eid);
    if (rc != VW_OK) { rwlock_wrunlock(&ctx->users_lock); return rc; }

    /* Phase 2: persist record by appending to users.dat. */
    rc = vw_fs_append(ctx->users_path, &rec, sizeof(rec));
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        rwlock_wrunlock(&ctx->users_lock);
        return rc;
    }

    /* Phase 3: sync to durable storage. */
    rc = vw_fs_sync_file(ctx->users_path);
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        rwlock_wrunlock(&ctx->users_lock);
        return rc;
    }

    /* Phase 4: commit next_user_id and update in-memory indexes. */
    ctx->next_user_id++;
    ctx->user_slots++;

    if (uid_to_slot_ensure(ctx, user_id) != 0 ||
        uname_ht_insert(ctx, uname, new_slot) != 0 ||
        email_ht_insert(ctx, email_str, new_slot) != 0) {
        /* OOM on index update: data is durable but indexes are stale.
         * Abort the oplog entry. On the next open, indexes rebuild correctly. */
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        rwlock_wrunlock(&ctx->users_lock);
        return VW_ERR_OOM;
    }
    ctx->uid_to_slot[user_id] = new_slot;

    /* Phase 5: confirm oplog entry. */
    confirm_rc = vw_oplog_confirm(ctx->oplog, eid);
    if (confirm_rc != VW_OK) {
        /* Data is durable on disk; the unconfirmed oplog hole will be truncated
         * by seg_scan on next open. The write succeeded from the caller's view. */
    }

    *out_user_id = user_id;
    rwlock_wrunlock(&ctx->users_lock);
    return VW_OK;
}

/* ── User lookup helpers ──────────────────────────────────────────────────── */

/*
 * Read one user record from disk at the given slot, zero sensitive fields,
 * and write the result to out_record. Caller must hold at least users_rlock.
 */
static vw_err_t read_user_slot(vw_store_t *ctx, uint64_t slot,
                                vw_user_record_t *out_record)
{
    vw_user_record_t tmp;
    uint64_t         off = slot * (uint64_t)sizeof(vw_user_record_t);

    /* Read exactly one slot — avoids loading all password hashes into memory. */
    if (store_pread(ctx->users_path, &tmp, sizeof(tmp), off) != 0) {
        secure_zero(&tmp, sizeof(tmp));
        return VW_ERR_IO;
    }

    if (tmp.user_id == 0) {
        secure_zero(&tmp, sizeof(tmp));
        return VW_ERR_NOT_FOUND;
    }

    /* Zero sensitive fields before returning. */
    memset(tmp.password_hash, 0, sizeof(tmp.password_hash));
    memset(tmp.password_salt, 0, sizeof(tmp.password_salt));
    *out_record = tmp;
    return VW_OK;
}

/* ── vw_store_user_get_by_id ──────────────────────────────────────────────── */

vw_err_t vw_store_user_get_by_id(vw_store_t *ctx,
                                  uint64_t user_id,
                                  vw_user_record_t *out_record)
{
    uint64_t slot;
    vw_err_t rc;

    if (!ctx || !out_record || user_id == 0) return VW_ERR_NOT_FOUND;

    rwlock_rdlock(&ctx->users_lock);

    if (user_id >= (uint64_t)ctx->uid_to_slot_cap) {
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }
    slot = ctx->uid_to_slot[user_id];
    if (slot == 0) {
        /* uid_to_slot[user_id] == 0 means no entry (slot 0 is the guard). */
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }

    rc = read_user_slot(ctx, slot, out_record);
    rwlock_rdunlock(&ctx->users_lock);
    return rc;
}

/* ── vw_store_user_get_by_username ────────────────────────────────────────── */

vw_err_t vw_store_user_get_by_username(vw_store_t *ctx,
                                        const char *username,
                                        vw_user_record_t *out_record)
{
    uint64_t slot;
    vw_err_t rc;

    if (!ctx || !username || !out_record) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->users_lock);
    slot = uname_ht_find(ctx, username);
    if (slot == 0) {
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }
    rc = read_user_slot(ctx, slot, out_record);
    rwlock_rdunlock(&ctx->users_lock);
    return rc;
}

/* ── vw_store_user_get_by_email ───────────────────────────────────────────── */

vw_err_t vw_store_user_get_by_email(vw_store_t *ctx,
                                     const char *email,
                                     vw_user_record_t *out_record)
{
    uint64_t slot;
    vw_err_t rc;

    if (!ctx || !email || !out_record) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->users_lock);
    slot = email_ht_find(ctx, email);
    if (slot == 0) {
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }
    rc = read_user_slot(ctx, slot, out_record);
    rwlock_rdunlock(&ctx->users_lock);
    return rc;
}

/* ── vw_store_user_scan ───────────────────────────────────────────────────── */

vw_err_t vw_store_user_scan(vw_store_t *ctx,
                              int (*callback)(const vw_user_record_t *rec, void *ud),
                              void *userdata)
{
    void     *buf     = NULL;
    size_t    buf_len = 0;
    vw_err_t  rc;
    uint64_t  uid;

    if (!ctx || !callback) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->users_lock);

    rc = vw_fs_read_file(ctx->users_path, &buf, &buf_len);
    if (rc != VW_OK) {
        rwlock_rdunlock(&ctx->users_lock);
        return rc;
    }

    for (uid = 1; uid < ctx->next_user_id; uid++) {
        uint64_t         slot;
        size_t           off;
        vw_user_record_t rec;

        if (uid >= (uint64_t)ctx->uid_to_slot_cap) break;
        slot = ctx->uid_to_slot[uid];
        if (slot == 0) continue;

        off = (size_t)slot * sizeof(vw_user_record_t);
        if (off + sizeof(vw_user_record_t) > buf_len) continue;

        memcpy(&rec, (uint8_t *)buf + off, sizeof(rec));
        if (rec.user_id == 0 || !rec.is_active) continue;

        secure_zero(rec.password_hash, sizeof(rec.password_hash));
        secure_zero(rec.password_salt, sizeof(rec.password_salt));

        if (callback(&rec, userdata) != 0) break;
    }

    secure_zero(buf, buf_len);
    free(buf);
    rwlock_rdunlock(&ctx->users_lock);
    return VW_OK;
}

/* ── vw_store_user_update_field ───────────────────────────────────────────── */

vw_err_t vw_store_user_update_field(vw_store_t *ctx,
                                     uint64_t user_id,
                                     uint32_t field_offset,
                                     const void *data, size_t len)
{
    vw_err_t rc = VW_OK;
    vw_err_t confirm_rc = VW_OK;
    vw_err_t abort_rc = VW_OK;
    uint64_t slot = 0;
    uint64_t eid = 0;
    uint64_t file_off = 0;

    if (!ctx || !data) return VW_ERR_INVALID_ARG;
    if ((uint64_t)field_offset + (uint64_t)len > sizeof(vw_user_record_t))
        return VW_ERR_INVALID_ARG;
    if (user_id == 0) return VW_ERR_NOT_FOUND;

    rwlock_wrlock(&ctx->users_lock);

    if (user_id >= (uint64_t)ctx->uid_to_slot_cap) {
        rwlock_wrunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }
    slot = ctx->uid_to_slot[user_id];
    if (slot == 0) {
        rwlock_wrunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }

    rc = vw_oplog_append(ctx->oplog, VW_OPLOG_USER_WRITE,
                         &user_id, sizeof(user_id), &eid);
    if (rc != VW_OK) { rwlock_wrunlock(&ctx->users_lock); return rc; }

    file_off = slot * (uint64_t)sizeof(vw_user_record_t) + field_offset;
    rc = vw_fs_pwrite(ctx->users_path, file_off, data, len);
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        rwlock_wrunlock(&ctx->users_lock);
        return rc;
    }

    rc = vw_fs_sync_file(ctx->users_path);
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        rwlock_wrunlock(&ctx->users_lock);
        return rc;
    }

    confirm_rc = vw_oplog_confirm(ctx->oplog, eid);
    if (confirm_rc != VW_OK) {
        /* Data is durable; unconfirmed oplog hole truncated by seg_scan on next open. */
    }

    rwlock_wrunlock(&ctx->users_lock);
    return VW_OK;
}

/* ── vw_store_session_create ──────────────────────────────────────────────── */

vw_err_t vw_store_session_create(vw_store_t *ctx,
                                  const vw_session_record_t *record,
                                  uint8_t out_token[32])
{
    vw_err_t            rc = VW_OK;
    vw_err_t            confirm_rc = VW_OK;
    vw_err_t            abort_rc = VW_OK;
    vw_session_record_t srec;
    uint64_t            eid = 0;
    uint64_t            new_slot = 0;
    uint64_t            slot_payload = 0;
    int                 slot_is_reuse = 0;

    if (!ctx || !record || !out_token) return VW_ERR_INVALID_ARG;

    memcpy(&srec, record, sizeof(srec));
    srec.is_active = 1;

    /* Generate a random session token — caller's token field is ignored. */
    rc = vw_crypto_random(srec.token, 32);
    if (rc != VW_OK) return rc;

    rwlock_wrlock(&ctx->sessions_lock);

    /* Pop a free slot from the list, or extend the file. */
    if (ctx->session_free_len > 0) {
        new_slot = ctx->session_free_slots[--ctx->session_free_len];
        slot_is_reuse = 1;
    } else {
        new_slot = ctx->session_slots;
        slot_is_reuse = 0;
    }
    slot_payload = new_slot;

    rc = vw_oplog_append(ctx->oplog, VW_OPLOG_SESSION_WRITE,
                         &slot_payload, sizeof(slot_payload), &eid);
    if (rc != VW_OK) {
        if (slot_is_reuse) {
            /* Return the slot to the free list on oplog failure. */
            (void)session_free_push(ctx, new_slot);
        }
        secure_zero(srec.token, 32);
        rwlock_wrunlock(&ctx->sessions_lock);
        return rc;
    }

    if (slot_is_reuse) {
        /* Overwrite an existing inactive slot in place. */
        rc = vw_fs_pwrite(ctx->sessions_path,
                          new_slot * (uint64_t)sizeof(vw_session_record_t),
                          &srec, sizeof(srec));
    } else {
        /* Extend the file with a new slot. */
        rc = vw_fs_append(ctx->sessions_path, &srec, sizeof(srec));
    }

    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        if (slot_is_reuse) {
            (void)session_free_push(ctx, new_slot);
        }
        secure_zero(srec.token, 32);
        rwlock_wrunlock(&ctx->sessions_lock);
        return rc;
    }

    rc = vw_fs_sync_file(ctx->sessions_path);
    if (rc != VW_OK) {
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        if (slot_is_reuse) {
            (void)session_free_push(ctx, new_slot);
        }
        secure_zero(srec.token, 32);
        rwlock_wrunlock(&ctx->sessions_lock);
        return rc;
    }

    if (!slot_is_reuse) {
        ctx->session_slots++;
    }

    if (token_ht_insert(ctx, srec.token, new_slot) != 0) {
        abort_rc = vw_oplog_abort(ctx->oplog, eid);
        if (abort_rc != VW_OK && abort_rc != VW_ERR_NOT_FOUND) {
            /* abort failure leaks a pending slot; log when logging exists */
        }
        if (slot_is_reuse) {
            (void)session_free_push(ctx, new_slot);
        } else {
            ctx->session_slots--;
        }
        secure_zero(srec.token, 32);
        rwlock_wrunlock(&ctx->sessions_lock);
        return VW_ERR_OOM;
    }

    confirm_rc = vw_oplog_confirm(ctx->oplog, eid);
    if (confirm_rc != VW_OK) {
        /* Data is durable; unconfirmed oplog hole truncated by seg_scan on next open. */
    }

    /* Copy token to caller output before zeroing the stack copy. */
    memcpy(out_token, srec.token, 32);
    secure_zero(srec.token, 32);

    rwlock_wrunlock(&ctx->sessions_lock);
    return VW_OK;
}

/* ── vw_store_session_get ─────────────────────────────────────────────────── */

vw_err_t vw_store_session_get(vw_store_t *ctx,
                               const uint8_t token[32],
                               vw_session_record_t *out_record)
{
    void                *buf = NULL;
    size_t               buf_len = 0;
    uint64_t             slot = 0;
    size_t               off = 0;
    int                  found = 0;
    vw_err_t             rc = VW_OK;
    vw_session_record_t  tmp;
    uint64_t             now = 0;

    if (!ctx || !token || !out_record) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->sessions_lock);

    slot = token_ht_find(ctx, token, &found);
    if (!found) {
        rwlock_rdunlock(&ctx->sessions_lock);
        return VW_ERR_NOT_FOUND;
    }

    rc = vw_fs_read_file(ctx->sessions_path, &buf, &buf_len);
    if (rc != VW_OK) {
        rwlock_rdunlock(&ctx->sessions_lock);
        return rc;
    }

    off = (size_t)slot * sizeof(vw_session_record_t);
    if (off + sizeof(vw_session_record_t) > buf_len) {
        /* Zero entire buffer before freeing — it contains session tokens. */
        secure_zero(buf, buf_len);
        free(buf);
        rwlock_rdunlock(&ctx->sessions_lock);
        return VW_ERR_NOT_FOUND;
    }

    memcpy(&tmp, (uint8_t *)buf + off, sizeof(tmp));

    /* Zero entire buffer before freeing — it contains session tokens. */
    secure_zero(buf, buf_len);
    free(buf);

    now = (uint64_t)time(NULL);
    if (!tmp.is_active || (tmp.expires_at != 0 && tmp.expires_at <= now)) {
        rwlock_rdunlock(&ctx->sessions_lock);
        return VW_ERR_NOT_FOUND;
    }

    *out_record = tmp;
    rwlock_rdunlock(&ctx->sessions_lock);
    return VW_OK;
}

/* ── vw_store_session_delete ──────────────────────────────────────────────── */

vw_err_t vw_store_session_delete(vw_store_t *ctx, const uint8_t token[32])
{
    uint64_t slot = 0;
    int      found = 0;
    uint64_t file_off = 0;
    uint64_t slot_payload = 0;
    uint64_t eid = 0;
    uint8_t  inactive = 0;
    vw_err_t rc = VW_OK;

    if (!ctx || !token) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&ctx->sessions_lock);

    slot = token_ht_find(ctx, token, &found);
    if (!found) {
        rwlock_wrunlock(&ctx->sessions_lock);
        return VW_ERR_NOT_FOUND;
    }

    /* Mark is_active = 0 in the on-disk record at the exact field offset. */
    file_off = slot * (uint64_t)sizeof(vw_session_record_t)
               + (uint64_t)offsetof(vw_session_record_t, is_active);

    inactive = 0;
    rc = vw_fs_pwrite(ctx->sessions_path, file_off, &inactive, 1);
    if (rc != VW_OK) {
        rwlock_wrunlock(&ctx->sessions_lock);
        return rc;
    }

    rc = vw_fs_sync_file(ctx->sessions_path);
    if (rc != VW_OK) {
        rwlock_wrunlock(&ctx->sessions_lock);
        return rc;
    }

    /* Remove from in-memory index and make slot available for reuse. */
    token_ht_remove(ctx, token);
    if (session_free_push(ctx, slot) != 0) {
        /* OOM: slot not added to free list; will be picked up on next open. Non-fatal. */
    }

    /* Append an oplog entry recording this invalidation (for replication).
     * This intentionally comes AFTER the disk write: session invalidation is
     * idempotent and the disk state is authoritative. Oplog failure is non-fatal. */
    slot_payload = slot;
    rc = vw_oplog_append(ctx->oplog, VW_OPLOG_SESSION_WRITE,
                         &slot_payload, sizeof(slot_payload), &eid);
    if (rc == VW_OK) {
        vw_err_t confirm_rc = vw_oplog_confirm(ctx->oplog, eid);
        if (confirm_rc != VW_OK) {
            /* Session is already inactive on disk; oplog entry is best-effort. */
        }
    }
    /* Oplog failure here is non-fatal: the session is already inactive on disk. */

    rwlock_wrunlock(&ctx->sessions_lock);
    return VW_OK;
}

/* ── vw_store_session_gc ─────────────────────────────────────────────────── */

vw_err_t vw_store_session_gc(vw_store_t *ctx, uint64_t now_unix,
                              uint32_t *out_count)
{
    void    *buf     = NULL;
    size_t   buf_len = 0;
    vw_err_t rc      = VW_OK;
    uint64_t i, nslots;
    uint32_t expired = 0;

    if (!ctx) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&ctx->sessions_lock);

    rc = vw_fs_read_file(ctx->sessions_path, &buf, &buf_len);
    if (rc != VW_OK) {
        rwlock_wrunlock(&ctx->sessions_lock);
        return rc;
    }

    nslots = buf_len / sizeof(vw_session_record_t);

    for (i = 0; i < nslots; i++) {
        vw_session_record_t srec;
        memcpy(&srec, (uint8_t *)buf + i * sizeof(vw_session_record_t),
               sizeof(srec));

        if (!srec.is_active) continue;
        if (srec.expires_at == 0) continue;
        if (srec.expires_at > now_unix) continue;

        /* Expired active session: write is_active=0 in place. */
        {
            uint64_t file_off = i * (uint64_t)sizeof(vw_session_record_t)
                               + (uint64_t)offsetof(vw_session_record_t, is_active);
            uint8_t inactive = 0;
            vw_err_t wr = vw_fs_pwrite(ctx->sessions_path, file_off, &inactive, 1);
            if (wr != VW_OK) continue; /* skip; will retry on next GC cycle */
        }

        token_ht_remove(ctx, srec.token);
        if (session_free_push(ctx, i) != 0) {
            /* OOM: slot not in free list until next open. Non-fatal. */
        }
        expired++;
    }

    if (expired > 0) {
        vw_err_t sync_rc = vw_fs_sync_file(ctx->sessions_path);
        (void)sync_rc; /* best-effort; expired sessions are zeroed; GC retries on next cycle */
    }

    /* Zero buffer — it contains session tokens. */
    secure_zero(buf, buf_len);
    free(buf);

    rwlock_wrunlock(&ctx->sessions_lock);

    if (out_count) *out_count = expired;
    return VW_OK;
}

/* ── vw_store_sessions_revoke_by_user ───────────────────────────────────── */

/*
 * Invalidate all active sessions belonging to user_id.
 * Called after a successful password reset to log out any existing sessions.
 * Holds the sessions write lock for the full scan (same as vw_store_session_gc).
 */
vw_err_t vw_store_sessions_revoke_by_user(vw_store_t *ctx, uint64_t user_id,
                                           uint32_t *out_count)
{
    void    *buf     = NULL;
    size_t   buf_len = 0;
    vw_err_t rc      = VW_OK;
    uint64_t i, nslots;
    uint32_t revoked = 0;

    if (!ctx) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&ctx->sessions_lock);

    rc = vw_fs_read_file(ctx->sessions_path, &buf, &buf_len);
    if (rc != VW_OK) {
        rwlock_wrunlock(&ctx->sessions_lock);
        return rc;
    }

    nslots = buf_len / sizeof(vw_session_record_t);

    for (i = 0; i < nslots; i++) {
        vw_session_record_t srec;
        memcpy(&srec, (uint8_t *)buf + i * sizeof(vw_session_record_t),
               sizeof(srec));

        if (!srec.is_active || srec.user_id != user_id) continue;

        /* Write is_active=0 in place. */
        {
            uint64_t file_off = i * (uint64_t)sizeof(vw_session_record_t)
                               + (uint64_t)offsetof(vw_session_record_t, is_active);
            uint8_t inactive = 0;
            vw_err_t wr = vw_fs_pwrite(ctx->sessions_path, file_off, &inactive, 1);
            if (wr != VW_OK) continue; /* skip; GC will eventually expire it */
        }

        token_ht_remove(ctx, srec.token);
        if (session_free_push(ctx, i) != 0) {
            /* OOM: slot not in free list until next open. Non-fatal. */
        }
        revoked++;
    }

    if (revoked > 0) {
        vw_err_t sync_rc = vw_fs_sync_file(ctx->sessions_path);
        (void)sync_rc; /* best-effort; revoked sessions are zeroed; GC retries on next cycle */
    }

    /* Buffer contains session tokens — zero before free. */
    secure_zero(buf, buf_len);
    free(buf);

    rwlock_wrunlock(&ctx->sessions_lock);

    if (out_count) *out_count = revoked;
    return VW_OK;
}

/* ── vw_store_user_get_credentials ───────────────────────────────────────── */

vw_err_t vw_store_user_get_credentials(vw_store_t *ctx, uint64_t user_id,
                                        uint8_t out_hash[32],
                                        uint8_t out_salt[16])
{
    void            *buf = NULL;
    size_t           buf_len = 0;
    uint64_t         slot = 0;
    size_t           off = 0;
    vw_err_t         rc = VW_OK;
    vw_user_record_t tmp;

    if (!ctx || !out_hash || !out_salt || user_id == 0) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->users_lock);

    if (user_id >= (uint64_t)ctx->uid_to_slot_cap) {
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }
    slot = ctx->uid_to_slot[user_id];
    if (slot == 0) {
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }

    rc = vw_fs_read_file(ctx->users_path, &buf, &buf_len);
    if (rc != VW_OK) {
        rwlock_rdunlock(&ctx->users_lock);
        return rc;
    }

    off = (size_t)slot * sizeof(vw_user_record_t);
    if (off + sizeof(vw_user_record_t) > buf_len) {
        secure_zero(buf, buf_len);
        free(buf);
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }

    memcpy(&tmp, (uint8_t *)buf + off, sizeof(tmp));
    secure_zero(buf, buf_len);
    free(buf);

    if (tmp.user_id == 0) {
        rwlock_rdunlock(&ctx->users_lock);
        return VW_ERR_NOT_FOUND;
    }

    memcpy(out_hash, tmp.password_hash, 32);
    memcpy(out_salt, tmp.password_salt, 16);

    /* Zero sensitive fields in the stack copy before it goes out of scope. */
    secure_zero(tmp.password_hash, sizeof(tmp.password_hash));
    secure_zero(tmp.password_salt, sizeof(tmp.password_salt));

    rwlock_rdunlock(&ctx->users_lock);
    return VW_OK;
}

/* ── Quota helpers ────────────────────────────────────────────────────────── */

/* Find the slot for user_id in the quota table; returns UINT64_MAX if absent. */
static uint64_t quota_find_slot(const vw_store_t *ctx, uint64_t user_id)
{
    uint64_t i;
    for (i = 1; i < ctx->quota_nslots; i++) {
        if (ctx->quotas[i].user_id == user_id) return i;
    }
    return UINT64_MAX;
}

/* Write a quota record at slot to disk. Caller must hold quota_lock exclusive. */
static vw_err_t quota_write_slot(vw_store_t *ctx, uint64_t slot)
{
    vw_err_t err = vw_fs_pwrite(ctx->quotas_path,
                                  slot * sizeof(vw_quota_record_t),
                                  &ctx->quotas[slot], sizeof(vw_quota_record_t));
    if (err != VW_OK) return err;
    return vw_fs_sync_file(ctx->quotas_path);
}

/* Allocate a new slot (from free list or append). Caller holds quota_lock exclusive. */
static vw_err_t quota_alloc_slot(vw_store_t *ctx, uint64_t *out_slot)
{
    if (ctx->quota_free_len > 0) {
        *out_slot = ctx->quota_free[--ctx->quota_free_len];
        return VW_OK;
    }

    /* Append a new slot on disk, then grow the in-memory array. */
    uint64_t new_nslots = ctx->quota_nslots + 1;
    vw_quota_record_t *p = (vw_quota_record_t *)realloc(ctx->quotas,
        new_nslots * sizeof(vw_quota_record_t));
    if (!p) return VW_ERR_OOM;
    ctx->quotas = p;
    memset(&ctx->quotas[ctx->quota_nslots], 0, sizeof(vw_quota_record_t));

    /* Write the empty slot to disk. */
    vw_err_t err = vw_fs_pwrite(ctx->quotas_path,
                                  ctx->quota_nslots * sizeof(vw_quota_record_t),
                                  &ctx->quotas[ctx->quota_nslots],
                                  sizeof(vw_quota_record_t));
    if (err != VW_OK) return err;

    *out_slot = ctx->quota_nslots;
    ctx->quota_nslots = new_nslots;
    return VW_OK;
}

/* ── vw_store_quota_get ───────────────────────────────────────────────────── */

vw_err_t vw_store_quota_get(vw_store_t *ctx, uint64_t user_id,
                              vw_quota_record_t *out)
{
    if (!ctx || !user_id || !out) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&ctx->quota_lock);
    uint64_t slot = quota_find_slot(ctx, user_id);
    if (slot != UINT64_MAX) *out = ctx->quotas[slot];
    rwlock_rdunlock(&ctx->quota_lock);

    return (slot == UINT64_MAX) ? VW_ERR_NOT_FOUND : VW_OK;
}

/* ── vw_store_quota_set ───────────────────────────────────────────────────── */

vw_err_t vw_store_quota_set(vw_store_t *ctx, uint64_t user_id,
                              uint64_t quota_bytes)
{
    vw_err_t err;
    uint64_t slot;

    if (!ctx || !user_id) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&ctx->quota_lock);

    slot = quota_find_slot(ctx, user_id);
    if (slot == UINT64_MAX) {
        err = quota_alloc_slot(ctx, &slot);
        if (err != VW_OK) goto unlock;
        ctx->quotas[slot].user_id   = user_id;
        ctx->quotas[slot].used_bytes = 0;
    }
    ctx->quotas[slot].quota_bytes = quota_bytes;
    err = quota_write_slot(ctx, slot);

unlock:
    rwlock_wrunlock(&ctx->quota_lock);
    return err;
}

/* ── vw_store_quota_add ───────────────────────────────────────────────────── */

vw_err_t vw_store_quota_add(vw_store_t *ctx, uint64_t user_id, int64_t delta)
{
    vw_err_t err;
    uint64_t slot;

    if (!ctx || !user_id) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&ctx->quota_lock);

    slot = quota_find_slot(ctx, user_id);
    if (slot == UINT64_MAX) {
        /* No record yet — create a free-unlimited one. */
        err = quota_alloc_slot(ctx, &slot);
        if (err != VW_OK) goto unlock;
        ctx->quotas[slot].user_id    = user_id;
        ctx->quotas[slot].quota_bytes = 0; /* unlimited */
        ctx->quotas[slot].used_bytes  = 0;
    }

    if (delta > 0) {
        uint64_t add = (uint64_t)delta;
        uint64_t limit = ctx->quotas[slot].quota_bytes;
        if (limit != 0 && ctx->quotas[slot].used_bytes + add > limit) {
            err = VW_ERR_QUOTA_EXCEEDED;
            goto unlock;
        }
        ctx->quotas[slot].used_bytes += add;
    } else if (delta < 0) {
        uint64_t sub = (uint64_t)(-delta);
        ctx->quotas[slot].used_bytes =
            (ctx->quotas[slot].used_bytes >= sub) ?
            ctx->quotas[slot].used_bytes - sub : 0;
    }

    err = quota_write_slot(ctx, slot);

unlock:
    rwlock_wrunlock(&ctx->quota_lock);
    return err;
}
