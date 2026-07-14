#include "vw_sync.h"
#include "vw_client_core.h"
#include "vw_cache.h"
#include "../core/vw_fs.h"
#include "../core/vw_proto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/stat.h>
#endif

/* ── Platform helpers ────────────────────────────────────────────────────── */

#ifdef _WIN32
static int is_directory(const char *path) {
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}
static int64_t get_mtime(const char *path) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &d)) return -1;
    ULARGE_INTEGER ft;
    ft.LowPart  = d.ftLastWriteTime.dwLowDateTime;
    ft.HighPart = d.ftLastWriteTime.dwHighDateTime;
    return (int64_t)((ft.QuadPart - 116444736000000000ULL) / 10000000ULL);
}
static uint64_t get_fsize(const char *path) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &d)) return 0;
    ULARGE_INTEGER sz;
    sz.LowPart  = d.nFileSizeLow;
    sz.HighPart = d.nFileSizeHigh;
    return sz.QuadPart;
}
#else
static int is_directory(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}
static int64_t get_mtime(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (int64_t)st.st_mtime : -1;
}
static uint64_t get_fsize(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (uint64_t)st.st_size : 0;
}
#endif

static int under_root(const char *path, const char *root) {
    size_t n = strlen(root);
    while (n > 0 && (root[n-1] == '/' || root[n-1] == '\\')) n--;
    if (strncmp(path, root, n) != 0) return 0;
    return path[n] == '/' || path[n] == '\\' || path[n] == '\0';
}

/* ── Offline queue ────────────────────────────────────────────────────────── */

#define OQ_ACT_UPLOAD   1
#define OQ_ACT_DOWNLOAD 2
#define OQ_ACT_DELETE   3
#define OQ_MAX          65535u

typedef struct {
    char    virtual_path[512];
    char    local_path[512];
    int32_t action;
    int32_t _pad;
    int64_t queued_at;
} oq_entry_t;

_Static_assert(sizeof(oq_entry_t) == 1040, "oq_entry_t size mismatch");

/* ── Action plan ──────────────────────────────────────────────────────────── */

#define ACT_UPLOAD      1
#define ACT_DOWNLOAD    2
#define ACT_DEL_REMOTE  3
#define ACT_DEL_LOCAL   4
#define ACT_CONFLICT    5

typedef struct {
    char     virtual_path[512];
    char     local_path[512];
    char     local_root[512];  /* registered root (security anchor for DEL_LOCAL) */
    int      action;
    uint64_t size;
} action_t;

typedef struct {
    action_t *arr;
    uint32_t  count;
    uint32_t  cap;
} action_list_t;

static vw_err_t action_push(action_list_t *al, int act,
                             const char *vpath, const char *lpath,
                             const char *lroot, uint64_t size) {
    if (al->count >= al->cap) {
        uint32_t nc = al->cap ? al->cap * 2u : 32u;
        action_t *tmp = realloc(al->arr, nc * sizeof(action_t));
        if (!tmp) return VW_ERR_OOM;
        al->arr = tmp; al->cap = nc;
    }
    action_t *a = &al->arr[al->count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->virtual_path, sizeof(a->virtual_path), "%s", vpath);
    snprintf(a->local_path,   sizeof(a->local_path),   "%s", lpath);
    snprintf(a->local_root,   sizeof(a->local_root),   "%s", lroot ? lroot : "");
    a->action = act;
    a->size   = size;
    return VW_OK;
}

/* ── Local file entries ───────────────────────────────────────────────────── */

typedef struct {
    char     local_path[512];
    char     virtual_path[512];
    int64_t  mtime;
    uint64_t size;
} lfile_t;

typedef struct {
    lfile_t *arr;
    uint32_t count;
    uint32_t cap;
    vw_err_t err;
} lfiles_t;

static vw_err_t lfiles_push(lfiles_t *lf, const char *lpath, const char *vpath,
                              int64_t mtime, uint64_t size) {
    if (lf->count >= lf->cap) {
        uint32_t nc = lf->cap ? lf->cap * 2u : 64u;
        lfile_t *tmp = realloc(lf->arr, nc * sizeof(lfile_t));
        if (!tmp) return VW_ERR_OOM;
        lf->arr = tmp; lf->cap = nc;
    }
    lfile_t *e = &lf->arr[lf->count++];
    snprintf(e->local_path,   sizeof(e->local_path),   "%s", lpath);
    snprintf(e->virtual_path, sizeof(e->virtual_path), "%s", vpath);
    e->mtime = mtime;
    e->size  = size;
    return VW_OK;
}

typedef struct {
    lfiles_t   *lf;
    char        dir_local[512];
    char        dir_virtual[512];
} walk_ctx_t;

static vw_err_t walk_recursive(lfiles_t *lf,
                                const char *dir_local, const char *dir_virtual);

static int walk_cb(const char *name, void *ud) {
    walk_ctx_t *wc = ud;
    char lpath[512], vpath[512];
    snprintf(lpath, sizeof(lpath), "%s/%s", wc->dir_local,   name);
    snprintf(vpath, sizeof(vpath), "%s/%s", wc->dir_virtual, name);

    if (is_directory(lpath)) {
        wc->lf->err = walk_recursive(wc->lf, lpath, vpath);
        return (wc->lf->err != VW_OK) ? 1 : 0;
    }
    int64_t  mt = get_mtime(lpath);
    uint64_t sz = get_fsize(lpath);
    wc->lf->err = lfiles_push(wc->lf, lpath, vpath, mt, sz);
    return (wc->lf->err != VW_OK) ? 1 : 0;
}

static vw_err_t walk_recursive(lfiles_t *lf,
                                const char *dir_local, const char *dir_virtual) {
    walk_ctx_t wc;
    memset(&wc, 0, sizeof(wc));
    wc.lf = lf;
    snprintf(wc.dir_local,   sizeof(wc.dir_local),   "%s", dir_local);
    snprintf(wc.dir_virtual, sizeof(wc.dir_virtual), "%s", dir_virtual);
    vw_err_t err = vw_fs_list_dir(dir_local, walk_cb, &wc);
    if (err != VW_OK) return err;
    return lf->err;
}

/* ── Server entry list ────────────────────────────────────────────────────── */

typedef struct {
    char     virtual_path[512];
    uint64_t file_id;
    uint64_t size_bytes;
    int64_t  mtime_unix;
    uint64_t version_id;
    uint8_t  entry_type;
} srv_entry_t;

typedef struct {
    srv_entry_t *arr;
    uint32_t     count;
    uint32_t     cap;
} srv_list_t;

static vw_err_t srv_push(srv_list_t *sl, const char *vpath, const vw_file_entry_t *e) {
    if (sl->count >= sl->cap) {
        uint32_t nc = sl->cap ? sl->cap * 2u : 64u;
        srv_entry_t *tmp = realloc(sl->arr, nc * sizeof(srv_entry_t));
        if (!tmp) return VW_ERR_OOM;
        sl->arr = tmp; sl->cap = nc;
    }
    srv_entry_t *s = &sl->arr[sl->count++];
    snprintf(s->virtual_path, sizeof(s->virtual_path), "%s", vpath);
    s->file_id   = e->file_id;
    s->size_bytes = e->size_bytes;
    s->mtime_unix = e->mtime_unix;
    s->version_id = e->version_id;
    s->entry_type = e->entry_type;
    return VW_OK;
}

/*
 * Client-side BFS using non-recursive FILE_LIST calls.
 * The server returns leaf names per entry; constructing full virtual paths
 * requires iterating one directory level at a time.
 *
 * This avoids the protocol ambiguity where recursive=1 returns leaf names
 * without path context for subdirectory entries.
 */
static vw_err_t srv_collect(vw_client_sess_t *sess,
                              const char *virtual_root, srv_list_t *sl) {
    /* BFS queue of virtual directory paths to visit */
    char **dir_queue = NULL;
    uint32_t q_head = 0, q_tail = 0, q_cap = 0;

    /* Push root */
    dir_queue = malloc(16 * sizeof(char *));
    if (!dir_queue) return VW_ERR_OOM;
    q_cap = 16;
    dir_queue[q_tail] = strdup(virtual_root);
    if (!dir_queue[q_tail]) { free(dir_queue); return VW_ERR_OOM; }
    q_tail++;

    vw_err_t err = VW_OK;
    while (q_head < q_tail) {
        const char *cur = dir_queue[q_head++];
        vw_file_entry_t *entries = NULL;
        uint32_t n = 0;
        vw_err_t lerr = vw_client_file_list(sess, cur, 0, &entries, &n);
        if (lerr == VW_ERR_NOT_FOUND) {
            free((void *)cur);
            continue; /* empty or non-existent dir — skip */
        }
        if (lerr != VW_OK) {
            free((void *)cur);
            err = lerr; break;
        }
        for (uint32_t i = 0; i < n; i++) {
            char vpath[512];
            snprintf(vpath, sizeof(vpath), "%s/%s", cur, entries[i].name);
            if (entries[i].entry_type == VW_ENTRY_DIR) {
                /* Enqueue subdirectory */
                if (q_tail >= q_cap) {
                    uint32_t nc = q_cap * 2u;
                    char **nq = realloc(dir_queue, nc * sizeof(char *));
                    if (!nq) { free(entries); free((void *)cur); err = VW_ERR_OOM; goto done; }
                    dir_queue = nq; q_cap = nc;
                }
                dir_queue[q_tail] = strdup(vpath);
                if (!dir_queue[q_tail]) { free(entries); free((void *)cur); err = VW_ERR_OOM; goto done; }
                q_tail++;
            }
            err = srv_push(sl, vpath, &entries[i]);
            if (err != VW_OK) { free(entries); free((void *)cur); goto done; }
        }
        free(entries);
        free((void *)cur);
    }
done:
    /* Free remaining unvisited queue entries */
    while (q_head < q_tail) free(dir_queue[q_head++]);
    free(dir_queue);
    return err;
}

/* ── Struct vw_sync_ctx ──────────────────────────────────────────────────── */

struct vw_sync_ctx {
    vw_client_sess_t *sess;
    vw_cache_t       *cache;
    pthread_mutex_t   mu;
    char              offline_path[512];
    oq_entry_t       *oq;
    uint32_t          oq_count;
    uint32_t          oq_cap;
    uint64_t          bytes_done;
    uint64_t          bytes_total;
};

/* ── Offline queue helpers ────────────────────────────────────────────────── */

static vw_err_t oq_save(vw_sync_ctx_t *ctx) {
    if (ctx->oq_count == 0) {
        uint8_t dummy = 0;
        return vw_fs_atomic_write(ctx->offline_path, &dummy, 0);
    }
    return vw_fs_atomic_write(ctx->offline_path,
                              ctx->oq,
                              (size_t)ctx->oq_count * sizeof(oq_entry_t));
}

static vw_err_t oq_push(vw_sync_ctx_t *ctx, int action,
                          const char *vpath, const char *lpath) {
    if (ctx->oq_count >= OQ_MAX) {
        /* Drop oldest entry to make room */
        memmove(&ctx->oq[0], &ctx->oq[1],
                (ctx->oq_count - 1u) * sizeof(oq_entry_t));
        ctx->oq_count--;
    }
    if (ctx->oq_count >= ctx->oq_cap) {
        uint32_t nc = ctx->oq_cap ? ctx->oq_cap * 2u : 16u;
        if (nc > OQ_MAX) nc = OQ_MAX;
        oq_entry_t *tmp = realloc(ctx->oq, nc * sizeof(oq_entry_t));
        if (!tmp) return VW_ERR_OOM;
        ctx->oq = tmp; ctx->oq_cap = nc;
    }
    oq_entry_t *e = &ctx->oq[ctx->oq_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->virtual_path, sizeof(e->virtual_path), "%s", vpath);
    snprintf(e->local_path,   sizeof(e->local_path),   "%s", lpath);
    e->action     = (int32_t)action;
    e->queued_at  = (int64_t)time(NULL);
    return oq_save(ctx);
}

static int is_net_err(vw_err_t err) {
    return err == VW_ERR_NET_CONNECT || err == VW_ERR_NET_CLOSED ||
           err == VW_ERR_NET_TIMEOUT || err == VW_ERR_NET_TLS;
}

static void oq_drain(vw_sync_ctx_t *ctx, vw_client_sess_t *sess) {
    uint32_t i = 0;
    while (i < ctx->oq_count) {
        oq_entry_t *e = &ctx->oq[i];
        vw_err_t err = VW_OK;
        switch (e->action) {
        case OQ_ACT_UPLOAD:
            err = vw_client_file_upload(sess, e->virtual_path, e->local_path, NULL, NULL);
            break;
        case OQ_ACT_DOWNLOAD:
            err = vw_client_file_download(sess, e->virtual_path, e->local_path, NULL, NULL);
            break;
        case OQ_ACT_DELETE:
            err = vw_client_file_delete(sess, e->virtual_path);
            break;
        }
        if (is_net_err(err)) break; /* still offline */
        /* On success or permanent error: remove entry */
        memmove(&ctx->oq[i], &ctx->oq[i + 1],
                (ctx->oq_count - i - 1u) * sizeof(oq_entry_t));
        ctx->oq_count--;
    }
    (void)oq_save(ctx);
}

/* ── Progress callback ────────────────────────────────────────────────────── */

typedef struct { vw_sync_ctx_t *ctx; uint64_t prev; } prog_ud_t;

static void sync_prog_cb(uint64_t done, uint64_t total, void *ud) {
    (void)total;
    prog_ud_t *p = ud;
    uint64_t delta = (done >= p->prev) ? (done - p->prev) : 0;
    p->prev = done;
    pthread_mutex_lock(&p->ctx->mu);
    p->ctx->bytes_done += delta;
    pthread_mutex_unlock(&p->ctx->mu);
}

/* ── Convert virtual path → local path ───────────────────────────────────── */

static void vpath_to_local(const char *vpath, const vw_sync_folder_t *f,
                             char *out, size_t outsz) {
    size_t vlen = strlen(f->virtual_root);
    const char *rel = vpath + vlen;
    snprintf(out, outsz, "%s%s", f->local_root, rel);
}

/* ── Conflict copy filename ───────────────────────────────────────────────── */

static void make_conflict_path(const char *local_path, int64_t ts,
                               char *out, size_t outsz) {
    char dir[512] = ".", stem[512] = "", ext[64] = "";
    const char *slash = strrchr(local_path, '/');
#ifdef _WIN32
    {
        const char *bs = strrchr(local_path, '\\');
        if (!slash || (bs && bs > slash)) slash = bs;
    }
#endif
    const char *base = slash ? slash + 1 : local_path;
    if (slash) {
        size_t dl = (size_t)(slash - local_path);
        if (dl >= sizeof(dir)) dl = sizeof(dir) - 1u;
        memcpy(dir, local_path, dl); dir[dl] = '\0';
    }
    const char *dot = strrchr(base, '.');
    if (dot && dot != base) {
        size_t sl = (size_t)(dot - base);
        if (sl >= sizeof(stem)) sl = sizeof(stem) - 1u;
        memcpy(stem, base, sl); stem[sl] = '\0';
        snprintf(ext, sizeof(ext), "%s", dot + 1);
    } else {
        snprintf(stem, sizeof(stem), "%s", base);
    }
    time_t t = (time_t)ts;
    struct tm gm;
#ifdef _WIN32
    gmtime_s(&gm, &t);
#else
    gmtime_r(&t, &gm);
#endif
    char ts_str[20];
    strftime(ts_str, sizeof(ts_str), "%Y%m%dT%H%M%S", &gm);
    if (ext[0])
        snprintf(out, outsz, "%s/%s.conflict.%s.%s", dir, stem, ts_str, ext);
    else
        snprintf(out, outsz, "%s/%s.conflict.%s", dir, stem, ts_str);
}

/* ── Execute one action ───────────────────────────────────────────────────── */

static vw_err_t exec_action(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                              const action_t *a) {
    prog_ud_t prog = { ctx, 0 };
    vw_err_t err = VW_OK;
    int queued = 0;

    switch (a->action) {

    case ACT_UPLOAD:
        err = vw_client_file_upload(sess, a->virtual_path, a->local_path,
                                    sync_prog_cb, &prog);
        if (err == VW_OK) {
            /* Update cache: mtime+size from local stat, state=SYNCED */
            vw_cache_entry_t ce;
            if (vw_cache_get(ctx->cache, a->virtual_path, &ce) == VW_OK) {
                ce.local_mtime = get_mtime(a->local_path);
                ce.local_size  = get_fsize(a->local_path);
                ce.sync_state  = VW_SYNC_SYNCED;
                /* server_version_id will be refreshed on next server diff */
                (void)vw_cache_upsert(ctx->cache, &ce);
            }
        } else if (is_net_err(err)) {
            (void)oq_push(ctx, OQ_ACT_UPLOAD, a->virtual_path, a->local_path);
            queued = 1;
        }
        break;

    case ACT_DOWNLOAD: {
        /* Security: verify local_path is under the registered local_root */
        if (!under_root(a->local_path, a->local_root))
            return VW_ERR_INVALID_ARG; /* server-provided path escapes local_root */
        /* Ensure parent directory exists */
        char parent[512];
        snprintf(parent, sizeof(parent), "%s", a->local_path);
        char *sl = strrchr(parent, '/');
        if (sl) { *sl = '\0'; vw_fs_ensure_dir(parent); }
        err = vw_client_file_download(sess, a->virtual_path, a->local_path,
                                      sync_prog_cb, &prog);
        if (err == VW_OK) {
            vw_cache_entry_t ce;
            if (vw_cache_get(ctx->cache, a->virtual_path, &ce) == VW_OK) {
                ce.local_mtime = get_mtime(a->local_path);
                ce.local_size  = get_fsize(a->local_path);
                ce.sync_state  = VW_SYNC_SYNCED;
                (void)vw_cache_upsert(ctx->cache, &ce);
            }
        } else if (is_net_err(err)) {
            (void)oq_push(ctx, OQ_ACT_DOWNLOAD, a->virtual_path, a->local_path);
            queued = 1;
        }
        break;
    }

    case ACT_DEL_REMOTE:
        err = vw_client_file_delete(sess, a->virtual_path);
        if (err == VW_OK || err == VW_ERR_NOT_FOUND) {
            (void)vw_cache_delete(ctx->cache, a->virtual_path);
            err = VW_OK;
        } else if (is_net_err(err)) {
            (void)oq_push(ctx, OQ_ACT_DELETE, a->virtual_path, a->local_path);
            queued = 1;
        }
        break;

    case ACT_DEL_LOCAL:
        /* Security: verify local_path is under the registered local_root */
        if (!under_root(a->local_path, a->local_root))
            return VW_ERR_INVALID_ARG; /* path traversal attempt */
        err = vw_fs_delete(a->local_path);
        if (err == VW_OK || err == VW_ERR_NOT_FOUND) {
            (void)vw_cache_delete(ctx->cache, a->virtual_path);
            err = VW_OK;
        }
        /* IO errors are non-fatal for local deletes; continue sync */
        break;

    case ACT_CONFLICT: {
        /* Security: verify local_path is under the registered local_root */
        if (!under_root(a->local_path, a->local_root))
            return VW_ERR_INVALID_ARG;
        /*
         * Conflict resolution:
         *   1. Download server version to <stem>.conflict.<ts>.<ext>.
         *   2. Upload the local file as the new server version.
         *   3. Update cache to SYNCED.
         */
        char conflict_path[512];
        make_conflict_path(a->local_path, (int64_t)time(NULL),
                           conflict_path, sizeof(conflict_path));

        /* Ensure parent directory for conflict copy exists */
        char cp_parent[512];
        snprintf(cp_parent, sizeof(cp_parent), "%s", conflict_path);
        char *csl = strrchr(cp_parent, '/');
        if (csl) { *csl = '\0'; vw_fs_ensure_dir(cp_parent); }

        /* Download server version to conflict path */
        err = vw_client_file_download(sess, a->virtual_path, conflict_path,
                                      sync_prog_cb, &prog);
        if (is_net_err(err)) {
            (void)oq_push(ctx, OQ_ACT_UPLOAD, a->virtual_path, a->local_path);
            queued = 1;
            break;
        }
        /* Even if download fails (e.g. not found), still upload local */

        /* Upload local version as new server HEAD */
        prog.prev = 0;
        vw_err_t uerr = vw_client_file_upload(sess, a->virtual_path, a->local_path,
                                               sync_prog_cb, &prog);
        if (uerr == VW_OK) {
            vw_cache_entry_t ce;
            if (vw_cache_get(ctx->cache, a->virtual_path, &ce) == VW_OK) {
                ce.local_mtime = get_mtime(a->local_path);
                ce.local_size  = get_fsize(a->local_path);
                ce.sync_state  = VW_SYNC_SYNCED;
                (void)vw_cache_upsert(ctx->cache, &ce);
            }
        } else if (is_net_err(uerr)) {
            (void)oq_push(ctx, OQ_ACT_UPLOAD, a->virtual_path, a->local_path);
            queued = 1;
        }
        err = uerr;
        break;
    }
    } /* switch */

    (void)queued;
    return err;
}

/* ── Compute action plan (two-pass) ─────────────────────────────────────── */

static vw_err_t compute_actions(vw_sync_ctx_t *ctx,
                                 const vw_sync_folder_t *folder,
                                 const lfiles_t *lfiles,
                                 const srv_list_t *srv,
                                 action_list_t *out) {
    size_t vroot_len = strlen(folder->virtual_root);
    vw_err_t err = VW_OK;

    /* ── Pass 1: Update cache states from local walk ─────────────────── */

    /* Mark files present in local walk as LOCAL_MOD or NEW_LOCAL */
    for (uint32_t i = 0; i < lfiles->count; i++) {
        const lfile_t *lf = &lfiles->arr[i];
        vw_cache_entry_t ce;
        vw_err_t cerr = vw_cache_get(ctx->cache, lf->virtual_path, &ce);
        if (cerr == VW_ERR_NOT_FOUND) {
            memset(&ce, 0, sizeof(ce));
            snprintf(ce.virtual_path, sizeof(ce.virtual_path), "%s", lf->virtual_path);
            snprintf(ce.local_path,   sizeof(ce.local_path),   "%s", lf->local_path);
            ce.sync_state  = VW_SYNC_NEW_LOCAL;
            ce.entry_type  = VW_ENTRY_FILE;
            ce.local_mtime = lf->mtime;
            ce.local_size  = lf->size;
            (void)vw_cache_upsert(ctx->cache, &ce);
        } else if (cerr == VW_OK) {
            if (lf->mtime != ce.local_mtime || lf->size != ce.local_size) {
                if (ce.sync_state == VW_SYNC_SYNCED ||
                    ce.sync_state == VW_SYNC_REMOTE_MOD) {
                    ce.sync_state = VW_SYNC_LOCAL_MOD;
                }
                ce.local_mtime = lf->mtime;
                ce.local_size  = lf->size;
                (void)vw_cache_upsert(ctx->cache, &ce);
            }
        }
    }

    /* Detect LOCAL_DEL: SYNCED cache entries absent from local walk */
    vw_cache_entry_t *all_ce = NULL; uint32_t n_ce = 0;
    (void)vw_cache_list(ctx->cache, -1, &all_ce, &n_ce);

    for (uint32_t i = 0; i < n_ce; i++) {
        vw_cache_entry_t *ce = &all_ce[i];
        if (strncmp(ce->virtual_path, folder->virtual_root, vroot_len) != 0) continue;
        if (ce->entry_type != VW_ENTRY_FILE) continue;
        if (ce->sync_state != VW_SYNC_SYNCED) continue;
        int found = 0;
        for (uint32_t j = 0; j < lfiles->count; j++) {
            if (strcmp(lfiles->arr[j].virtual_path, ce->virtual_path) == 0) {
                found = 1; break;
            }
        }
        if (!found) {
            ce->sync_state = VW_SYNC_LOCAL_DEL;
            (void)vw_cache_upsert(ctx->cache, ce);
        }
    }
    free(all_ce); all_ce = NULL; n_ce = 0;

    /* ── Pass 2: Server cross-reference (if online) ──────────────────── */

    if (srv->arr) {
        for (uint32_t i = 0; i < srv->count; i++) {
            const srv_entry_t *se = &srv->arr[i];
            if (se->entry_type == VW_ENTRY_DIR) continue;
            vw_cache_entry_t ce;
            vw_err_t cerr = vw_cache_get(ctx->cache, se->virtual_path, &ce);
            if (cerr == VW_ERR_NOT_FOUND) {
                /* File exists on server but not in cache: new remote file */
                char lpath[512];
                vpath_to_local(se->virtual_path, folder, lpath, sizeof(lpath));
                memset(&ce, 0, sizeof(ce));
                snprintf(ce.virtual_path, sizeof(ce.virtual_path), "%s", se->virtual_path);
                snprintf(ce.local_path,   sizeof(ce.local_path),   "%s", lpath);
                ce.sync_state        = VW_SYNC_REMOTE_MOD;
                ce.entry_type        = VW_ENTRY_FILE;
                ce.file_id           = se->file_id;
                ce.server_version_id = se->version_id;
                ce.server_mtime      = se->mtime_unix;
                ce.server_size       = se->size_bytes;
                (void)vw_cache_upsert(ctx->cache, &ce);
            } else if (cerr == VW_OK) {
                if (ce.server_version_id != se->version_id) {
                    /* Server has a newer version */
                    if (ce.sync_state == VW_SYNC_LOCAL_MOD ||
                        ce.sync_state == VW_SYNC_NEW_LOCAL) {
                        ce.sync_state = VW_SYNC_CONFLICT;
                    } else {
                        ce.sync_state = VW_SYNC_REMOTE_MOD;
                    }
                    ce.server_version_id = se->version_id;
                    ce.server_mtime      = se->mtime_unix;
                    ce.server_size       = se->size_bytes;
                    ce.file_id           = se->file_id;
                    (void)vw_cache_upsert(ctx->cache, &ce);
                }
                /* version_id matches → no change from server side */
            }
        }

        /* Detect REMOTE_DEL: SYNCED cache entries absent from server list */
        (void)vw_cache_list(ctx->cache, -1, &all_ce, &n_ce);
        for (uint32_t i = 0; i < n_ce; i++) {
            vw_cache_entry_t *ce = &all_ce[i];
            if (strncmp(ce->virtual_path, folder->virtual_root, vroot_len) != 0) continue;
            if (ce->entry_type != VW_ENTRY_FILE) continue;
            if (ce->sync_state != VW_SYNC_SYNCED) continue;
            /* Check if present in server list */
            int on_srv = 0;
            for (uint32_t j = 0; j < srv->count; j++) {
                if (strcmp(srv->arr[j].virtual_path, ce->virtual_path) == 0) {
                    on_srv = 1; break;
                }
            }
            if (!on_srv) {
                /* Security: only mark REMOTE_DEL if local path is under local_root */
                if (!under_root(ce->local_path, folder->local_root)) continue;
                ce->sync_state = VW_SYNC_REMOTE_DEL;
                (void)vw_cache_upsert(ctx->cache, ce);
            }
        }
        free(all_ce); all_ce = NULL; n_ce = 0;
    }

    /* ── Pass 3: Build action list from final cache states ───────────── */

    (void)vw_cache_list(ctx->cache, -1, &all_ce, &n_ce);
    for (uint32_t i = 0; i < n_ce; i++) {
        const vw_cache_entry_t *ce = &all_ce[i];
        if (strncmp(ce->virtual_path, folder->virtual_root, vroot_len) != 0) continue;
        if (ce->entry_type != VW_ENTRY_FILE) continue;
        switch (ce->sync_state) {
        case VW_SYNC_LOCAL_MOD:
        case VW_SYNC_NEW_LOCAL:
            err = action_push(out, ACT_UPLOAD,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, ce->local_size);
            break;
        case VW_SYNC_REMOTE_MOD:
            err = action_push(out, ACT_DOWNLOAD,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, ce->server_size);
            break;
        case VW_SYNC_LOCAL_DEL:
            err = action_push(out, ACT_DEL_REMOTE,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, 0);
            break;
        case VW_SYNC_REMOTE_DEL:
            err = action_push(out, ACT_DEL_LOCAL,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, 0);
            break;
        case VW_SYNC_CONFLICT:
            err = action_push(out, ACT_CONFLICT,
                              ce->virtual_path, ce->local_path,
                              folder->local_root,
                              ce->local_size + ce->server_size);
            break;
        case VW_SYNC_SYNCED:
            break;
        }
        if (err != VW_OK) break;
    }
    free(all_ce);
    return err;
}

/* ── Sync one folder ─────────────────────────────────────────────────────── */

static vw_err_t sync_one_folder(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                                  const vw_sync_folder_t *folder) {
    /* Step 1: Local tree walk */
    lfiles_t lf = {0};
    vw_err_t err = walk_recursive(&lf, folder->local_root, folder->virtual_root);
    if (err == VW_ERR_NOT_FOUND || err == VW_ERR_IO) {
        /* Local root missing or unreadable; treat as empty for this cycle */
        free(lf.arr); lf.arr = NULL; lf.count = 0; lf.cap = 0;
        err = VW_OK;
    } else if (err != VW_OK) {
        free(lf.arr); return err;
    }

    /* Step 2: Server BFS (if online) */
    srv_list_t srv = {0};
    if (sess) {
        err = srv_collect(sess, folder->virtual_root, &srv);
        if (err == VW_ERR_NOT_FOUND) err = VW_OK;
        else if (err != VW_OK && !is_net_err(err)) err = VW_OK; /* non-fatal server errors */
        else if (is_net_err(err)) {
            free(lf.arr); free(srv.arr); return err;
        }
    }

    /* Steps 3 and 4: compute + execute */
    action_list_t actions = {0};
    err = compute_actions(ctx, folder, &lf, &srv, &actions);
    free(lf.arr);
    free(srv.arr);
    if (err != VW_OK) { free(actions.arr); return err; }

    /* Accumulate bytes_total for progress */
    pthread_mutex_lock(&ctx->mu);
    for (uint32_t i = 0; i < actions.count; i++)
        ctx->bytes_total += actions.arr[i].size;
    pthread_mutex_unlock(&ctx->mu);

    /* Execute uploads first */
    for (uint32_t i = 0; i < actions.count; i++) {
        if (actions.arr[i].action == ACT_UPLOAD ||
            actions.arr[i].action == ACT_CONFLICT) {
            (void)exec_action(ctx, sess, &actions.arr[i]);
        }
    }
    /* Then downloads */
    for (uint32_t i = 0; i < actions.count; i++) {
        if (actions.arr[i].action == ACT_DOWNLOAD)
            (void)exec_action(ctx, sess, &actions.arr[i]);
    }
    /* Then deletes */
    for (uint32_t i = 0; i < actions.count; i++) {
        if (actions.arr[i].action == ACT_DEL_REMOTE ||
            actions.arr[i].action == ACT_DEL_LOCAL)
            (void)exec_action(ctx, sess, &actions.arr[i]);
    }

    free(actions.arr);
    return VW_OK;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_sync_open(const vw_sync_cfg_t *cfg, vw_sync_ctx_t **out) {
    if (!cfg || !cfg->cache || !cfg->state_dir || !out) return VW_ERR_INVALID_ARG;

    vw_sync_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->sess  = cfg->sess;
    ctx->cache = cfg->cache;
    if (pthread_mutex_init(&ctx->mu, NULL) != 0) { free(ctx); return VW_ERR_IO; }

    snprintf(ctx->offline_path, sizeof(ctx->offline_path),
             "%s/offline_queue.db", cfg->state_dir);

    /* Load existing offline queue */
    void *oq_data = NULL; size_t oq_len = 0;
    vw_err_t err = vw_fs_read_file(ctx->offline_path, &oq_data, &oq_len);
    if (err == VW_OK && oq_len >= sizeof(oq_entry_t)) {
        uint32_t n = (uint32_t)(oq_len / sizeof(oq_entry_t));
        ctx->oq = malloc(n * sizeof(oq_entry_t));
        if (!ctx->oq) {
            free(oq_data);
            pthread_mutex_destroy(&ctx->mu);
            free(ctx);
            return VW_ERR_OOM;
        }
        memcpy(ctx->oq, oq_data, n * sizeof(oq_entry_t));
        ctx->oq_count = n;
        ctx->oq_cap   = n;
        free(oq_data);
    }

    *out = ctx;
    return VW_OK;
}

void vw_sync_close(vw_sync_ctx_t *ctx) {
    if (!ctx) return;
    pthread_mutex_destroy(&ctx->mu);
    free(ctx->oq);
    free(ctx);
}

void vw_sync_set_session(vw_sync_ctx_t *ctx, vw_client_sess_t *sess) {
    pthread_mutex_lock(&ctx->mu);
    ctx->sess = sess;
    pthread_mutex_unlock(&ctx->mu);
}

vw_err_t vw_sync_run(vw_sync_ctx_t *ctx) {
    if (!ctx) return VW_ERR_INVALID_ARG;

    pthread_mutex_lock(&ctx->mu);
    vw_client_sess_t *sess = ctx->sess;
    ctx->bytes_done  = 0;
    ctx->bytes_total = 0;
    pthread_mutex_unlock(&ctx->mu);

    /* Drain offline queue first when online */
    if (sess) oq_drain(ctx, sess);

    /* Iterate sync folders */
    vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
    vw_err_t err = vw_cache_folder_list(ctx->cache, &folders, &nf);
    if (err != VW_OK) return err;

    vw_err_t net_err = VW_OK;
    for (uint32_t i = 0; i < nf; i++) {
        if (folders[i].paused) continue;
        vw_err_t ferr = sync_one_folder(ctx, sess, &folders[i]);
        if (is_net_err(ferr)) { net_err = ferr; break; }
        /* Local IO errors: continue with remaining folders */
    }

    free(folders);
    return net_err;
}

vw_err_t vw_sync_mark_local_modified(vw_sync_ctx_t *ctx, const char *local_path) {
    if (!ctx || !local_path || !local_path[0]) return VW_ERR_INVALID_ARG;

    vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
    vw_err_t err = vw_cache_folder_list(ctx->cache, &folders, &nf);
    if (err != VW_OK) return err;

    err = VW_OK;
    for (uint32_t i = 0; i < nf; i++) {
        size_t rlen = strlen(folders[i].local_root);
        if (strncmp(local_path, folders[i].local_root, rlen) != 0) continue;
        if (local_path[rlen] != '/' && local_path[rlen] != '\\' &&
            local_path[rlen] != '\0') continue;

        const char *rel = local_path + rlen;
        char vpath[512];
        snprintf(vpath, sizeof(vpath), "%s%s", folders[i].virtual_root, rel);

        vw_cache_entry_t ce;
        vw_err_t cerr = vw_cache_get(ctx->cache, vpath, &ce);
        if (cerr == VW_OK) {
            ce.sync_state = VW_SYNC_LOCAL_MOD;
        } else {
            memset(&ce, 0, sizeof(ce));
            snprintf(ce.virtual_path, sizeof(ce.virtual_path), "%s", vpath);
            snprintf(ce.local_path,   sizeof(ce.local_path),   "%s", local_path);
            ce.sync_state = VW_SYNC_NEW_LOCAL;
            ce.entry_type = VW_ENTRY_FILE;
        }
        err = vw_cache_upsert(ctx->cache, &ce);
        break;
    }

    free(folders);
    return err;
}

uint32_t vw_sync_pending_count(const vw_sync_ctx_t *ctx) {
    return ctx ? ctx->oq_count : 0;
}

void vw_sync_get_progress(const vw_sync_ctx_t *ctx,
                           uint64_t *out_done, uint64_t *out_total) {
    if (!ctx) { if (out_done) *out_done = 0; if (out_total) *out_total = 0; return; }
    vw_sync_ctx_t *nc = (vw_sync_ctx_t *)(uintptr_t)ctx;
    pthread_mutex_lock(&nc->mu);
    if (out_done)  *out_done  = nc->bytes_done;
    if (out_total) *out_total = nc->bytes_total;
    pthread_mutex_unlock(&nc->mu);
}
