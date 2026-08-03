#include "vw_sync.h"
#include "vw_client_core.h"
#include "vw_cache.h"
#include "../core/vw_fs.h"
#include "../core/vw_proto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
   typedef CRITICAL_SECTION vw__mutex_t;
#  define vw__mu_init(m)    (InitializeCriticalSection(m), 0)
#  define vw__mu_lock(m)    EnterCriticalSection(m)
#  define vw__mu_unlock(m)  LeaveCriticalSection(m)
#  define vw__mu_destroy(m) DeleteCriticalSection(m)
#else
#  include <sys/stat.h>
#  include <pthread.h>
   typedef pthread_mutex_t vw__mutex_t;
#  define vw__mu_init(m)    pthread_mutex_init((m), NULL)
#  define vw__mu_lock(m)    pthread_mutex_lock(m)
#  define vw__mu_unlock(m)  pthread_mutex_unlock(m)
#  define vw__mu_destroy(m) pthread_mutex_destroy(m)
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
    int      shared;         /* TASK-106: 1 = target folder is shared (file-id
                                 addressed); 0 = owned (path-addressed), the
                                 pre-TASK-106 behavior, byte-for-byte unchanged */
    uint64_t file_id;        /* TASK-106: target file's own file_id; 0 if it
                                 doesn't exist on the server yet (new upload) */
    uint64_t parent_dir_id;  /* TASK-106: immediate parent folder's file_id —
                                 only meaningful for a shared-folder ACT_UPLOAD
                                 with file_id == 0 (vw_client_file_upload_into_folder) */
} action_t;

typedef struct {
    action_t *arr;
    uint32_t  count;
    uint32_t  cap;
} action_list_t;

static vw_err_t action_push(action_list_t *al, int act,
                             const char *vpath, const char *lpath,
                             const char *lroot, uint64_t size,
                             int shared, uint64_t file_id, uint64_t parent_dir_id) {
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
    a->action        = act;
    a->size          = size;
    a->shared        = shared;
    a->file_id       = file_id;
    a->parent_dir_id = parent_dir_id;
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

/*
 * Append name (never starting with '/') as a child of dir_virtual into out.
 * dir_virtual == "/" is a special case: a naive "dir_virtual/name"
 * concatenation double-slashes there, since "/" already IS the separator —
 * every other dir_virtual value (e.g. "/sub") has no trailing slash, so the
 * normal concatenation is correct as-is.
 */
static void vpath_child(char *out, size_t outsz, const char *dir_virtual, const char *name) {
    int root = (dir_virtual[0] == '/' && dir_virtual[1] == '\0');
    size_t dv = root ? 0 : strlen(dir_virtual);
    size_t nl = strlen(name);
    /* +1 for the '/' separator, +1 for the NUL terminator */
    size_t avail = (outsz > dv + 2u) ? outsz - dv - 2u : 0u;
    if (nl > avail) nl = avail;
    memcpy(out, dir_virtual, dv);
    out[dv] = '/';
    memcpy(out + dv + 1u, name, nl);
    out[dv + 1u + nl] = '\0';
}

static int walk_cb(const char *name, void *ud) {
    walk_ctx_t *wc = ud;
    char lpath[512], vpath[512];
    { size_t _dl = strlen(wc->dir_local),   _nl = strlen(name);
      size_t _ll = _dl + 1 + _nl < sizeof(lpath) - 1 ? _nl : sizeof(lpath) - _dl - 2;
      memcpy(lpath, wc->dir_local,   _dl); lpath[_dl] = '/'; memcpy(lpath + _dl + 1, name, _ll); lpath[_dl + 1 + _ll] = '\0'; }
    vpath_child(vpath, sizeof(vpath), wc->dir_virtual, name);

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
            vpath_child(vpath, sizeof(vpath), cur, entries[i].name);
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

/* ── Directory id map (shared-folder sync, TASK-106) ─────────────────────── */

/*
 * Maps a shared folder's directories (client-local virtual_path → server
 * file_id), populated during srv_collect_by_id's BFS. Needed so compute_actions
 * can resolve the immediate parent folder's file_id for a brand-new local file
 * (vw_client_file_upload_into_folder requires it) — unlike an owned folder,
 * a shared folder has no path the client can address directly, so nothing
 * short of "the id we discovered while listing this directory's parent" can
 * name it.
 */
typedef struct {
    char     virtual_path[512];
    uint64_t dir_id;
} dir_entry_t;

typedef struct {
    dir_entry_t *arr;
    uint32_t     count;
    uint32_t     cap;
} dirmap_t;

static vw_err_t dirmap_push(dirmap_t *dm, const char *vpath, uint64_t dir_id) {
    if (dm->count >= dm->cap) {
        uint32_t nc = dm->cap ? dm->cap * 2u : 16u;
        dir_entry_t *tmp = realloc(dm->arr, nc * sizeof(dir_entry_t));
        if (!tmp) return VW_ERR_OOM;
        dm->arr = tmp; dm->cap = nc;
    }
    dir_entry_t *e = &dm->arr[dm->count++];
    snprintf(e->virtual_path, sizeof(e->virtual_path), "%s", vpath);
    e->dir_id = dir_id;
    return VW_OK;
}

/* Returns 0 if vpath is not a known directory (caller treats as unresolvable). */
static uint64_t dirmap_lookup(const dirmap_t *dm, const char *vpath) {
    if (!dm) return 0;
    for (uint32_t i = 0; i < dm->count; i++)
        if (strcmp(dm->arr[i].virtual_path, vpath) == 0) return dm->arr[i].dir_id;
    return 0;
}

/*
 * TASK-111: ceiling on the total number of directory+file entries observed
 * across a whole shared-folder BFS walk (summed over however many
 * FILE_LIST_BY_ID calls it takes) — mirrors the per-call 65535-entry cap
 * already applied server-side (vw_file_handlers.c), this time against the
 * *cumulative* walk size, since a share's owner controls that tree's shape,
 * not the grantee whose client has to walk it every cycle.
 */
#define VW_SHARED_TREE_MAX_ITEMS_DEFAULT 65535u

static uint32_t shared_tree_max_items(void) {
#ifdef VW_SYNC_TEST_HOOKS
    /* Overridable via VW_SHARED_TREE_MAX_ITEMS, but only in test binaries
     * that opt into VW_SYNC_TEST_HOOKS (CQR.08 finding: gating this the
     * same way as the BFS test hook below avoids a stray/forgotten env var
     * silently defeating this protection for a real user — production
     * binaries never read this env var at all, not even if it happens to
     * be set). strtoul, not atol: getenv() input is untrusted and atol's
     * behavior on an out-of-range value is undefined, not just clamped. */
    const char *env = getenv("VW_SHARED_TREE_MAX_ITEMS");
    if (env && env[0]) {
        char *endp = NULL;
        unsigned long v = strtoul(env, &endp, 10);
        if (endp != env && *endp == '\0' && v > 0 && v <= UINT32_MAX)
            return (uint32_t)v;
    }
#endif
    return VW_SHARED_TREE_MAX_ITEMS_DEFAULT;
}

#ifdef VW_SYNC_TEST_HOOKS
/*
 * Test-only instrumentation (TASK-111 regression test for the shared-folder
 * BFS TOCTOU race). Compiled in only for test binaries that define
 * VW_SYNC_TEST_HOOKS; absent from every production target. When set,
 * invoked synchronously immediately before srv_collect_by_id lists a
 * directory, letting a test deterministically delete/revoke access to that
 * exact directory in the window the real race would occur in, instead of
 * racing real threads against real network timing.
 */
void (*vw_sync_test_before_list_dir)(const char *vpath, uint64_t dir_id) = NULL;
#endif

/*
 * Id-addressed counterpart of srv_collect for a shared folder: BFS via
 * FILE_LIST's dir_file_id extension instead of path-based FILE_LIST, since a
 * grantee's own FILE_LIST can never resolve into someone else's tree by path
 * (docs/PROTOCOL.md §7.2). virtual_root/dir_root here name the shared
 * folder's client-local naming root and its server-side file_id.
 *
 * TASK-111: only a NOT_FOUND/PERMISSION on the ROOT id is treated as a
 * revocation signal by the caller. A subdirectory discovered earlier in
 * this same walk can legitimately vanish between discovery and its own
 * listing call (the owner deletes it mid-cycle) — that is a routine race,
 * not a revocation (permission can only be equal-or-higher moving down an
 * inherited subtree per vw_share_resolve_permission, so a *valid* share
 * never has a subtree selectively cut off; a NOT_FOUND/PERMISSION below the
 * root is therefore always this race, never a real access change worth
 * pausing the whole folder over). Such a level is skipped — same as
 * srv_collect already does for an owned folder's missing directory — rather
 * than aborting the whole walk.
 */
static vw_err_t srv_collect_by_id(vw_client_sess_t *sess,
                                   const char *virtual_root, uint64_t dir_root,
                                   srv_list_t *sl, dirmap_t *dm) {
    typedef struct { char vpath[512]; uint64_t dir_id; } q_item_t;
    q_item_t *queue = NULL;
    uint32_t q_head = 0, q_tail = 0, q_cap = 16;
    uint32_t total_items = 0;
    const uint32_t max_items = shared_tree_max_items();

    queue = malloc(q_cap * sizeof(q_item_t));
    if (!queue) return VW_ERR_OOM;
    snprintf(queue[q_tail].vpath, sizeof(queue[q_tail].vpath), "%s", virtual_root);
    queue[q_tail].dir_id = dir_root;
    q_tail++;

    vw_err_t err = dirmap_push(dm, virtual_root, dir_root);
    if (err != VW_OK) { free(queue); return err; }

    while (q_head < q_tail) {
        q_item_t cur = queue[q_head++];
#ifdef VW_SYNC_TEST_HOOKS
        if (vw_sync_test_before_list_dir)
            vw_sync_test_before_list_dir(cur.vpath, cur.dir_id);
#endif
        vw_file_entry_t *entries = NULL;
        uint32_t n = 0;
        vw_err_t lerr = vw_client_file_list_by_id(sess, cur.dir_id, 0, &entries, &n);
        if (lerr == VW_ERR_NOT_FOUND || lerr == VW_ERR_PERMISSION) {
            if (cur.dir_id == dir_root) {
                /* Root-level failure: the share itself is gone or revoked. */
                err = lerr; break;
            }
            /* A subdirectory raced out from under us this cycle — benign,
             * skip it and keep walking the rest of the tree. */
            continue;
        }
        if (lerr != VW_OK) { err = lerr; break; }

        if (total_items + n > max_items) {
            free(entries);
            err = VW_ERR_SYNC_TREE_TOO_LARGE;
            break;
        }
        total_items += n;

        for (uint32_t i = 0; i < n; i++) {
            char vpath[512];
            vpath_child(vpath, sizeof(vpath), cur.vpath, entries[i].name);
            if (entries[i].entry_type == VW_ENTRY_DIR) {
                err = dirmap_push(dm, vpath, entries[i].file_id);
                if (err != VW_OK) { free(entries); goto done; }
                if (q_tail >= q_cap) {
                    uint32_t nc = q_cap * 2u;
                    q_item_t *nq = realloc(queue, nc * sizeof(q_item_t));
                    if (!nq) { free(entries); err = VW_ERR_OOM; goto done; }
                    queue = nq; q_cap = nc;
                }
                snprintf(queue[q_tail].vpath, sizeof(queue[q_tail].vpath), "%s", vpath);
                queue[q_tail].dir_id = entries[i].file_id;
                q_tail++;
            } else {
                err = srv_push(sl, vpath, &entries[i]);
                if (err != VW_OK) { free(entries); goto done; }
            }
        }
        free(entries);
    }
done:
    free(queue);
    return err;
}

/* ── Struct vw_sync_ctx ──────────────────────────────────────────────────── */

struct vw_sync_ctx {
    vw_client_sess_t *sess;
    vw_cache_t       *cache;
    vw__mutex_t       mu;
    char              offline_path[512];
    oq_entry_t       *oq;
    uint32_t          oq_count;
    uint32_t          oq_cap;
    uint64_t          bytes_done;
    uint64_t          bytes_total;
    uint32_t          action_errors; /* per-cycle count of non-network action failures */
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

/*
 * Record a non-network action failure (e.g. a quota-rejected upload) so it
 * reaches the daemon's status error count (TASK-112). Network errors are
 * deliberately excluded — those are already handled via the offline queue
 * (or, for shared-folder actions, transparent per-cycle retry) and are not
 * counted here.
 */
static void note_action_error(vw_sync_ctx_t *ctx) {
    vw__mu_lock(&ctx->mu);
    ctx->action_errors++;
    vw__mu_unlock(&ctx->mu);
}

/* Defined below, near exec_action(); forward-declared here for oq_drain(). */
static void update_cache_after_upload(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                                        const char *virtual_path, const char *local_path,
                                        uint64_t known_file_id);

static void oq_drain(vw_sync_ctx_t *ctx, vw_client_sess_t *sess) {
    uint32_t i = 0;
    while (i < ctx->oq_count) {
        oq_entry_t *e = &ctx->oq[i];
        vw_err_t err = VW_OK;
        switch (e->action) {
        case OQ_ACT_UPLOAD:
            err = vw_client_file_upload(sess, e->virtual_path, e->local_path, NULL, NULL);
            if (err == VW_OK)
                update_cache_after_upload(ctx, sess, e->virtual_path, e->local_path, 0);
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
    vw__mu_lock(&p->ctx->mu);
    p->ctx->bytes_done += delta;
    vw__mu_unlock(&p->ctx->mu);
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

/*
 * After a successful upload, populate the cache entry's server-side fields
 * (file_id, server_version_id, server_mtime, server_size) from a fresh
 * FILE_STAT rather than leaving them at their pre-upload values.
 *
 * Bug found via TASK-096 (GUI sharing): vw_client_file_upload has no way to
 * return the file_id/version_id FILE_COMMIT_ACK just handed back, so every
 * call site here previously left ce.file_id at 0 after a file's first-ever
 * upload — the comment "server_version_id will be refreshed on next server
 * diff" assumed a later sync cycle's Pass 2 reconciliation would catch it,
 * but that only fires when ce.server_version_id (still 0) doesn't match the
 * server's version — which is true immediately after upload too, so in
 * practice it did eventually self-heal on the *next* sync cycle, but left a
 * real window where a freshly synced file's cache entry claims
 * sync_state=SYNCED with file_id=0. Nothing could have shared that file by
 * file_id in that window. Fixed by resolving it immediately instead of
 * waiting.
 */
/*
 * known_file_id (TASK-106): 0 for an owned-folder upload (unchanged
 * behavior — resolve via path-based FILE_STAT); nonzero for a shared-folder
 * upload, where a path-based FILE_STAT can never resolve (the caller
 * doesn't own that path) — the file_id learned from the upload itself
 * (either already known, for an update, or just returned by
 * vw_client_file_upload_into_folder for a create) is used instead.
 */
static void update_cache_after_upload(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                                        const char *virtual_path, const char *local_path,
                                        uint64_t known_file_id) {
    vw_cache_entry_t ce;
    if (vw_cache_get(ctx->cache, virtual_path, &ce) != VW_OK) return;

    ce.local_mtime = get_mtime(local_path);
    ce.local_size  = get_fsize(local_path);
    ce.sync_state  = VW_SYNC_SYNCED;

    /* The caller already knows the real file_id when known_file_id != 0
     * (either it was already known, for an update, or vw_client_file_
     * upload_into_folder just returned it for a create) — set it
     * unconditionally rather than only on FILE_STAT success, so a
     * transient stat failure right after a successful create-upload can't
     * leave ce.file_id at 0 (CQR.08 finding during TASK-106 review). */
    if (known_file_id != 0) ce.file_id = known_file_id;

    vw_file_entry_t stat_entry;
    vw_err_t serr = known_file_id != 0
        ? vw_client_file_stat_by_id(sess, known_file_id, &stat_entry)
        : vw_client_file_stat(sess, virtual_path, &stat_entry);
    if (serr == VW_OK) {
        ce.file_id           = stat_entry.file_id;
        ce.server_version_id = stat_entry.version_id;
        ce.server_mtime      = stat_entry.mtime_unix;
        ce.server_size       = stat_entry.size_bytes;
    }

    (void)vw_cache_upsert(ctx->cache, &ce);
}

/* ── Execute one action ───────────────────────────────────────────────────── */

static vw_err_t exec_action(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                              const action_t *a) {
    prog_ud_t prog = { ctx, 0 };
    vw_err_t err = VW_OK;
    int queued = 0;

    switch (a->action) {

    case ACT_UPLOAD:
        if (a->shared) {
            /* TASK-106: file-id-addressed upload for a shared folder. The
             * offline queue is deliberately NOT used here (it's path-based
             * only, by design) — a network error just fails this cycle and
             * is retried on the next one. */
            if (a->file_id != 0) {
                err = vw_client_file_upload_to_id(sess, a->file_id, a->local_path,
                                                  sync_prog_cb, &prog);
                if (err == VW_OK)
                    update_cache_after_upload(ctx, sess, a->virtual_path, a->local_path,
                                               a->file_id);
                else if (!is_net_err(err))
                    note_action_error(ctx);
            } else if (a->parent_dir_id != 0) {
                const char *sl = strrchr(a->virtual_path, '/');
                const char *leaf = sl ? sl + 1 : a->virtual_path;
                uint64_t new_id = 0, new_ver = 0;
                err = vw_client_file_upload_into_folder(sess, a->parent_dir_id, leaf,
                                                        a->local_path, sync_prog_cb, &prog,
                                                        &new_id, &new_ver);
                if (err == VW_OK)
                    update_cache_after_upload(ctx, sess, a->virtual_path, a->local_path, new_id);
                else if (!is_net_err(err))
                    note_action_error(ctx);
            } else {
                /* Parent directory unresolvable this cycle (e.g. a brand-new
                 * local subdirectory with no server-side counterpart yet) —
                 * not a network error, but not necessarily self-healing
                 * either: nothing in this sync engine auto-creates a
                 * missing remote directory for a shared folder (see
                 * TASK-113), so this can in practice recur every cycle
                 * indefinitely. Count it so it's at least visible via
                 * status rather than a second permanently-silent gap of
                 * the same kind TASK-112 exists to close. */
                err = VW_ERR_NOT_FOUND;
                note_action_error(ctx);
            }
        } else {
            err = vw_client_file_upload(sess, a->virtual_path, a->local_path,
                                        sync_prog_cb, &prog);
            if (err == VW_OK) {
                update_cache_after_upload(ctx, sess, a->virtual_path, a->local_path, 0);
            } else if (is_net_err(err)) {
                (void)oq_push(ctx, OQ_ACT_UPLOAD, a->virtual_path, a->local_path);
                queued = 1;
            } else {
                note_action_error(ctx);
            }
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
        err = a->shared
            ? vw_client_file_download_by_id(sess, a->file_id, a->local_path,
                                            sync_prog_cb, &prog)
            : vw_client_file_download(sess, a->virtual_path, a->local_path,
                                      sync_prog_cb, &prog);
        if (err == VW_OK) {
            vw_cache_entry_t ce;
            if (vw_cache_get(ctx->cache, a->virtual_path, &ce) == VW_OK) {
                ce.local_mtime = get_mtime(a->local_path);
                ce.local_size  = get_fsize(a->local_path);
                ce.sync_state  = VW_SYNC_SYNCED;
                (void)vw_cache_upsert(ctx->cache, &ce);
            }
        } else if (is_net_err(err) && !a->shared) {
            (void)oq_push(ctx, OQ_ACT_DOWNLOAD, a->virtual_path, a->local_path);
            queued = 1;
        } else if (!is_net_err(err)) {
            note_action_error(ctx);
        }
        break;
    }

    case ACT_DEL_REMOTE:
        err = a->shared
            ? vw_client_file_delete_by_id(sess, a->file_id)
            : vw_client_file_delete(sess, a->virtual_path);
        if (err == VW_OK || err == VW_ERR_NOT_FOUND) {
            (void)vw_cache_delete(ctx->cache, a->virtual_path);
            err = VW_OK;
        } else if (is_net_err(err) && !a->shared) {
            (void)oq_push(ctx, OQ_ACT_DELETE, a->virtual_path, a->local_path);
            queued = 1;
        } else if (!is_net_err(err)) {
            note_action_error(ctx);
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
        } else {
            /* Local IO errors are non-fatal for the sync cycle (it
             * continues with remaining actions) but are still counted —
             * a persistently undeletable local file is worth surfacing. */
            note_action_error(ctx);
        }
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
        err = a->shared
            ? vw_client_file_download_by_id(sess, a->file_id, conflict_path,
                                            sync_prog_cb, &prog)
            : vw_client_file_download(sess, a->virtual_path, conflict_path,
                                      sync_prog_cb, &prog);
        if (is_net_err(err) && !a->shared) {
            (void)oq_push(ctx, OQ_ACT_UPLOAD, a->virtual_path, a->local_path);
            queued = 1;
            break;
        }
        /* Even if download fails (e.g. not found), still upload local */

        /* Upload local version as new server HEAD. A conflict always means
         * the file already exists server-side (file_id known), so a shared
         * folder always takes the update-by-id path here — never a create. */
        prog.prev = 0;
        vw_err_t uerr = a->shared
            ? vw_client_file_upload_to_id(sess, a->file_id, a->local_path,
                                          sync_prog_cb, &prog)
            : vw_client_file_upload(sess, a->virtual_path, a->local_path,
                                    sync_prog_cb, &prog);
        if (uerr == VW_OK) {
            update_cache_after_upload(ctx, sess, a->virtual_path, a->local_path,
                                       a->shared ? a->file_id : 0);
        } else if (is_net_err(uerr) && !a->shared) {
            (void)oq_push(ctx, OQ_ACT_UPLOAD, a->virtual_path, a->local_path);
            queued = 1;
        } else if (!is_net_err(uerr)) {
            note_action_error(ctx);
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
                                 const dirmap_t *dm,
                                 action_list_t *out) {
    size_t vroot_len = strlen(folder->virtual_root);
    int shared = folder->remote_dir_id != 0;
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
                /* TASK-109: FILE_LIST_RESP now carries a real version_id
                 * per entry (a trailing parallel array — see
                 * docs/PROTOCOL.md §7.2 version 16), the same
                 * current_version_id field FILE_STAT_RESP reports, so
                 * ce.server_version_id (set from either message) and
                 * se->version_id are directly comparable again. Comparing
                 * it alongside mtime_unix/size_bytes is defense-in-depth
                 * against a version bump that happens to leave both mtime
                 * and size unchanged (e.g. a restore to byte-identical
                 * content). Before this fix, se->version_id was always 0
                 * while ce.server_version_id could be real (populated by
                 * update_cache_after_upload's FILE_STAT calls) — comparing
                 * across those two provenances produced a deterministic
                 * false "changed" on every cycle after any upload (an
                 * independent review caught this during TASK-106's
                 * closeout); that's why version_id was dropped from this
                 * comparison for a while — now that both sides come from
                 * the same source, it's safe to compare again. */
                if (ce.server_version_id != se->version_id ||
                    ce.server_mtime      != se->mtime_unix ||
                    ce.server_size       != se->size_bytes) {
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
                /* else: no change from server side */
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
        case VW_SYNC_NEW_LOCAL: {
            uint64_t parent_dir_id = 0;
            if (shared && ce->file_id == 0) {
                /* New file inside a shared folder: resolve its immediate
                 * parent's file_id from the dirmap built during this
                 * cycle's BFS. dirname(ce->virtual_path) — strip the leaf. */
                char parent_vpath[512];
                snprintf(parent_vpath, sizeof(parent_vpath), "%s", ce->virtual_path);
                char *psl = strrchr(parent_vpath, '/');
                if (psl) *psl = '\0';
                if (parent_vpath[0] == '\0')
                    snprintf(parent_vpath, sizeof(parent_vpath), "/");
                parent_dir_id = dirmap_lookup(dm, parent_vpath);
            }
            err = action_push(out, ACT_UPLOAD,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, ce->local_size,
                              shared, ce->file_id, parent_dir_id);
            break;
        }
        case VW_SYNC_REMOTE_MOD:
            err = action_push(out, ACT_DOWNLOAD,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, ce->server_size,
                              shared, ce->file_id, 0);
            break;
        case VW_SYNC_LOCAL_DEL:
            err = action_push(out, ACT_DEL_REMOTE,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, 0,
                              shared, ce->file_id, 0);
            break;
        case VW_SYNC_REMOTE_DEL:
            err = action_push(out, ACT_DEL_LOCAL,
                              ce->virtual_path, ce->local_path,
                              folder->local_root, 0,
                              shared, ce->file_id, 0);
            break;
        case VW_SYNC_CONFLICT:
            err = action_push(out, ACT_CONFLICT,
                              ce->virtual_path, ce->local_path,
                              folder->local_root,
                              ce->local_size + ce->server_size,
                              shared, ce->file_id, 0);
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
    int shared = folder->remote_dir_id != 0;

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
    dirmap_t   dm  = {0};
    if (sess) {
        if (shared) {
            err = srv_collect_by_id(sess, folder->virtual_root, folder->remote_dir_id,
                                     &srv, &dm);
            if (err == VW_ERR_NOT_FOUND || err == VW_ERR_PERMISSION) {
                /* TASK-106 live revocation: the share no longer grants this
                 * client any access at the root (TASK-111: srv_collect_by_id
                 * now only surfaces this for a root-id failure — a same-
                 * cycle subdirectory race no longer reaches here). Auto-
                 * pause rather than retry forever — the folder stays
                 * visible/inspectable but stops advancing. */
                (void)vw_cache_folder_set_pause_reason(ctx->cache, folder->local_root,
                                                       VW_PAUSE_REASON_REVOKED);
                free(lf.arr); free(srv.arr); free(dm.arr);
                return VW_OK;
            }
            if (err == VW_ERR_SYNC_TREE_TOO_LARGE) {
                /* TASK-111: the shared tree exceeds this client's per-cycle
                 * resource ceiling. Auto-pause with a distinct reason — this
                 * is not a revocation and must not be reported as one. */
                (void)vw_cache_folder_set_pause_reason(ctx->cache, folder->local_root,
                                                       VW_PAUSE_REASON_TREE_TOO_LARGE);
                free(lf.arr); free(srv.arr); free(dm.arr);
                return VW_OK;
            }
            if (err != VW_OK && !is_net_err(err)) err = VW_OK;
            else if (is_net_err(err)) {
                free(lf.arr); free(srv.arr); free(dm.arr); return err;
            }
        } else {
            err = srv_collect(sess, folder->virtual_root, &srv);
            if (err == VW_ERR_NOT_FOUND) err = VW_OK;
            else if (err != VW_OK && !is_net_err(err)) err = VW_OK; /* non-fatal server errors */
            else if (is_net_err(err)) {
                free(lf.arr); free(srv.arr); return err;
            }
        }
    }

    /* Steps 3 and 4: compute + execute */
    action_list_t actions = {0};
    err = compute_actions(ctx, folder, &lf, &srv, &dm, &actions);
    free(lf.arr);
    free(srv.arr);
    free(dm.arr);
    if (err != VW_OK) { free(actions.arr); return err; }

    /* Accumulate bytes_total for progress */
    vw__mu_lock(&ctx->mu);
    for (uint32_t i = 0; i < actions.count; i++)
        ctx->bytes_total += actions.arr[i].size;
    vw__mu_unlock(&ctx->mu);

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
    if (vw__mu_init(&ctx->mu) != 0) { free(ctx); return VW_ERR_IO; }

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
            vw__mu_destroy(&ctx->mu);
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
    vw__mu_destroy(&ctx->mu);
    free(ctx->oq);
    free(ctx);
}

void vw_sync_set_session(vw_sync_ctx_t *ctx, vw_client_sess_t *sess) {
    vw__mu_lock(&ctx->mu);
    ctx->sess = sess;
    vw__mu_unlock(&ctx->mu);
}

vw_err_t vw_sync_run(vw_sync_ctx_t *ctx) {
    if (!ctx) return VW_ERR_INVALID_ARG;

    vw__mu_lock(&ctx->mu);
    vw_client_sess_t *sess = ctx->sess;
    ctx->bytes_done    = 0;
    ctx->bytes_total   = 0;
    ctx->action_errors = 0;
    vw__mu_unlock(&ctx->mu);

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
        /* rel already carries the separator ('/' or '\\') from local_path;
         * virtual_root == "/" would otherwise double it up ("//name"). */
        if (folders[i].virtual_root[0] == '/' && folders[i].virtual_root[1] == '\0')
            snprintf(vpath, sizeof(vpath), "%s", rel);
        else
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
    vw__mu_lock(&nc->mu);
    if (out_done)  *out_done  = nc->bytes_done;
    if (out_total) *out_total = nc->bytes_total;
    vw__mu_unlock(&nc->mu);
}

uint32_t vw_sync_action_error_count(const vw_sync_ctx_t *ctx) {
    if (!ctx) return 0;
    vw_sync_ctx_t *nc = (vw_sync_ctx_t *)(uintptr_t)ctx;
    vw__mu_lock(&nc->mu);
    uint32_t n = nc->action_errors;
    vw__mu_unlock(&nc->mu);
    return n;
}
