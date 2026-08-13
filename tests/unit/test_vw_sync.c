/*
 * test_vw_sync.c — unit tests for the client sync engine (TASK-114).
 *
 * vw_sync.c had zero unit tests before this — coverage came entirely from
 * integration binaries (tests/integration/test_shared_sync*.c) that need a
 * live server round-trip to exercise even a single branch of
 * compute_actions()/exec_action()/resolve_or_create_dir(). This file adds
 * fast, server-free coverage of the pure/near-pure logic in that module:
 *
 *   - under_root(): the path-traversal guard exec_action() checks before
 *     any ACT_DOWNLOAD/ACT_DEL_LOCAL/ACT_CONFLICT touches the filesystem
 *     (§SEC.07 in vw_sync.h's module header).
 *   - compute_actions(): the three-pass local/server state-classification
 *     logic, exercised for an owned folder (all six action kinds in one
 *     realistic multi-file cycle) and for a shared folder whose new-file
 *     parent directory is already known via dirmap (the fast path through
 *     resolve_or_create_dir that never needs a network call).
 *   - resolve_or_create_dir(): the recursion/memoization structure —
 *     offline (root never seeded), already-resolved (found immediately via
 *     dirmap), already-memoized-as-unresolvable (sentinel short-circuit),
 *     and the root-path-normalization fallback branch — all chosen
 *     specifically so no scenario here ever reaches an actual
 *     vw_client_file_mkdir() call (sess = NULL throughout). The real
 *     mkdir-outcome classification (success / VW_ERR_PERMISSION /
 *     VW_ERR_ALREADY_EXISTS / network error) still requires a live server
 *     and remains covered by tests/integration/test_shared_sync_mkdir.c —
 *     see TASK-114's acceptance criteria, which scopes it exactly this way.
 *   - exec_action()'s ACT_DEL_LOCAL branch: the one exec_action path that
 *     never touches the network (sess = NULL is safe), letting the
 *     under_root() guard be proven end-to-end ("a rejected path never
 *     reaches vw_fs_delete") rather than just as an isolated function call.
 *
 * These are reached via vw_sync_internal.h, a test-only header that gives
 * external linkage to functions that are `static` in every production
 * build (VW_SYNC_TESTABLE, gated on VW_SYNC_TEST_HOOKS — see that header
 * and the CMake target below). vw_sync.h, the real public API, is
 * untouched.
 */

#include "vw_test.h"
#include "vw_sync.h"
#include "vw_sync_internal.h"
#include "vw_cache.h"
#include "vw_fs.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <dirent.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/*
 * path_join: routing dir+suffix concatenation through a helper taking
 * plain `const char *` parameters (rather than inline snprintf against a
 * known-fixed-size array local) avoids a GCC -Wformat-truncation false
 * positive — GCC can bound a known fixed-size array's max length and warn
 * that appending a literal suffix to it "may" overflow the destination,
 * but has no such static bound on a plain pointer parameter. Same pattern
 * already used in tests/integration/test_shared_sync*.c.
 */
static void path_join(char *out, size_t sz, const char *dir, const char *name) {
    snprintf(out, sz, "%s/%s", dir, name);
}

/* Same rationale as path_join — appends `suffix` directly (no separator)
 * via plain pointer parameters to dodge the same false-positive warning. */
static void suffix_str(char *out, size_t sz, const char *base, const char *suffix) {
    snprintf(out, sz, "%s%s", base, suffix);
}

/* ── Temp-dir helpers (same pattern as test_vw_share.c / test_vw_gc.c) ───── */

static void make_tmpdir(char *out, size_t sz, const char *label) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_synctest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_synctest_%u_%s", VW_PID(), label);
    mkdir(out, 0700);
#endif
}

static void rm_rf(const char *dir) {
#ifdef _WIN32
    char pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            char child[MAX_PATH];
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) rm_rf(child);
            else DeleteFileA(child);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char child[512];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode)) rm_rf(child);
        else remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

/* ── Fixture: a real vw_cache_t + vw_sync_ctx_t, no session ──────────────── */

typedef struct {
    char           tmpdir[512];
    vw_cache_t    *cache;
    vw_sync_ctx_t *ctx;
} sync_stack_t;

static void stack_open(sync_stack_t *s, const char *label) {
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_cache_open(s->tmpdir, &s->cache));
    vw_sync_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sess      = NULL; /* offline — every scenario in this file is chosen
                            * specifically so no code path here needs a real
                            * network session. */
    cfg.cache     = s->cache;
    cfg.state_dir = s->tmpdir;
    VW_ASSERT_OK(vw_sync_open(&cfg, &s->ctx));
}

static void stack_close(sync_stack_t *s) {
    vw_sync_close(s->ctx);
    vw_cache_close(s->cache);
    rm_rf(s->tmpdir);
}

/* Seed a SYNCED cache entry with the given local/server metadata. */
static void seed_synced(vw_cache_t *cache, const char *vpath, const char *lpath,
                         int64_t local_mtime, uint64_t local_size,
                         uint64_t server_version_id, int64_t server_mtime,
                         uint64_t server_size, uint64_t file_id) {
    vw_cache_entry_t ce;
    memset(&ce, 0, sizeof(ce));
    snprintf(ce.virtual_path, sizeof(ce.virtual_path), "%s", vpath);
    snprintf(ce.local_path,   sizeof(ce.local_path),   "%s", lpath);
    ce.entry_type        = VW_ENTRY_FILE;
    ce.sync_state        = VW_SYNC_SYNCED;
    ce.local_mtime       = local_mtime;
    ce.local_size        = local_size;
    ce.server_version_id = server_version_id;
    ce.server_mtime      = server_mtime;
    ce.server_size       = server_size;
    ce.file_id           = file_id;
    VW_ASSERT_OK(vw_cache_upsert(cache, &ce));
}

/* Find an action for `vpath` in an action_list_t; returns NULL if absent. */
static const action_t *find_action(const action_list_t *al, const char *vpath) {
    for (uint32_t i = 0; i < al->count; i++)
        if (strcmp(al->arr[i].virtual_path, vpath) == 0) return &al->arr[i];
    return NULL;
}

static vw_file_entry_t make_srv_entry(const char *name, uint64_t file_id,
                                       uint64_t size_bytes, int64_t mtime_unix,
                                       uint64_t version_id, uint8_t entry_type) {
    vw_file_entry_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.name, sizeof(e.name), "%s", name);
    e.file_id     = file_id;
    e.size_bytes  = size_bytes;
    e.mtime_unix  = mtime_unix;
    e.version_id  = version_id;
    e.entry_type  = entry_type;
    return e;
}

VW_TEST_SUITE("vw_sync")

/* ══════════════════════════════════════════════════════════════════════
 * under_root() — path-traversal guard
 * ══════════════════════════════════════════════════════════════════════ */
VW_TEST_CASE("under_root: child path is under root") {
    VW_ASSERT(under_root("/a/b/file.txt", "/a/b"));
}

VW_TEST_CASE("under_root: exact match counts as under root") {
    VW_ASSERT(under_root("/a/b", "/a/b"));
}

VW_TEST_CASE("under_root: sibling-directory prefix collision rejected") {
    /* "/a/bad" shares the string prefix "/a/b" with root "/a/b" but is not
     * a subdirectory of it — the boundary-character check must catch this. */
    VW_ASSERT(!under_root("/a/bad/file.txt", "/a/b"));
}

VW_TEST_CASE("under_root: unrelated path rejected") {
    VW_ASSERT(!under_root("/other/file.txt", "/a/b"));
}

VW_TEST_CASE("under_root: trailing slash on path accepted") {
    VW_ASSERT(under_root("/a/b/", "/a/b"));
}

VW_TEST_CASE("under_root: trailing slash on root is normalized away") {
    VW_ASSERT(under_root("/a/b/file.txt", "/a/b/"));
}

VW_TEST_CASE("under_root: backslash separator recognized (Windows paths)") {
    VW_ASSERT(under_root("C:\\a\\b\\file.txt", "C:\\a\\b"));
}

/* ══════════════════════════════════════════════════════════════════════
 * exec_action() ACT_DEL_LOCAL — proves the under_root() rejection happens
 * BEFORE vw_fs_delete is ever called, not just that under_root() itself
 * returns the right boolean in isolation.
 *
 * Note: under_root() is a pure string-prefix check — it does NOT resolve
 * ".." components (a path like "<root>/../outside.txt" still has <root>
 * as a literal string prefix, so under_root would actually ACCEPT it).
 * That's fine: it's a defense-in-depth backstop against the sync engine
 * constructing/receiving a path outside its registered sync-folder tree
 * (e.g. a sibling directory whose name happens to share a string prefix),
 * not the sole line of defense against ".." — server-side vw_path_validate
 * rejects ".." components before a virtual path is ever accepted, which is
 * where that specific threat is actually handled. The scenario below is
 * the one under_root() is actually documented and designed to catch.
 * ══════════════════════════════════════════════════════════════════════ */
VW_TEST_CASE("exec_action ACT_DEL_LOCAL: sibling-prefix path outside local_root is rejected, file untouched") {
    sync_stack_t s;
    stack_open(&s, "del_reject");

    char evil_dir[768];
    suffix_str(evil_dir, sizeof(evil_dir), s.tmpdir, "_sibling");
#ifdef _WIN32
    CreateDirectoryA(evil_dir, NULL);
#else
    mkdir(evil_dir, 0700);
#endif
    char victim[512];
    path_join(victim, sizeof(victim), evil_dir, "outside.txt");
    /* Write the "victim" file for real so we can prove it survives. */
    FILE *f = fopen(victim, "wb");
    VW_ASSERT(f != NULL);
    if (f) { fputs("do not delete me", f); fclose(f); }

    action_t a;
    memset(&a, 0, sizeof(a));
    a.action = ACT_DEL_LOCAL;
    snprintf(a.local_path, sizeof(a.local_path), "%s", victim);
    snprintf(a.local_root, sizeof(a.local_root), "%s", s.tmpdir); /* victim is NOT under this */

    vw_err_t err = exec_action(s.ctx, NULL, &a);
    VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);

    void *buf = NULL; size_t len = 0;
    VW_ASSERT_OK(vw_fs_read_file(victim, &buf, &len));
    VW_ASSERT_MEM_EQ(buf, "do not delete me", len);
    free(buf);
    remove(victim);
    rm_rf(evil_dir);

    stack_close(&s);
}

VW_TEST_CASE("exec_action ACT_DEL_LOCAL: path under local_root is actually deleted") {
    sync_stack_t s;
    stack_open(&s, "del_accept");

    char victim[512];
    path_join(victim, sizeof(victim), s.tmpdir, "inside.txt");
    FILE *f = fopen(victim, "wb");
    VW_ASSERT(f != NULL);
    if (f) { fputs("x", f); fclose(f); }

    /* Give the cache an entry so ACT_DEL_LOCAL's vw_cache_delete has
     * something to remove too (not asserted directly — vw_cache_delete's
     * own behavior is out of this file's scope — just exercised so this
     * path doesn't rely on undefined behavior for a missing entry). */
    vw_cache_entry_t ce;
    memset(&ce, 0, sizeof(ce));
    snprintf(ce.virtual_path, sizeof(ce.virtual_path), "/sync/inside.txt");
    snprintf(ce.local_path,   sizeof(ce.local_path),   "%s", victim);
    ce.entry_type = VW_ENTRY_FILE;
    ce.sync_state = VW_SYNC_REMOTE_DEL;
    VW_ASSERT_OK(vw_cache_upsert(s.cache, &ce));

    action_t a;
    memset(&a, 0, sizeof(a));
    a.action = ACT_DEL_LOCAL;
    snprintf(a.virtual_path, sizeof(a.virtual_path), "/sync/inside.txt");
    snprintf(a.local_path,   sizeof(a.local_path),   "%s", victim);
    snprintf(a.local_root,   sizeof(a.local_root),   "%s", s.tmpdir);

    vw_err_t err = exec_action(s.ctx, NULL, &a);
    VW_ASSERT_OK(err);

    void *buf = NULL; size_t len = 0;
    VW_ASSERT_ERR(vw_fs_read_file(victim, &buf, &len), VW_ERR_NOT_FOUND);

    stack_close(&s);
}

/* ══════════════════════════════════════════════════════════════════════
 * compute_actions() — owned folder, all six Pass-3 action kinds in one
 * realistic multi-file cycle.
 * ══════════════════════════════════════════════════════════════════════ */
VW_TEST_CASE("compute_actions (owned folder): classifies new/mod/remote-mod/local-del/remote-del/conflict") {
    sync_stack_t s;
    stack_open(&s, "owned");

    vw_sync_folder_t folder;
    memset(&folder, 0, sizeof(folder));
    snprintf(folder.local_root,   sizeof(folder.local_root),   "%s", s.tmpdir);
    snprintf(folder.virtual_root, sizeof(folder.virtual_root), "/sync");
    folder.remote_dir_id = 0; /* owned */

    char lroot[512]; snprintf(lroot, sizeof(lroot), "%s", s.tmpdir);
    char lp_mod[512], lp_rmod[512], lp_ldel[512], lp_rdel[512], lp_conf[512];
    path_join(lp_mod,  sizeof(lp_mod),  lroot, "mod.txt");
    path_join(lp_rmod, sizeof(lp_rmod), lroot, "rmod.txt");
    path_join(lp_ldel, sizeof(lp_ldel), lroot, "ldel.txt");
    path_join(lp_rdel, sizeof(lp_rdel), lroot, "rdel.txt");
    path_join(lp_conf, sizeof(lp_conf), lroot, "conf.txt");

    /* Prior synced state */
    seed_synced(s.cache, "/sync/mod.txt",  lp_mod,  100, 50, 1, 100, 50, 10);
    seed_synced(s.cache, "/sync/rmod.txt", lp_rmod, 100, 50, 1, 100, 50, 11);
    seed_synced(s.cache, "/sync/ldel.txt", lp_ldel, 100, 50, 1, 100, 50, 12);
    seed_synced(s.cache, "/sync/rdel.txt", lp_rdel, 100, 50, 1, 100, 50, 13);
    seed_synced(s.cache, "/sync/conf.txt", lp_conf, 100, 50, 1, 100, 50, 14);

    /* This cycle's local walk: new.txt is brand new; mod.txt and conf.txt
     * changed locally (mtime/size differ); rmod.txt and rdel.txt unchanged;
     * ldel.txt is absent (deleted locally). */
    lfiles_t lf = {0};
    VW_ASSERT_OK(lfiles_push(&lf, "irrelevant", "/sync/new.txt",  999, 999));
    VW_ASSERT_OK(lfiles_push(&lf, lp_mod,       "/sync/mod.txt",  200, 999));
    VW_ASSERT_OK(lfiles_push(&lf, lp_rmod,      "/sync/rmod.txt", 100, 50));
    VW_ASSERT_OK(lfiles_push(&lf, lp_rdel,      "/sync/rdel.txt", 100, 50));
    VW_ASSERT_OK(lfiles_push(&lf, lp_conf,      "/sync/conf.txt", 200, 999));

    /* This cycle's server list: rmod.txt and conf.txt got a new version;
     * rdel.txt and ldel.txt are absent (deleted remotely / never existed
     * for ldel from the server's perspective in this fixture). */
    srv_list_t srv = {0};
    vw_file_entry_t se1 = make_srv_entry("rmod.txt", 11, 60, 200, 2, VW_ENTRY_FILE);
    vw_file_entry_t se2 = make_srv_entry("conf.txt", 14, 60, 200, 2, VW_ENTRY_FILE);
    VW_ASSERT_OK(srv_push(&srv, "/sync/rmod.txt", &se1));
    VW_ASSERT_OK(srv_push(&srv, "/sync/conf.txt", &se2));

    dirmap_t dm = {0};
    action_list_t actions = {0};
    vw_err_t err = compute_actions(s.ctx, NULL, &folder, &lf, &srv, &dm, &actions);
    VW_ASSERT_OK(err);

    const action_t *a;

    a = find_action(&actions, "/sync/new.txt");
    VW_ASSERT(a != NULL);
    if (a) VW_ASSERT_EQ(a->action, ACT_UPLOAD);

    a = find_action(&actions, "/sync/mod.txt");
    VW_ASSERT(a != NULL);
    if (a) VW_ASSERT_EQ(a->action, ACT_UPLOAD);

    a = find_action(&actions, "/sync/rmod.txt");
    VW_ASSERT(a != NULL);
    if (a) VW_ASSERT_EQ(a->action, ACT_DOWNLOAD);

    a = find_action(&actions, "/sync/ldel.txt");
    VW_ASSERT(a != NULL);
    if (a) VW_ASSERT_EQ(a->action, ACT_DEL_REMOTE);

    a = find_action(&actions, "/sync/rdel.txt");
    VW_ASSERT(a != NULL);
    if (a) VW_ASSERT_EQ(a->action, ACT_DEL_LOCAL);

    a = find_action(&actions, "/sync/conf.txt");
    VW_ASSERT(a != NULL);
    if (a) VW_ASSERT_EQ(a->action, ACT_CONFLICT);

    VW_ASSERT_EQ(actions.count, 6u);

    free(lf.arr);
    free(srv.arr);
    free(dm.arr);
    free(actions.arr);
    stack_close(&s);
}

VW_TEST_CASE("compute_actions (shared folder): new-file parent already known via dirmap needs no session") {
    sync_stack_t s;
    stack_open(&s, "shared_known");

    vw_sync_folder_t folder;
    memset(&folder, 0, sizeof(folder));
    snprintf(folder.local_root,   sizeof(folder.local_root),   "%s", s.tmpdir);
    snprintf(folder.virtual_root, sizeof(folder.virtual_root), "/shared");
    folder.remote_dir_id = 999; /* shared */

    char lp[512];
    path_join(lp, sizeof(lp), s.tmpdir, "newfile.txt");

    vw_cache_entry_t ce;
    memset(&ce, 0, sizeof(ce));
    snprintf(ce.virtual_path, sizeof(ce.virtual_path), "/shared/newfile.txt");
    snprintf(ce.local_path,   sizeof(ce.local_path),   "%s", lp);
    ce.entry_type = VW_ENTRY_FILE;
    ce.sync_state = VW_SYNC_NEW_LOCAL;
    ce.file_id    = 0; /* not yet uploaded */
    VW_ASSERT_OK(vw_cache_upsert(s.cache, &ce));

    lfiles_t lf = {0};
    srv_list_t srv = {0};
    dirmap_t dm = {0};
    /* Parent ("/shared", the folder root) is already known — the fast
     * path through resolve_or_create_dir that returns without ever
     * touching sess. */
    VW_ASSERT_OK(dirmap_push(&dm, "/shared", 555));

    action_list_t actions = {0};
    vw_err_t err = compute_actions(s.ctx, NULL, &folder, &lf, &srv, &dm, &actions);
    VW_ASSERT_OK(err);

    const action_t *a = find_action(&actions, "/shared/newfile.txt");
    VW_ASSERT(a != NULL);
    if (a) {
        VW_ASSERT_EQ(a->action, ACT_UPLOAD);
        VW_ASSERT_EQ(a->shared, 1);
        VW_ASSERT_EQ(a->parent_dir_id, 555u);
    }
    VW_ASSERT_EQ(vw_sync_permission_denied_count(s.ctx), 0u);
    VW_ASSERT_EQ(vw_sync_action_error_count(s.ctx), 0u);

    free(dm.arr);
    free(actions.arr);
    stack_close(&s);
}

/* ══════════════════════════════════════════════════════════════════════
 * resolve_or_create_dir() — recursion / memoization / offline edge cases.
 * Every scenario here is chosen so parent_id never resolves to a nonzero
 * value except via a pre-seeded dirmap entry — i.e. vw_client_file_mkdir
 * is never reached, so sess = NULL is always safe. The actual mkdir-outcome
 * classification (success / permission-denied / already-exists / network
 * error) remains covered only at integration level, deliberately — see
 * this file's header comment and TASK-114's acceptance criteria.
 * ══════════════════════════════════════════════════════════════════════ */
VW_TEST_CASE("resolve_or_create_dir: fully offline (root never seeded) resolves to 0, uncounted") {
    sync_stack_t s;
    stack_open(&s, "resolve_offline");

    dirmap_t dm = {0}; /* root NOT pushed — simulates "never went online this cycle" */
    uint64_t out_id = 12345; /* poison value to prove it gets overwritten to 0 */
    vw_err_t err = resolve_or_create_dir(s.ctx, NULL, &dm, "/shared", "/shared/a/b", &out_id);

    VW_ASSERT_OK(err);
    VW_ASSERT_EQ(out_id, 0u);
    /* Offline is silent, not an error and not a permission denial — it's
     * simply nothing to do yet, distinct from an actually-attempted and
     * rejected/failed create. */
    VW_ASSERT_EQ(vw_sync_action_error_count(s.ctx), 0u);
    VW_ASSERT_EQ(vw_sync_permission_denied_count(s.ctx), 0u);

    free(dm.arr);
    stack_close(&s);
}

VW_TEST_CASE("resolve_or_create_dir: intermediate ancestors get memoized as unresolvable") {
    sync_stack_t s;
    stack_open(&s, "resolve_memo");

    dirmap_t dm = {0};
    uint64_t out_id = 0;
    VW_ASSERT_OK(resolve_or_create_dir(s.ctx, NULL, &dm, "/shared", "/shared/a/b", &out_id));

    VW_ASSERT_EQ(dirmap_lookup(&dm, "/shared/a"),   VW_DIRMAP_UNRESOLVABLE);
    VW_ASSERT_EQ(dirmap_lookup(&dm, "/shared/a/b"), VW_DIRMAP_UNRESOLVABLE);

    free(dm.arr);
    stack_close(&s);
}

VW_TEST_CASE("resolve_or_create_dir: root already known resolves immediately") {
    sync_stack_t s;
    stack_open(&s, "resolve_root_known");

    dirmap_t dm = {0};
    VW_ASSERT_OK(dirmap_push(&dm, "/shared", 111));

    uint64_t out_id = 0;
    VW_ASSERT_OK(resolve_or_create_dir(s.ctx, NULL, &dm, "/shared", "/shared", &out_id));
    VW_ASSERT_EQ(out_id, 111u);

    free(dm.arr);
    stack_close(&s);
}

VW_TEST_CASE("resolve_or_create_dir: already-known target short-circuits without recursing") {
    sync_stack_t s;
    stack_open(&s, "resolve_target_known");

    dirmap_t dm = {0};
    VW_ASSERT_OK(dirmap_push(&dm, "/shared", 111));
    VW_ASSERT_OK(dirmap_push(&dm, "/shared/sub", 222));

    uint64_t out_id = 0;
    VW_ASSERT_OK(resolve_or_create_dir(s.ctx, NULL, &dm, "/shared", "/shared/sub", &out_id));
    VW_ASSERT_EQ(out_id, 222u);

    free(dm.arr);
    stack_close(&s);
}

VW_TEST_CASE("resolve_or_create_dir: sentinel short-circuits without re-attempting") {
    sync_stack_t s;
    stack_open(&s, "resolve_sentinel");

    dirmap_t dm = {0};
    /* Pre-seed as already-failed, WITHOUT seeding root or any ancestor —
     * if the sentinel check didn't short-circuit first, this would recurse
     * into an unresolvable chain. It must return immediately instead. */
    VW_ASSERT_OK(dirmap_push(&dm, "/shared/x", VW_DIRMAP_UNRESOLVABLE));

    uint64_t out_id = 999; /* poison */
    VW_ASSERT_OK(resolve_or_create_dir(s.ctx, NULL, &dm, "/shared", "/shared/x", &out_id));
    VW_ASSERT_EQ(out_id, 0u);
    VW_ASSERT_EQ(vw_sync_action_error_count(s.ctx), 0u);
    VW_ASSERT_EQ(vw_sync_permission_denied_count(s.ctx), 0u);

    free(dm.arr);
    stack_close(&s);
}

VW_TEST_CASE("resolve_or_create_dir: root-path-normalization fallback branch") {
    sync_stack_t s;
    stack_open(&s, "resolve_root_fallback");

    /* root_vpath == "/" — vpath "/x" is one level below it. strrchr finds
     * the '/' at the very start of the buffer (sl == parent_vpath), which
     * must fall back to root_vpath rather than leaving an empty string. */
    dirmap_t dm = {0}; /* root not seeded -> still resolves to "offline" */
    uint64_t out_id = 0;
    vw_err_t err = resolve_or_create_dir(s.ctx, NULL, &dm, "/", "/x", &out_id);

    VW_ASSERT_OK(err);
    VW_ASSERT_EQ(out_id, 0u);
    VW_ASSERT_EQ(dirmap_lookup(&dm, "/x"), VW_DIRMAP_UNRESOLVABLE);

    free(dm.arr);
    stack_close(&s);
}

VW_TEST_CASE("vw_cache_open: pre-TASK-158 (1088-byte record) cache.db is safely reset, not misread") {
    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir), "cache_migrate");
    char cache_path[600];
    path_join(cache_path, sizeof(cache_path), tmpdir, "cache.db");

    /* Simulate a pre-TASK-158 cache.db: 3 old-sized (1088-byte) records,
     * the middle one carrying a fake but well-formed virtual_path at the
     * byte offset that used to be its start (64) in the old layout. If
     * vw_cache_open ever went back to naively dividing buf_len by the
     * current (1096-byte) record size, every field past this record
     * would misalign and this path string would corrupt on decode
     * instead of being cleanly discarded. */
    size_t old_total = 3u * VW_CACHE_ENTRY_SIZE_PRE_TASK158;
    uint8_t *old_buf = (uint8_t *)calloc(1, old_total);
    VW_ASSERT(old_buf != NULL);
    snprintf((char *)(old_buf + VW_CACHE_ENTRY_SIZE_PRE_TASK158 + 64), 64, "/old/format/file.txt");
    FILE *f = fopen(cache_path, "wb");
    VW_ASSERT(f != NULL);
    size_t written = fwrite(old_buf, 1, old_total, f);
    fclose(f);
    free(old_buf);
    VW_ASSERT_EQ(written, old_total);

    vw_cache_t *cache = NULL;
    VW_ASSERT_OK(vw_cache_open(tmpdir, &cache));

    vw_cache_entry_t *entries = NULL; uint32_t n = 0;
    VW_ASSERT_OK(vw_cache_list(cache, -1, &entries, &n));
    VW_ASSERT_EQ(n, 0u); /* migrated to fresh — no garbage/misread entries surfaced */
    free(entries);

    /* A real record inserted after migration must round-trip cleanly. */
    vw_cache_entry_t ce;
    memset(&ce, 0, sizeof(ce));
    snprintf(ce.virtual_path, sizeof(ce.virtual_path), "%s", "/after/migration.txt");
    ce.entry_type = VW_ENTRY_FILE;
    ce.vault_id = 424242;
    VW_ASSERT_OK(vw_cache_upsert(cache, &ce));
    vw_cache_entry_t got;
    VW_ASSERT_OK(vw_cache_get(cache, "/after/migration.txt", &got));
    VW_ASSERT_EQ(got.vault_id, 424242u);

    vw_cache_close(cache);

    /* The on-disk file itself must also have been rewritten to the
     * current record size at migration time — not just the in-memory
     * view — so a later reopen (e.g. after a daemon restart) doesn't
     * re-trigger this same migration path against stale trailing bytes. */
    FILE *check = fopen(cache_path, "rb");
    VW_ASSERT(check != NULL);
    fseek(check, 0, SEEK_END);
    long sz = ftell(check);
    fclose(check);
    uint64_t remainder = (uint64_t)sz % sizeof(vw_cache_entry_t);
    VW_ASSERT_EQ(remainder, 0u);

    rm_rf(tmpdir);
}

VW_TEST_SUITE_END()
