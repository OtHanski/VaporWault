/*
 * test_vw_file_handlers.c — unit tests for the server's file-operation
 * request handlers (TASK-115).
 *
 * src/server/vw_file_handlers.c had zero unit tests before this — it was
 * covered only at integration level (tests/integration/test_sharing.py,
 * test_file_ops.py, run_integration.py), which is real coverage but can't
 * cheaply enumerate the full permission matrix (owner / grantee / scoped
 * public-link session / no access, crossed with every handler).
 *
 * Scope, deliberately: every mutating/reading handler in this file makes
 * its access-control decision by calling effective_permission() or
 * permission_on_dir_or_root(), then hands the result to
 * require_permission() to send the actual wire response. That last step
 * needs a real vw_conn_t — a fully opaque type outside vw_net.c,
 * constructible only via a genuine TLS accept/connect — so it isn't
 * unit-testable without a live server, and remains integration-tested
 * (already extensively, as above). This file instead directly tests the
 * two permission-decision functions themselves (exposed only for testing
 * via vw_file_handlers_internal.h — see that header), which is the actual
 * per-caller-class access decision TASK-115 is about; require_permission's
 * decision→error-code mapping is two lines and already reviewed, not
 * re-derived here.
 *
 * Also covers vw_path_validate() explicitly against every rule in its own
 * documented contract (vw_file_handlers.h) — it was already public and
 * fuzz-tested (tests/fuzz/fuzz_path_validate.c catches crashes) but had no
 * unit test asserting the documented accept/reject behavior per rule.
 */

#include "vw_test.h"
#include "vw_file_handlers.h"
#include "vw_file_handlers_internal.h"
#include "vw_store.h"
#include "vw_share.h"
#include "vw_oplog.h"
#include "vw_crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <windows.h>
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <dirent.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Temp-dir helpers (same pattern as test_vw_share.c) ───────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_fhtest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_fhtest_%u_%s", VW_PID(), label);
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

/* ── Stack helper: oplog + file_store + share_store (same as test_vw_share.c) ── */

typedef struct {
    char              tmpdir[512];
    vw_oplog_t       *oplog;
    vw_file_store_t  *fs;
    vw_share_store_t *ss;
} fh_stack_t;

static void stack_open(fh_stack_t *s, const char *label) {
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_oplog_open(s->tmpdir, &s->oplog));
    VW_ASSERT_OK(vw_file_store_open(s->tmpdir, s->oplog, &s->fs));
    VW_ASSERT_OK(vw_share_store_open(s->tmpdir, s->oplog, &s->ss));
}

static void stack_close(fh_stack_t *s) {
    vw_share_store_close(s->ss);
    vw_file_store_close(s->fs);
    vw_oplog_close(s->oplog);
    rm_rf(s->tmpdir);
}

/* Create a file/dir record owned by owner_id under parent_dir_id. */
static uint64_t make_entry(fh_stack_t *s, uint64_t owner_id,
                            uint64_t parent_dir_id, const char *name, uint8_t entry_type) {
    vw_file_record_t rec;
    uint64_t file_id = 0;
    memset(&rec, 0, sizeof(rec));
    rec.owner_id      = owner_id;
    rec.parent_dir_id = parent_dir_id;
    rec.entry_type    = entry_type;
    snprintf(rec.name, sizeof(rec.name), "%s", name);
    VW_ASSERT_OK(vw_store_file_create(s->fs, &rec, &file_id));
    return file_id;
}

/* Rename/move in place (TASK-157 regression tests below) — same
 * update-in-place pattern handle_file_move uses: mutate a copy of the
 * current record, call vw_store_file_update. */
static vw_err_t rename_entry(fh_stack_t *s, uint64_t file_id,
                              uint64_t new_parent_dir_id, const char *new_name) {
    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s->fs, file_id, &rec));
    rec.parent_dir_id = new_parent_dir_id;
    memset(rec.name, 0, sizeof(rec.name));
    snprintf(rec.name, sizeof(rec.name), "%s", new_name);
    return vw_store_file_update(s->fs, file_id, &rec);
}

VW_TEST_SUITE("vw_file_handlers")

VW_ASSERT_OK(vw_crypto_init()); /* needed for vw_crypto_random (link tokens) */

/* ══════════════════════════════════════════════════════════════════════
 * vw_path_validate() — every rule in its documented contract
 * ══════════════════════════════════════════════════════════════════════ */

VW_TEST_CASE("vw_path_validate: NULL path rejected") {
    VW_ASSERT_ERR(vw_path_validate(NULL, 5), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: zero length rejected") {
    VW_ASSERT_ERR(vw_path_validate("/a", 0), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: length over VW_MAX_PATH_BYTES rejected") {
    VW_ASSERT_ERR(vw_path_validate("/a", VW_MAX_PATH_BYTES + 1u), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: does not start with '/' rejected") {
    VW_ASSERT_ERR(vw_path_validate("a/b", 3), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: embedded NUL byte rejected") {
    char p[] = { '/', 'a', '\0', 'b' };
    VW_ASSERT_ERR(vw_path_validate(p, sizeof(p)), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: backslash rejected") {
    VW_ASSERT_ERR(vw_path_validate("/a\\b", 4), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: empty component ('//') rejected") {
    VW_ASSERT_ERR(vw_path_validate("/a//b", 5), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: '..' component at end of path rejected") {
    VW_ASSERT_ERR(vw_path_validate("/a/..", 5), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: '..' component followed by '/' rejected") {
    VW_ASSERT_ERR(vw_path_validate("/a/../b", 7), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: '..' as the very first component rejected") {
    VW_ASSERT_ERR(vw_path_validate("/../a", 5), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_path_validate: a component merely STARTING with '..' (not exactly '..') is fine") {
    /* "..foo" is a legitimate (if odd) filename component — only a
     * component that is EXACTLY ".." is a traversal attempt. */
    VW_ASSERT_OK(vw_path_validate("/a/..foo", 8));
}

VW_TEST_CASE("vw_path_validate: root path '/' alone is valid") {
    VW_ASSERT_OK(vw_path_validate("/", 1));
}

VW_TEST_CASE("vw_path_validate: ordinary nested path is valid") {
    VW_ASSERT_OK(vw_path_validate("/a/b/c.txt", 10));
}

VW_TEST_CASE("vw_path_validate: trailing slash on an ordinary path is valid") {
    VW_ASSERT_OK(vw_path_validate("/a/b/", 5));
}

VW_TEST_CASE("vw_path_validate: exactly VW_MAX_PATH_BYTES is valid (boundary)") {
    char *p = malloc(VW_MAX_PATH_BYTES);
    VW_ASSERT(p != NULL);
    if (p) {
        p[0] = '/';
        for (uint32_t i = 1; i < VW_MAX_PATH_BYTES; i++) p[i] = 'a';
        VW_ASSERT_OK(vw_path_validate(p, VW_MAX_PATH_BYTES));
        free(p);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * vw_leaf_name_validate() — the bare-leaf-name check FILE_MKDIR and
 * FILE_MOVE both apply (extracted from what used to be near-duplicated
 * inline logic in each handler — the one real difference between them,
 * allow_empty, is FILE_MOVE's "empty new_name means keep the current
 * name" semantics, which FILE_MKDIR does not share).
 * ══════════════════════════════════════════════════════════════════════ */

VW_TEST_CASE("vw_leaf_name_validate: empty name rejected when allow_empty=0 (FILE_MKDIR)") {
    VW_ASSERT_ERR(vw_leaf_name_validate("x", 0, 0), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_leaf_name_validate: empty name accepted when allow_empty=1 (FILE_MOVE)") {
    VW_ASSERT_OK(vw_leaf_name_validate("x", 0, 1));
}

VW_TEST_CASE("vw_leaf_name_validate: name containing '/' rejected") {
    VW_ASSERT_ERR(vw_leaf_name_validate("a/b", 3, 0), VW_ERR_PATH_INVALID);
    VW_ASSERT_ERR(vw_leaf_name_validate("a/b", 3, 1), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_leaf_name_validate: embedded NUL rejected") {
    char n[] = { 'a', '\0', 'b' };
    VW_ASSERT_ERR(vw_leaf_name_validate(n, sizeof(n), 0), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_leaf_name_validate: length >= 64 rejected") {
    char n[64];
    memset(n, 'a', sizeof(n));
    VW_ASSERT_ERR(vw_leaf_name_validate(n, 64, 0), VW_ERR_PATH_INVALID);
}

VW_TEST_CASE("vw_leaf_name_validate: length 63 (boundary) accepted") {
    char n[63];
    memset(n, 'a', sizeof(n));
    VW_ASSERT_OK(vw_leaf_name_validate(n, 63, 0));
}

VW_TEST_CASE("vw_leaf_name_validate: ordinary name accepted") {
    VW_ASSERT_OK(vw_leaf_name_validate("notes.txt", 9, 0));
}

/* ══════════════════════════════════════════════════════════════════════
 * effective_permission() — owner / grant / scoped-link / no-access
 * ══════════════════════════════════════════════════════════════════════ */

VW_TEST_CASE("effective_permission: owner gets OWNER regardless of any grant") {
    fh_stack_t s; stack_open(&s, "eff_owner");
    uint64_t owner = 100, other = 200;
    uint64_t file = make_entry(&s, owner, 0, "doc.txt", VW_ENTRY_FILE);
    /* Grant `other` only VIEW — must not affect the owner's own result. */
    uint64_t share_id = 0;
    VW_ASSERT_OK(vw_share_grant_create(s.ss, file, owner, other, VW_PERM_VIEW, 0, &share_id));

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s.fs, file, &rec));
    vw_perm_t p = effective_permission(s.ss, s.fs, &rec, owner, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_OWNER);

    stack_close(&s);
}

VW_TEST_CASE("effective_permission: unrelated user with no grant gets NONE") {
    fh_stack_t s; stack_open(&s, "eff_none");
    uint64_t owner = 100, stranger = 999;
    uint64_t file = make_entry(&s, owner, 0, "doc.txt", VW_ENTRY_FILE);

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s.fs, file, &rec));
    vw_perm_t p = effective_permission(s.ss, s.fs, &rec, stranger, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_NONE);

    stack_close(&s);
}

VW_TEST_CASE("effective_permission: grantee with EDIT grant on an ancestor folder gets EDIT") {
    fh_stack_t s; stack_open(&s, "eff_grant");
    uint64_t owner = 100, grantee = 200;
    uint64_t folder = make_entry(&s, owner, 0, "shared", VW_ENTRY_DIR);
    uint64_t file   = make_entry(&s, owner, folder, "notes.txt", VW_ENTRY_FILE);

    uint64_t share_id = 0;
    VW_ASSERT_OK(vw_share_grant_create(s.ss, folder, owner, grantee, VW_PERM_EDIT, 0, &share_id));

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s.fs, file, &rec));
    vw_perm_t p = effective_permission(s.ss, s.fs, &rec, grantee, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_EDIT);

    stack_close(&s);
}

VW_TEST_CASE("effective_permission: NULL share store (sharing disabled) yields NONE for a non-owner") {
    fh_stack_t s; stack_open(&s, "eff_nullss");
    uint64_t owner = 100, other = 200;
    uint64_t file = make_entry(&s, owner, 0, "doc.txt", VW_ENTRY_FILE);

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s.fs, file, &rec));
    /* ss == NULL: effective_permission must fall back to "owner check
     * only" rather than dereferencing a NULL share store. */
    vw_perm_t p = effective_permission(NULL, s.fs, &rec, other, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_NONE);
    /* The owner still resolves correctly even with sharing disabled. */
    p = effective_permission(NULL, s.fs, &rec, owner, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_OWNER);

    stack_close(&s);
}

VW_TEST_CASE("effective_permission: anonymous scoped public-link session resolves via scope_share_id") {
    fh_stack_t s; stack_open(&s, "eff_scoped");
    uint64_t owner = 100;
    uint64_t file = make_entry(&s, owner, 0, "public.txt", VW_ENTRY_FILE);

    uint8_t token[32];
    uint64_t link_share_id = 0;
    VW_ASSERT_OK(vw_share_link_create(s.ss, file, owner, VW_PERM_VIEW, 0, token, &link_share_id));

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s.fs, file, &rec));
    /* user_id = 0 (anonymous), scope_share_id = the link's share_id. */
    vw_perm_t p = effective_permission(s.ss, s.fs, &rec, 0, link_share_id);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_VIEW);

    /* A share_id that doesn't scope to this file grants nothing. */
    uint64_t other_file = make_entry(&s, owner, 0, "other.txt", VW_ENTRY_FILE);
    vw_file_record_t other_rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s.fs, other_file, &other_rec));
    p = effective_permission(s.ss, s.fs, &other_rec, 0, link_share_id);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_NONE);

    stack_close(&s);
}

/* ══════════════════════════════════════════════════════════════════════
 * permission_on_dir_or_root() — the root special-case plus delegation
 * ══════════════════════════════════════════════════════════════════════ */

VW_TEST_CASE("permission_on_dir_or_root: dir_id == 0, matching root owner gets OWNER") {
    fh_stack_t s; stack_open(&s, "root_owner_match");
    uint64_t owner = 100;
    vw_perm_t p = permission_on_dir_or_root(s.ss, s.fs, 0, owner, owner, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_OWNER);
    stack_close(&s);
}

VW_TEST_CASE("permission_on_dir_or_root: dir_id == 0, mismatched user gets NONE (no grant can target a root)") {
    fh_stack_t s; stack_open(&s, "root_mismatch");
    uint64_t owner = 100, other = 200;
    vw_perm_t p = permission_on_dir_or_root(s.ss, s.fs, 0, owner, other, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_NONE);
    stack_close(&s);
}

VW_TEST_CASE("permission_on_dir_or_root: dir_id == 0, anonymous user_id 0 gets NONE even if root_owner_id happens to be 0") {
    fh_stack_t s; stack_open(&s, "root_anon");
    /* user_id == 0 must never be treated as "owns the root" even in the
     * degenerate case root_owner_id == 0 — anonymous callers never own
     * anything. */
    vw_perm_t p = permission_on_dir_or_root(s.ss, s.fs, 0, 0, 0, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_NONE);
    stack_close(&s);
}

VW_TEST_CASE("permission_on_dir_or_root: nonexistent dir_id gets NONE") {
    fh_stack_t s; stack_open(&s, "dir_missing");
    uint64_t owner = 100;
    vw_perm_t p = permission_on_dir_or_root(s.ss, s.fs, 999999, owner, owner, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_NONE);
    stack_close(&s);
}

VW_TEST_CASE("permission_on_dir_or_root: real directory, owner gets OWNER") {
    fh_stack_t s; stack_open(&s, "dir_owner");
    uint64_t owner = 100;
    uint64_t folder = make_entry(&s, owner, 0, "docs", VW_ENTRY_DIR);
    vw_perm_t p = permission_on_dir_or_root(s.ss, s.fs, folder, owner, owner, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_OWNER);
    stack_close(&s);
}

VW_TEST_CASE("permission_on_dir_or_root: real directory, grantee with EDIT gets EDIT") {
    fh_stack_t s; stack_open(&s, "dir_grantee");
    uint64_t owner = 100, grantee = 200;
    uint64_t folder = make_entry(&s, owner, 0, "docs", VW_ENTRY_DIR);
    uint64_t share_id = 0;
    VW_ASSERT_OK(vw_share_grant_create(s.ss, folder, owner, grantee, VW_PERM_EDIT, 0, &share_id));
    vw_perm_t p = permission_on_dir_or_root(s.ss, s.fs, folder, owner, grantee, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_EDIT);
    stack_close(&s);
}

VW_TEST_CASE("permission_on_dir_or_root: real directory, VIEW-only grantee is not EDIT") {
    fh_stack_t s; stack_open(&s, "dir_view_only");
    uint64_t owner = 100, grantee = 200;
    uint64_t folder = make_entry(&s, owner, 0, "docs", VW_ENTRY_DIR);
    uint64_t share_id = 0;
    VW_ASSERT_OK(vw_share_grant_create(s.ss, folder, owner, grantee, VW_PERM_VIEW, 0, &share_id));
    vw_perm_t p = permission_on_dir_or_root(s.ss, s.fs, folder, owner, grantee, 0);
    VW_ASSERT_EQ((int)p, (int)VW_PERM_VIEW);
    VW_ASSERT(p < VW_PERM_EDIT);
    stack_close(&s);
}

/* ══════════════════════════════════════════════════════════════════════
 * TASK-157 regression — vw_store_file_update() must keep path_ht in sync
 * with a name/parent_dir_id change, so FILE_STAT (vw_store_file_get_by_path)
 * resolves correctly immediately after a rename or move, no server restart
 * required. Exercises vw_store_files.c's public API directly (no gateway,
 * no wire protocol) via the same fh_stack_t fixture used above (rename_entry
 * helper defined above VW_TEST_SUITE, alongside make_entry).
 * ══════════════════════════════════════════════════════════════════════ */

VW_TEST_CASE("TASK-157: rename resolves by new path immediately, old path is NOT_FOUND") {
    fh_stack_t s; stack_open(&s, "task157_rename");
    uint64_t owner = 100;
    uint64_t fid = make_entry(&s, owner, 0, "before.txt", VW_ENTRY_FILE);

    VW_ASSERT_OK(rename_entry(&s, fid, 0, "after.txt"));

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_path(s.fs, owner, "/after.txt", &rec));
    VW_ASSERT_EQ((int)rec.file_id, (int)fid);

    VW_ASSERT_ERR(vw_store_file_get_by_path(s.fs, owner, "/before.txt", &rec),
                  VW_ERR_NOT_FOUND);
    stack_close(&s);
}

VW_TEST_CASE("TASK-157: move to a different directory resolves by new path immediately") {
    fh_stack_t s; stack_open(&s, "task157_move");
    uint64_t owner = 100;
    uint64_t src_dir = make_entry(&s, owner, 0, "src", VW_ENTRY_DIR);
    uint64_t dst_dir = make_entry(&s, owner, 0, "dst", VW_ENTRY_DIR);
    uint64_t fid = make_entry(&s, owner, src_dir, "item.txt", VW_ENTRY_FILE);

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_path(s.fs, owner, "/src/item.txt", &rec));
    VW_ASSERT_EQ((int)rec.file_id, (int)fid);

    VW_ASSERT_OK(rename_entry(&s, fid, dst_dir, "item.txt"));

    VW_ASSERT_OK(vw_store_file_get_by_path(s.fs, owner, "/dst/item.txt", &rec));
    VW_ASSERT_EQ((int)rec.file_id, (int)fid);

    VW_ASSERT_ERR(vw_store_file_get_by_path(s.fs, owner, "/src/item.txt", &rec),
                  VW_ERR_NOT_FOUND);
    stack_close(&s);
}

VW_TEST_CASE("TASK-157: renaming to a stale name frees it for reuse by a new file") {
    fh_stack_t s; stack_open(&s, "task157_reuse");
    uint64_t owner = 100;
    uint64_t fid = make_entry(&s, owner, 0, "first.txt", VW_ENTRY_FILE);

    VW_ASSERT_OK(rename_entry(&s, fid, 0, "renamed.txt"));

    /* The old name must be genuinely free — not just NOT_FOUND on lookup,
     * but actually creatable again (proves the stale path_ht entry, if any,
     * no longer shadows this name for duplicate-detection purposes). */
    uint64_t fid2 = make_entry(&s, owner, 0, "first.txt", VW_ENTRY_FILE);
    VW_ASSERT_NE((int)fid2, (int)fid);

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_path(s.fs, owner, "/first.txt", &rec));
    VW_ASSERT_EQ((int)rec.file_id, (int)fid2);
    VW_ASSERT_OK(vw_store_file_get_by_path(s.fs, owner, "/renamed.txt", &rec));
    VW_ASSERT_EQ((int)rec.file_id, (int)fid);
    stack_close(&s);
}

VW_TEST_CASE("TASK-157: repeated rename chain leaves only the final name resolvable") {
    fh_stack_t s; stack_open(&s, "task157_chain");
    uint64_t owner = 100;
    uint64_t fid = make_entry(&s, owner, 0, "v1.txt", VW_ENTRY_FILE);

    VW_ASSERT_OK(rename_entry(&s, fid, 0, "v2.txt"));
    VW_ASSERT_OK(rename_entry(&s, fid, 0, "v3.txt"));
    VW_ASSERT_OK(rename_entry(&s, fid, 0, "v4.txt"));

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_path(s.fs, owner, "/v4.txt", &rec));
    VW_ASSERT_EQ((int)rec.file_id, (int)fid);

    VW_ASSERT_ERR(vw_store_file_get_by_path(s.fs, owner, "/v1.txt", &rec), VW_ERR_NOT_FOUND);
    VW_ASSERT_ERR(vw_store_file_get_by_path(s.fs, owner, "/v2.txt", &rec), VW_ERR_NOT_FOUND);
    VW_ASSERT_ERR(vw_store_file_get_by_path(s.fs, owner, "/v3.txt", &rec), VW_ERR_NOT_FOUND);
    stack_close(&s);
}

VW_TEST_CASE("TASK-157: update that does not change name/parent leaves path_ht untouched") {
    fh_stack_t s; stack_open(&s, "task157_noop");
    uint64_t owner = 100;
    uint64_t fid = make_entry(&s, owner, 0, "steady.txt", VW_ENTRY_FILE);

    vw_file_record_t rec;
    VW_ASSERT_OK(vw_store_file_get_by_id(s.fs, fid, &rec));
    rec.entry_type = rec.entry_type; /* touch a non-path field, same name/parent */
    VW_ASSERT_OK(vw_store_file_update(s.fs, fid, &rec));

    VW_ASSERT_OK(vw_store_file_get_by_path(s.fs, owner, "/steady.txt", &rec));
    VW_ASSERT_EQ((int)rec.file_id, (int)fid);
    stack_close(&s);
}

VW_TEST_SUITE_END()
