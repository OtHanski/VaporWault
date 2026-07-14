/*
 * test_vw_fs.c — unit tests for vw_fs.
 *
 * Tests:
 *   atomic_write + read_file round-trip
 *   pwrite + sync_file: in-place byte patching, verify read-back
 *   list_dir: enumerate 3 known files, verify all present
 *   path helpers: ensure_dir, exists, file_size, delete
 */

#include "vw_test.h"
#include "vw_fs.h"
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

/* ── Temp-dir helpers ────────────────────────────────────────────────────── */

static void make_tmpdir(char *out, size_t sz)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_fstest_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_fstest_%u", VW_PID());
    mkdir(out, 0700);
#endif
}

/* Recursively delete a directory (all files must be plain files, no nesting). */
static void rm_rf(const char *dir)
{
#ifdef _WIN32
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) goto rmdir_only;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        char child[MAX_PATH];
        snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            rm_rf(child);
        else
            DeleteFileA(child);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
rmdir_only:
    RemoveDirectoryA(dir);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[512];
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(child);
        else
            remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

/* Build path: dir + sep + name. */
static void path_join(char *out, size_t sz, const char *dir, const char *name)
{
#ifdef _WIN32
    snprintf(out, sz, "%s\\%s", dir, name);
#else
    snprintf(out, sz, "%s/%s", dir, name);
#endif
}

/* ── list_dir callback helpers ───────────────────────────────────────────── */

typedef struct {
    char names[8][64];
    int  count;
} dir_listing_t;

static int collect_names(const char *name, void *ud)
{
    dir_listing_t *l = (dir_listing_t *)ud;
    if (l->count < 8)
        snprintf(l->names[l->count++], 64, "%s", name);
    return 0;
}

static int has_name(const dir_listing_t *l, const char *name)
{
    for (int i = 0; i < l->count; i++)
        if (strcmp(l->names[i], name) == 0) return 1;
    return 0;
}

/* ── Test suite ──────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_fs") {

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));

    /* ── atomic_write + read_file ─────────────────────────────────────── */

    VW_TEST_CASE("atomic_write creates a file with the correct content") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "atomic.bin");
        static const char data[] = "hello, VaporWault";
        VW_ASSERT_OK(vw_fs_atomic_write(p, data, sizeof(data) - 1));
        VW_ASSERT(vw_fs_exists(p));

        void *buf = NULL;
        size_t len = 0;
        VW_ASSERT_OK(vw_fs_read_file(p, &buf, &len));
        VW_ASSERT_EQ((int)len, (int)(sizeof(data) - 1));
        VW_ASSERT(memcmp(buf, data, len) == 0);
        free(buf);
    }

    VW_TEST_CASE("atomic_write overwrites an existing file") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "atomic_ow.bin");
        VW_ASSERT_OK(vw_fs_atomic_write(p, "old content", 11));
        VW_ASSERT_OK(vw_fs_atomic_write(p, "NEW", 3));

        void *buf = NULL;
        size_t len = 0;
        VW_ASSERT_OK(vw_fs_read_file(p, &buf, &len));
        VW_ASSERT_EQ((int)len, 3);
        VW_ASSERT(memcmp(buf, "NEW", 3) == 0);
        free(buf);
    }

    VW_TEST_CASE("read_file on non-existent path returns VW_ERR_NOT_FOUND") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "does_not_exist.bin");
        void *buf = NULL; size_t len = 0;
        VW_ASSERT_ERR(vw_fs_read_file(p, &buf, &len), VW_ERR_NOT_FOUND);
    }

    /* ── file_size + delete ───────────────────────────────────────────── */

    VW_TEST_CASE("file_size returns correct byte count") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "size_test.bin");
        VW_ASSERT_OK(vw_fs_atomic_write(p, "1234567890", 10));
        uint64_t sz = 0;
        VW_ASSERT_OK(vw_fs_file_size(p, &sz));
        VW_ASSERT_EQ((int)sz, 10);
    }

    VW_TEST_CASE("delete removes the file; exists returns 0 after") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "to_delete.bin");
        VW_ASSERT_OK(vw_fs_atomic_write(p, "x", 1));
        VW_ASSERT_EQ(vw_fs_exists(p), 1);
        VW_ASSERT_OK(vw_fs_delete(p));
        VW_ASSERT_EQ(vw_fs_exists(p), 0);
    }

    VW_TEST_CASE("delete on non-existent file returns VW_OK (idempotent)") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "never_existed.bin");
        VW_ASSERT_OK(vw_fs_delete(p));
    }

    /* ── pwrite + sync_file ───────────────────────────────────────────── */

    VW_TEST_CASE("pwrite patches bytes in-place; sync_file flushes") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "pwrite_test.bin");

        /* Write 16 bytes of 'A' */
        char initial[16];
        memset(initial, 'A', sizeof(initial));
        VW_ASSERT_OK(vw_fs_atomic_write(p, initial, sizeof(initial)));

        /* Patch bytes [4..7] to "BBBB" */
        VW_ASSERT_OK(vw_fs_pwrite(p, 4, "BBBB", 4));
        VW_ASSERT_OK(vw_fs_sync_file(p));

        /* Read back and verify */
        void *buf = NULL; size_t len = 0;
        VW_ASSERT_OK(vw_fs_read_file(p, &buf, &len));
        VW_ASSERT_EQ((int)len, 16);

        char *cb = (char *)buf;
        int prefix_ok = (cb[0]=='A' && cb[1]=='A' && cb[2]=='A' && cb[3]=='A');
        int patch_ok  = (cb[4]=='B' && cb[5]=='B' && cb[6]=='B' && cb[7]=='B');
        int suffix_ok = (cb[8]=='A' && cb[9]=='A' && cb[10]=='A' && cb[11]=='A'
                      && cb[12]=='A' && cb[13]=='A' && cb[14]=='A' && cb[15]=='A');
        VW_ASSERT(prefix_ok);
        VW_ASSERT(patch_ok);
        VW_ASSERT(suffix_ok);
        free(buf);
    }

    VW_TEST_CASE("pwrite at offset 0 works correctly") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "pwrite_off0.bin");
        VW_ASSERT_OK(vw_fs_atomic_write(p, "XXXX", 4));
        VW_ASSERT_OK(vw_fs_pwrite(p, 0, "YYYY", 4));
        VW_ASSERT_OK(vw_fs_sync_file(p));

        void *buf = NULL; size_t len = 0;
        VW_ASSERT_OK(vw_fs_read_file(p, &buf, &len));
        VW_ASSERT(memcmp(buf, "YYYY", 4) == 0);
        free(buf);
    }

    /* ── list_dir ─────────────────────────────────────────────────────── */

    VW_TEST_CASE("list_dir enumerates all entries excluding . and ..") {
        char subdir[512];
        path_join(subdir, sizeof(subdir), tmpdir, "listtest");
        VW_ASSERT_OK(vw_fs_ensure_dir(subdir));

        /* Create 3 files */
        char fa[512], fb[512], fc[512];
        path_join(fa, sizeof(fa), subdir, "alpha.txt");
        path_join(fb, sizeof(fb), subdir, "beta.txt");
        path_join(fc, sizeof(fc), subdir, "gamma.txt");
        VW_ASSERT_OK(vw_fs_atomic_write(fa, "a", 1));
        VW_ASSERT_OK(vw_fs_atomic_write(fb, "b", 1));
        VW_ASSERT_OK(vw_fs_atomic_write(fc, "c", 1));

        dir_listing_t listing = {{{0}}, 0};
        VW_ASSERT_OK(vw_fs_list_dir(subdir, collect_names, &listing));
        VW_ASSERT_EQ(listing.count, 3);
        VW_ASSERT(has_name(&listing, "alpha.txt"));
        VW_ASSERT(has_name(&listing, "beta.txt"));
        VW_ASSERT(has_name(&listing, "gamma.txt"));
    }

    VW_TEST_CASE("list_dir on empty directory returns VW_OK with 0 callbacks") {
        char emptydir[512];
        path_join(emptydir, sizeof(emptydir), tmpdir, "emptydir");
        VW_ASSERT_OK(vw_fs_ensure_dir(emptydir));
        dir_listing_t listing = {{{0}}, 0};
        VW_ASSERT_OK(vw_fs_list_dir(emptydir, collect_names, &listing));
        VW_ASSERT_EQ(listing.count, 0);
    }

    VW_TEST_CASE("list_dir on non-existent directory returns VW_ERR_IO") {
        char p[512];
        path_join(p, sizeof(p), tmpdir, "no_such_dir");
        dir_listing_t listing = {{{0}}, 0};
        VW_ASSERT_ERR(vw_fs_list_dir(p, collect_names, &listing), VW_ERR_IO);
    }

    /* ── ensure_dir (mkdir -p) ────────────────────────────────────────── */

    VW_TEST_CASE("ensure_dir creates nested directories") {
        char nested[512];
        path_join(nested, sizeof(nested), tmpdir, "a");
        char nested2[512];
        path_join(nested2, sizeof(nested2), nested, "b");
        VW_ASSERT_OK(vw_fs_ensure_dir(nested2));
        VW_ASSERT(vw_fs_exists(nested2));
    }

    VW_TEST_CASE("ensure_dir on existing directory returns VW_OK") {
        VW_ASSERT_OK(vw_fs_ensure_dir(tmpdir));
    }

    /* ── cleanup ──────────────────────────────────────────────────────── */
    rm_rf(tmpdir);
}
VW_TEST_SUITE_END()
