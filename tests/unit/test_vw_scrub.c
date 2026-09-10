/*
 * test_vw_scrub.c — unit tests for vw_scrub / vw_storage_scrub_run.
 *
 * TASK-255 (Phase 22 detection foundation). Exercises the scrub walk
 * directly against a real on-disk chunk store (vw_storage_open), corrupting
 * chunk files in place the same way bit rot would, then verifying:
 *   - a clean store scans clean
 *   - a still-referenced (ref_count > 0) corrupted chunk is detected and
 *     reported via the callback
 *   - a ref_count == 0 chunk (tombstone) is never reported as corrupt, even
 *     if its bytes are also tampered with
 *   - the vw_scrub module wrapper (background-thread API) wires
 *     vw_storage_scrub_run through to vw_scrub_get_last_stats correctly
 *
 * vw_scrub_create takes `cluster` (TASK-260) and `notify` (TASK-261)
 * parameters that this test always passes NULL — none of these tests need
 * real replica-fetch behavior (that's vw_repair.c/vw_cluster.c's own
 * territory, covered by test_cluster_repair_fetch.c) or a real admin
 * alert dispatch (vw_notify.c's own territory). vw_repair.c is still
 * linked in (it's
 * vw_scrub.c's own dependency now) and references vw_cluster_node_list/
 * vw_cluster_repair_fetch unconditionally at the source level even
 * though a NULL cluster means they're never actually called at runtime
 * here — this test target deliberately doesn't link the real
 * vw_cluster.c (same reasoning test_vw_gc.c already established for its
 * own two cluster-function stubs below), so it provides trivial stub
 * definitions of just those two instead.
 */

#include "vw_test.h"
#include "vw_scrub.h"
#include "vw_storage.h"
#include "vw_cluster.h"
#include "vw_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Stub vw_cluster functions (see file header comment) ─────────────────── */

vw_err_t vw_cluster_node_list(vw_cluster_t *ctx, vw_node_record_t **out_recs,
                               uint32_t *out_count)
{
    (void)ctx;
    *out_recs = NULL;
    *out_count = 0;
    return VW_OK;
}

vw_err_t vw_cluster_repair_fetch(vw_cluster_t *ctx, uint64_t node_id,
                                  const uint8_t hash[VW_HASH_BYTES],
                                  uint32_t timeout_ms,
                                  uint8_t **out_data, uint32_t *out_len)
{
    (void)ctx; (void)node_id; (void)hash; (void)timeout_ms;
    (void)out_data; (void)out_len;
    return VW_ERR_NOT_FOUND;
}

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <dirent.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Temp-dir helpers (same pattern as test_vw_gc.c) ──────────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_scrubtest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_scrubtest_%u_%s", VW_PID(), label);
    mkdir(out, 0700);
#endif
}

static void rm_rf(const char *dir)
{
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
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                rm_rf(child);
            else
                DeleteFileA(child);
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
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(child);
        else
            remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

/* ── Chunk-path / corruption helpers ──────────────────────────────────────── */

static void hash_to_hex(const uint8_t *hash, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < VW_HASH_BYTES; i++) {
        out[i * 2]     = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    out[VW_HASH_BYTES * 2] = '\0';
}

static void chunk_path(const char *data_dir, const uint8_t *hash,
                        char *out, size_t out_size)
{
    char hex[VW_HASH_BYTES * 2 + 1];
    hash_to_hex(hash, hex);
    snprintf(out, out_size, "%s/chunks/%.2s/%s.chunk", data_dir, hex, hex);
}

/* Flip the first byte of the file at path, corrupting it in place. */
static void corrupt_file(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f) { VW__FAIL("corrupt_file: fopen"); return; }
    int c = fgetc(f);
    if (c == EOF) { fclose(f); VW__FAIL("corrupt_file: fgetc"); return; }
    rewind(f);
    fputc(c ^ 0xFF, f);
    fclose(f);
}

/* ── Corrupt-callback capture ─────────────────────────────────────────────── */

typedef struct {
    int      called;
    uint8_t  hash[VW_HASH_BYTES];
} cb_capture_t;

static void capture_cb(const uint8_t hash[VW_HASH_BYTES], void *ud)
{
    cb_capture_t *c = (cb_capture_t *)ud;
    c->called++;
    memcpy(c->hash, hash, VW_HASH_BYTES);
}

/* ── Test suite ───────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_scrub") {
    VW_ASSERT_OK(vw_crypto_init());

    VW_TEST_CASE("scrub_run finds no corruption on a clean store") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "clean");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        uint8_t data[256];
        memset(data, 0x42, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), 1));

        vw_storage_scrub_stats_t stats;
        cb_capture_t cap = {0};
        VW_ASSERT_OK(vw_storage_scrub_run(st, capture_cb, &cap, &stats));
        VW_ASSERT_EQ(stats.scanned, 1u);
        VW_ASSERT_EQ(stats.corrupt, 0u);
        VW_ASSERT_EQ(stats.tombstoned, 0u);
        VW_ASSERT_EQ(cap.called, 0);

        vw_storage_close(st);
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("scrub_run detects a corrupted still-referenced chunk") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "corrupt");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        uint8_t data[256];
        memset(data, 0x7A, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), 1));
        /* chunk_put_impl doesn't pre-establish a reference (TASK-180) —
         * addref it so ref_count > 0, matching a real committed file. */
        VW_ASSERT_OK(vw_storage_chunk_addref(st, hash));

        char path[768];
        chunk_path(tmpdir, hash, path, sizeof(path));
        corrupt_file(path);

        vw_storage_scrub_stats_t stats;
        cb_capture_t cap = {0};
        VW_ASSERT_OK(vw_storage_scrub_run(st, capture_cb, &cap, &stats));
        VW_ASSERT_EQ(stats.scanned, 1u);
        VW_ASSERT_EQ(stats.corrupt, 1u);
        VW_ASSERT_EQ(stats.tombstoned, 0u);
        VW_ASSERT_EQ(cap.called, 1);
        VW_ASSERT_MEM_EQ(cap.hash, hash, VW_HASH_BYTES);

        vw_storage_close(st);
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("scrub_run never flags a ref_count==0 tombstone as corrupt") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "tombstone");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        uint8_t data[256];
        memset(data, 0x11, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), 1));
        /* ref_count starts at 0 (TASK-180) — never addref'd here, so this
         * chunk is already in the legitimate-tombstone state (present on
         * disk, ref_count == 0) without needing a GC pass to get there. */

        char path[768];
        chunk_path(tmpdir, hash, path, sizeof(path));
        corrupt_file(path);

        vw_storage_scrub_stats_t stats;
        cb_capture_t cap = {0};
        VW_ASSERT_OK(vw_storage_scrub_run(st, capture_cb, &cap, &stats));
        VW_ASSERT_EQ(stats.scanned, 1u);
        VW_ASSERT_EQ(stats.corrupt, 0u);
        VW_ASSERT_EQ(stats.tombstoned, 1u);
        VW_ASSERT_EQ(cap.called, 0);

        vw_storage_close(st);
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("vw_scrub module wires run_once through to get_last_stats") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "module");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        uint8_t data[256];
        memset(data, 0x99, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), 1));

        vw_scrub_cfg_t cfg = {0}; /* interval_secs = 0: never auto-starts */
        vw_scrub_ctx_t *scrub = NULL;
        VW_ASSERT_OK(vw_scrub_create(&cfg, st, NULL, NULL, &scrub));

        vw_storage_scrub_stats_t stats;
        int64_t last_run = -1;
        vw_scrub_get_last_stats(scrub, &stats, &last_run);
        VW_ASSERT_EQ(last_run, 0); /* never run yet */

        VW_ASSERT_OK(vw_scrub_run_once(scrub));
        vw_scrub_get_last_stats(scrub, &stats, &last_run);
        VW_ASSERT_NE(last_run, 0);
        VW_ASSERT_EQ(stats.scanned, 1u);
        VW_ASSERT_EQ(stats.corrupt, 0u);

        vw_scrub_destroy(scrub);
        vw_storage_close(st);
        rm_rf(tmpdir);
    }
}
VW_TEST_SUITE_END()
