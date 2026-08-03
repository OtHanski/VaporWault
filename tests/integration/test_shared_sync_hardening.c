/*
 * test_shared_sync_hardening.c — regression tests for TASK-111 (two advisory
 * hardening findings from TASK-106's independent review, see TODO/TASK-111.md).
 *
 * Companion to test_shared_sync.c (TASK-106's own lifecycle test, which
 * already covers initial/incremental sync, grantee-created files, and that
 * a genuine root-level revocation auto-pauses the folder with
 * VW_PAUSE_REASON_REVOKED). This file covers the two gaps TASK-111 closes:
 *
 *   1. Revocation-detection was coarser than "revocation": ANY
 *      NOT_FOUND/PERMISSION from srv_collect_by_id — even for a
 *      subdirectory discovered moments earlier in the same BFS pass — used
 *      to pause the whole folder. A subdirectory the owner deletes mid-
 *      cycle (a benign TOCTOU race, not a revocation) must NOT pause the
 *      folder. Reproducing the real race deterministically (rather than
 *      racing real threads against real network timing, which would make
 *      this test flaky) uses vw_sync_test_before_list_dir — a hook
 *      compiled in only via VW_SYNC_TEST_HOOKS (see this binary's CMake
 *      target) — to delete the subdirectory for real, synchronously, at
 *      the exact instant srv_collect_by_id is about to list it. The
 *      resulting NOT_FOUND is genuine server behavior, not mocked.
 *
 *   2. srv_collect_by_id had no ceiling on total directories/entries walked
 *      for a shared folder — a folder owner controls that tree's shape,
 *      not the grantee. VW_SHARED_TREE_MAX_ITEMS (env override, only read
 *      in builds that define VW_SYNC_TEST_HOOKS) lets this test exercise
 *      the cap cheaply instead of creating 65535+ real entries over the
 *      wire. Covered by two scenarios: a single FILE_LIST_BY_ID call that
 *      alone exceeds the cap, and a multi-directory tree where no single
 *      call exceeds it but the cumulative total across three separate
 *      calls does — proving the ceiling tracks running totals correctly,
 *      not just a single call's entry count.
 *
 * Usage: test_shared_sync_hardening <host> <port> <cert_path>
 *          <owner_user> <owner_pass> <grantee_user> <grantee_pass>
 * (cert_path is accepted for symmetry with the Python fixtures but unused,
 * same rationale as test_shared_sync.c.)
 */

#include "vw_client_core.h"
#include "vw_cache.h"
#include "vw_sync.h"
#include "vw_fs.h"
#include "vw_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
static void set_env(const char *name, const char *value) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s=%s", name, value);
    _putenv(buf);
}
#else
#  include <sys/stat.h>
#  include <unistd.h>
#  define VW_PID() ((unsigned)getpid())
static void set_env(const char *name, const char *value) {
    setenv(name, value, 1);
}
#endif

/* ── Minimal TAP-ish harness (mirrors test_shared_sync.c) ────────────────── */

static int g_checks = 0, g_failed = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        g_checks++;                                                         \
        if (cond) {                                                         \
            printf("ok %d - %s\n", g_checks, msg);                           \
        } else {                                                             \
            printf("not ok %d - %s\n", g_checks, msg);                       \
            printf("  # FAILED at %s:%d\n", __FILE__, __LINE__);             \
            g_failed++;                                                      \
        }                                                                    \
    } while (0)

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_sharedhard_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_sharedhard_%u", VW_PID());
    mkdir(out, 0700);
#endif
}

static void path_join(char *out, size_t sz, const char *dir, const char *name) {
#ifdef _WIN32
    snprintf(out, sz, "%s\\%s", dir, name);
#else
    snprintf(out, sz, "%s/%s", dir, name);
#endif
}

static int write_bytes(const char *path, const char *data) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t len = strlen(data);
    size_t written = len ? fwrite(data, 1, len, f) : 0;
    fclose(f);
    return (written == len) ? 0 : -1;
}

/* Finds a folder's paused/pause_reason by local_root. *out_found = 0 if absent. */
static void folder_pause_state(vw_cache_t *cache, const char *local_root,
                                int *out_found, int *out_paused, int *out_reason) {
    vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
    *out_found = 0; *out_paused = 0; *out_reason = -1;
    if (vw_cache_folder_list(cache, &folders, &nf) != VW_OK) return;
    for (uint32_t i = 0; i < nf; i++) {
        if (strcmp(folders[i].local_root, local_root) == 0) {
            *out_found  = 1;
            *out_paused = folders[i].paused ? 1 : 0;
            *out_reason = (int)folders[i].pause_reason;
            break;
        }
    }
    free(folders);
}

/* ── Test-hook glue (finding #1: non-root TOCTOU race) ───────────────────── */

static vw_client_sess_t *g_hook_owner_sess = NULL;
static uint64_t          g_hook_victim_id  = 0;
static int               g_hook_fired      = 0;
static vw_err_t          g_hook_delete_err = VW_ERR_INVALID_ARG;

static void before_list_dir_delete_victim(const char *vpath, uint64_t dir_id) {
    (void)vpath;
    if (dir_id == g_hook_victim_id && !g_hook_fired) {
        g_hook_fired = 1;
        /* Delete the subdirectory for real, right as srv_collect_by_id is
         * about to list it — this is the exact TOCTOU window a genuine
         * concurrent owner delete would land in. Capture the result: if
         * this delete ever silently failed, the subsequent FILE_LIST_BY_ID
         * would find the directory still there and return VW_OK, and the
         * "not paused" assertion below would pass vacuously without ever
         * exercising the fix — CQR.08 finding on TASK-111's review. */
        g_hook_delete_err = vw_client_file_delete_by_id(g_hook_owner_sess, dir_id);
    }
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (argc < 8) {
        fprintf(stderr,
                "usage: %s <host> <port> <cert_path> <owner_user> <owner_pass> "
                "<grantee_user> <grantee_pass>\n", argv[0]);
        return 2;
    }
    const char *host          = argv[1];
    uint16_t    port          = (uint16_t)atoi(argv[2]);
    const char *owner_user    = argv[4];
    const char *owner_pass    = argv[5];
    const char *grantee_user  = argv[6];
    const char *grantee_pass  = argv[7];

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");

    if (vw_crypto_init() != VW_OK) {
        fprintf(stderr, "vw_crypto_init failed\n");
        return 1;
    }

    /* Small cap so the ceiling test doesn't need 65535+ real entries. */
    set_env("VW_SHARED_TREE_MAX_ITEMS", "5");

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));

    vw_client_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host             = host;
    cfg.port             = port;
    cfg.cert_verify      = VW_CERT_VERIFY_NONE;
    cfg.ca_cert_pem_path = NULL;
    cfg.conn_opts        = NULL;

    vw_client_sess_t *owner_sess = NULL;
    vw_err_t err = vw_client_connect(&cfg, owner_user, (uint16_t)strlen(owner_user),
                                      owner_pass, strlen(owner_pass), NULL, NULL, &owner_sess);
    CHECK(err == VW_OK, "owner: connect/login");
    if (err != VW_OK) return 1;

    vw_client_sess_t *grantee_sess = NULL;
    err = vw_client_connect(&cfg, grantee_user, (uint16_t)strlen(grantee_user),
                             grantee_pass, strlen(grantee_pass), NULL, NULL, &grantee_sess);
    CHECK(err == VW_OK, "grantee: connect/login");
    if (err != VW_OK) return 1;

    g_hook_owner_sess = owner_sess;

    /* ══════════════════════════════════════════════════════════════════════
     * Scenario 1: a subdirectory deleted mid-BFS (benign race) must NOT
     * pause the folder — only a root-level NOT_FOUND/PERMISSION may.
     * ══════════════════════════════════════════════════════════════════════ */

    uint64_t race_root_id = 0;
    err = vw_client_file_mkdir(owner_sess, 0, "race_root", &race_root_id);
    CHECK(err == VW_OK && race_root_id != 0, "owner: mkdir race_root");

    uint64_t victim_id = 0;
    err = vw_client_file_mkdir(owner_sess, race_root_id, "victim", &victim_id);
    CHECK(err == VW_OK && victim_id != 0, "owner: mkdir race_root/victim");

    uint64_t race_share_id = 0;
    err = vw_client_share_grant(owner_sess, race_root_id, grantee_user, VW_PERM_EDIT, 0, &race_share_id);
    CHECK(err == VW_OK && race_share_id != 0, "owner: grant EDIT on race_root to grantee");

    char race_state_dir[512], race_local_root[512];
    path_join(race_state_dir,  sizeof(race_state_dir),  tmpdir, "race_state");
    path_join(race_local_root, sizeof(race_local_root), tmpdir, "race_local");
    vw_fs_ensure_dir(race_state_dir);
    vw_fs_ensure_dir(race_local_root);

    vw_cache_t *race_cache = NULL;
    err = vw_cache_open(race_state_dir, &race_cache);
    CHECK(err == VW_OK, "grantee: open race-scenario cache");

    vw_sync_folder_t race_sf;
    memset(&race_sf, 0, sizeof(race_sf));
    snprintf(race_sf.local_root,   sizeof(race_sf.local_root),   "%s", race_local_root);
    snprintf(race_sf.virtual_root, sizeof(race_sf.virtual_root), "%s", "/race");
    race_sf.remote_dir_id = race_root_id;
    err = vw_cache_folder_add(race_cache, &race_sf);
    CHECK(err == VW_OK, "grantee: register race-scenario sync folder");

    vw_sync_cfg_t race_scfg;
    memset(&race_scfg, 0, sizeof(race_scfg));
    race_scfg.sess      = grantee_sess;
    race_scfg.cache     = race_cache;
    race_scfg.state_dir = race_state_dir;
    vw_sync_ctx_t *race_sync_ctx = NULL;
    err = vw_sync_open(&race_scfg, &race_sync_ctx);
    CHECK(err == VW_OK, "grantee: open race-scenario sync context");

    g_hook_victim_id = victim_id;
    g_hook_fired     = 0;
    vw_sync_test_before_list_dir = before_list_dir_delete_victim;

    err = vw_sync_run(race_sync_ctx);
    CHECK(err == VW_OK, "grantee: sync_run during subdir delete race returns cleanly");

    vw_sync_test_before_list_dir = NULL;
    CHECK(g_hook_fired, "test harness: race hook actually fired (victim really raced)");
    CHECK(g_hook_delete_err == VW_OK,
          "test harness: race hook's delete actually succeeded (not a vacuous race)");

    int found = 0, paused = 0, reason = -1;
    folder_pause_state(race_cache, race_local_root, &found, &paused, &reason);
    CHECK(found, "grantee: race-scenario folder still listed after the race");
    CHECK(!paused,
          "grantee: folder NOT paused after a benign subdirectory delete race "
          "(TASK-111 fix: only a root-level failure pauses)");

    vw_sync_close(race_sync_ctx);
    vw_cache_close(race_cache);

    /* ══════════════════════════════════════════════════════════════════════
     * Scenario 2: a shared tree bigger than the (test-overridden) BFS
     * ceiling must auto-pause with VW_PAUSE_REASON_TREE_TOO_LARGE, distinct
     * from a revocation.
     * ══════════════════════════════════════════════════════════════════════ */

    uint64_t big_root_id = 0;
    err = vw_client_file_mkdir(owner_sess, 0, "big_root", &big_root_id);
    CHECK(err == VW_OK && big_root_id != 0, "owner: mkdir big_root");

    uint64_t big_share_id = 0;
    err = vw_client_share_grant(owner_sess, big_root_id, grantee_user, VW_PERM_EDIT, 0, &big_share_id);
    CHECK(err == VW_OK && big_share_id != 0, "owner: grant EDIT on big_root to grantee");

    /* 8 direct children > the test's overridden cap of 5. */
    int upload_ok = 1;
    for (int i = 0; i < 8; i++) {
        char local_path[600], vpath[64];
        snprintf(vpath, sizeof(vpath), "big_%d.txt", i);
        path_join(local_path, sizeof(local_path), tmpdir, vpath);
        write_bytes(local_path, "x");
        char full_vpath[128];
        snprintf(full_vpath, sizeof(full_vpath), "/big_root/big_%d.txt", i);
        if (vw_client_file_upload(owner_sess, full_vpath, local_path, NULL, NULL) != VW_OK)
            upload_ok = 0;
        vw_fs_delete(local_path);
    }
    CHECK(upload_ok, "owner: uploaded 8 files under big_root (> test cap of 5)");

    char big_state_dir[512], big_local_root[512];
    path_join(big_state_dir,  sizeof(big_state_dir),  tmpdir, "big_state");
    path_join(big_local_root, sizeof(big_local_root), tmpdir, "big_local");
    vw_fs_ensure_dir(big_state_dir);
    vw_fs_ensure_dir(big_local_root);

    vw_cache_t *big_cache = NULL;
    err = vw_cache_open(big_state_dir, &big_cache);
    CHECK(err == VW_OK, "grantee: open big-tree-scenario cache");

    vw_sync_folder_t big_sf;
    memset(&big_sf, 0, sizeof(big_sf));
    snprintf(big_sf.local_root,   sizeof(big_sf.local_root),   "%s", big_local_root);
    snprintf(big_sf.virtual_root, sizeof(big_sf.virtual_root), "%s", "/big");
    big_sf.remote_dir_id = big_root_id;
    err = vw_cache_folder_add(big_cache, &big_sf);
    CHECK(err == VW_OK, "grantee: register big-tree-scenario sync folder");

    vw_sync_cfg_t big_scfg;
    memset(&big_scfg, 0, sizeof(big_scfg));
    big_scfg.sess      = grantee_sess;
    big_scfg.cache     = big_cache;
    big_scfg.state_dir = big_state_dir;
    vw_sync_ctx_t *big_sync_ctx = NULL;
    err = vw_sync_open(&big_scfg, &big_sync_ctx);
    CHECK(err == VW_OK, "grantee: open big-tree-scenario sync context");

    err = vw_sync_run(big_sync_ctx);
    CHECK(err == VW_OK, "grantee: sync_run over an oversized shared tree returns cleanly");

    folder_pause_state(big_cache, big_local_root, &found, &paused, &reason);
    CHECK(found, "grantee: big-tree-scenario folder still listed");
    CHECK(paused, "grantee: folder auto-paused for an oversized shared tree");
    CHECK(reason == VW_PAUSE_REASON_TREE_TOO_LARGE,
          "grantee: pause_reason is VW_PAUSE_REASON_TREE_TOO_LARGE, "
          "not conflated with VW_PAUSE_REASON_REVOKED");

    vw_sync_close(big_sync_ctx);
    vw_cache_close(big_cache);

    /* ══════════════════════════════════════════════════════════════════════
     * Scenario 3: the ceiling must catch CUMULATIVE growth across several
     * FILE_LIST_BY_ID calls, not just a single oversized one (QA.06 finding
     * on TASK-111's review: scenario 2 alone only proves the first-call
     * case). Layout: multi_root/{sub_a,sub_b}, 3 files each. multi_root's
     * own listing (2 entries) stays under the cap of 5; sub_a's listing (3
     * entries) brings the running total to 5 (still not over); sub_b's
     * listing (3 more) is the one that finally pushes the cumulative total
     * to 8 — the third separate call, not the first.
     * ══════════════════════════════════════════════════════════════════════ */

    uint64_t multi_root_id = 0;
    err = vw_client_file_mkdir(owner_sess, 0, "multi_root", &multi_root_id);
    CHECK(err == VW_OK && multi_root_id != 0, "owner: mkdir multi_root");

    uint64_t sub_a_id = 0, sub_b_id = 0;
    err = vw_client_file_mkdir(owner_sess, multi_root_id, "sub_a", &sub_a_id);
    CHECK(err == VW_OK && sub_a_id != 0, "owner: mkdir multi_root/sub_a");
    err = vw_client_file_mkdir(owner_sess, multi_root_id, "sub_b", &sub_b_id);
    CHECK(err == VW_OK && sub_b_id != 0, "owner: mkdir multi_root/sub_b");

    int multi_upload_ok = 1;
    const char *subs[2] = { "sub_a", "sub_b" };
    for (int s = 0; s < 2; s++) {
        for (int i = 0; i < 3; i++) {
            char local_path[600], vpath[64], full_vpath[128];
            snprintf(vpath, sizeof(vpath), "multi_%s_%d.txt", subs[s], i);
            path_join(local_path, sizeof(local_path), tmpdir, vpath);
            write_bytes(local_path, "x");
            snprintf(full_vpath, sizeof(full_vpath), "/multi_root/%s/f%d.txt", subs[s], i);
            if (vw_client_file_upload(owner_sess, full_vpath, local_path, NULL, NULL) != VW_OK)
                multi_upload_ok = 0;
            vw_fs_delete(local_path);
        }
    }
    CHECK(multi_upload_ok, "owner: uploaded 3+3 files under multi_root/sub_a and sub_b");

    uint64_t multi_share_id = 0;
    err = vw_client_share_grant(owner_sess, multi_root_id, grantee_user, VW_PERM_EDIT, 0, &multi_share_id);
    CHECK(err == VW_OK && multi_share_id != 0, "owner: grant EDIT on multi_root to grantee");

    char multi_state_dir[512], multi_local_root[512];
    path_join(multi_state_dir,  sizeof(multi_state_dir),  tmpdir, "multi_state");
    path_join(multi_local_root, sizeof(multi_local_root), tmpdir, "multi_local");
    vw_fs_ensure_dir(multi_state_dir);
    vw_fs_ensure_dir(multi_local_root);

    vw_cache_t *multi_cache = NULL;
    err = vw_cache_open(multi_state_dir, &multi_cache);
    CHECK(err == VW_OK, "grantee: open multi-dir-scenario cache");

    vw_sync_folder_t multi_sf;
    memset(&multi_sf, 0, sizeof(multi_sf));
    snprintf(multi_sf.local_root,   sizeof(multi_sf.local_root),   "%s", multi_local_root);
    snprintf(multi_sf.virtual_root, sizeof(multi_sf.virtual_root), "%s", "/multi");
    multi_sf.remote_dir_id = multi_root_id;
    err = vw_cache_folder_add(multi_cache, &multi_sf);
    CHECK(err == VW_OK, "grantee: register multi-dir-scenario sync folder");

    vw_sync_cfg_t multi_scfg;
    memset(&multi_scfg, 0, sizeof(multi_scfg));
    multi_scfg.sess      = grantee_sess;
    multi_scfg.cache     = multi_cache;
    multi_scfg.state_dir = multi_state_dir;
    vw_sync_ctx_t *multi_sync_ctx = NULL;
    err = vw_sync_open(&multi_scfg, &multi_sync_ctx);
    CHECK(err == VW_OK, "grantee: open multi-dir-scenario sync context");

    err = vw_sync_run(multi_sync_ctx);
    CHECK(err == VW_OK, "grantee: sync_run over a cumulatively-oversized tree returns cleanly");

    folder_pause_state(multi_cache, multi_local_root, &found, &paused, &reason);
    CHECK(found, "grantee: multi-dir-scenario folder still listed");
    CHECK(paused, "grantee: folder auto-paused once cumulative entries across "
                  "multiple FILE_LIST_BY_ID calls exceed the ceiling");
    CHECK(reason == VW_PAUSE_REASON_TREE_TOO_LARGE,
          "grantee: cumulative-growth case also reports VW_PAUSE_REASON_TREE_TOO_LARGE");

    vw_sync_close(multi_sync_ctx);
    vw_cache_close(multi_cache);

    /* ── Cleanup ── */

    vw_client_close(owner_sess);
    vw_client_close(grantee_sess);

    {
        char p[600];
        path_join(p, sizeof(p), race_state_dir, "cache.db");         vw_fs_delete(p);
        path_join(p, sizeof(p), race_state_dir, "sync_folders.db");  vw_fs_delete(p);
        path_join(p, sizeof(p), race_state_dir, "offline_queue.db"); vw_fs_delete(p);
        path_join(p, sizeof(p), big_state_dir,  "cache.db");         vw_fs_delete(p);
        path_join(p, sizeof(p), big_state_dir,  "sync_folders.db");  vw_fs_delete(p);
        path_join(p, sizeof(p), big_state_dir,  "offline_queue.db"); vw_fs_delete(p);
        path_join(p, sizeof(p), multi_state_dir, "cache.db");         vw_fs_delete(p);
        path_join(p, sizeof(p), multi_state_dir, "sync_folders.db");  vw_fs_delete(p);
        path_join(p, sizeof(p), multi_state_dir, "offline_queue.db"); vw_fs_delete(p);
    }

    printf("1..%d\n", g_checks);
    return g_failed ? 1 : 0;
}
