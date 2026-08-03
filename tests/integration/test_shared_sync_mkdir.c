/*
 * test_shared_sync_mkdir.c — regression tests for TASK-113 (shared-folder
 * sync auto-creates a locally-new subdirectory's missing server-side
 * counterpart, instead of retrying the same no-op forever).
 *
 * Companion to test_shared_sync.c (TASK-106) and test_shared_sync_hardening.c
 * (TASK-111). Covers:
 *
 *   1. An EDIT grantee creates a new local subdirectory (including a
 *      *nested* one, two levels deep) inside a synced shared folder and
 *      adds files to it. Before TASK-113, srv_collect_by_id's dirmap never
 *      gained an entry for a directory with no server-side counterpart, so
 *      the upload action's parent_dir_id stayed 0 forever — this proves
 *      resolve_or_create_dir() now issues FILE_MKDIR (recursively, for
 *      however many missing ancestor levels) and the files land in the
 *      right place server-side, within a single sync cycle.
 *
 *   2. A VIEW-only grantee who creates a local subdirectory (with TWO
 *      sibling files in it, to exercise memoization — one FILE_MKDIR
 *      attempt and one counted outcome for the directory, not one per
 *      file) gets a clear, distinct signal (vw_sync_permission_denied_count,
 *      checked for an EXACT count, and vw_sync_action_error_count checked
 *      as EXACTLY zero — this pairing is what caught a real double-
 *      counting bug during this task's own CQR.08 review, where a stale
 *      TASK-112 fallback branch in exec_action was still counting the same
 *      already-classified outcome a second time) rather than being
 *      silently indistinguishable from any other action failure. The
 *      attempted FILE_MKDIR is actually rejected server-side for both
 *      files (no unauthorized write happens for either), the sync cycle
 *      still completes cleanly, and the folder is NOT auto-paused (this is
 *      a per-item permission problem, not a share-wide one).
 *
 * Usage: test_shared_sync_mkdir <host> <port> <cert_path>
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
#else
#  include <sys/stat.h>
#  include <unistd.h>
#  define VW_PID() ((unsigned)getpid())
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
    snprintf(out, sz, "%svw_sharedmkdir_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_sharedmkdir_%u", VW_PID());
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

static void folder_pause_state(vw_cache_t *cache, const char *local_root,
                                int *out_found, int *out_paused) {
    vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
    *out_found = 0; *out_paused = 0;
    if (vw_cache_folder_list(cache, &folders, &nf) != VW_OK) return;
    for (uint32_t i = 0; i < nf; i++) {
        if (strcmp(folders[i].local_root, local_root) == 0) {
            *out_found  = 1;
            *out_paused = folders[i].paused ? 1 : 0;
            break;
        }
    }
    free(folders);
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

    /* ══════════════════════════════════════════════════════════════════════
     * Scenario 1: EDIT grantee — a new local subdirectory (one level, plus
     * a nested two-level one) auto-creates its missing server-side
     * counterpart(s) and the files land in the right place, in one cycle.
     * ══════════════════════════════════════════════════════════════════════ */

    uint64_t edit_root_id = 0;
    err = vw_client_file_mkdir(owner_sess, 0, "edit_root", &edit_root_id);
    CHECK(err == VW_OK && edit_root_id != 0, "owner: mkdir edit_root");

    uint64_t edit_share_id = 0;
    err = vw_client_share_grant(owner_sess, edit_root_id, grantee_user, VW_PERM_EDIT, 0, &edit_share_id);
    CHECK(err == VW_OK && edit_share_id != 0, "owner: grant EDIT on edit_root to grantee");

    char edit_state_dir[512], edit_local_root[512];
    path_join(edit_state_dir,  sizeof(edit_state_dir),  tmpdir, "edit_state");
    path_join(edit_local_root, sizeof(edit_local_root), tmpdir, "edit_local");
    vw_fs_ensure_dir(edit_state_dir);
    vw_fs_ensure_dir(edit_local_root);

    vw_cache_t *edit_cache = NULL;
    err = vw_cache_open(edit_state_dir, &edit_cache);
    CHECK(err == VW_OK, "grantee: open EDIT-scenario cache");

    vw_sync_folder_t edit_sf;
    memset(&edit_sf, 0, sizeof(edit_sf));
    snprintf(edit_sf.local_root,   sizeof(edit_sf.local_root),   "%s", edit_local_root);
    snprintf(edit_sf.virtual_root, sizeof(edit_sf.virtual_root), "%s", "/editmkdir");
    edit_sf.remote_dir_id = edit_root_id;
    err = vw_cache_folder_add(edit_cache, &edit_sf);
    CHECK(err == VW_OK, "grantee: register EDIT-scenario sync folder");

    vw_sync_cfg_t edit_scfg;
    memset(&edit_scfg, 0, sizeof(edit_scfg));
    edit_scfg.sess      = grantee_sess;
    edit_scfg.cache     = edit_cache;
    edit_scfg.state_dir = edit_state_dir;
    vw_sync_ctx_t *edit_sync_ctx = NULL;
    err = vw_sync_open(&edit_scfg, &edit_sync_ctx);
    CHECK(err == VW_OK, "grantee: open EDIT-scenario sync context");

    /* One-level-new subdirectory */
    char newsub_dir[600], newsub_file[600];
    path_join(newsub_dir, sizeof(newsub_dir), edit_local_root, "newsub");
    vw_fs_ensure_dir(newsub_dir);
    path_join(newsub_file, sizeof(newsub_file), newsub_dir, "f.txt");
    write_bytes(newsub_file, "one level deep");

    /* Two-levels-new nested subdirectory, exercising recursive ancestor
     * creation within a single resolve_or_create_dir call. */
    char deep_dir[600], deeper_dir[600], deeper_file[600];
    path_join(deep_dir,   sizeof(deep_dir),   edit_local_root, "deep");
    path_join(deeper_dir, sizeof(deeper_dir), deep_dir,        "deeper");
    vw_fs_ensure_dir(deep_dir);
    vw_fs_ensure_dir(deeper_dir);
    path_join(deeper_file, sizeof(deeper_file), deeper_dir, "f2.txt");
    write_bytes(deeper_file, "two levels deep");

    err = vw_sync_run(edit_sync_ctx);
    CHECK(err == VW_OK, "grantee: sync_run auto-creating new subdirectories returns cleanly");

    CHECK(vw_sync_permission_denied_count(edit_sync_ctx) == 0,
          "grantee: EDIT grantee sees zero permission-denied auto-mkdir attempts");
    CHECK(vw_sync_action_error_count(edit_sync_ctx) == 0,
          "grantee: a successful auto-mkdir is not counted as an action error");

    vw_file_entry_t stat_entry;
    err = vw_client_file_stat(owner_sess, "/edit_root/newsub/f.txt", &stat_entry);
    CHECK(err == VW_OK, "owner: one-level newsub/f.txt landed server-side");

    err = vw_client_file_stat(owner_sess, "/edit_root/deep/deeper/f2.txt", &stat_entry);
    CHECK(err == VW_OK, "owner: two-level deep/deeper/f2.txt landed server-side "
                         "(recursive ancestor auto-creation)");

    vw_sync_close(edit_sync_ctx);
    vw_cache_close(edit_cache);

    /* ══════════════════════════════════════════════════════════════════════
     * Scenario 2: VIEW-only grantee — a new local subdirectory must not be
     * silently created server-side, must surface a distinct permission-
     * denied signal (not the generic action-error count), must not hang
     * or error out the sync cycle, and must not auto-pause the folder
     * (this is a per-item problem, not a share-wide one).
     * ══════════════════════════════════════════════════════════════════════ */

    uint64_t view_root_id = 0;
    err = vw_client_file_mkdir(owner_sess, 0, "view_root", &view_root_id);
    CHECK(err == VW_OK && view_root_id != 0, "owner: mkdir view_root");

    uint64_t view_share_id = 0;
    err = vw_client_share_grant(owner_sess, view_root_id, grantee_user, VW_PERM_VIEW, 0, &view_share_id);
    CHECK(err == VW_OK && view_share_id != 0, "owner: grant VIEW (only) on view_root to grantee");

    char view_state_dir[512], view_local_root[512];
    path_join(view_state_dir,  sizeof(view_state_dir),  tmpdir, "view_state");
    path_join(view_local_root, sizeof(view_local_root), tmpdir, "view_local");
    vw_fs_ensure_dir(view_state_dir);
    vw_fs_ensure_dir(view_local_root);

    vw_cache_t *view_cache = NULL;
    err = vw_cache_open(view_state_dir, &view_cache);
    CHECK(err == VW_OK, "grantee: open VIEW-scenario cache");

    vw_sync_folder_t view_sf;
    memset(&view_sf, 0, sizeof(view_sf));
    snprintf(view_sf.local_root,   sizeof(view_sf.local_root),   "%s", view_local_root);
    snprintf(view_sf.virtual_root, sizeof(view_sf.virtual_root), "%s", "/viewmkdir");
    view_sf.remote_dir_id = view_root_id;
    err = vw_cache_folder_add(view_cache, &view_sf);
    CHECK(err == VW_OK, "grantee: register VIEW-scenario sync folder");

    vw_sync_cfg_t view_scfg;
    memset(&view_scfg, 0, sizeof(view_scfg));
    view_scfg.sess      = grantee_sess;
    view_scfg.cache     = view_cache;
    view_scfg.state_dir = view_state_dir;
    vw_sync_ctx_t *view_sync_ctx = NULL;
    err = vw_sync_open(&view_scfg, &view_sync_ctx);
    CHECK(err == VW_OK, "grantee: open VIEW-scenario sync context");

    /* Two sibling files under the same new, permission-denied subdirectory
     * — proves resolve_or_create_dir's memoization: exactly ONE FILE_MKDIR
     * attempt (and one counted outcome) for the directory, not one per
     * file (CQR.08 finding on this task's own review). */
    char vsub_dir[600], vsub_file[600], vsub_file2[600];
    path_join(vsub_dir, sizeof(vsub_dir), view_local_root, "vsub");
    vw_fs_ensure_dir(vsub_dir);
    path_join(vsub_file, sizeof(vsub_file), vsub_dir, "vf.txt");
    write_bytes(vsub_file, "should never reach the server");
    path_join(vsub_file2, sizeof(vsub_file2), vsub_dir, "vf2.txt");
    write_bytes(vsub_file2, "neither should this one");

    err = vw_sync_run(view_sync_ctx);
    CHECK(err == VW_OK, "grantee: VIEW-only sync_run over a locally-new subdirectory "
                         "returns cleanly (no hang/crash)");

    CHECK(vw_sync_permission_denied_count(view_sync_ctx) == 1,
          "grantee: exactly ONE permission-denied count for the directory, "
          "not one per sibling file (memoization) and not undercounted");
    CHECK(vw_sync_action_error_count(view_sync_ctx) == 0,
          "grantee: permission denial does NOT also double-count as a "
          "generic action error (CQR.08 finding on this task's review)");

    err = vw_client_file_stat(owner_sess, "/view_root/vsub/vf.txt", &stat_entry);
    CHECK(err == VW_ERR_NOT_FOUND,
          "owner: vsub/vf.txt was NOT created server-side (no unauthorized write)");
    err = vw_client_file_stat(owner_sess, "/view_root/vsub/vf2.txt", &stat_entry);
    CHECK(err == VW_ERR_NOT_FOUND,
          "owner: vsub/vf2.txt was NOT created server-side either");

    int found = 0, paused = 0;
    folder_pause_state(view_cache, view_local_root, &found, &paused);
    CHECK(found, "grantee: VIEW-scenario folder still listed");
    CHECK(!paused,
          "grantee: folder NOT auto-paused for a per-item permission denial "
          "(this is not a share-wide revocation)");

    vw_sync_close(view_sync_ctx);
    vw_cache_close(view_cache);

    /* ── Cleanup ── */

    vw_client_close(owner_sess);
    vw_client_close(grantee_sess);

    vw_fs_delete(newsub_file);
    vw_fs_delete(deeper_file);
    vw_fs_delete(vsub_file);
    vw_fs_delete(vsub_file2);
    {
        char p[600];
        path_join(p, sizeof(p), edit_state_dir, "cache.db");         vw_fs_delete(p);
        path_join(p, sizeof(p), edit_state_dir, "sync_folders.db");  vw_fs_delete(p);
        path_join(p, sizeof(p), edit_state_dir, "offline_queue.db"); vw_fs_delete(p);
        path_join(p, sizeof(p), view_state_dir, "cache.db");         vw_fs_delete(p);
        path_join(p, sizeof(p), view_state_dir, "sync_folders.db");  vw_fs_delete(p);
        path_join(p, sizeof(p), view_state_dir, "offline_queue.db"); vw_fs_delete(p);
    }

    printf("1..%d\n", g_checks);
    return g_failed ? 1 : 0;
}
