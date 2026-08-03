/*
 * test_shared_sync.c — integration test for TASK-106 (sync engine awareness
 * of shared folders).
 *
 * Like test_vault_e2ee.c, this connects to a real, already-running
 * vapourwaultd (spawned by the pytest wrapper test_shared_sync.py) and
 * exercises the real production code — here vw_sync.c's shared-folder
 * branch (srv_collect_by_id/dirmap, action_t's file_id/parent_dir_id/shared,
 * exec_action's id-addressed calls) plus vw_cache.c's remote_dir_id field,
 * driven directly rather than through the daemon/IPC layer (there is no
 * standalone unit test for vw_sync.c at all — see TODO/TASK-106.md's notes
 * on why: coverage for this module has always come from integration-level
 * exercise, not unit tests, and this file continues that pattern for the
 * shared-folder branch specifically).
 *
 * Exercises TASK-106's stated acceptance criteria:
 *   - initial sync of a shared folder (grantee has never seen it before)
 *   - incremental sync after the owner adds a new file AND modifies an
 *     existing one (the latter specifically exercises the TASK-109
 *     mtime/size workaround in compute_actions — FILE_LIST_RESP's
 *     always-zero version_id would otherwise make this undetectable)
 *   - a grantee-created file inside the shared folder reaches the server
 *     under the folder owner's ownership (vw_client_file_upload_into_folder)
 *   - a grantee-modified already-synced file updates the existing file_id
 *     in place (vw_client_file_upload_to_id), not a duplicate create
 *   - sync behavior immediately after the share is revoked: no crash/hang,
 *     and the affected sync folder auto-pauses rather than retrying forever
 *
 * Usage: test_shared_sync <host> <port> <cert_path>
 *          <owner_user> <owner_pass> <grantee_user> <grantee_pass>
 * (cert_path is accepted for symmetry with the Python fixtures but unused,
 * same rationale as test_vault_e2ee.c.)
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

/* ── Minimal TAP-ish harness (mirrors test_vault_e2ee.c) ─────────────────── */

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

/* ── Temp-dir / file helpers (adapted from test_vault_e2ee.c) ────────────── */

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_sharedsync_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_sharedsync_%u", VW_PID());
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

static void rm_dir_best_effort(const char *dir) {
#ifdef _WIN32
    RemoveDirectoryA(dir);
#else
    rmdir(dir);
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

/* Returns 1 if path exists and its content equals `expected`, else 0. */
static int file_content_equals(const char *path, const char *expected) {
    void *buf = NULL; size_t len = 0;
    if (vw_fs_read_file(path, &buf, &len) != VW_OK) return 0;
    size_t elen = strlen(expected);
    int match = (len == elen) && (elen == 0 || memcmp(buf, expected, elen) == 0);
    free(buf);
    return match;
}

static int count_cb(const char *name, void *ud) { (void)name; *(int *)ud += 1; return 0; }

/* Counts entries in `dir` — used to catch a spurious extra file (e.g. a
 * bogus *.conflict.* artifact) that a correct sync cycle must not create. */
static int count_dir_entries(const char *dir) {
    int count = 0;
    vw_fs_list_dir(dir, count_cb, &count);
    return count;
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

    /* ── Owner: create the shared folder + an initial file, grant EDIT ── */

    vw_client_sess_t *owner_sess = NULL;
    vw_err_t err = vw_client_connect(&cfg, owner_user, (uint16_t)strlen(owner_user),
                                      owner_pass, strlen(owner_pass), NULL, NULL, &owner_sess);
    CHECK(err == VW_OK, "owner: connect/login");
    if (err != VW_OK) return 1;

    uint64_t folder_id = 0;
    err = vw_client_file_mkdir(owner_sess, 0, "shared_root", &folder_id);
    CHECK(err == VW_OK && folder_id != 0, "owner: mkdir shared_root");

    char orig_local[600];
    path_join(orig_local, sizeof(orig_local), tmpdir, "orig_owner.txt");
    write_bytes(orig_local, "hello v1");
    err = vw_client_file_upload(owner_sess, "/shared_root/orig.txt", orig_local, NULL, NULL);
    CHECK(err == VW_OK, "owner: upload orig.txt v1");

    uint64_t share_id = 0;
    err = vw_client_share_grant(owner_sess, folder_id, grantee_user, VW_PERM_EDIT, 0, &share_id);
    CHECK(err == VW_OK && share_id != 0, "owner: grant EDIT on shared_root to grantee");

    /* ── Grantee: set up a sync folder rooted at the shared item's file_id ── */

    vw_client_sess_t *grantee_sess = NULL;
    err = vw_client_connect(&cfg, grantee_user, (uint16_t)strlen(grantee_user),
                             grantee_pass, strlen(grantee_pass), NULL, NULL, &grantee_sess);
    CHECK(err == VW_OK, "grantee: connect/login");
    if (err != VW_OK) return 1;

    char state_dir[512], local_root[512];
    path_join(state_dir,  sizeof(state_dir),  tmpdir, "grantee_state");
    path_join(local_root, sizeof(local_root), tmpdir, "grantee_local");
    vw_fs_ensure_dir(state_dir);
    vw_fs_ensure_dir(local_root);

    vw_cache_t *cache = NULL;
    err = vw_cache_open(state_dir, &cache);
    CHECK(err == VW_OK, "grantee: open cache");

    vw_sync_folder_t sf;
    memset(&sf, 0, sizeof(sf));
    snprintf(sf.local_root,   sizeof(sf.local_root),   "%s", local_root);
    snprintf(sf.virtual_root, sizeof(sf.virtual_root), "%s", "/shared");
    sf.remote_dir_id = folder_id;
    err = vw_cache_folder_add(cache, &sf);
    CHECK(err == VW_OK, "grantee: register shared sync folder (remote_dir_id set)");

    vw_sync_cfg_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.sess      = grantee_sess;
    scfg.cache     = cache;
    scfg.state_dir = state_dir;
    vw_sync_ctx_t *sync_ctx = NULL;
    err = vw_sync_open(&scfg, &sync_ctx);
    CHECK(err == VW_OK, "grantee: open sync context");

    /* ── Initial sync: orig.txt should appear locally ── */

    err = vw_sync_run(sync_ctx);
    CHECK(err == VW_OK, "grantee: initial sync_run succeeds");

    char down_orig[600];
    path_join(down_orig, sizeof(down_orig), local_root, "orig.txt");
    CHECK(file_content_equals(down_orig, "hello v1"),
          "grantee: orig.txt downloaded with correct v1 content (initial sync)");

    /* ── Incremental sync: owner modifies orig.txt and adds second.txt ── */

    write_bytes(orig_local, "hello v2 modified");
    err = vw_client_file_upload(owner_sess, "/shared_root/orig.txt", orig_local, NULL, NULL);
    CHECK(err == VW_OK, "owner: upload orig.txt v2 (modify)");

    char second_local[600];
    path_join(second_local, sizeof(second_local), tmpdir, "second_owner.txt");
    write_bytes(second_local, "second file content");
    err = vw_client_file_upload(owner_sess, "/shared_root/second.txt", second_local, NULL, NULL);
    CHECK(err == VW_OK, "owner: upload second.txt (new file)");

    err = vw_sync_run(sync_ctx);
    CHECK(err == VW_OK, "grantee: incremental sync_run succeeds");

    CHECK(file_content_equals(down_orig, "hello v2 modified"),
          "grantee: orig.txt content updated to v2 (TASK-109 mtime/size workaround)");

    char down_second[600];
    path_join(down_second, sizeof(down_second), local_root, "second.txt");
    CHECK(file_content_equals(down_second, "second file content"),
          "grantee: second.txt downloaded (new remote file detected)");

    /* ── Grantee creates a new local file inside the shared folder ── */

    char new_local[600];
    path_join(new_local, sizeof(new_local), local_root, "grantee_new.txt");
    write_bytes(new_local, "created by grantee");

    err = vw_sync_run(sync_ctx);
    CHECK(err == VW_OK, "grantee: sync_run after local create succeeds");

    vw_file_entry_t stat_entry;
    err = vw_client_file_stat(owner_sess, "/shared_root/grantee_new.txt", &stat_entry);
    CHECK(err == VW_OK, "owner: grantee-created file is visible under shared_root");

    /* ── Grantee modifies an already-synced file (update-by-id path) ── */

    write_bytes(down_second, "second file content, edited by grantee");
    err = vw_sync_run(sync_ctx);
    CHECK(err == VW_OK, "grantee: sync_run after local modify succeeds");

    /* Regression check (TASK-106 review finding #2): grantee_new.txt's
     * cache entry just got a real server_version_id from the upload two
     * cycles ago (update_cache_after_upload's FILE_STAT_BY_ID call), while
     * this cycle's FILE_LIST reports it with version_id always 0 — an
     * unconditional version_id comparison would spuriously flag it as
     * "changed" here even though nothing about it changed, producing an
     * unwanted extra download or, worse, a bogus *.conflict.* file (if this
     * cycle's Pass 1 had also marked it LOCAL_MOD/NEW_LOCAL). Confirm
     * neither happened: exactly 3 entries in local_root (orig.txt,
     * second.txt, grantee_new.txt — no spurious conflict artifact), and
     * grantee_new.txt's content is exactly what was written, untouched. */
    CHECK(count_dir_entries(local_root) == 3,
          "grantee: no spurious extra file in local_root after an unrelated sync cycle");
    CHECK(file_content_equals(new_local, "created by grantee"),
          "grantee: grantee_new.txt untouched by an unrelated sync cycle");

    char owner_check_local[600];
    path_join(owner_check_local, sizeof(owner_check_local), tmpdir, "owner_check.txt");
    err = vw_client_file_download(owner_sess, "/shared_root/second.txt", owner_check_local, NULL, NULL);
    CHECK(err == VW_OK, "owner: can re-download second.txt after grantee's edit");
    CHECK(file_content_equals(owner_check_local, "second file content, edited by grantee"),
          "owner: sees grantee's edit to second.txt (update-by-id, not a duplicate)");

    /* ── Revocation: sync must not crash/hang and must auto-pause the folder ── */

    err = vw_client_share_revoke(owner_sess, share_id);
    CHECK(err == VW_OK, "owner: revoke the grant");

    err = vw_sync_run(sync_ctx);
    CHECK(err == VW_OK, "grantee: sync_run after revocation returns cleanly (no hang/crash)");

    vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
    err = vw_cache_folder_list(cache, &folders, &nf);
    CHECK(err == VW_OK, "grantee: can list sync folders after revocation");
    int found_paused = 0, found_reason = -1;
    for (uint32_t i = 0; i < nf; i++) {
        if (strcmp(folders[i].local_root, local_root) == 0) {
            found_paused = folders[i].paused ? 1 : 0;
            found_reason = (int)folders[i].pause_reason;
            break;
        }
    }
    CHECK(found_paused, "grantee: shared folder auto-paused after revocation");
    /* TASK-111: a root-level revocation must record VW_PAUSE_REASON_REVOKED
     * specifically, not be conflated with (e.g.) the BFS-size-ceiling
     * reason — see test_shared_sync_hardening.c for that scenario. */
    CHECK(found_reason == VW_PAUSE_REASON_REVOKED,
          "grantee: pause_reason is VW_PAUSE_REASON_REVOKED after revocation");
    free(folders);

    vw_sync_close(sync_ctx);
    vw_cache_close(cache);
    vw_client_close(owner_sess);
    vw_client_close(grantee_sess);

    /* ── Best-effort cleanup (mirrors test_vault_e2ee.c) ── */
    vw_fs_delete(orig_local);
    vw_fs_delete(second_local);
    vw_fs_delete(owner_check_local);
    vw_fs_delete(down_orig);
    vw_fs_delete(down_second);
    vw_fs_delete(new_local);
    {
        char p[600];
        path_join(p, sizeof(p), state_dir, "cache.db");         vw_fs_delete(p);
        path_join(p, sizeof(p), state_dir, "sync_folders.db");  vw_fs_delete(p);
        path_join(p, sizeof(p), state_dir, "offline_queue.db"); vw_fs_delete(p);
    }
    rm_dir_best_effort(local_root);
    rm_dir_best_effort(state_dir);
    rm_dir_best_effort(tmpdir);

    printf("1..%d\n", g_checks);
    return g_failed ? 1 : 0;
}
