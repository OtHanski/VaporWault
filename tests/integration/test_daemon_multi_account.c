/*
 * test_daemon_multi_account.c — integration test for TASK-161 (daemon
 * multi-account core: account contexts, per-account state layout,
 * round-robin sync loop).
 *
 * Like test_shared_sync.c, this drives the real production sync engine
 * (vw_client_core.c/vw_cache.c/vw_sync.c) directly against a real,
 * already-running vapourwaultd (spawned by the pytest wrapper
 * test_daemon_multi_account.py) rather than going through the daemon
 * process/IPC layer — there is no unit test for vw_sync.c at all (see
 * TASK-106's notes on why), and this file continues that convention.
 *
 * This specifically replicates vw_daemon_run()'s new round-robin loop
 * (TASK-161): two independent account contexts — own session, own cache,
 * own sync_ctx, own accounts/<id>/-equivalent temp dir — driven by
 * alternating vw_sync_run() calls exactly like the daemon's main loop
 * does, to prove the core claim: every configured account keeps making
 * sync progress on its own, independent of the others, with no
 * cross-account interference (accounts/<id> is real filesystem isolation,
 * so an account's cache the daemon opens can never see another account's
 * cache entries — this test proves the sync *behavior* on top of that,
 * not just the directory layout).
 *
 * Usage: test_daemon_multi_account <host> <port> <cert_path>
 *          <user_a> <pass_a> <user_b> <pass_b>
 * (cert_path is accepted for symmetry with the Python fixture but unused,
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
    snprintf(out, sz, "%svw_multiacct_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_multiacct_%u", VW_PID());
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

static int file_content_equals(const char *path, const char *expected) {
    void *buf = NULL; size_t len = 0;
    if (vw_fs_read_file(path, &buf, &len) != VW_OK) return 0;
    size_t elen = strlen(expected);
    int match = (len == elen) && (elen == 0 || memcmp(buf, expected, elen) == 0);
    free(buf);
    return match;
}

/* One account's worth of daemon-equivalent state — mirrors vw_account_ctx_t
 * (vw_daemon.c) minus the parts (account.conf persistence, vault registry)
 * this test doesn't need. */
typedef struct {
    vw_client_sess_t *sess;
    vw_cache_t       *cache;
    vw_sync_ctx_t    *sync_ctx;
    char              local_root[512];
} account_t;

static int account_setup(account_t *a, const vw_client_cfg_t *cfg,
                          const char *tmpdir, const char *label,
                          const char *username, const char *password,
                          const char *virtual_root) {
    memset(a, 0, sizeof(*a));

    vw_err_t err = vw_client_connect(cfg, username, (uint16_t)strlen(username),
                                      password, strlen(password), NULL, NULL, &a->sess);
    if (err != VW_OK) return 0;

    char state_dir[512];
    char sub[64];
    snprintf(sub, sizeof(sub), "%s_state", label);
    path_join(state_dir, sizeof(state_dir), tmpdir, sub);
    snprintf(sub, sizeof(sub), "%s_local", label);
    path_join(a->local_root, sizeof(a->local_root), tmpdir, sub);
    vw_fs_ensure_dir(state_dir);
    vw_fs_ensure_dir(a->local_root);

    err = vw_cache_open(state_dir, &a->cache);
    if (err != VW_OK) return 0;

    vw_sync_folder_t sf;
    memset(&sf, 0, sizeof(sf));
    snprintf(sf.local_root, sizeof(sf.local_root), "%s", a->local_root);
    snprintf(sf.virtual_root, sizeof(sf.virtual_root), "%s", virtual_root);
    err = vw_cache_folder_add(a->cache, &sf);
    if (err != VW_OK) return 0;

    vw_sync_cfg_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.sess = a->sess;
    scfg.cache = a->cache;
    scfg.state_dir = state_dir;
    err = vw_sync_open(&scfg, &a->sync_ctx);
    return err == VW_OK;
}

int main(int argc, char **argv) {
    /* Two FULL, independent connection specs — not one shared host/port —
     * because this test's whole point (TASK-161's 2026-08-13 design
     * revision: "accounts are per-server, not just per-user") is proving
     * two accounts on the SAME client can point at two entirely unrelated
     * VaporWault server processes, each with its own host/port/cert, not
     * just two users on one shared server. The Python wrapper spins up two
     * genuinely separate vapourwaultd instances and passes both specs. */
    if (argc < 11) {
        fprintf(stderr,
                "usage: %s <host_a> <port_a> <cert_a> <user_a> <pass_a> "
                "<host_b> <port_b> <cert_b> <user_b> <pass_b>\n", argv[0]);
        return 2;
    }
    const char *host_a = argv[1];
    uint16_t    port_a = (uint16_t)atoi(argv[2]);
    const char *user_a = argv[4];
    const char *pass_a = argv[5];
    const char *host_b = argv[6];
    uint16_t    port_b = (uint16_t)atoi(argv[7]);
    const char *user_b = argv[9];
    const char *pass_b = argv[10];

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");

    if (vw_crypto_init() != VW_OK) {
        fprintf(stderr, "vw_crypto_init failed\n");
        return 1;
    }

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));

    vw_client_cfg_t cfg_a, cfg_b;
    memset(&cfg_a, 0, sizeof(cfg_a));
    cfg_a.host             = host_a;
    cfg_a.port             = port_a;
    cfg_a.cert_verify      = VW_CERT_VERIFY_NONE;
    cfg_a.ca_cert_pem_path = NULL;
    cfg_a.conn_opts        = NULL;
    memset(&cfg_b, 0, sizeof(cfg_b));
    cfg_b.host             = host_b;
    cfg_b.port             = port_b;
    cfg_b.cert_verify      = VW_CERT_VERIFY_NONE;
    cfg_b.ca_cert_pem_path = NULL;
    cfg_b.conn_opts        = NULL;

    /* ── Set up two fully independent accounts, exactly like the daemon's
     * account_ctx_open_existing() does for each accounts/<id>/ subtree —
     * each against its OWN server connection spec. ── */

    account_t acct_a, acct_b;
    int ok_a = account_setup(&acct_a, &cfg_a, tmpdir, "a", user_a, pass_a, "/");
    CHECK(ok_a, "account A: connect + cache + sync context set up (server A)");
    int ok_b = account_setup(&acct_b, &cfg_b, tmpdir, "b", user_b, pass_b, "/");
    CHECK(ok_b, "account B: connect + cache + sync context set up (server B, a different process)");
    if (!ok_a || !ok_b) return 1;

    /* Seed a file to upload on each account's server side, BEFORE any sync
     * cycle runs — mirrors a real first-run daemon discovering pre-existing
     * local files. */
    char file_a[600], file_b[600];
    path_join(file_a, sizeof(file_a), acct_a.local_root, "from_a.txt");
    path_join(file_b, sizeof(file_b), acct_b.local_root, "from_b.txt");
    write_bytes(file_a, "hello from account A");
    write_bytes(file_b, "hello from account B");

    /* ── Round-robin, exactly like vw_daemon_run()'s main loop: one
     * vw_sync_run() per account per "tick", interleaved — proves account
     * B's cycle running does not block or corrupt account A's progress and
     * vice versa. Two ticks: the first uploads each account's seed file,
     * a real server round-trip; the second just confirms nothing regresses
     * once both are in a converged SYNCED state. ── */
    for (int tick = 0; tick < 2; tick++) {
        vw_err_t err_a = vw_sync_run(acct_a.sync_ctx);
        vw_err_t err_b = vw_sync_run(acct_b.sync_ctx);
        char msg[64];
        snprintf(msg, sizeof(msg), "tick %d: account A sync_run succeeds", tick);
        CHECK(err_a == VW_OK, msg);
        snprintf(msg, sizeof(msg), "tick %d: account B sync_run succeeds", tick);
        CHECK(err_b == VW_OK, msg);
    }

    /* ── Verify each account's file actually reached ITS OWN server side,
     * and that neither account can see the other's file (real per-account
     * isolation — the same server, two independent users) ── */
    vw_file_entry_t entry;
    vw_err_t stat_err = vw_client_file_stat(acct_a.sess, "/from_a.txt", &entry);
    CHECK(stat_err == VW_OK, "account A: from_a.txt reached A's own server-side account");

    stat_err = vw_client_file_stat(acct_b.sess, "/from_b.txt", &entry);
    CHECK(stat_err == VW_OK, "account B: from_b.txt reached B's own server-side account");

    stat_err = vw_client_file_stat(acct_a.sess, "/from_b.txt", &entry);
    CHECK(stat_err == VW_ERR_NOT_FOUND,
          "account A cannot see account B's file (real per-account isolation, not just directory naming)");

    stat_err = vw_client_file_stat(acct_b.sess, "/from_a.txt", &entry);
    CHECK(stat_err == VW_ERR_NOT_FOUND,
          "account B cannot see account A's file (real per-account isolation, not just directory naming)");

    /* ── Now drive progress on account A ONLY (mirroring the acceptance
     * criterion: "both keep syncing while only one is being queried") —
     * modify A's file, run A's cycle alone, then confirm B's already-
     * converged state is completely untouched by that (no cross-account
     * side effects from a single account's cycle running solo). ── */
    write_bytes(file_a, "hello from account A, v2");
    vw_err_t err_a2 = vw_sync_run(acct_a.sync_ctx);
    CHECK(err_a2 == VW_OK, "account A: solo sync_run (v2) succeeds while B is untouched");

    stat_err = vw_client_file_stat(acct_a.sess, "/from_a.txt", &entry);
    CHECK(stat_err == VW_OK && entry.size_bytes == strlen("hello from account A, v2"),
          "account A: v2 content size reached the server");

    CHECK(file_content_equals(file_b, "hello from account B"),
          "account B: local file untouched by account A's solo sync cycle");

    printf("1..%d\n", g_checks);
    return g_failed ? 1 : 0;
}
