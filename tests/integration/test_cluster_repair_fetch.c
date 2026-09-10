/*
 * test_cluster_repair_fetch.c — integration test for TASK-259.
 *
 * Stands up a real primary + replica pair (two full vw_cluster_t
 * contexts, real TLS listener, real NODE_HELLO pairing/handshake, real
 * primary_repl_loop/replica_repl_session threads — same machinery
 * test_cluster.py already exercises for ordinary oplog/file/chunk sync,
 * driven here from C since vw_cluster_repair_fetch has no wire-level
 * client exposure of its own to reach from Python) and exercises the new
 * CLUSTER_CHUNK_REPAIR_FETCH/_DATA round trip end to end:
 *
 *   TC-1: primary asks a connected replica for a chunk the replica has
 *         — gets back the correct, hash-verified bytes.
 *   TC-2: primary asks for a chunk the replica does NOT have — clean
 *         VW_ERR_NOT_FOUND, not a hang or crash.
 *   TC-3: primary asks a registered-but-never-connected node_id — times
 *         out cleanly (VW_ERR_TIMEOUT) rather than hanging forever.
 *
 * Deliberately seeds the chunk directly onto the replica's own local
 * chunk store (vw_storage_chunk_put) rather than driving the full
 * oplog-triggered file/chunk sync pass — that machinery is already
 * covered by test_cluster.py's own suite; this test's job is the new
 * repair-fetch primitive itself, which only cares that the replica's
 * local store has the chunk, however it got there.
 *
 * Build/run on WSL or another real POSIX target, not build-msvc-105
 * (same rule as everything under tests/integration/ — see
 * project_build_validation memory / CLAUDE.md's build notes): this
 * test's primary listener binds all interfaces
 * (vw_cluster_start -> vw_net_listen_cluster(NULL, ...), unlike
 * test_auth_handshake.c's explicit "127.0.0.1"), which at least one
 * sandboxed Windows dev environment has been observed to silently
 * firewall-block non-interactively, causing every connect attempt to
 * fail at the raw TCP level and (separately, on cleanup after many
 * failed-connect/backoff cycles) a crash in the replica's pre-existing
 * reconnect-backoff/shutdown path — not reproduced on a real POSIX
 * build, and not in any code this task touched (no repair-fetch code
 * ever runs if no connection ever succeeds). Passes cleanly and
 * completely on Linux, including under -Wall -Wextra -Wpedantic -Werror.
 */

#include "vw_test.h"

#include "vw_cluster.h"
#include "vw_oplog.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_crypto.h"
#include "vw_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Embedded test certificate (EC P-256, self-signed) ────────────────────
 *
 * NOT test_auth_handshake.c's embedded cert: that one has no SAN entries
 * (its own file header explains why it needs VW_CERT_VERIFY_NONE client
 * side). vw_cluster.c's replica connection always uses
 * VW_CERT_VERIFY_REQUIRED with no override (vw_cluster.c's own comment:
 * "TLS 1.3, certificate verification required" — not test-mode
 * relaxable), so this test needs a cert whose SAN actually covers
 * 127.0.0.1/localhost — the same property tests/integration/test.crt
 * (gen_test_cert.sh) has, generated fresh here rather than depending on
 * that external file's path (this binary may run directly, not just via
 * ctest from a known working directory).
 */

static const char TEST_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBtTCCAVugAwIBAgIUPTnsIZ15IoqtH/R64SORLgJzHVwwCgYIKoZIzj0EAwIw\n"
    "IjEgMB4GA1UEAwwXVmFwb3JXYXVsdCBDbHVzdGVyIFRlc3QwHhcNMjYwOTA5MTQy\n"
    "NDMzWhcNMzYwOTA2MTQyNDMzWjAiMSAwHgYDVQQDDBdWYXBvcldhdWx0IENsdXN0\n"
    "ZXIgVGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF/9QdVxssstL7ctkZgn\n"
    "XtQStAu7zWydMveNHqFAoMOFTn+PNd5FCqrwEIrRwgz/JDPyy8wWQk+2E9QzMGFv\n"
    "cqSjbzBtMB0GA1UdDgQWBBTn3Uz1wCW2E8ql/L2kYecmdHPCwDAfBgNVHSMEGDAW\n"
    "gBTn3Uz1wCW2E8ql/L2kYecmdHPCwDAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQT\n"
    "MBGHBH8AAAGCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNIADBFAiEAxaRZk+2p/8+w\n"
    "lkvwDP6A/ETP8y6d7pAZ4Jsqis4kzjACIE8TDu+VeEcweAUlaqCP4G7z3koXFZeh\n"
    "/fTJSw4M4OgM\n"
    "-----END CERTIFICATE-----\n";

static const char TEST_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgphfUV3+1R/i06bXs\n"
    "n4ridBuOyhtzMidejUm1Jx6bm0ehRANCAARf/UHVcbLLLS+3LZGYJ17UErQLu81s\n"
    "nTL3jR6hQKDDhU5/jzXeRQqq8BCK0cIM/yQz8svMFkJPthPUMzBhb3Kk\n"
    "-----END PRIVATE KEY-----\n";

#define TEST_CLUSTER_PORT 43910u

/* ── Temp-dir helpers (adapted from test_auth_handshake.c) ───────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_repairfetch_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_repairfetch_%u_%s", VW_PID(), label);
    mkdir(out, 0700);
#endif
}

static void rm_rf(const char *dir)
{
#ifdef _WIN32
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) goto rmdir_only;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char child[MAX_PATH];
        snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) rm_rf(child);
        else DeleteFileA(child);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
rmdir_only:
    RemoveDirectoryA(dir);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char child[600];
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

static void path_join(char *out, size_t sz, const char *base, const char *leaf)
{
    snprintf(out, sz, "%s/%s", base, leaf);
}

static int write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = strlen(content);
    size_t w = fwrite(content, 1, n, f);
    fclose(f);
    return (w == n) ? 0 : -1;
}

#ifdef _WIN32
static void sleep_ms(unsigned ms) { Sleep(ms); }
#else
static void sleep_ms(unsigned ms) { usleep((useconds_t)ms * 1000u); }
#endif

/* ── One node's full stack (oplog + store + file_store + chunks + cluster) ── */

typedef struct {
    char           tmpdir[512];
    vw_oplog_t     *oplog;
    vw_store_t     *store;
    vw_file_store_t *file_store;
    vw_storage_t   *chunks;
    vw_cluster_t   *cluster;
} node_stack_t;

static void node_stack_open(node_stack_t *n, const char *label,
                             const char *cert_path, const char *key_path,
                             const vw_cluster_cfg_t *cfg)
{
    make_tmpdir(n->tmpdir, sizeof(n->tmpdir), label);

    char oplog_dir[560], data_dir[560];
    path_join(oplog_dir, sizeof(oplog_dir), n->tmpdir, "oplog");
    path_join(data_dir,  sizeof(data_dir),  n->tmpdir, "data");

    VW_ASSERT_OK(vw_oplog_open(oplog_dir, &n->oplog));
    VW_ASSERT_OK(vw_store_open(data_dir, n->oplog, &n->store));
    VW_ASSERT_OK(vw_file_store_open(data_dir, n->oplog, &n->file_store));
    VW_ASSERT_OK(vw_storage_open(data_dir, &n->chunks));

    VW_ASSERT_OK(vw_cluster_open(data_dir, cfg, cert_path, key_path,
                                  n->oplog, n->store, n->file_store, n->chunks,
                                  NULL, NULL, &n->cluster));
}

static void node_stack_close(node_stack_t *n)
{
    vw_cluster_close(n->cluster);
    vw_storage_close(n->chunks);
    vw_file_store_close(n->file_store);
    vw_store_close(n->store);
    vw_oplog_close(n->oplog);
    rm_rf(n->tmpdir);
}

VW_TEST_SUITE("cluster_repair_fetch") {
    VW_ASSERT_OK(vw_crypto_init());

    char tmproot[512];
    make_tmpdir(tmproot, sizeof(tmproot), "root");
    char cert_path[560], key_path[560];
    path_join(cert_path, sizeof(cert_path), tmproot, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmproot, "test_key.pem");
    VW_ASSERT(write_file(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file(key_path,  TEST_KEY_PEM)  == 0);

    /* ── Primary ─────────────────────────────────────────────────────── */
    vw_cluster_cfg_t primary_cfg;
    memset(&primary_cfg, 0, sizeof(primary_cfg));
    primary_cfg.cluster_port = (uint16_t)TEST_CLUSTER_PORT;

    node_stack_t primary;
    node_stack_open(&primary, "primary", cert_path, key_path, &primary_cfg);
    VW_ASSERT_OK(vw_cluster_start(primary.cluster));

    /* Register a replica node on the primary. */
    uint64_t node_id = 0;
    uint8_t  token[32];
    VW_ASSERT_OK(vw_cluster_node_add(primary.cluster, "test-replica",
                                      VW_NODE_ROLE_REPLICA, &node_id, token));

    /* ── Replica ─────────────────────────────────────────────────────── */
    vw_cluster_cfg_t replica_cfg;
    memset(&replica_cfg, 0, sizeof(replica_cfg));
    replica_cfg.is_replica = 1;
    snprintf(replica_cfg.primary_host, sizeof(replica_cfg.primary_host), "127.0.0.1");
    replica_cfg.primary_cluster_port      = (uint16_t)TEST_CLUSTER_PORT;
    replica_cfg.replica_poll_interval_secs = 1; /* fast polling for a quick test */

    node_stack_t replica;
    node_stack_open(&replica, "replica", cert_path, key_path, &replica_cfg);
    VW_ASSERT_OK(vw_cluster_node_add_self(replica.cluster, node_id, token, "test-replica"));
    memset(token, 0, sizeof(token));
    VW_ASSERT_OK(vw_cluster_start(replica.cluster));

    /* No separate "is it connected yet" gate here: vw_cluster_has_active_
     * replicas only reflects nodes.db's admin-level is_active flag (true
     * from registration, regardless of live TCP state), and
     * sync_watermark only advances on a real OPLOG_ACK — which an idle
     * replica with nothing to sync never sends. vw_cluster_repair_fetch's
     * own timeout below is exactly the right tool for "wait for this
     * node's primary_repl_loop to actually be looping" — a short settle
     * sleep here just keeps the first test case's timeout budget mostly
     * for genuine connection setup rather than this test's own polling
     * overhead. */
    sleep_ms(300);

    /* ── TC-1: replica has the chunk — repair-fetch succeeds ──────────── */
    VW_TEST_CASE("repair-fetch returns hash-verified bytes from a connected replica") {
        uint8_t data[512];
        for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i * 7 + 3);
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));

        /* Seed directly onto the replica's own store — see file header
         * comment for why this test doesn't drive the full oplog/chunk
         * sync pass to get it there. */
        VW_ASSERT_OK(vw_storage_chunk_put(replica.chunks, hash, data, sizeof(data), 1));

        uint8_t *out_data = NULL;
        uint32_t out_len = 0;
        VW_ASSERT_OK(vw_cluster_repair_fetch(primary.cluster, node_id, hash,
                                              15000, &out_data, &out_len));
        VW_ASSERT_EQ(out_len, (uint32_t)sizeof(data));
        VW_ASSERT_MEM_EQ(out_data, data, sizeof(data));
        free(out_data);
    }

    /* ── TC-2: replica does NOT have the chunk — clean NOT_FOUND ──────── */
    VW_TEST_CASE("repair-fetch against a chunk the replica doesn't have returns NOT_FOUND") {
        uint8_t bogus_hash[VW_HASH_BYTES];
        memset(bogus_hash, 0xCD, sizeof(bogus_hash));

        uint8_t *out_data = NULL;
        uint32_t out_len = 0;
        VW_ASSERT_ERR(vw_cluster_repair_fetch(primary.cluster, node_id, bogus_hash,
                                               15000, &out_data, &out_len),
                      VW_ERR_NOT_FOUND);
    }

    /* ── TC-3: a registered-but-never-connected node_id times out ─────── */
    VW_TEST_CASE("repair-fetch against an unconnected node_id times out cleanly") {
        uint64_t ghost_node_id = 0;
        uint8_t  ghost_token[32];
        VW_ASSERT_OK(vw_cluster_node_add(primary.cluster, "ghost-replica",
                                          VW_NODE_ROLE_REPLICA, &ghost_node_id, ghost_token));
        memset(ghost_token, 0, sizeof(ghost_token));

        uint8_t hash[VW_HASH_BYTES];
        memset(hash, 0x11, sizeof(hash));
        uint8_t *out_data = NULL;
        uint32_t out_len = 0;
        /* Short timeout — this node never connects, so this must return
         * promptly rather than hang. */
        VW_ASSERT_ERR(vw_cluster_repair_fetch(primary.cluster, ghost_node_id, hash,
                                               600, &out_data, &out_len),
                      VW_ERR_TIMEOUT);
    }

    node_stack_close(&replica);
    node_stack_close(&primary);
    rm_rf(tmproot);
}
VW_TEST_SUITE_END()
