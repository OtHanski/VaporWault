/*
 * test_repair_pipeline.c — integration test for TASK-260.
 *
 * Exercises vw_repair_chunk end to end, per that task's own acceptance
 * criteria:
 *   TC-1: corrupt one member of a sealed parity group with an otherwise
 *         intact group -> local Reed-Solomon reconstruction repairs it,
 *         no cluster/network involved (vw_repair_chunk(..., NULL, ...)).
 *   TC-2: corrupt a second member of that same group (exceeding
 *         single-fault redundancy) with a live, connected replica that
 *         holds a clean copy of one of the corrupted hashes -> the
 *         pipeline falls through to cluster replica-fetch and repairs it
 *         from there instead.
 *   TC-3: corrupt a member with NEITHER local redundancy NOR any replica
 *         holding a clean copy -> vw_repair_chunk cleanly returns
 *         VW_ERR_NOT_FOUND (still corrupt on disk, not served, no crash).
 *
 * Compiled with VW_ECC_MAX_DATA_SHARDS overridden small (see
 * tests/integration/CMakeLists.txt), same reasoning as
 * test_vw_storage_parity.c. Primary+replica pairing machinery duplicated
 * from test_cluster_repair_fetch.c per this project's own established
 * precedent for small test scaffolding (see that file's own comments) —
 * not worth a shared header for two ~500-line integration tests.
 *
 * Build/run on WSL or another real POSIX target — see
 * test_cluster_repair_fetch.c's file header for why (a firewall-blocked
 * all-interfaces listener has been observed in at least one sandboxed
 * Windows dev environment; unrelated to code correctness).
 */

#include "vw_test.h"

#include "vw_cluster.h"
#include "vw_repair.h"
#include "vw_oplog.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_ecc.h"
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

/* ── Embedded test certificate — same one test_cluster_repair_fetch.c
 * generated (EC P-256, self-signed, SAN covers 127.0.0.1/localhost). ── */

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

#define TEST_CLUSTER_PORT 43920u

/* ── Temp-dir helpers ──────────────────────────────────────────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_repairpipe_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_repairpipe_%u_%s", VW_PID(), label);
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

static int write_file_content(const char *path, const char *content)
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

static uint32_t g_rng_state = 0xC0FFEEu;
static uint32_t next_rand(void)
{
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 17;
    g_rng_state ^= g_rng_state << 5;
    return g_rng_state;
}
static void fill_random(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (uint8_t)(next_rand() & 0xFF);
}

/* Same on-disk convention as vw_storage.c's own build_chunk_path — a
 * duplicate here since that helper is file-static there. */
static void chunk_file_path(const char *data_dir, const uint8_t *hash,
                             char *out, size_t out_size)
{
    static const char hexch[] = "0123456789abcdef";
    char hex[VW_HASH_BYTES * 2 + 1];
    size_t i;
    for (i = 0; i < VW_HASH_BYTES; i++) {
        hex[i * 2]     = hexch[hash[i] >> 4];
        hex[i * 2 + 1] = hexch[hash[i] & 0xF];
    }
    hex[VW_HASH_BYTES * 2] = '\0';
    snprintf(out, out_size, "%s/chunks/%.2s/%s.chunk", data_dir, hex, hex);
}

/* Flip the first byte of the chunk file on disk for hash — corrupts it
 * in place, the same way test_vw_scrub.c does. */
static void corrupt_chunk_on_disk(const char *data_dir, const uint8_t *hash)
{
    char path[800];
    chunk_file_path(data_dir, hash, path, sizeof(path));
    FILE *f = fopen(path, "r+b");
    if (!f) { VW__FAIL("corrupt_chunk_on_disk: fopen"); return; }
    int c = fgetc(f);
    if (c == EOF) { fclose(f); VW__FAIL("corrupt_chunk_on_disk: fgetc"); return; }
    rewind(f);
    fputc(c ^ 0xFF, f);
    fclose(f);
}

/* ── One node's full stack ────────────────────────────────────────────────── */

typedef struct {
    char             tmpdir[512];
    char             data_dir[560];
    vw_oplog_t      *oplog;
    vw_store_t      *store;
    vw_file_store_t *file_store;
    vw_storage_t    *chunks;
    vw_cluster_t    *cluster;
} node_stack_t;

static void node_stack_open(node_stack_t *n, const char *label,
                             const char *cert_path, const char *key_path,
                             const vw_cluster_cfg_t *cfg)
{
    make_tmpdir(n->tmpdir, sizeof(n->tmpdir), label);

    char oplog_dir[560];
    path_join(oplog_dir, sizeof(oplog_dir), n->tmpdir, "oplog");
    path_join(n->data_dir, sizeof(n->data_dir), n->tmpdir, "data");

    VW_ASSERT_OK(vw_oplog_open(oplog_dir, &n->oplog));
    VW_ASSERT_OK(vw_store_open(n->data_dir, n->oplog, &n->store));
    VW_ASSERT_OK(vw_file_store_open(n->data_dir, n->oplog, &n->file_store));
    VW_ASSERT_OK(vw_storage_open(n->data_dir, &n->chunks));

    VW_ASSERT_OK(vw_cluster_open(n->data_dir, cfg, cert_path, key_path,
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

/* Upload + commit (put then addref — matches the real FILE_COMMIT flow
 * and TASK-263's addref-time parity registration) k distinct chunks into
 * st, filling exactly one parity group. Returns the k hashes/lens/data
 * via caller-supplied arrays (already sized VW_ECC_MAX_DATA_SHARDS). */
static void seal_one_group(vw_storage_t *st,
                            uint8_t hashes[][VW_HASH_BYTES],
                            uint8_t *datas[], uint32_t lens[])
{
    uint32_t k = VW_ECC_MAX_DATA_SHARDS;
    uint32_t i;
    for (i = 0; i < k; i++) {
        lens[i] = 300 + i * 37;
        datas[i] = (uint8_t *)malloc(lens[i]);
        fill_random(datas[i], lens[i]);
        VW_ASSERT_OK(vw_crypto_sha256(datas[i], lens[i], hashes[i]));
        VW_ASSERT_OK(vw_storage_chunk_put(st, hashes[i], datas[i], lens[i], 1));
        VW_ASSERT_OK(vw_storage_chunk_addref(st, hashes[i]));
    }
    VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 1);
}

VW_TEST_SUITE("repair_pipeline") {
    VW_ASSERT_OK(vw_crypto_init());
    vw_ecc_init();

    char tmproot[512];
    make_tmpdir(tmproot, sizeof(tmproot), "root");
    char cert_path[560], key_path[560];
    path_join(cert_path, sizeof(cert_path), tmproot, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmproot, "test_key.pem");
    VW_ASSERT(write_file_content(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file_content(key_path,  TEST_KEY_PEM)  == 0);

    /* ── Primary ─────────────────────────────────────────────────────── */
    vw_cluster_cfg_t primary_cfg;
    memset(&primary_cfg, 0, sizeof(primary_cfg));
    primary_cfg.cluster_port = (uint16_t)TEST_CLUSTER_PORT;

    node_stack_t primary;
    node_stack_open(&primary, "primary", cert_path, key_path, &primary_cfg);
    VW_ASSERT_OK(vw_cluster_start(primary.cluster));

    uint64_t node_id = 0;
    uint8_t  token[32];
    VW_ASSERT_OK(vw_cluster_node_add(primary.cluster, "test-replica",
                                      VW_NODE_ROLE_REPLICA, &node_id, token));

    /* ── Replica ─────────────────────────────────────────────────────── */
    vw_cluster_cfg_t replica_cfg;
    memset(&replica_cfg, 0, sizeof(replica_cfg));
    replica_cfg.is_replica = 1;
    snprintf(replica_cfg.primary_host, sizeof(replica_cfg.primary_host), "127.0.0.1");
    replica_cfg.primary_cluster_port       = (uint16_t)TEST_CLUSTER_PORT;
    replica_cfg.replica_poll_interval_secs = 1;

    node_stack_t replica;
    node_stack_open(&replica, "replica", cert_path, key_path, &replica_cfg);
    VW_ASSERT_OK(vw_cluster_node_add_self(replica.cluster, node_id, token, "test-replica"));
    memset(token, 0, sizeof(token));
    VW_ASSERT_OK(vw_cluster_start(replica.cluster));
    sleep_ms(300); /* let the replica connect; vw_cluster_repair_fetch's own timeout covers the rest */

    /* Seal one parity group of VW_ECC_MAX_DATA_SHARDS chunks on the primary. */
    uint8_t  hashes[VW_ECC_MAX_DATA_SHARDS][VW_HASH_BYTES];
    uint8_t *datas[VW_ECC_MAX_DATA_SHARDS];
    uint32_t lens[VW_ECC_MAX_DATA_SHARDS];
    seal_one_group(primary.chunks, hashes, datas, lens);

    /* ── TC-1: one corrupt member, intact group -> local repair ───────── */
    VW_TEST_CASE("single corruption in an intact group repairs locally, no cluster needed") {
        corrupt_chunk_on_disk(primary.data_dir, hashes[0]);

        VW_ASSERT_OK(vw_repair_chunk(primary.chunks, NULL, hashes[0]));

        uint8_t *out = NULL;
        uint32_t out_len = 0;
        VW_ASSERT_OK(vw_storage_chunk_get(primary.chunks, hashes[0], &out, &out_len));
        VW_ASSERT_EQ(out_len, lens[0]);
        VW_ASSERT_MEM_EQ(out, datas[0], lens[0]);
        free(out);
    }

    /* ── TC-2: two corrupt members, replica has one -> replica-fetch ──── */
    VW_TEST_CASE("second corruption exceeding local redundancy falls through to replica-fetch") {
        /* hashes[0] is already corrupt-then-repaired (clean again) from
         * TC-1. Corrupt hashes[1] AND hashes[2] now — two simultaneous
         * gaps, more than this group's single-parity redundancy can
         * locally cover. Seed the replica with a clean copy of
         * hashes[1] only (simulating it synced before corruption hit
         * the primary), so repairing hashes[1] must come from there. */
        corrupt_chunk_on_disk(primary.data_dir, hashes[1]);
        corrupt_chunk_on_disk(primary.data_dir, hashes[2]);

        /* Confirm local reconstruction really can't cover this before
         * relying on the cluster fallback. */
        uint8_t *local_out = NULL;
        uint32_t local_len = 0;
        VW_ASSERT_ERR(vw_storage_repair_local(primary.chunks, hashes[1], &local_out, &local_len),
                      VW_ERR_INVALID_ARG);
        free(local_out);

        VW_ASSERT_OK(vw_storage_chunk_put(replica.chunks, hashes[1], datas[1], lens[1], 1));

        VW_ASSERT_OK(vw_repair_chunk(primary.chunks, primary.cluster, hashes[1]));

        uint8_t *out = NULL;
        uint32_t out_len = 0;
        VW_ASSERT_OK(vw_storage_chunk_get(primary.chunks, hashes[1], &out, &out_len));
        VW_ASSERT_EQ(out_len, lens[1]);
        VW_ASSERT_MEM_EQ(out, datas[1], lens[1]);
        free(out);
    }

    /* ── TC-3: unrepairable — neither local nor any replica has it ─────── */
    VW_TEST_CASE("unrepairable corruption returns NOT_FOUND cleanly") {
        /* hashes[2] is still corrupt from TC-2, but by itself that's only
         * a single fault in the group again (TC-1/TC-2 already repaired
         * hashes[0]/[1] back to clean) — local reconstruction would
         * actually succeed for it now, which would test the wrong thing.
         * Corrupt hashes[3] too so the group has two simultaneous faults
         * again, and the replica has neither — genuinely unrepairable
         * by either path. */
        corrupt_chunk_on_disk(primary.data_dir, hashes[3]);

        VW_ASSERT_ERR(vw_repair_chunk(primary.chunks, primary.cluster, hashes[2]),
                      VW_ERR_NOT_FOUND);
    }

    {
        uint32_t i;
        for (i = 0; i < VW_ECC_MAX_DATA_SHARDS; i++) free(datas[i]);
    }
    node_stack_close(&replica);
    node_stack_close(&primary);
    rm_rf(tmproot);
}
VW_TEST_SUITE_END()
