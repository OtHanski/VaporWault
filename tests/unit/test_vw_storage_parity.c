/*
 * test_vw_storage_parity.c — integration tests for vw_storage's Phase 22
 * parity-group formation (TASK-258), on top of a real vw_storage_t chunk
 * store (not synthetic buffers — test_vw_ecc.c already covers the pure
 * codec in isolation).
 *
 * Compiled with VW_ECC_MAX_DATA_SHARDS overridden small (see
 * tests/unit/CMakeLists.txt) so a group seals after a handful of chunks
 * instead of 16, keeping this fast — VW_CHUNK_SIZE_DEFAULT itself is NOT
 * overridden (it isn't wrapped in an #ifndef in vw_proto.h, and doing so
 * just for this test isn't worth touching a shared, widely-used
 * constant); each seal still allocates/XORs real 4 MiB buffers per
 * member, which is fast enough in practice (bulk XOR over a few tens of
 * MB, no disk I/O beyond the small real chunk files and one ~4 MiB
 * parity file) to not matter for a unit test's runtime.
 *
 * Disclosed gap: this suite does not exercise vw_storage_open's
 * crash-mid-seal recovery path (a group left at exactly
 * VW_ECC_MAX_DATA_SHARDS members with no parity file, from a prior
 * process crashing between the last member's pgdb_append and
 * seal_group's parity write) — that path is internal (seal_group and the
 * recovery scan are both static to vw_storage.c) and reaching it from
 * outside would mean hand-constructing parity_groups.db's binary record
 * layout in this file, fragile to keep in sync with the real struct.
 * Reviewed by inspection instead; flagged here rather than silently
 * uncovered.
 */

#include "vw_test.h"
#include "vw_storage.h"
#include "vw_ecc.h"
#include "vw_crypto.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <dirent.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Temp-dir helpers (same pattern as test_vw_scrub.c) ──────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_paritytest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_paritytest_%u_%s", VW_PID(), label);
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

static uint32_t g_rng_state = 0x9e3779b9u;
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

/* Mirrors build_chunk_path's convention (vw_storage.c, static there):
 * {tmpdir}/chunks/{hex[0:2]}/{hex}.chunk — needed here (TASK-264) to
 * delete/restore a member's on-disk file directly, simulating the real
 * GC-race scenario that leaves a parity group stuck. */
static void chunk_file_path(char *out, size_t out_sz,
                             const char *tmpdir, const uint8_t hash[VW_HASH_BYTES])
{
    static const char hexch[] = "0123456789abcdef";
    char hex[VW_HASH_BYTES * 2 + 1];
    size_t i;
    for (i = 0; i < VW_HASH_BYTES; i++) {
        hex[i * 2]     = hexch[hash[i] >> 4];
        hex[i * 2 + 1] = hexch[hash[i] & 0xF];
    }
    hex[VW_HASH_BYTES * 2] = '\0';
    snprintf(out, out_sz, "%s/chunks/%.2s/%s.chunk", tmpdir, hex, hex);
}

VW_TEST_SUITE("vw_storage_parity") {
    VW_ASSERT_OK(vw_crypto_init());
    vw_ecc_init();

    VW_TEST_CASE("group seals after VW_ECC_MAX_DATA_SHARDS new chunks; dedup doesn't consume a slot") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "seal");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        const uint32_t k = VW_ECC_MAX_DATA_SHARDS;
        uint8_t hashes[16][VW_HASH_BYTES];
        uint8_t datas[16][300];
        uint32_t lens[16];
        uint32_t i;

        for (i = 0; i < k; i++) {
            lens[i] = 250 + (i * 7); /* distinct, non-uniform lengths */
            fill_random(datas[i], lens[i]);
            VW_ASSERT_OK(vw_crypto_sha256(datas[i], lens[i], hashes[i]));

            /* Registration now happens at first addref (FILE_COMMIT),
             * not at put (upload) time — see register_parity_member's
             * doc comment for why. vw_storage_chunk_put alone must never
             * seal a group. */
            VW_ASSERT_OK(vw_storage_chunk_put(st, hashes[i], datas[i], lens[i], 1));
            VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 0);

            int sealed_before = vw_storage_parity_group_is_sealed(st, 1);
            VW_ASSERT_OK(vw_storage_chunk_addref(st, hashes[i]));

            if (i + 1 < k) {
                VW_ASSERT_EQ(sealed_before, 0);
                VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 0);
            }
        }
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 1);

        /* Every member landed in group 1 at a unique slot matching its
         * upload order, with the real length recorded. */
        for (i = 0; i < k; i++) {
            vw_parity_membership_t m;
            VW_ASSERT_OK(vw_storage_parity_lookup(st, hashes[i], &m));
            VW_ASSERT_EQ(m.group_id, 1u);
            VW_ASSERT_EQ(m.slot_index, i);
            VW_ASSERT_EQ(m.chunk_len, lens[i]);
        }

        /* Re-uploading an already-known hash (dedup hit) plus a second
         * FILE_COMMIT addref against it (e.g. a second file referencing
         * the same content) must not create a second membership or
         * disturb group 1's sealed state — register_parity_member's
         * self-guard (already-registered => no-op) is what's under test
         * here now that addref, not put, drives registration. */
        VW_ASSERT_OK(vw_storage_chunk_put(st, hashes[0], datas[0], lens[0], 1));
        VW_ASSERT_OK(vw_storage_chunk_addref(st, hashes[0]));
        vw_parity_membership_t m0_again;
        VW_ASSERT_OK(vw_storage_parity_lookup(st, hashes[0], &m0_again));
        VW_ASSERT_EQ(m0_again.group_id, 1u);
        VW_ASSERT_EQ(m0_again.slot_index, 0u);
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 1);
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 2), 0);

        /* group_members reports all k, at the right slots. */
        uint8_t out_hashes[16][VW_HASH_BYTES];
        vw_parity_membership_t out_members[16];
        uint32_t out_count = 0;
        VW_ASSERT_OK(vw_storage_parity_group_members(st, 1, out_hashes, out_members, &out_count));
        VW_ASSERT_EQ(out_count, k);
        for (i = 0; i < k; i++) {
            VW_ASSERT_MEM_EQ(out_hashes[i], hashes[i], VW_HASH_BYTES);
            VW_ASSERT_EQ(out_members[i].chunk_len, lens[i]);
        }

        /* A fresh new chunk after the seal opens group 2, unsealed. */
        uint8_t hash_next[VW_HASH_BYTES], data_next[64];
        fill_random(data_next, sizeof(data_next));
        VW_ASSERT_OK(vw_crypto_sha256(data_next, sizeof(data_next), hash_next));
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash_next, data_next, sizeof(data_next), 1));
        VW_ASSERT_OK(vw_storage_chunk_addref(st, hash_next));
        vw_parity_membership_t m_next;
        VW_ASSERT_OK(vw_storage_parity_lookup(st, hash_next, &m_next));
        VW_ASSERT_EQ(m_next.group_id, 2u);
        VW_ASSERT_EQ(m_next.slot_index, 0u);
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 2), 0);

        /* Sealed group's parity shard is readable and full-size. */
        uint8_t *parity = NULL;
        uint32_t parity_len = 0;
        VW_ASSERT_OK(vw_storage_parity_shard_read(st, 1, &parity, &parity_len));
        VW_ASSERT_EQ(parity_len, (uint32_t)VW_CHUNK_SIZE_DEFAULT);
        free(parity);

        /* Reading an unsealed group's shard is a clean NOT_FOUND, not a crash. */
        uint8_t *no_parity = NULL;
        uint32_t no_len = 0;
        VW_ASSERT_ERR(vw_storage_parity_shard_read(st, 2, &no_parity, &no_len),
                      VW_ERR_NOT_FOUND);

        vw_storage_close(st);
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("reconstruct each real chunk in a sealed group from its siblings + parity") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "reconstruct");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        const uint32_t k = VW_ECC_MAX_DATA_SHARDS;
        uint8_t hashes[16][VW_HASH_BYTES];
        uint8_t *original_data[16];
        uint32_t lens[16];
        uint32_t i;

        for (i = 0; i < k; i++) {
            lens[i] = 1000 + i * 111;
            original_data[i] = (uint8_t *)malloc(lens[i]);
            fill_random(original_data[i], lens[i]);
            VW_ASSERT_OK(vw_crypto_sha256(original_data[i], lens[i], hashes[i]));
            VW_ASSERT_OK(vw_storage_chunk_put(st, hashes[i], original_data[i], lens[i], 1));
            VW_ASSERT_OK(vw_storage_chunk_addref(st, hashes[i])); /* FILE_COMMIT — registers the parity slot */
        }
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 1);

        uint8_t out_hashes[16][VW_HASH_BYTES];
        vw_parity_membership_t out_members[16];
        uint32_t member_count = 0;
        VW_ASSERT_OK(vw_storage_parity_group_members(st, 1, out_hashes, out_members, &member_count));
        VW_ASSERT_EQ(member_count, k);

        uint8_t *parity = NULL;
        uint32_t parity_len = 0;
        VW_ASSERT_OK(vw_storage_parity_shard_read(st, 1, &parity, &parity_len));

        uint32_t missing;
        for (missing = 0; missing < k; missing++) {
            uint8_t *padded[16];
            const uint8_t *shard_ptrs[16];
            uint32_t j;
            for (j = 0; j < k; j++) {
                if (j == missing) { padded[j] = NULL; shard_ptrs[j] = NULL; continue; }
                padded[j] = (uint8_t *)calloc(1, VW_CHUNK_SIZE_DEFAULT);
                uint8_t *data = NULL; uint32_t data_len = 0;
                VW_ASSERT_OK(vw_storage_chunk_get(st, out_hashes[j], &data, &data_len));
                VW_ASSERT_EQ(data_len, out_members[j].chunk_len);
                memcpy(padded[j], data, data_len);
                free(data);
                shard_ptrs[j] = padded[j];
            }

            uint8_t *reconstructed = (uint8_t *)malloc(VW_CHUNK_SIZE_DEFAULT);
            VW_ASSERT_OK(vw_ecc_decode_single(shard_ptrs, k, parity, missing,
                                               VW_CHUNK_SIZE_DEFAULT, reconstructed));
            VW_ASSERT_MEM_EQ(reconstructed, original_data[missing], lens[missing]);

            free(reconstructed);
            for (j = 0; j < k; j++) free(padded[j]);
        }

        free(parity);
        for (i = 0; i < k; i++) free(original_data[i]);
        vw_storage_close(st);
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("stuck group is detected and self-heals once the missing member is restored") {
        /* TASK-264: simulate the real scenario register_parity_member's
         * own doc comment discloses — a member legitimately deleted (a
         * GC sweep, simulated here by removing the file directly rather
         * than going through vw_storage_gc_run, which this test has no
         * need to exercise) while its group is still open, so the seal
         * attempt triggered by the group's last member fails and the
         * failure is silently discarded — leaving a "stuck" group: k
         * members recorded, no parity file, no longer the open group. */
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "stuck");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        const uint32_t k = VW_ECC_MAX_DATA_SHARDS;
        uint8_t hashes[16][VW_HASH_BYTES];
        uint8_t *original_data[16];
        uint32_t lens[16];
        uint32_t i;

        for (i = 0; i < k; i++) {
            lens[i] = 200 + i * 3;
            original_data[i] = (uint8_t *)malloc(lens[i]);
            fill_random(original_data[i], lens[i]);
            VW_ASSERT_OK(vw_crypto_sha256(original_data[i], lens[i], hashes[i]));
            VW_ASSERT_OK(vw_storage_chunk_put(st, hashes[i], original_data[i], lens[i], 1));

            if (i + 1 == k) {
                /* Delete member 0's chunk file right before this last
                 * addref triggers the group's seal attempt — member 0
                 * was already successfully registered by its own earlier
                 * addref call below, back when its file still existed. */
                char victim_path[600];
                chunk_file_path(victim_path, sizeof(victim_path), tmpdir, hashes[0]);
                VW_ASSERT_EQ(remove(victim_path), 0);
            }

            VW_ASSERT_OK(vw_storage_chunk_addref(st, hashes[i]));
        }

        /* Stuck: full member count, but never sealed, and no longer the
         * store's current open group (group 2 is, with 0 members). */
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 0);

        uint64_t stuck_ids[8];
        uint32_t stuck_count = 0;
        VW_ASSERT_OK(vw_storage_parity_stuck_groups(st, stuck_ids, 8, &stuck_count));
        VW_ASSERT_EQ(stuck_count, 1u);
        VW_ASSERT_EQ(stuck_ids[0], 1u);

        /* Retry while the cause is still present: fails cleanly, not a
         * crash, and does not fabricate a parity file over missing data. */
        VW_ASSERT_NE((int)vw_storage_parity_group_reseal(st, 1), (int)VW_OK);
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 0);

        /* Simulate the transient-cause-now-resolved case: restore member
         * 0's file with its exact original bytes. */
        {
            char victim_path[600];
            chunk_file_path(victim_path, sizeof(victim_path), tmpdir, hashes[0]);
            FILE *f = fopen(victim_path, "wb");
            VW_ASSERT(f != NULL);
            VW_ASSERT_EQ(fwrite(original_data[0], 1, lens[0], f), (size_t)lens[0]);
            fclose(f);
        }

        VW_ASSERT_OK(vw_storage_parity_group_reseal(st, 1));
        VW_ASSERT_EQ(vw_storage_parity_group_is_sealed(st, 1), 1);

        /* Healed: no longer reported as stuck. */
        stuck_count = 0xFFFFFFFFu;
        VW_ASSERT_OK(vw_storage_parity_stuck_groups(st, stuck_ids, 8, &stuck_count));
        VW_ASSERT_EQ(stuck_count, 0u);

        /* Idempotent: re-sealing an already-sealed group is a harmless no-op. */
        VW_ASSERT_OK(vw_storage_parity_group_reseal(st, 1));

        for (i = 0; i < k; i++) free(original_data[i]);
        vw_storage_close(st);
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("parity_lookup on a hash never assigned a group returns NOT_FOUND") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "unknown");
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));

        uint8_t bogus_hash[VW_HASH_BYTES];
        memset(bogus_hash, 0xAB, sizeof(bogus_hash));
        vw_parity_membership_t m;
        VW_ASSERT_ERR(vw_storage_parity_lookup(st, bogus_hash, &m), VW_ERR_NOT_FOUND);

        vw_storage_close(st);
        rm_rf(tmpdir);
    }
}
VW_TEST_SUITE_END()
