/*
 * test_vault_regression.c — E2EE regression suite for TASK-101.
 *
 * Companion to test_vault_e2ee.c (TASK-099's own acceptance test, which
 * already covers: single-chunk round-trip, unlock-from-scratch, wrong
 * passphrase rejection, same-vault DEK-freshness-per-version, and basic
 * chunk-upload-retry idempotency at a synthetic 64-byte scale). This file
 * covers the scope TASK-101 adds on top of that:
 *
 *   - Dedup-defeat: identical plaintext uploaded as a plain file AND as
 *     encrypted content in two DIFFERENT vaults never shares a chunk hash
 *     across any pair of the three.
 *   - Key-loss scoping: three vaults (two different passphrases, plus a
 *     third vault reusing one of those same passphrase VALUES but with
 *     its own independently-generated VK) — losing/forgetting one vault's
 *     passphrase must not affect any other vault's accessibility,
 *     including the one sharing the same passphrase text.
 *   - Multi-chunk round-trip: every existing test so far only exercised
 *     single-chunk (small) files. This uploads/downloads a file that
 *     spans two real VW_VAULT_PLAINTEXT_CHUNK_BYTES-sized chunks.
 *   - Retry/nonce-safety at realistic scale: encrypts a full-size
 *     (~4 MiB) chunk twice with the same DEK+chunk_index (simulating a
 *     dropped-connection retry of the *same* upload attempt, as opposed
 *     to test_vault_e2ee.c's whole-new-attempt-gets-a-fresh-DEK case) and
 *     confirms byte-identical (nonce, ciphertext, tag) plus idempotent
 *     re-upload — the direct regression test for the nonce-reuse gap that
 *     motivated HKDF(DEK, chunk_index) in docs/PROTOCOL.md §7.11.2.
 *
 * Server opacity (no plaintext/key material ever observable server-side)
 * is NOT checked here — it needs to read the server's raw on-disk storage,
 * which only the pytest wrapper (test_vault_regression.py) has a path to;
 * see that file for the actual scan. This binary uploads the distinctive
 * marker string that wrapper searches for.
 *
 * Version DEK freshness (two versions of one file get different wrapped
 * DEKs) is already covered by test_vault_e2ee.c and not repeated here.
 */

#include "vw_client_core.h"
#include "vw_vault.h"
#include "vw_crypto.h"
#include "vw_fs.h"

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

/* Must match test_vault_regression.py's MARKER constant exactly — the
 * server-opacity scan searches server-side storage for this literal
 * byte string. */
#define MARKER "VW_E2EE_REGRESSION_MARKER_98237456_do_not_change_without_updating_the_py_wrapper"

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
    snprintf(out, sz, "%svw_vaultregr_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_vaultregr_%u", VW_PID());
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

static int write_bytes(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t written = len ? fwrite(data, 1, len, f) : 0;
    fclose(f);
    return (written == len) ? 0 : -1;
}

static void rm_dir_best_effort(const char *dir) {
#ifdef _WIN32
    RemoveDirectoryA(dir);
#else
    rmdir(dir);
#endif
}

static int hashes_equal(const uint8_t *a, const uint8_t *b, uint32_t count) {
    return count > 0 && memcmp(a, b, (size_t)count * VW_HASH_BYTES) == 0;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s <host> <port> <cert_path> <username> <password>\n", argv[0]);
        return 2;
    }
    const char *host     = argv[1];
    uint16_t    port     = (uint16_t)atoi(argv[2]);
    const char *username = argv[4];
    const char *password = argv[5];

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");

    if (vw_crypto_init() != VW_OK) { fprintf(stderr, "vw_crypto_init failed\n"); return 1; }

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));

    vw_client_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = host; cfg.port = port; cfg.cert_verify = VW_CERT_VERIFY_NONE;

    vw_client_sess_t *sess = NULL;
    vw_err_t err = vw_client_connect(&cfg, username, (uint16_t)strlen(username),
                                      password, strlen(password), NULL, NULL, &sess);
    if (err != VW_OK) { fprintf(stderr, "connect/login failed: %d\n", (int)err); return 1; }

    /* ── Setup: two anchor directories, two vaults with different
     * passphrases (A, B), and a third vault reusing passphrase A's exact
     * text but with its own independently-generated VK (key-loss
     * scoping's "same passphrase, different vault" case). ── */
    uint64_t dir1 = 0, dir2 = 0, dir3 = 0;
    CHECK(vw_client_file_mkdir(sess, 0, "regr_dir1", &dir1) == VW_OK, "mkdir regr_dir1");
    CHECK(vw_client_file_mkdir(sess, 0, "regr_dir2", &dir2) == VW_OK, "mkdir regr_dir2");
    CHECK(vw_client_file_mkdir(sess, 0, "regr_dir3", &dir3) == VW_OK, "mkdir regr_dir3");

    const char *pass_a = "regression-passphrase-A";
    const char *pass_b = "regression-passphrase-B-different";

    vw_vault_t *vault_a = NULL, *vault_b = NULL, *vault_c = NULL;
    uint64_t vid_a = 0, vid_b = 0, vid_c = 0;
    CHECK(vw_vault_setup(sess, dir1, pass_a, strlen(pass_a), NULL, &vault_a, &vid_a) == VW_OK,
          "vault A setup (passphrase A)");
    CHECK(vw_vault_setup(sess, dir2, pass_b, strlen(pass_b), NULL, &vault_b, &vid_b) == VW_OK,
          "vault B setup (passphrase B)");
    CHECK(vw_vault_setup(sess, dir3, pass_a, strlen(pass_a), NULL, &vault_c, &vid_c) == VW_OK,
          "vault C setup (passphrase A again, independent VK)");
    CHECK(vid_a != vid_b && vid_a != vid_c && vid_b != vid_c,
          "all three vaults have distinct vault_ids");

    /* ── Dedup-defeat: identical plaintext, plain file + two vaults ── */
    char plain_local[600];
    path_join(plain_local, sizeof(plain_local), tmpdir, "dedup.bin");
    /* Deliberately does NOT contain MARKER: this content is uploaded both
     * as a genuinely-unencrypted plain file below (its plaintext is
     * SUPPOSED to be visible in server storage — that's correct, not a
     * violation) and as encrypted content. MARKER is reserved for content
     * that is ONLY EVER uploaded encrypted, further down, so the opacity
     * scan in test_vault_regression.py can check for its absence without
     * a false positive from this intentionally-plaintext control copy. */
    const char *dedup_content = "identical plaintext across plain+encrypted uploads";
    write_bytes(plain_local, dedup_content, strlen(dedup_content));

    err = vw_client_file_upload(sess, "/regr_plain.bin", plain_local, NULL, NULL);
    CHECK(err == VW_OK, "upload plaintext copy (unencrypted)");
    vw_file_entry_t plain_entry;
    vw_client_file_stat(sess, "/regr_plain.bin", &plain_entry);

    uint64_t fid_a = 0, ver_a = 0, fid_b = 0, ver_b = 0;
    err = vw_vault_upload_file(vault_a, sess, 0, "dedup.bin", plain_local, NULL, NULL, &fid_a, &ver_a);
    CHECK(err == VW_OK, "upload encrypted copy into vault A");
    err = vw_vault_upload_file(vault_b, sess, 0, "dedup.bin", plain_local, NULL, NULL, &fid_b, &ver_b);
    CHECK(err == VW_OK, "upload encrypted copy into vault B");

    uint8_t *h_plain = NULL, *h_a = NULL, *h_b = NULL;
    uint32_t cc_plain = 0, cc_a = 0, cc_b = 0;
    uint64_t vv = 0; uint8_t *wd = NULL; uint16_t wdl = 0;
    vw_client_version_chunks_raw(sess, plain_entry.version_id, &h_plain, &cc_plain, &vv, &wd, &wdl);
    free(wd); wd = NULL;
    vw_client_version_chunks_raw(sess, ver_a, &h_a, &cc_a, &vv, &wd, &wdl);
    free(wd); wd = NULL;
    vw_client_version_chunks_raw(sess, ver_b, &h_b, &cc_b, &vv, &wd, &wdl);
    free(wd); wd = NULL;

    CHECK(cc_plain == cc_a && cc_a == cc_b && cc_plain > 0, "all three uploads have the same chunk_count");
    CHECK(!hashes_equal(h_plain, h_a, cc_plain), "plain vs vault-A ciphertext: different chunk hash");
    CHECK(!hashes_equal(h_plain, h_b, cc_plain), "plain vs vault-B ciphertext: different chunk hash");
    CHECK(!hashes_equal(h_a, h_b, cc_plain), "vault-A vs vault-B ciphertext: different chunk hash (cross-vault dedup-defeat)");
    free(h_plain); free(h_a); free(h_b);

    /* ── Key-loss scoping ──
     * "Forget" vault A: attempting to unlock it with a wrong passphrase
     * fails (simulates the passphrase being lost — there is no local
     * cache to wipe in this test harness, so the loss is simulated by
     * simply never supplying the correct passphrase again). Vault B
     * (different passphrase) and vault C (SAME passphrase text as A, but
     * an independent VK) must remain fully accessible with their own
     * correct passphrases regardless. */
    vw_vault_t *vault_a_wrong = NULL;
    err = vw_vault_unlock(sess, vid_a, "not the real passphrase", 24, &vault_a_wrong);
    CHECK(err == VW_ERR_AUTH_BAD_CREDS, "vault A: wrong passphrase correctly rejected (simulated forgotten passphrase)");
    CHECK(vault_a_wrong == NULL, "vault A: rejected unlock returns no handle");

    vw_vault_t *vault_b2 = NULL, *vault_c2 = NULL;
    err = vw_vault_unlock(sess, vid_b, pass_b, strlen(pass_b), &vault_b2);
    CHECK(err == VW_OK, "vault B: still unlockable with its own correct passphrase after A's loss");
    err = vw_vault_unlock(sess, vid_c, pass_a, strlen(pass_a), &vault_c2);
    CHECK(err == VW_OK, "vault C: still unlockable with passphrase A's text (independent VK, unaffected by A's loss)");

    if (vault_b2) {
        char down_b[600];
        path_join(down_b, sizeof(down_b), tmpdir, "down_b.bin");
        err = vw_vault_download_file(vault_b2, sess, fid_b, down_b, NULL, NULL);
        CHECK(err == VW_OK, "vault B: file still downloads+decrypts correctly");
        void *buf = NULL; size_t len = 0;
        err = vw_fs_read_file(down_b, &buf, &len);
        CHECK(err == VW_OK && len == strlen(dedup_content) && memcmp(buf, dedup_content, len) == 0,
              "vault B: downloaded plaintext byte-identical");
        free(buf);
        vw_vault_close(vault_b2);
    }
    if (vault_c2) vw_vault_close(vault_c2);

    /* ── Server opacity marker ──
     * Uploads MARKER exclusively as encrypted content (into vault A) —
     * never as a plain file anywhere — so test_vault_regression.py's
     * black-box scan of the server's raw on-disk storage has a
     * meaningful, unambiguous absence to check for: if this string shows
     * up anywhere server-side, it can only have leaked from the encrypted
     * path. */
    {
        char marker_local[600];
        path_join(marker_local, sizeof(marker_local), tmpdir, "marker.bin");
        write_bytes(marker_local, MARKER, strlen(MARKER));
        uint64_t marker_fid = 0, marker_vid = 0;
        err = vw_vault_upload_file(vault_a, sess, 0, "marker.bin", marker_local, NULL, NULL,
                                    &marker_fid, &marker_vid);
        CHECK(err == VW_OK, "upload opacity-marker content (encrypted only, never plaintext)");
        vw_fs_delete(marker_local);
    }

    /* ── Multi-chunk round-trip (first time any test spans >1 chunk) ── */
    size_t big_len = (size_t)VW_VAULT_PLAINTEXT_CHUNK_BYTES + 12345u;
    uint8_t *big_buf = malloc(big_len);
    CHECK(big_buf != NULL, "allocate multi-chunk test buffer");
    if (big_buf) {
        for (size_t i = 0; i < big_len; i++) big_buf[i] = (uint8_t)(i % 251u);
        char big_local[600], big_down[600];
        path_join(big_local, sizeof(big_local), tmpdir, "big.bin");
        path_join(big_down, sizeof(big_down), tmpdir, "big_down.bin");
        write_bytes(big_local, big_buf, big_len);

        uint64_t big_fid = 0, big_vid = 0;
        err = vw_vault_upload_file(vault_a, sess, 0, "big.bin", big_local, NULL, NULL, &big_fid, &big_vid);
        CHECK(err == VW_OK, "multi-chunk encrypted upload succeeds");

        uint8_t *big_hashes = NULL; uint32_t big_cc = 0;
        vw_client_version_chunks_raw(sess, big_vid, &big_hashes, &big_cc, &vv, &wd, &wdl);
        free(wd); wd = NULL;
        CHECK(big_cc == 2, "multi-chunk upload produced exactly 2 chunks");
        free(big_hashes);

        err = vw_vault_download_file(vault_a, sess, big_fid, big_down, NULL, NULL);
        CHECK(err == VW_OK, "multi-chunk encrypted download succeeds");

        void *down_buf = NULL; size_t down_len = 0;
        err = vw_fs_read_file(big_down, &down_buf, &down_len);
        CHECK(err == VW_OK && down_len == big_len && memcmp(down_buf, big_buf, big_len) == 0,
              "multi-chunk round-trip byte-identical across the chunk boundary");
        free(down_buf);
        free(big_buf);
        vw_fs_delete(big_local);
        vw_fs_delete(big_down);
    }

    /* ── Retry/nonce-safety at realistic (~4 MiB) chunk scale ──
     * Simulates a dropped-connection retry of the SAME upload attempt
     * (same DEK, same chunk_index) — as opposed to test_vault_e2ee.c's
     * whole-new-attempt case, which gets a fresh DEK and is safe by
     * construction. This is the actual regression test for the
     * nonce-reuse gap: re-encrypting chunk 0 with the same dek must
     * reproduce the exact same nonce and ciphertext, so re-uploading it
     * is a true no-op, never a second distinct ciphertext under the same
     * (key, nonce) pair. */
    {
        uint8_t dek[VW_AES_GCM_KEY_BYTES];
        vw_crypto_random(dek, sizeof(dek));

        size_t pt_len = VW_VAULT_PLAINTEXT_CHUNK_BYTES;
        uint8_t *pt = malloc(pt_len);
        uint8_t *ct1 = malloc(pt_len + VW_AES_GCM_TAG_BYTES);
        uint8_t *ct2 = malloc(pt_len + VW_AES_GCM_TAG_BYTES);
        CHECK(pt && ct1 && ct2, "allocate full-size chunk buffers");
        if (pt && ct1 && ct2) {
            for (size_t i = 0; i < pt_len; i++) pt[i] = (uint8_t)((i * 7) % 256u);

            uint8_t nonce1[VW_AES_GCM_NONCE_BYTES], nonce2[VW_AES_GCM_NONCE_BYTES];
            vw_crypto_vault_chunk_nonce(dek, 0, nonce1);
            err = vw_crypto_aes256gcm_encrypt(dek, nonce1, NULL, 0, pt, pt_len, ct1, ct1 + pt_len);
            CHECK(err == VW_OK, "first encryption of full-size chunk 0 succeeds");

            /* Simulated retry: re-derive and re-encrypt from scratch. */
            vw_crypto_vault_chunk_nonce(dek, 0, nonce2);
            err = vw_crypto_aes256gcm_encrypt(dek, nonce2, NULL, 0, pt, pt_len, ct2, ct2 + pt_len);
            CHECK(err == VW_OK, "retry encryption of full-size chunk 0 succeeds");

            CHECK(memcmp(nonce1, nonce2, sizeof(nonce1)) == 0, "retry derives the identical nonce");
            CHECK(memcmp(ct1, ct2, pt_len + VW_AES_GCM_TAG_BYTES) == 0,
                  "retry produces byte-identical ciphertext+tag (no nonce-reuse-with-different-output)");

            uint8_t hash1[VW_HASH_BYTES], hash2[VW_HASH_BYTES];
            vw_crypto_sha256(ct1, pt_len + VW_AES_GCM_TAG_BYTES, hash1);
            vw_crypto_sha256(ct2, pt_len + VW_AES_GCM_TAG_BYTES, hash2);
            CHECK(memcmp(hash1, hash2, VW_HASH_BYTES) == 0, "retry's chunk hash matches the first attempt's");

            err = vw_client_chunk_upload_if_missing(sess, hash1, ct1, (uint32_t)(pt_len + VW_AES_GCM_TAG_BYTES));
            CHECK(err == VW_OK, "first upload of the full-size chunk succeeds");
            err = vw_client_chunk_upload_if_missing(sess, hash2, ct2, (uint32_t)(pt_len + VW_AES_GCM_TAG_BYTES));
            CHECK(err == VW_OK, "retried upload of the (identical) full-size chunk is idempotent");
        }
        free(pt); free(ct1); free(ct2);
        vw_crypto_secure_zero(dek, sizeof(dek));
    }

    vw_vault_close(vault_a);
    vw_vault_close(vault_b);
    vw_vault_close(vault_c);
    vw_client_close(sess);
    vw_crypto_cleanup();

    vw_fs_delete(plain_local);
    rm_dir_best_effort(tmpdir);

    printf("1..%d\n", g_checks);
    return (g_failed > 0) ? 1 : 0;
}
