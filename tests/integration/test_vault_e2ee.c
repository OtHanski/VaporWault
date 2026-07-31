/*
 * test_vault_e2ee.c — integration test for TASK-099 (client vault module).
 *
 * Unlike test_auth_handshake.c, this does NOT self-host a server: it
 * connects to a real, already-running vapourwaultd (spawned by the
 * pytest wrapper test_vault_e2ee.py, which reuses the existing conftest.py
 * `server`/`admin_client` fixtures). This exercises the actual production
 * client code (vw_client_core.c + vw_vault.c) against the actual production
 * server code, closing the gap that neither test_vw_vault.c (server-side
 * storage, unit-level) nor test_vw_crypto.c (crypto primitives, unit-level)
 * nor test_vault.py (server wire behavior with meaningless opaque bytes)
 * cover on their own.
 *
 * Usage: test_vault_e2ee <host> <port> <cert_path> <username> <password>
 * (cert_path is accepted for symmetry with the Python fixtures but unused —
 * the client connects with VW_CERT_VERIFY_NONE, same as test_auth_handshake.c,
 * since the test cert has no SAN meaningful for verification.)
 *
 * Exercises the acceptance criteria from TODO/TASK-099.md:
 *   - byte-identical plaintext round-trip (upload -> download)
 *   - a new version of an encrypted file gets a genuinely new wrapped DEK
 *   - two different files, same vault, identical plaintext -> different
 *     ciphertext (per-file DEK, not per-vault)
 *   - re-uploading an already-uploaded chunk (retry simulation) is
 *     idempotent, not an error
 *   - vw_vault_unlock (new-device path) round-trips through the wire
 *     (VAULT_KEY_FETCH) rather than just the in-memory handle from setup
 *   - a wrong passphrase fails unlock with VW_ERR_AUTH_BAD_CREDS
 *
 * The remaining acceptance criterion — "the encryption passphrase never
 * appears in any wire message" — is a code-review claim, not something a
 * running test can prove by absence; see the CLI.02/SEC.07 notes in
 * TODO/TASK-099.md for that review.
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

/* ── Minimal TAP-ish harness (can't use vw_test.h: it generates its own
 * argv-less main()) ────────────────────────────────────────────────────── */

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

/* ── Temp-dir / file helpers (adapted from test_auth_handshake.c) ────────── */

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_vaulttest_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_vaulttest_%u", VW_PID());
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

/* ── Main ─────────────────────────────────────────────────────────────────── */

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

    vw_client_sess_t *sess = NULL;
    vw_err_t err = vw_client_connect(&cfg, username, (uint16_t)strlen(username),
                                      password, strlen(password), NULL, NULL, &sess);
    if (err != VW_OK) {
        fprintf(stderr, "connect/login failed: %d\n", (int)err);
        return 1;
    }

    /* ── Anchor file: vault_setup's folder_file_id just needs to be a file
     * the caller owns (the server does not require it to be a directory —
     * see handle_vault_create; test_vault.py relies on the same fact). */
    char anchor_local[600];
    path_join(anchor_local, sizeof(anchor_local), tmpdir, "anchor.txt");
    write_bytes(anchor_local, "anchor", 6);
    err = vw_client_file_upload(sess, "/vault_anchor.txt", anchor_local, NULL, NULL);
    CHECK(err == VW_OK, "upload anchor file");

    vw_file_entry_t anchor_entry;
    memset(&anchor_entry, 0, sizeof(anchor_entry));
    err = vw_client_file_stat(sess, "/vault_anchor.txt", &anchor_entry);
    CHECK(err == VW_OK, "stat anchor file");
    uint64_t folder_id = anchor_entry.file_id;

    /* ── Vault setup ── */
    const char *passphrase = "correct horse battery staple 42";
    vw_vault_t *vault = NULL;
    uint64_t vault_id = 0;
    err = vw_vault_setup(sess, folder_id, passphrase, strlen(passphrase), NULL, &vault, &vault_id);
    CHECK(err == VW_OK, "vault setup");
    CHECK(vault_id != 0, "vault_id is nonzero");

    /* ── Single-chunk file: upload, download, byte-identical round trip ── */
    char plain1_local[600], down1_local[600];
    path_join(plain1_local, sizeof(plain1_local), tmpdir, "plain1.bin");
    path_join(down1_local, sizeof(down1_local), tmpdir, "down1.bin");
    const char *content1 = "hello vault, this is a small secret file";
    write_bytes(plain1_local, content1, strlen(content1));

    uint64_t file1_id = 0, ver1_id = 0;
    err = vw_vault_upload_file(vault, sess, 0, "secret1.bin", plain1_local, NULL, NULL,
                                &file1_id, &ver1_id);
    CHECK(err == VW_OK, "upload encrypted file1 v1");

    err = vw_vault_download_file(vault, sess, file1_id, down1_local, NULL, NULL);
    CHECK(err == VW_OK, "download+decrypt file1 v1");

    void *down1_buf = NULL; size_t down1_len = 0;
    err = vw_fs_read_file(down1_local, &down1_buf, &down1_len);
    CHECK(err == VW_OK, "read back downloaded file1 v1");
    CHECK(down1_buf && down1_len == strlen(content1) &&
          memcmp(down1_buf, content1, down1_len) == 0,
          "file1 v1 byte-identical plaintext round-trip");
    free(down1_buf);

    /* ── New version of file1 must get a genuinely new wrapped DEK ── */
    const char *content1v2 = "hello vault, this is version two of the secret";
    write_bytes(plain1_local, content1v2, strlen(content1v2));

    uint64_t ver1b_id = 0;
    err = vw_vault_upload_file(vault, sess, file1_id, NULL, plain1_local, NULL, NULL,
                                NULL, &ver1b_id);
    CHECK(err == VW_OK, "upload encrypted file1 v2 (update)");
    CHECK(ver1b_id != 0 && ver1b_id != ver1_id, "file1 v2 has a different version_id than v1");

    uint8_t *hashes_v1 = NULL, *hashes_v2 = NULL;
    uint32_t cc_v1 = 0, cc_v2 = 0;
    uint64_t vid_v1 = 0, vid_v2 = 0;
    uint8_t *wdek_v1 = NULL, *wdek_v2 = NULL;
    uint16_t wdek_v1_len = 0, wdek_v2_len = 0;

    err = vw_client_version_chunks_raw(sess, ver1_id, &hashes_v1, &cc_v1,
                                        &vid_v1, &wdek_v1, &wdek_v1_len);
    CHECK(err == VW_OK, "fetch version_chunks for file1 v1");
    err = vw_client_version_chunks_raw(sess, ver1b_id, &hashes_v2, &cc_v2,
                                        &vid_v2, &wdek_v2, &wdek_v2_len);
    CHECK(err == VW_OK, "fetch version_chunks for file1 v2");

    CHECK(vid_v1 == vault_id && vid_v2 == vault_id, "both versions report this vault's vault_id");
    CHECK(wdek_v1 && wdek_v2 && wdek_v1_len == wdek_v2_len &&
          memcmp(wdek_v1, wdek_v2, wdek_v1_len) != 0,
          "wrapped_dek differs between file1 v1 and v2 (fresh DEK per version)");

    /* ── Two different files, same vault, identical plaintext -> different
     * ciphertext (per-file DEK, never per-vault) ── */
    char plain2_local[600];
    path_join(plain2_local, sizeof(plain2_local), tmpdir, "plain2.bin");
    write_bytes(plain2_local, content1v2, strlen(content1v2)); /* same bytes as file1 v2 */

    uint64_t file2_id = 0, ver2_id = 0;
    err = vw_vault_upload_file(vault, sess, 0, "secret2.bin", plain2_local, NULL, NULL,
                                &file2_id, &ver2_id);
    CHECK(err == VW_OK, "upload encrypted file2 (identical plaintext to file1 v2)");
    CHECK(file2_id != 0 && file2_id != file1_id, "file2 has a distinct file_id from file1");

    uint8_t *hashes_f2 = NULL;
    uint32_t cc_f2 = 0;
    uint64_t vid_f2 = 0;
    uint8_t *wdek_f2 = NULL;
    uint16_t wdek_f2_len = 0;
    err = vw_client_version_chunks_raw(sess, ver2_id, &hashes_f2, &cc_f2,
                                        &vid_f2, &wdek_f2, &wdek_f2_len);
    CHECK(err == VW_OK, "fetch version_chunks for file2");
    CHECK(cc_f2 == cc_v2 && cc_f2 > 0, "file1 v2 and file2 have the same chunk_count");
    CHECK(cc_f2 > 0 && memcmp(hashes_f2, hashes_v2, (size_t)cc_f2 * VW_HASH_BYTES) != 0,
          "identical plaintext across two files produces different ciphertext (chunk hash differs)");
    CHECK(wdek_f2 && (wdek_f2_len != wdek_v2_len || memcmp(wdek_f2, wdek_v2, wdek_f2_len) != 0),
          "file2's wrapped_dek differs from file1 v2's (per-file DEK, not per-vault)");

    free(hashes_v1); free(hashes_v2); free(hashes_f2);
    free(wdek_v1); free(wdek_v2); free(wdek_f2);

    /* ── Retry-safety: re-uploading an already-present chunk is idempotent,
     * matching what an interrupted-and-retried upload attempt needs (the
     * nonce-collision-free property itself is proven deterministically at
     * the crypto-primitive level in test_vw_crypto.c; this checks the wire
     * behavior a real retry would hit). ── */
    {
        uint8_t retry_data[64];
        memset(retry_data, 0x5A, sizeof(retry_data));
        uint8_t retry_hash[VW_HASH_BYTES];
        vw_crypto_sha256(retry_data, sizeof(retry_data), retry_hash);

        err = vw_client_chunk_upload_if_missing(sess, retry_hash, retry_data, sizeof(retry_data));
        CHECK(err == VW_OK, "first upload-if-missing of a fresh chunk succeeds");
        err = vw_client_chunk_upload_if_missing(sess, retry_hash, retry_data, sizeof(retry_data));
        CHECK(err == VW_OK, "retrying upload-if-missing of the same chunk is idempotent");
    }

    /* ── New-device simulation: close the in-memory handle, unlock from
     * scratch via the wire (VAULT_KEY_FETCH), and confirm it still decrypts
     * correctly — proves the wrap/unwrap round-trips through persistence,
     * not just within one process's memory. ── */
    vw_vault_close(vault);
    vault = NULL;

    vw_vault_t *vault2 = NULL;
    err = vw_vault_unlock(sess, vault_id, passphrase, strlen(passphrase), &vault2);
    CHECK(err == VW_OK, "vw_vault_unlock with correct passphrase succeeds");

    char down1b_local[600];
    path_join(down1b_local, sizeof(down1b_local), tmpdir, "down1b.bin");
    err = vault2 ? vw_vault_download_file(vault2, sess, file1_id, down1b_local, NULL, NULL)
                 : VW_ERR_INVALID_ARG;
    CHECK(err == VW_OK, "download file1 (current = v2) after fresh unlock");

    void *down1b_buf = NULL; size_t down1b_len = 0;
    err = vw_fs_read_file(down1b_local, &down1b_buf, &down1b_len);
    CHECK(err == VW_OK && down1b_buf && down1b_len == strlen(content1v2) &&
          memcmp(down1b_buf, content1v2, down1b_len) == 0,
          "file1 v2 byte-identical after unlock-from-scratch round trip");
    free(down1b_buf);

    /* ── Wrong passphrase must fail, not silently produce garbage ── */
    vw_vault_t *vault_wrong = NULL;
    err = vw_vault_unlock(sess, vault_id, "totally the wrong passphrase", 28, &vault_wrong);
    CHECK(err == VW_ERR_AUTH_BAD_CREDS,
          "vw_vault_unlock with wrong passphrase fails with VW_ERR_AUTH_BAD_CREDS");
    CHECK(vault_wrong == NULL, "wrong-passphrase unlock does not return a vault handle");

    /* ── Teardown ── */
    if (vault2) vw_vault_close(vault2);
    vw_client_close(sess);
    vw_crypto_cleanup();

    vw_fs_delete(anchor_local);
    vw_fs_delete(plain1_local);
    vw_fs_delete(plain2_local);
    vw_fs_delete(down1_local);
    vw_fs_delete(down1b_local);
    rm_dir_best_effort(tmpdir);

    printf("1..%d\n", g_checks);
    return (g_failed > 0) ? 1 : 0;
}
