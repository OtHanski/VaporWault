#include "vw_vault.h"
#include "../core/vw_fs.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#   include <windows.h>
#else
#   include <unistd.h>
#   include <fcntl.h>
#endif

/* ── Opaque vault handle ─────────────────────────────────────────────────── */

struct vw_vault {
    uint64_t vault_id;
    uint64_t folder_file_id;
    uint8_t  vk[VW_AES_GCM_KEY_BYTES];
};

uint64_t vw_vault_id_of(const vw_vault_t *vault) { return vault ? vault->vault_id : 0; }
uint64_t vw_vault_folder_file_id_of(const vw_vault_t *vault) { return vault ? vault->folder_file_id : 0; }

void vw_vault_close(vw_vault_t *vault) {
    if (!vault) return;
    vw_crypto_secure_zero(vault->vk, sizeof(vault->vk));
    free(vault);
}

/* ── kdf_params wire encoding ─────────────────────────────────────────────
 * VAULT_CREATE/VAULT_KEY_FETCH's kdf_params field is opaque to the server
 * (docs/PROTOCOL.md §7.11) but must round-trip through it intact so a
 * future vw_vault_unlock() call knows what Argon2id parameters the vault
 * was actually created with. Fixed 12-byte encoding: 3x uint32 LE
 * (mem_cost_kib, time_cost, parallelism). A length other than 12 is
 * treated as a corrupted/foreign blob, not a valid-but-different encoding
 * — this module is the only writer of this field, so any other length
 * cannot be a value it produced.
 */

static void encode_kdf_params(const vw_vault_kdf_params_t *p, uint8_t out[12]) {
    vw_write_u32le(out,     p->mem_cost_kib);
    vw_write_u32le(out + 4, p->time_cost);
    vw_write_u32le(out + 8, p->parallelism);
}

static vw_err_t decode_kdf_params(const uint8_t *buf, uint16_t len,
                                   vw_vault_kdf_params_t *out) {
    if (len != 12u) return VW_ERR_INVALID_ARG;
    out->mem_cost_kib = vw_read_u32le(buf);
    out->time_cost    = vw_read_u32le(buf + 4);
    out->parallelism  = vw_read_u32le(buf + 8);
    return VW_OK;
}

/* ── VK wrap / unwrap ──────────────────────────────────────────────────────
 * wrapped_vk / wrapped_dek both use the same fixed 60-byte blob layout:
 * nonce[12] || ciphertext[N] || tag[16], where N is 32 for both VK and DEK
 * (both are VW_AES_GCM_KEY_BYTES).
 *
 * The wrap nonce is random, not the deterministic per-chunk scheme, and
 * its safety argument differs by caller (TASK-106 review correction — an
 * earlier version of this comment claimed every wrapping key is used
 * exactly once, which is true for KEK→VK in vw_vault_setup but false for
 * VK→DEK: the same VK wraps every file's DEK for that vault's whole
 * lifetime):
 *   - KEK→VK (vw_vault_setup): the KEK is freshly derived and used for
 *     this one wrap only, so nonce reuse under that key is structurally
 *     impossible regardless of nonce choice.
 *   - VK→DEK (vw_vault_upload_file): the VK IS reused across every file
 *     ever uploaded to the vault. Safety here rests on the standard
 *     NIST SP 800-38D birthday-bound argument for independent random
 *     96-bit GCM nonces under a fixed key — collision probability stays
 *     negligible up to roughly 2^32 wraps, far beyond any realistic
 *     per-vault file count. This is a different (weaker, probabilistic)
 *     guarantee than the deterministic per-chunk scheme's "impossible by
 *     construction," and any future change that increases per-vault wrap
 *     volume by orders of magnitude (e.g. VK reuse across many vaults)
 *     should re-examine this bound rather than assume it still holds.
 */
#define VW_VAULT_WRAPPED_KEY_BYTES (VW_AES_GCM_NONCE_BYTES + VW_AES_GCM_KEY_BYTES + VW_AES_GCM_TAG_BYTES)

static vw_err_t wrap_key(const uint8_t wrapping_key[VW_AES_GCM_KEY_BYTES],
                          const uint8_t key_to_wrap[VW_AES_GCM_KEY_BYTES],
                          uint8_t out_blob[VW_VAULT_WRAPPED_KEY_BYTES]) {
    uint8_t *nonce = out_blob;
    uint8_t *ct    = out_blob + VW_AES_GCM_NONCE_BYTES;
    uint8_t *tag   = out_blob + VW_AES_GCM_NONCE_BYTES + VW_AES_GCM_KEY_BYTES;

    vw_err_t err = vw_crypto_random(nonce, VW_AES_GCM_NONCE_BYTES);
    if (err != VW_OK) return err;
    return vw_crypto_aes256gcm_encrypt(wrapping_key, nonce, NULL, 0,
                                        key_to_wrap, VW_AES_GCM_KEY_BYTES, ct, tag);
}

/* Returns VW_ERR_CRYPTO on GCM auth failure (wrong wrapping_key or
 * corrupted blob) — callers map this to a more specific error for their
 * context (e.g. vw_vault_unlock maps it to VW_ERR_AUTH_BAD_CREDS). */
static vw_err_t unwrap_key(const uint8_t wrapping_key[VW_AES_GCM_KEY_BYTES],
                            const uint8_t *blob, uint16_t blob_len,
                            uint8_t out_key[VW_AES_GCM_KEY_BYTES]) {
    if (blob_len != VW_VAULT_WRAPPED_KEY_BYTES) return VW_ERR_INVALID_ARG;
    const uint8_t *nonce = blob;
    const uint8_t *ct    = blob + VW_AES_GCM_NONCE_BYTES;
    const uint8_t *tag   = blob + VW_AES_GCM_NONCE_BYTES + VW_AES_GCM_KEY_BYTES;
    return vw_crypto_aes256gcm_decrypt(wrapping_key, nonce, NULL, 0,
                                        ct, VW_AES_GCM_KEY_BYTES, tag, out_key);
}

/* ── vw_vault_setup / vw_vault_unlock ─────────────────────────────────────── */

vw_err_t vw_vault_setup(vw_client_sess_t *sess, uint64_t folder_file_id,
                         const void *passphrase, size_t passphrase_len,
                         const vw_vault_kdf_params_t *kdf_params,
                         vw_vault_t **out_vault, uint64_t *out_vault_id) {
    if (!sess || folder_file_id == 0 || !passphrase || !out_vault || !out_vault_id)
        return VW_ERR_INVALID_ARG;
    if (passphrase_len < VW_VAULT_MIN_PASSPHRASE_BYTES) return VW_ERR_INVALID_ARG;

    vw_vault_kdf_params_t params = kdf_params ? *kdf_params
        : (vw_vault_kdf_params_t){ VW_VAULT_ARGON2_MIN_MEM_KB, VW_VAULT_ARGON2_MIN_TIME_COST,
                                    VW_VAULT_ARGON2_PARALLELISM };

    uint8_t vk[VW_AES_GCM_KEY_BYTES];
    uint8_t kdf_salt[VW_VAULT_KDF_SALT_BYTES];
    uint8_t kek[VW_VAULT_KEK_BYTES];
    uint8_t wrapped_vk[VW_VAULT_WRAPPED_KEY_BYTES];
    uint8_t kdf_params_buf[12];

    vw_err_t err = vw_crypto_random(vk, sizeof(vk));
    if (err == VW_OK) err = vw_crypto_random(kdf_salt, sizeof(kdf_salt));
    if (err == VW_OK) err = vw_crypto_vault_derive_kek(passphrase, passphrase_len,
                                                        kdf_salt, &params, kek);
    if (err == VW_OK) err = wrap_key(kek, vk, wrapped_vk);
    vw_crypto_secure_zero(kek, sizeof(kek));
    if (err != VW_OK) { vw_crypto_secure_zero(vk, sizeof(vk)); return err; }

    encode_kdf_params(&params, kdf_params_buf);

    uint64_t vault_id = 0;
    err = vw_client_vault_create(sess, folder_file_id, wrapped_vk, sizeof(wrapped_vk),
                                  kdf_salt, kdf_params_buf, sizeof(kdf_params_buf), &vault_id);
    if (err != VW_OK) { vw_crypto_secure_zero(vk, sizeof(vk)); return err; }

    vw_vault_t *vault = malloc(sizeof(*vault));
    if (!vault) { vw_crypto_secure_zero(vk, sizeof(vk)); return VW_ERR_OOM; }
    vault->vault_id = vault_id;
    vault->folder_file_id = folder_file_id;
    memcpy(vault->vk, vk, sizeof(vk));
    vw_crypto_secure_zero(vk, sizeof(vk));

    *out_vault = vault;
    *out_vault_id = vault_id;
    return VW_OK;
}

vw_err_t vw_vault_unlock(vw_client_sess_t *sess, uint64_t vault_id,
                          const void *passphrase, size_t passphrase_len,
                          vw_vault_t **out_vault) {
    if (!sess || vault_id == 0 || !passphrase || !out_vault) return VW_ERR_INVALID_ARG;

    uint8_t *wrapped_vk = NULL;
    uint16_t wrapped_vk_len = 0;
    uint8_t  kdf_salt[VW_VAULT_KDF_SALT_BYTES];
    uint8_t *kdf_params_buf = NULL;
    uint16_t kdf_params_len = 0;
    uint64_t folder_file_id = 0;

    vw_err_t err = vw_client_vault_key_fetch(sess, vault_id, &wrapped_vk, &wrapped_vk_len,
                                              kdf_salt, &kdf_params_buf, &kdf_params_len,
                                              &folder_file_id);
    if (err != VW_OK) return err;

    vw_vault_kdf_params_t params;
    err = decode_kdf_params(kdf_params_buf, kdf_params_len, &params);
    free(kdf_params_buf);
    if (err != VW_OK) { free(wrapped_vk); return err; }

    uint8_t kek[VW_VAULT_KEK_BYTES];
    err = vw_crypto_vault_derive_kek(passphrase, passphrase_len, kdf_salt, &params, kek);
    if (err != VW_OK) { free(wrapped_vk); return err; }

    uint8_t vk[VW_AES_GCM_KEY_BYTES];
    err = unwrap_key(kek, wrapped_vk, wrapped_vk_len, vk);
    vw_crypto_secure_zero(kek, sizeof(kek));
    free(wrapped_vk);
    if (err != VW_OK) {
        /* GCM auth failure here means "wrong passphrase" specifically —
         * see this function's doc comment in vw_vault.h. A malformed
         * wrapped_vk_len (VW_ERR_INVALID_ARG) is passed through as-is:
         * that's a corrupted-blob problem, not a credentials problem. */
        return (err == VW_ERR_CRYPTO) ? VW_ERR_AUTH_BAD_CREDS : err;
    }

    vw_vault_t *vault = malloc(sizeof(*vault));
    if (!vault) { vw_crypto_secure_zero(vk, sizeof(vk)); return VW_ERR_OOM; }
    vault->vault_id = vault_id;
    vault->folder_file_id = folder_file_id;
    memcpy(vault->vk, vk, sizeof(vk));
    vw_crypto_secure_zero(vk, sizeof(vk));

    *out_vault = vault;
    return VW_OK;
}

/* ── Raw sequential file reader, chunked at VW_VAULT_PLAINTEXT_CHUNK_BYTES ──
 * Deliberately not vw_fs_chunk_open/_next: those always read exactly
 * VW_CHUNK_SIZE (the plaintext chunk size used everywhere else) per call,
 * which is 16 bytes larger than this module's per-chunk read size (see
 * VW_VAULT_PLAINTEXT_CHUNK_BYTES's doc comment in vw_vault.h for why that
 * 16-byte difference matters). Mirrors vw_fs_chunk_open/_next's exact
 * cross-platform idiom and its is_last/EOF detection (a plaintext file
 * whose size is an exact multiple of the chunk size produces one trailing
 * empty chunk, same pre-existing behavior as the unencrypted path).
 */
#ifdef _WIN32
typedef struct { HANDLE fh; int done; } vault_reader_t;
#else
typedef struct { int fd; int done; } vault_reader_t;
#endif

static vw_err_t vault_reader_open(const char *path, vault_reader_t *r) {
#ifdef _WIN32
    r->fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (r->fh == INVALID_HANDLE_VALUE)
        return (GetLastError() == ERROR_FILE_NOT_FOUND) ? VW_ERR_NOT_FOUND : VW_ERR_IO;
#else
    r->fd = open(path, O_RDONLY);
    if (r->fd < 0) return (errno == ENOENT) ? VW_ERR_NOT_FOUND : VW_ERR_IO;
#endif
    r->done = 0;
    return VW_OK;
}

static vw_err_t vault_reader_next(vault_reader_t *r, uint8_t *buf,
                                   size_t *out_len, int *out_is_last) {
    if (r->done) return VW_ERR_NOT_FOUND;
#ifdef _WIN32
    DWORD nread = 0;
    if (!ReadFile(r->fh, buf, (DWORD)VW_VAULT_PLAINTEXT_CHUNK_BYTES, &nread, NULL))
        return VW_ERR_IO;
    *out_len = (size_t)nread;
#else
    size_t pos = 0;
    while (pos < VW_VAULT_PLAINTEXT_CHUNK_BYTES) {
        ssize_t n = read(r->fd, buf + pos, VW_VAULT_PLAINTEXT_CHUNK_BYTES - pos);
        if (n < 0) { if (errno == EINTR) continue; return VW_ERR_IO; }
        if (n == 0) break;
        pos += (size_t)n;
    }
    *out_len = pos;
#endif
    if (*out_len < VW_VAULT_PLAINTEXT_CHUNK_BYTES) {
        *out_is_last = 1;
        r->done = 1;
    } else {
        *out_is_last = 0;
    }
    return VW_OK;
}

static void vault_reader_close(vault_reader_t *r) {
#ifdef _WIN32
    if (r->fh != INVALID_HANDLE_VALUE) { CloseHandle(r->fh); r->fh = INVALID_HANDLE_VALUE; }
#else
    if (r->fd >= 0) { close(r->fd); r->fd = -1; }
#endif
}

/* ── vw_vault_upload_file ─────────────────────────────────────────────────── */

vw_err_t vw_vault_upload_file(vw_vault_t *vault, vw_client_sess_t *sess,
                               uint64_t file_id, const char *leaf_name,
                               const char *local_path,
                               vw_client_progress_cb_t progress_cb, void *userdata,
                               uint64_t *out_file_id, uint64_t *out_version_id) {
    if (!vault || !sess || !local_path) return VW_ERR_INVALID_ARG;
    if (file_id == 0 && (!leaf_name || !leaf_name[0] || strchr(leaf_name, '/') != NULL))
        return VW_ERR_INVALID_ARG;

    uint64_t total_size = 0;
    (void)vw_fs_file_size(local_path, &total_size); /* best-effort; progress-only */

    uint8_t dek[VW_AES_GCM_KEY_BYTES];
    vw_err_t err = vw_crypto_random(dek, sizeof(dek));
    if (err != VW_OK) return err;

    vault_reader_t reader;
    err = vault_reader_open(local_path, &reader);
    if (err != VW_OK) { vw_crypto_secure_zero(dek, sizeof(dek)); return err; }

    uint8_t *pt_buf = malloc(VW_VAULT_PLAINTEXT_CHUNK_BYTES);
    uint8_t *ct_buf = malloc((size_t)VW_VAULT_PLAINTEXT_CHUNK_BYTES + VW_AES_GCM_TAG_BYTES);
    uint8_t *hashes = NULL;
    uint32_t hash_cap = 0, chunk_count = 0;
    uint64_t logical_size = 0, bytes_done = 0;

    if (!pt_buf || !ct_buf) { err = VW_ERR_OOM; goto cleanup_upload; }

    for (;;) {
        size_t pt_len;
        int is_last;
        err = vault_reader_next(&reader, pt_buf, &pt_len, &is_last);
        if (err != VW_OK) goto cleanup_upload;

        uint8_t nonce[VW_AES_GCM_NONCE_BYTES];
        err = vw_crypto_vault_chunk_nonce(dek, chunk_count, nonce);
        if (err != VW_OK) goto cleanup_upload;

        err = vw_crypto_aes256gcm_encrypt(dek, nonce, NULL, 0, pt_buf, pt_len,
                                           ct_buf, ct_buf + pt_len);
        if (err != VW_OK) goto cleanup_upload;
        size_t ct_len = pt_len + VW_AES_GCM_TAG_BYTES;

        if (chunk_count >= hash_cap) {
            uint32_t new_cap = hash_cap ? hash_cap * 2 : 64;
            uint8_t *new_hashes = realloc(hashes, (size_t)new_cap * VW_HASH_BYTES);
            if (!new_hashes) { err = VW_ERR_OOM; goto cleanup_upload; }
            hashes = new_hashes;
            hash_cap = new_cap;
        }
        uint8_t *hash_slot = hashes + (size_t)chunk_count * VW_HASH_BYTES;
        err = vw_crypto_sha256(ct_buf, ct_len, hash_slot);
        if (err != VW_OK) goto cleanup_upload;

        err = vw_client_chunk_upload_if_missing(sess, hash_slot, ct_buf, (uint32_t)ct_len);
        if (err != VW_OK) goto cleanup_upload;

        logical_size += pt_len;
        chunk_count++;
        bytes_done += pt_len;
        if (progress_cb) progress_cb(bytes_done, total_size, userdata);
        if (is_last) break;
    }

    {
        uint8_t wrapped_dek[VW_VAULT_WRAPPED_KEY_BYTES];
        err = wrap_key(vault->vk, dek, wrapped_dek);
        if (err != VW_OK) goto cleanup_upload;

        uint64_t target_file_id = (file_id != 0) ? file_id : vault->folder_file_id;
        const char *name = (file_id != 0) ? NULL : leaf_name;
        uint16_t name_len = (file_id != 0) ? 0 : (uint16_t)strlen(leaf_name);

        err = vw_client_file_commit_raw(sess, target_file_id, name, name_len,
                                         logical_size, chunk_count, hashes,
                                         vault->vault_id, wrapped_dek, sizeof(wrapped_dek),
                                         out_file_id, out_version_id);
    }

cleanup_upload:
    vw_crypto_secure_zero(dek, sizeof(dek));
    vault_reader_close(&reader);
    free(pt_buf);
    free(ct_buf);
    free(hashes);
    return err;
}

/* ── vw_vault_download_file ───────────────────────────────────────────────── */

vw_err_t vw_vault_download_file(vw_vault_t *vault, vw_client_sess_t *sess,
                                 uint64_t file_id, const char *local_path,
                                 vw_client_progress_cb_t progress_cb, void *userdata) {
    if (!vault || !sess || !local_path) return VW_ERR_INVALID_ARG;

    vw_file_entry_t entry;
    vw_err_t err = vw_client_file_stat_by_id(sess, file_id, &entry);
    if (err != VW_OK) return err;

    uint8_t *hashes = NULL;
    uint32_t chunk_count = 0;
    uint64_t v_vault_id = 0;
    uint8_t *wrapped_dek = NULL;
    uint16_t wrapped_dek_len = 0;
    err = vw_client_version_chunks_raw(sess, entry.version_id, &hashes, &chunk_count,
                                        &v_vault_id, &wrapped_dek, &wrapped_dek_len);
    if (err != VW_OK) return err;

    if (v_vault_id == 0 || v_vault_id != vault->vault_id) {
        free(hashes); free(wrapped_dek);
        return VW_ERR_INVALID_ARG;
    }

    uint8_t dek[VW_AES_GCM_KEY_BYTES];
    err = unwrap_key(vault->vk, wrapped_dek, wrapped_dek_len, dek);
    free(wrapped_dek);
    if (err != VW_OK) { free(hashes); return err; }

    size_t tmp_len = strlen(local_path) + 5u;
    char *tmp_path = malloc(tmp_len);
    if (!tmp_path) { vw_crypto_secure_zero(dek, sizeof(dek)); free(hashes); return VW_ERR_OOM; }
    snprintf(tmp_path, tmp_len, "%s.tmp", local_path);

    vw_fs_chunk_writer_ctx_t writer;
    err = vw_fs_chunk_writer_open(tmp_path, &writer);
    if (err != VW_OK) {
        vw_crypto_secure_zero(dek, sizeof(dek));
        free(tmp_path); free(hashes);
        return err;
    }

    uint64_t bytes_done = 0;
    for (uint32_t ci = 0; ci < chunk_count; ci++) {
        const uint8_t *chash = hashes + (size_t)ci * VW_HASH_BYTES;

        uint8_t *ct_data = NULL;
        uint32_t ct_len = 0;
        err = vw_client_chunk_download_raw(sess, chash, &ct_data, &ct_len);
        if (err != VW_OK) break;

        if (ct_len < VW_AES_GCM_TAG_BYTES) { free(ct_data); err = VW_ERR_PROTO_INVALID; break; }
        uint32_t pt_len = ct_len - VW_AES_GCM_TAG_BYTES;

        uint8_t *pt_data = malloc(pt_len ? pt_len : 1u);
        if (!pt_data) { free(ct_data); err = VW_ERR_OOM; break; }

        uint8_t nonce[VW_AES_GCM_NONCE_BYTES];
        err = vw_crypto_vault_chunk_nonce(dek, ci, nonce);
        if (err == VW_OK) {
            err = vw_crypto_aes256gcm_decrypt(dek, nonce, NULL, 0,
                                               ct_data, pt_len, ct_data + pt_len, pt_data);
        }
        free(ct_data);
        if (err != VW_OK) { free(pt_data); break; }

        err = vw_fs_chunk_writer_append(&writer, pt_data, pt_len);
        free(pt_data);
        if (err != VW_OK) break;

        bytes_done += pt_len;
        if (progress_cb) progress_cb(bytes_done, entry.size_bytes, userdata);
    }

    vw_crypto_secure_zero(dek, sizeof(dek));
    free(hashes);

    if (err != VW_OK) {
        vw_fs_chunk_writer_abort(&writer);
        free(tmp_path);
        return err;
    }

    err = vw_fs_chunk_writer_close(&writer);
    if (err == VW_OK) err = vw_fs_rename(tmp_path, local_path);
    if (err != VW_OK) vw_fs_delete(tmp_path);

    free(tmp_path);
    return err;
}
