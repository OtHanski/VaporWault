#ifndef VW_VAULT_H
#define VW_VAULT_H

/*
 * vw_vault — client-side E2EE vault (TASK-099).
 *
 * Implements the envelope-encryption key model designed in
 * docs/PROTOCOL.md §7.11: an Encryption Passphrase (never transmitted)
 * derives a KEK (Argon2id) that wraps a per-vault VK (AES-256-GCM), which
 * in turn wraps a fresh per-file DEK (AES-256-GCM) used to encrypt that
 * file's content, one AES-256-GCM tag per chunk, with a nonce derived
 * deterministically from (DEK, chunk_index) via vw_crypto_vault_chunk_nonce
 * — never randomly, so an interrupted-and-retried upload can never reuse a
 * (key, nonce) pair with different plaintext. See vw_crypto.h for the
 * underlying primitives and docs/PROTOCOL.md §7.11.5 for the accepted
 * security properties this design targets.
 *
 * This module owns ALL cryptographic logic for vaults. vw_client_core.c's
 * vw_client_vault_create/_key_fetch/_list, vw_client_file_commit_raw,
 * vw_client_version_chunks_raw, and vw_client_chunk_upload_if_missing /
 * _download_raw functions move bytes over the wire but never touch key
 * material or plaintext — see their doc comments in vw_client_core.h.
 *
 * Metadata (filenames, folder structure, sizes, timestamps) is NOT
 * encrypted — the server sees it by design (§7.11.1). Only file content
 * and the DEK/VK wrapping chain are protected.
 */

#include "vw_client_core.h"
#include "../core/vw_crypto.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vw_vault vw_vault_t;   /* opaque; holds the unwrapped VK */

/*
 * Plaintext chunk size for vault content. Deliberately smaller than
 * VW_CHUNK_SIZE_DEFAULT (the plaintext chunking size used everywhere
 * else) by exactly VW_AES_GCM_TAG_BYTES: a full-size ciphertext+tag then
 * lands at exactly VW_CHUNK_SIZE_DEFAULT bytes, which is the server's
 * CHUNK_UPLOAD size ceiling (vw_file_handlers.c's handle_chunk_upload
 * rejects data_len > VW_CHUNK_SIZE_DEFAULT). A full-size *plaintext*
 * chunk encrypted at the unencrypted chunk size would overflow that
 * ceiling by 16 bytes and be rejected — this constant exists to make
 * that impossible by construction rather than needing a special-cased
 * "vault chunks may exceed the normal ceiling" server-side carve-out.
 */
#define VW_VAULT_PLAINTEXT_CHUNK_BYTES (VW_CHUNK_SIZE_DEFAULT - VW_AES_GCM_TAG_BYTES)

/*
 * Create a brand-new vault for folder_file_id (caller must own it),
 * derived from the given Encryption Passphrase. Generates a fresh random
 * VK, wraps it under a KEK derived via Argon2id, and registers the vault
 * with the server (VAULT_CREATE) — the passphrase itself never crosses
 * the wire, only the resulting wrapped-VK ciphertext.
 *
 * kdf_params == NULL uses the SEC.07-pinned floor exactly
 * (VW_VAULT_ARGON2_MIN_MEM_KB/_MIN_TIME_COST/_PARALLELISM); a non-NULL
 * kdf_params must meet or exceed that floor or this call fails with
 * VW_ERR_INVALID_ARG (vw_crypto_vault_derive_kek enforces it).
 *
 * On success, *out_vault holds the unwrapped VK in memory — free with
 * vw_vault_close() when done, which zeroes it. *out_vault_id is the
 * server-assigned id; the caller should persist it (e.g. in local sync
 * config) so a future session can vw_vault_unlock() without a VAULT_LIST
 * round trip.
 */
vw_err_t vw_vault_setup(vw_client_sess_t *sess, uint64_t folder_file_id,
                         const void *passphrase, size_t passphrase_len,
                         const vw_vault_kdf_params_t *kdf_params,
                         vw_vault_t **out_vault, uint64_t *out_vault_id);

/*
 * Unlock an existing vault (new-device / new-session case): fetches the
 * wrapped VK + KDF salt/params via VAULT_KEY_FETCH, re-derives the KEK
 * using the exact params the vault was created with, and unwraps the VK.
 *
 * Returns VW_ERR_AUTH_BAD_CREDS if the passphrase is wrong (the VK
 * unwrap's GCM tag check fails) — this function's own, caller-context-
 * specific mapping of vw_crypto_aes256gcm_decrypt's deliberately generic
 * VW_ERR_CRYPTO (see that function's doc comment in vw_crypto.h for why
 * the primitive itself doesn't make this judgment).
 */
vw_err_t vw_vault_unlock(vw_client_sess_t *sess, uint64_t vault_id,
                          const void *passphrase, size_t passphrase_len,
                          vw_vault_t **out_vault);

/* Zero the in-memory VK and free *vault. Safe to call with NULL. */
void vw_vault_close(vw_vault_t *vault);

uint64_t vw_vault_id_of(const vw_vault_t *vault);
uint64_t vw_vault_folder_file_id_of(const vw_vault_t *vault);

/*
 * Encrypt local_path and upload it into vault's folder.
 *
 *   file_id == 0: create a new file named leaf_name (bare leaf, no '/')
 *                 inside vault's folder_file_id.
 *   file_id != 0: upload a new version of the existing file file_id
 *                 (leaf_name ignored; must itself already belong to this
 *                 vault — this function does not check that, the caller
 *                 is expected to route only vault-owned file_ids here).
 *
 * Generates a fresh random DEK for this file (never reused across files
 * or versions — §7.11.2), splits local_path into
 * VW_VAULT_PLAINTEXT_CHUNK_BYTES-sized plaintext chunks, encrypts each
 * with AES-256-GCM using vw_crypto_vault_chunk_nonce's deterministic
 * per-chunk nonce, uploads each ciphertext+tag as one chunk (content-
 * addressed by SHA-256 of the ciphertext, same as any other chunk), wraps
 * the DEK under vault's VK, and commits with vault_id + wrapped_dek.
 *
 * progress_cb reports plaintext bytes processed so far / total plaintext
 * size (may be NULL).
 */
vw_err_t vw_vault_upload_file(vw_vault_t *vault, vw_client_sess_t *sess,
                               uint64_t file_id, const char *leaf_name,
                               const char *local_path,
                               vw_client_progress_cb_t progress_cb, void *userdata,
                               uint64_t *out_file_id, uint64_t *out_version_id);

/*
 * Download and decrypt file_id's current version into local_path.
 *
 * Resolves the current version via FILE_STAT, fetches its wrapped_dek via
 * VERSION_CHUNKS_RESP's TASK-099 trailing fields, unwraps it under
 * vault's VK, then decrypts each chunk with the same deterministic-nonce
 * scheme used on upload before writing plaintext to local_path.
 *
 * Returns VW_ERR_INVALID_ARG if the file's current version is
 * unencrypted or belongs to a different vault than `vault` — a caller
 * bug (wrong vault handle for this file), not a crypto failure. Returns
 * VW_ERR_CRYPTO if any chunk fails GCM authentication (corrupted or
 * tampered ciphertext — distinct from a passphrase problem, since the
 * vault is already unlocked at this point).
 */
vw_err_t vw_vault_download_file(vw_vault_t *vault, vw_client_sess_t *sess,
                                 uint64_t file_id, const char *local_path,
                                 vw_client_progress_cb_t progress_cb, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* VW_VAULT_H */
