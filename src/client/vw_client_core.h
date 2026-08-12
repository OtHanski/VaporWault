#ifndef VW_CLIENT_CORE_H
#define VW_CLIENT_CORE_H

/*
 * vw_client_core — client-side connection and authentication.
 *
 * Establishes a TLS connection to the server, performs version negotiation
 * and the auth handshake, and holds the resulting session.
 *
 * Phase 1 scope: connect, authenticate with password, resume session, logout.
 * File-operation request sending is a future task.
 *
 * Password transport (PROTOCOL.md §8.1 Phase 1):
 *   The client computes SHA-256(password) and sends the 32-byte result as
 *   auth_token in AUTH_REQUEST. The server must store password hashes derived
 *   from Argon2id(SHA-256(password), server_salt).
 */

#include "../core/vw_net.h"
#include "../core/vw_proto.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque session handle ───────────────────────────────────────────────── */

typedef struct vw_client_sess vw_client_sess_t;

/* ── Connection config ───────────────────────────────────────────────────── */

typedef struct {
    const char        *host;
    uint16_t           port;
    vw_cert_verify_t   cert_verify;
    const char        *ca_cert_pem_path;  /* NULL when cert_verify == NONE */
    const vw_conn_opts_t *conn_opts;       /* NULL = use defaults */
} vw_client_cfg_t;

/* ── 2FA callback ────────────────────────────────────────────────────────── */

/*
 * Called when the server requires a 2FA OTP code.
 * Must write at most 8 ASCII digit characters into otp_buf (guaranteed
 * at least 16 bytes) and set *otp_len to the count written.
 * Return VW_OK on success; any other code aborts the login attempt with that
 * error as the return value of vw_client_connect.
 */
typedef vw_err_t (*vw_otp_callback_t)(void *userdata,
                                       char *otp_buf, uint16_t *otp_len);

/* ── Connect and authenticate ────────────────────────────────────────────── */

/*
 * Connect to the server and authenticate with username + password.
 *
 * If the server requires 2FA and otp_cb is NULL, returns
 * VW_ERR_AUTH_2FA_REQUIRED without sending AUTH_OTP.
 * If otp_cb is non-NULL it is called to obtain the OTP code from the caller.
 *
 * On success: *out_sess is heap-allocated; free with vw_client_close() or
 * vw_client_logout().
 */
vw_err_t vw_client_connect(const vw_client_cfg_t *cfg,
                             const char *username, uint16_t username_len,
                             const void *password, size_t pw_len,
                             vw_otp_callback_t otp_cb, void *otp_userdata,
                             vw_client_sess_t **out_sess);

/*
 * Connect and resume a saved session using a stored token.  The server
 * validates the token and issues a fresh replacement (single-use resumption
 * per PROTOCOL.md §7.1).  After success the caller should update any
 * persisted token via vw_client_get_token().
 *
 * On success: *out_sess is heap-allocated; free with vw_client_close().
 */
vw_err_t vw_client_resume(const vw_client_cfg_t *cfg,
                            const uint8_t saved_token[VW_TOKEN_BYTES],
                            vw_client_sess_t **out_sess);

/* ── Session accessors ───────────────────────────────────────────────────── */

/* Copy the current session token into out_token[VW_TOKEN_BYTES]. */
void vw_client_get_token(const vw_client_sess_t *sess,
                          uint8_t out_token[VW_TOKEN_BYTES]);

uint64_t vw_client_user_id_of(const vw_client_sess_t *sess);
int64_t  vw_client_expires_at_of(const vw_client_sess_t *sess);
uint8_t  vw_client_is_admin_of(const vw_client_sess_t *sess);

/* ── Disconnect ──────────────────────────────────────────────────────────── */

/*
 * Send AUTH_LOGOUT, perform TLS close_notify, and free the session.
 * Safe to call with NULL.
 */
void vw_client_logout(vw_client_sess_t *sess);

/*
 * Close the connection without logging out (use when the session is already
 * expired or the server already closed the connection). Frees the session.
 * Safe to call with NULL.
 */
void vw_client_close(vw_client_sess_t *sess);

/*
 * Return the underlying connection for further message dispatch (Phase 2).
 * Owned by the session; do not close separately.
 */
vw_conn_t *vw_client_conn(vw_client_sess_t *sess);

/* ── File transfer types (Phase 2) ──────────────────────────────────────── */

/*
 * A file or directory entry returned by vw_client_file_list / _file_stat.
 * name is NUL-terminated; entries beyond 255 bytes are truncated.
 */
typedef struct {
    uint8_t  entry_type;    /* VW_ENTRY_FILE=0 or VW_ENTRY_DIR=1              */
    uint64_t file_id;
    uint64_t size_bytes;
    int64_t  mtime_unix;
    uint64_t version_id;    /* current HEAD version; 0 if directory           */
    char     name[256];     /* leaf name, NUL-terminated                      */
    uint64_t vault_id;      /* TASK-100: current version's vault, 0 if
                              * unencrypted or a directory. Populated by
                              * vw_client_file_stat/_stat_by_id (FILE_STAT_RESP
                              * carries it) and, since TASK-156, by
                              * vw_client_file_list/_file_list_by_id too
                              * (FILE_LIST_RESP's trailing vault_id array) — an
                              * old server that hasn't been upgraded leaves
                              * this at its calloc-zeroed 0 for every entry
                              * instead, the same best-effort backward
                              * compatibility every other trailing-field
                              * extension in this protocol already gets. */
} vw_file_entry_t;

/*
 * A version record returned by vw_client_version_list.
 */
typedef struct {
    uint64_t version_id;
    int64_t  created_at;
    uint64_t size_bytes;
} vw_version_entry_t;

/*
 * Progress callback for upload / download.
 * bytes_done: bytes transferred so far. bytes_total: total file size.
 * May be NULL.
 */
typedef void (*vw_client_progress_cb_t)(uint64_t bytes_done,
                                        uint64_t bytes_total,
                                        void *userdata);

/* ── File transfer operations ────────────────────────────────────────────── */

/*
 * List files and directories under virtual_path.
 * recursive=1 enumerates subdirectories recursively (server-side BFS, max 65535 entries).
 * Returns a malloc'd array of vw_file_entry_t in *out; caller frees.
 * Returns VW_ERR_NOT_FOUND if the path does not exist.
 * Returns VW_ERR_AUTH_REQUIRED if the session is NULL or expired.
 */
vw_err_t vw_client_file_list(vw_client_sess_t *sess,
                               const char *virtual_path,
                               uint8_t recursive,
                               vw_file_entry_t **out,
                               uint32_t *out_count);

/*
 * List a folder by file_id (TASK-106) — works for a folder the caller
 * doesn't own but has at least VIEW access to (a share grant), unlike
 * vw_client_file_list. See docs/PROTOCOL.md §7.2's FILE_LIST dir_file_id
 * note for why path-based listing can't reach a shared folder at all.
 */
vw_err_t vw_client_file_list_by_id(vw_client_sess_t *sess,
                                    uint64_t dir_file_id,
                                    uint8_t recursive,
                                    vw_file_entry_t **out,
                                    uint32_t *out_count);

/*
 * Stat a single virtual path. Returns metadata in *out.
 * Returns VW_ERR_NOT_FOUND if the path does not exist for this user.
 */
vw_err_t vw_client_file_stat(vw_client_sess_t *sess,
                               const char *virtual_path,
                               vw_file_entry_t *out);

/*
 * Upload local_path to virtual_path on the server.
 *
 * Upload sequence (PROTOCOL.md §7.8):
 *   1. Read local file in 4 MiB chunks; compute SHA-256 per chunk.
 *   2. CHUNK_QUERY (up to 1024 per round) → bitmask of missing chunks.
 *   3. CHUNK_UPLOAD for each missing chunk.
 *   4. FILE_COMMIT with the full ordered chunk hash list.
 *
 * If interrupted and retried, CHUNK_QUERY will identify already-uploaded
 * chunks and only the missing ones are re-sent (resumable upload).
 *
 * progress_cb is called after each chunk upload completes (may be NULL).
 * Returns VW_ERR_PATH_INVALID if virtual_path fails validation.
 */
vw_err_t vw_client_file_upload(vw_client_sess_t *sess,
                                 const char *virtual_path,
                                 const char *local_path,
                                 vw_client_progress_cb_t progress_cb,
                                 void *userdata);

/*
 * Download virtual_path from the server to local_path.
 *
 * Download sequence:
 *   1. FILE_STAT → get current version_id.
 *   2. VERSION_CHUNKS {version_id} → ordered chunk hash list.
 *   3. CHUNK_DOWNLOAD_REQ for each chunk hash → receive CHUNK_DATA.
 *   4. Assemble chunks via vw_fs_chunk_writer_* into a temp file;
 *      rename to local_path when complete.
 *
 * progress_cb is called after each chunk is received and written (may be NULL).
 */
vw_err_t vw_client_file_download(vw_client_sess_t *sess,
                                   const char *virtual_path,
                                   const char *local_path,
                                   vw_client_progress_cb_t progress_cb,
                                   void *userdata);

/*
 * Delete virtual_path on the server (file or empty directory).
 * Returns VW_ERR_DIR_NOT_EMPTY for non-empty directories.
 */
vw_err_t vw_client_file_delete(vw_client_sess_t *sess,
                                 const char *virtual_path);

/*
 * Delete a file/folder directly by file_id (TASK-106) — works for content
 * the caller doesn't own (a grant target), unlike vw_client_file_delete.
 */
vw_err_t vw_client_file_delete_by_id(vw_client_sess_t *sess, uint64_t file_id);

/*
 * List all versions of virtual_path, oldest first.
 * Returns a malloc'd array; caller frees. *out_count may be 0.
 * The function calls FILE_STAT first to resolve the file_id.
 */
vw_err_t vw_client_version_list(vw_client_sess_t *sess,
                                  const char *virtual_path,
                                  vw_version_entry_t **out,
                                  uint32_t *out_count);

/*
 * Restore version_id as the new HEAD of virtual_path.
 * The server creates a new version record; the caller should call
 * vw_client_file_stat after restore to get the new version_id.
 */
vw_err_t vw_client_version_restore(vw_client_sess_t *sess,
                                     const char *virtual_path,
                                     uint64_t version_id);

/* ── File-id-based operations (TASK-095) ─────────────────────────────────── */
/*
 * All of the above (vw_client_file_list/_stat/_upload/_download/_delete) are
 * path-based, and vw_store_file_get_by_path/vw_store_file_list are namespaced
 * by owner_id server-side (see docs/PROTOCOL.md §7.5's implementation note on
 * SHARE_LIST_RESP) — a virtual_path only ever resolves within the caller's
 * OWN tree. Shared items (grants or scoped-link sessions) are reached by
 * file_id instead, learned from vw_client_share_list/vw_client_link_list, or
 * — for a scoped session specifically — via vw_client_file_list(sess, "/",
 * ...) at the root, which the server resolves from session state without any
 * client-supplied id at all (§7.5's scoped-session root navigation).
 *
 * A known gap, not fixed here: there is no way to shallow-browse a SHARED
 * FOLDER's children by file_id for an authenticated grant holder (only the
 * scoped-session root case above works) — FILE_LIST's wire payload has no
 * file_id field. See TASK-104's sibling note; filed as a follow-up rather
 * than extending FILE_LIST's wire format here.
 */

/*
 * Stat a file/folder directly by file_id — works for content the caller
 * doesn't own (a grant or scope target), unlike vw_client_file_stat.
 */
vw_err_t vw_client_file_stat_by_id(vw_client_sess_t *sess,
                                    uint64_t file_id,
                                    vw_file_entry_t *out);

/*
 * Download a file directly by file_id (skips the path-based FILE_STAT that
 * vw_client_file_download does internally). Same chunk-verification and
 * atomic-rename behavior as vw_client_file_download.
 */
vw_err_t vw_client_file_download_by_id(vw_client_sess_t *sess,
                                        uint64_t file_id,
                                        const char *local_path,
                                        vw_client_progress_cb_t progress_cb,
                                        void *userdata);

/*
 * Upload a new VERSION of an existing file identified by file_id (an
 * update, not a create) — the file_id-addressed equivalent of
 * vw_client_file_upload's "path resolves to an existing file I own" case,
 * usable through an EDIT grant/scope on a file this caller doesn't own.
 */
vw_err_t vw_client_file_upload_to_id(vw_client_sess_t *sess,
                                      uint64_t file_id,
                                      const char *local_path,
                                      vw_client_progress_cb_t progress_cb,
                                      void *userdata);

/*
 * Create a NEW file named leaf_name inside the folder identified by
 * folder_file_id — the file_id-addressed equivalent of creating a file at
 * an owned path, usable through an EDIT grant/scope on a shared folder
 * this caller doesn't own. leaf_name must not contain '/' (server-side
 * requirement, checked here first to fail fast).
 *
 * out_file_id/out_version_id (TASK-106) may be NULL; when non-NULL they
 * receive the newly created file's id and initial version id. The sync
 * engine needs this to address the file directly (upload_to_id/
 * download_by_id/delete_by_id) on every subsequent sync cycle, since a
 * path-based FILE_STAT can never resolve a file inside a folder this
 * caller doesn't own.
 */
vw_err_t vw_client_file_upload_into_folder(vw_client_sess_t *sess,
                                            uint64_t folder_file_id,
                                            const char *leaf_name,
                                            const char *local_path,
                                            vw_client_progress_cb_t progress_cb,
                                            void *userdata,
                                            uint64_t *out_file_id,
                                            uint64_t *out_version_id);

/*
 * Move and/or rename a file or folder identified by file_id.
 * new_parent_dir_id == 0 means "move to the file's owner's own root".
 * new_name == NULL or "" keeps the current name (move-only).
 */
vw_err_t vw_client_file_move(vw_client_sess_t *sess,
                              uint64_t file_id,
                              uint64_t new_parent_dir_id,
                              const char *new_name);

/*
 * Create a single directory named `name` (bare leaf, no '/') under
 * new_parent_dir_id (0 = caller's own root). *out_dir_id receives the new
 * directory's file_id. See docs/PROTOCOL.md §7.2 (TASK-104) — this is the
 * only wire mechanism that produces a real VW_ENTRY_DIR record.
 */
vw_err_t vw_client_file_mkdir(vw_client_sess_t *sess,
                               uint64_t new_parent_dir_id,
                               const char *name,
                               uint64_t *out_dir_id);

/* ── Vault registry (server side: TASK-098, docs/PROTOCOL.md §7.11) ──────── */
/*
 * These wrap VAULT_CREATE/VAULT_KEY_FETCH/VAULT_LIST exactly as the server
 * treats them: opaque byte blobs in, opaque byte blobs out. No crypto
 * happens here — wrapping/unwrapping the VK and deriving the KEK from a
 * passphrase is vw_vault.c's job (TASK-099); these functions only move the
 * already-wrapped bytes over the wire, same division of responsibility as
 * every other vw_client_core function.
 */

typedef struct {
    uint64_t vault_id;
    uint64_t folder_file_id;
    int64_t  created_at;
} vw_vault_entry_t;

/*
 * Register a new vault for folder_file_id (which the caller must own).
 * wrapped_vk/kdf_salt/kdf_params are opaque to the server; wrapped_vk_len
 * must be nonzero (rejected server-side with VW_ERR_INVALID_ARG otherwise).
 * *out_vault_id receives the new vault's id.
 */
vw_err_t vw_client_vault_create(vw_client_sess_t *sess, uint64_t folder_file_id,
                                 const uint8_t *wrapped_vk, uint16_t wrapped_vk_len,
                                 const uint8_t kdf_salt[16],
                                 const uint8_t *kdf_params, uint16_t kdf_params_len,
                                 uint64_t *out_vault_id);

/*
 * Fetch a vault's wrapped VK + KDF salt/params (new-device unlock).
 * *out_wrapped_vk and *out_kdf_params are malloc'd; caller frees both
 * (out_kdf_params may be set to NULL with *out_kdf_params_len == 0 if the
 * vault was created with empty kdf_params). Returns VW_ERR_PERMISSION if
 * vault_id exists but isn't owned by the caller. *out_folder_file_id (may
 * be NULL if not needed) receives the vault's folder — vw_vault_unlock
 * needs this so a vault unlocked (not created) this session can still
 * have new files created in it.
 */
vw_err_t vw_client_vault_key_fetch(vw_client_sess_t *sess, uint64_t vault_id,
                                    uint8_t **out_wrapped_vk, uint16_t *out_wrapped_vk_len,
                                    uint8_t out_kdf_salt[16],
                                    uint8_t **out_kdf_params, uint16_t *out_kdf_params_len,
                                    uint64_t *out_folder_file_id);

/*
 * List vaults owned by the caller. Never includes wrapped-key material —
 * use vw_client_vault_key_fetch for that. Returns a malloc'd array; caller
 * frees.
 */
vw_err_t vw_client_vault_list(vw_client_sess_t *sess,
                               vw_vault_entry_t **out, uint32_t *out_count);

/* ── Raw protocol primitives (TASK-099) ──────────────────────────────────── */
/*
 * Lower-level building blocks factored out of the plaintext upload/download
 * paths above so vw_vault.c can compose them for encrypted content, without
 * either duplicating this wire-encoding logic or vw_client_core exposing
 * struct vw_client_sess (which stays private to vw_client_core.c). The
 * vault module owns all cryptographic logic; these functions know nothing
 * about encryption — they move bytes exactly as given.
 */

/*
 * Query the server for one chunk hash and upload data (len bytes) if the
 * server doesn't already have it. Unlike the batched CHUNK_QUERY used by
 * vw_client_file_upload internally, this queries/uploads one chunk per
 * call — appropriate for a caller (vw_vault.c) whose "chunk data" is
 * produced transiently in memory (ciphertext) rather than re-read from a
 * plaintext file on disk.
 */
vw_err_t vw_client_chunk_upload_if_missing(vw_client_sess_t *sess,
                                            const uint8_t hash[VW_HASH_BYTES],
                                            const void *data, uint32_t len);

/*
 * Send FILE_COMMIT and decode FILE_COMMIT_ACK directly — the same
 * wire-encoding vw_client_file_upload/_to_id/_into_folder use internally,
 * exposed so vw_vault.c can commit an encrypted version with a real
 * vault_id/wrapped_dek. vault_id == 0 omits the optional trailing fields
 * entirely (identical to a plaintext commit); vault_id != 0 requires a
 * non-NULL, non-empty wrapped_dek. See docs/PROTOCOL.md §7.11.4.
 */
vw_err_t vw_client_file_commit_raw(vw_client_sess_t *sess, uint64_t file_id,
                                    const char *name_or_path, uint16_t name_len,
                                    uint64_t logical_size, uint32_t chunk_count,
                                    const uint8_t *chunk_hashes,
                                    uint64_t vault_id,
                                    const uint8_t *wrapped_dek, uint16_t wrapped_dek_len,
                                    uint64_t *out_file_id, uint64_t *out_version_id);

/*
 * VERSION_CHUNKS → ordered chunk hash list plus the TASK-099 vault_id/
 * wrapped_dek trailing fields (docs/PROTOCOL.md §7.3). *out_hashes is a
 * malloc'd chunk_count*VW_HASH_BYTES array; caller frees. For an
 * unencrypted version, *out_vault_id is set to 0 and *out_wrapped_dek to
 * NULL (if requested) — out_vault_id/out_wrapped_dek/out_wrapped_dek_len
 * may each be NULL if the caller doesn't need them (e.g. the plaintext
 * download path, which only wants the hash list).
 */
vw_err_t vw_client_version_chunks_raw(vw_client_sess_t *sess, uint64_t version_id,
                                       uint8_t **out_hashes, uint32_t *out_chunk_count,
                                       uint64_t *out_vault_id,
                                       uint8_t **out_wrapped_dek, uint16_t *out_wrapped_dek_len);

/*
 * Fetch and verify one chunk by content hash (CHUNK_DOWNLOAD_REQ /
 * CHUNK_DATA). *out_data is malloc'd *out_len bytes; caller frees. Returns
 * VW_ERR_PROTO_INVALID if the received bytes don't hash to `hash`. For an
 * encrypted version this returns the still-encrypted bytes — decryption is
 * the caller's job.
 */
vw_err_t vw_client_chunk_download_raw(vw_client_sess_t *sess,
                                       const uint8_t hash[VW_HASH_BYTES],
                                       uint8_t **out_data, uint32_t *out_len);

/* ── Sharing (TASK-095; server side: TASK-094, docs/PROTOCOL.md §7.5) ────── */

typedef struct {
    uint64_t share_id;
    uint64_t file_id;
    char     name[64];             /* shared item's leaf name; display-only */
    uint8_t  share_type;           /* 0 = user grant, 1 = public link       */
    char     target_username[65];  /* grants only; empty for links          */
    uint8_t  permission;           /* vw_perm_t                             */
    int64_t  created_at;
    int64_t  expires_at;           /* 0 = never                             */
    uint8_t  revoked;
} vw_share_entry_t;

typedef struct {
    uint64_t share_id;
    uint64_t file_id;
    char     name[64];
    uint8_t  permission;
    int64_t  created_at;
    int64_t  expires_at;
    uint8_t  revoked;
} vw_link_entry_t;

/*
 * Grant target_username VIEW/EDIT access to file_id.
 * expires_at == 0 means never. *out_share_id receives the new share's id.
 * Returns VW_ERR_PERMISSION if the caller's own effective permission on
 * file_id is lower than `permission`.
 */
vw_err_t vw_client_share_grant(vw_client_sess_t *sess,
                                uint64_t file_id,
                                const char *target_username,
                                vw_perm_t permission,
                                int64_t expires_at,
                                uint64_t *out_share_id);

/*
 * Revoke a grant or link by share_id. Returns VW_ERR_PERMISSION if the
 * caller isn't the share's creator (§7.5: only the creator may revoke,
 * not merely an EDIT grantee).
 */
vw_err_t vw_client_share_revoke(vw_client_sess_t *sess, uint64_t share_id);

/*
 * List user-to-user grants. mode: 0 = grants I created, 1 = grants
 * granted to me. Returns a malloc'd array; caller frees.
 */
vw_err_t vw_client_share_list(vw_client_sess_t *sess,
                               uint8_t mode,
                               vw_share_entry_t **out,
                               uint32_t *out_count);

/*
 * Mint a public link for file_id. out_link_token[32] receives the raw
 * token — the only time it is ever available; relay it to the user
 * immediately (e.g. print it once) and never persist it locally beyond
 * that, matching the server's own "never re-display" convention.
 */
vw_err_t vw_client_link_create(vw_client_sess_t *sess,
                                uint64_t file_id,
                                vw_perm_t permission,
                                int64_t expires_at,
                                uint64_t *out_share_id,
                                uint8_t out_link_token[32]);

/* Revoke a public link by share_id. Same ownership rule as share_revoke. */
vw_err_t vw_client_link_revoke(vw_client_sess_t *sess, uint64_t share_id);

/*
 * List public links I've created. file_id_filter == 0 lists all of them.
 * Returns a malloc'd array; caller frees. Never includes the raw token.
 */
vw_err_t vw_client_link_list(vw_client_sess_t *sess,
                              uint64_t file_id_filter,
                              vw_link_entry_t **out,
                              uint32_t *out_count);

/*
 * Redeem a public link — a separate connect flow from vw_client_connect,
 * since no username/password is involved: connects, negotiates the
 * protocol version, then sends LINK_ACCESS instead of AUTH_REQUEST.
 *
 * On success, *out_sess is a scoped (anonymous) session — user_id is
 * always 0 for it (vw_client_user_id_of returns 0), and its quota_bytes/
 * used_bytes are meaningless (always 0; quota is resolved against the
 * link's real owner server-side, never surfaced to the anonymous holder).
 * Use it with vw_client_file_list(sess, "/", ...) to browse the linked
 * item's scope (server-resolved root navigation, §7.5) and the other
 * file-op functions to read/write within it, subject to the link's
 * permission level.
 *
 * Returns VW_ERR_AUTH_BAD_CREDS for an unknown, revoked, or expired token
 * (indistinguishable, by design — anti-enumeration).
 */
vw_err_t vw_client_link_access(const vw_client_cfg_t *cfg,
                                const uint8_t link_token[32],
                                vw_client_sess_t **out_sess);

#ifdef __cplusplus
}
#endif

#endif /* VW_CLIENT_CORE_H */
