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

#ifdef __cplusplus
}
#endif

#endif /* VW_CLIENT_CORE_H */
