#ifndef VW_IPC_H
#define VW_IPC_H

/*
 * vw_ipc — VaporWault daemon IPC protocol.
 *
 * Provides a localhost-only TCP channel between the daemon and its clients
 * (CLI, GUI). Uses the same 8-byte message framing as the server wire protocol
 * (vw_proto) but with message-type constants in the 0x8000–0x8FFF range and
 * plain TCP (no TLS). The channel is loopback-only (127.0.0.1).
 *
 * Peer-UID verification on accept (TASK-093): SO_PEERCRED (the mechanism an
 * earlier version of this file tried to use on Linux) is an AF_UNIX-only
 * facility and produces undefined, kernel-dependent results on an AF_INET
 * socket like this one (confirmed empirically: at least one real Linux
 * kernel returns success with a garbage uid instead of failing, which
 * silently rejected every connection). On Linux, this is now replaced with
 * a real check via /proc/net/tcp (see vw_ipc_linux_proc_net_tcp_uid() in
 * vw_ipc.c), which exposes the owning uid of every TCP socket on the system
 * without needing SO_PEERCRED. On Windows (TASK-103), this is replaced with
 * a real check via GetExtendedTcpTable + a PID-to-SID lookup (see
 * vw_ipc_win_tcp_table_pid() in vw_ipc.c) — deliberately more permissive on
 * any failure to positively resolve a mismatched SID than the Linux check
 * is, since GetExtendedTcpTable is a heavier whole-system snapshot with a
 * real race window; see vw_ipc_server_accept()'s doc comment below. On
 * macOS, no peer-UID check is performed — loopback binding (127.0.0.1) is
 * the sole trust boundary there; macOS support is deferred project-wide so
 * this isn't tracked further.
 *
 * vw_ipc_conn_t is a thin raw-socket wrapper distinct from vw_conn_t (which
 * is TLS-only). Use vw_ipc_send/vw_ipc_recv for framing; do not call
 * vw_proto_send/vw_proto_recv on IPC connections.
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Default port ────────────────────────────────────────────────────────── */

#define VW_IPC_DEFAULT_PORT ((uint16_t)47832)

/* Filter value for VW_IPC_FILE_LIST_REQ: return all sync states */
#define VW_IPC_FILTER_ALL   ((uint8_t)0xFF)

/* ── IPC message types (0x8000–0x8FFF) ──────────────────────────────────── */

typedef enum {
    VW_IPC_STATUS_REQ         = 0x8001, /* C→D: request daemon status snapshot    */
    VW_IPC_STATUS_RESP        = 0x8002, /* D→C: connected, syncing, paused, …     */
    VW_IPC_SYNC_NOW_REQ       = 0x8003, /* C→D: trigger immediate sync cycle      */
    VW_IPC_SYNC_NOW_RESP      = 0x8004, /* D→C: acknowledged (sync queued)        */
    VW_IPC_PAUSE_REQ          = 0x8005, /* C→D: pause sync (all or one folder)    */
    VW_IPC_PAUSE_RESP         = 0x8006, /* D→C: acknowledged                      */
    VW_IPC_RESUME_REQ         = 0x8007, /* C→D: resume sync                       */
    VW_IPC_RESUME_RESP        = 0x8008, /* D→C: acknowledged                      */
    VW_IPC_FOLDER_ADD_REQ     = 0x8009, /* C→D: add sync folder                   */
    VW_IPC_FOLDER_ADD_RESP    = 0x800A, /* D→C: success or error_code             */
    VW_IPC_FOLDER_REMOVE_REQ  = 0x800B, /* C→D: remove sync folder by local_root  */
    VW_IPC_FOLDER_REMOVE_RESP = 0x800C, /* D→C: success or error_code             */
    VW_IPC_FOLDER_LIST_REQ    = 0x800D, /* C→D: list all sync folders             */
    VW_IPC_FOLDER_LIST_RESP   = 0x800E, /* D→C: count + array of folder entries   */
    VW_IPC_FILE_LIST_REQ      = 0x800F, /* C→D: list cache entries (opt. filter)  */
    VW_IPC_FILE_LIST_RESP     = 0x8010, /* D→C: count + array of file entries     */
    VW_IPC_SHUTDOWN_REQ       = 0x8011, /* C→D: ask daemon to shut down           */
    VW_IPC_SHUTDOWN_RESP      = 0x8012, /* D→C: acknowledged                      */
    VW_IPC_LOGIN_REQ          = 0x8013, /* C→D: authenticate with password (+OTP) */
    VW_IPC_LOGIN_RESP         = 0x8014, /* D→C: error_code                        */

    /* Sharing (TASK-095; server side: TASK-094, docs/PROTOCOL.md §7.5).
     * Every _REQ below requires an active daemon session (dc->sess) — the
     * daemon forwards to the real server via the vw_client_share_ and
     * vw_client_link_ functions, resolving the given virtual_path to a
     * file_id via vw_client_file_stat first. Every _RESP is prefixed with
     * error_code(u32) since these are genuine network round-trips that can
     * fail (unlike the local-cache-only FOLDER_LIST/FILE_LIST responses
     * above) — VW_ERR_AUTH_REQUIRED if there is no active session. */
    VW_IPC_SHARE_GRANT_REQ    = 0x8015, /* C→D: grant a user access to a path     */
    VW_IPC_SHARE_GRANT_RESP   = 0x8016, /* D→C: error_code + share_id             */
    VW_IPC_SHARE_REVOKE_REQ   = 0x8017, /* C→D: revoke a grant or link by share_id */
    VW_IPC_SHARE_REVOKE_RESP  = 0x8018, /* D→C: error_code                        */
    VW_IPC_SHARE_LIST_REQ     = 0x8019, /* C→D: list user-to-user grants          */
    VW_IPC_SHARE_LIST_RESP    = 0x801A, /* D→C: error_code + count + entries      */
    VW_IPC_LINK_CREATE_REQ    = 0x801B, /* C→D: mint a public link for a path     */
    VW_IPC_LINK_CREATE_RESP   = 0x801C, /* D→C: error_code + share_id + token[32] */
    VW_IPC_LINK_REVOKE_REQ    = 0x801D, /* C→D: revoke a public link by share_id  */
    VW_IPC_LINK_REVOKE_RESP   = 0x801E, /* D→C: error_code                        */
    VW_IPC_LINK_LIST_REQ      = 0x801F, /* C→D: list public links I've created    */
    VW_IPC_LINK_LIST_RESP     = 0x8020, /* D→C: error_code + count + entries      */

    /* Vault / E2EE (TASK-100; client library: TASK-099, docs/PROTOCOL.md
     * §7.11). Same conventions as Sharing above: every _REQ requires an
     * active daemon session, every _RESP is prefixed with error_code(u32).
     * VAULT_UNLOCK's unwrapped VK never leaves the daemon process — it is
     * held in an in-memory registry (vault_id -> unlocked vw_vault_t),
     * exactly mirroring how the account session token is held in dc->sess;
     * VAULT_UPLOAD/_DOWNLOAD reference a vault purely by vault_id and
     * require it to already be in that registry (VW_ERR_AUTH_REQUIRED if
     * not — same error the Sharing block above uses for "no session"). */
    VW_IPC_FILE_MKDIR_REQ     = 0x8021, /* C→D: create a directory                */
    VW_IPC_FILE_MKDIR_RESP    = 0x8022, /* D→C: error_code + new dir's file_id    */
    VW_IPC_VAULT_CREATE_REQ   = 0x8023, /* C→D: create+unlock a new vault         */
    VW_IPC_VAULT_CREATE_RESP  = 0x8024, /* D→C: error_code + vault_id             */
    VW_IPC_VAULT_UNLOCK_REQ   = 0x8025, /* C→D: unlock an existing vault          */
    VW_IPC_VAULT_UNLOCK_RESP  = 0x8026, /* D→C: error_code                        */
    VW_IPC_VAULT_LIST_REQ     = 0x8027, /* C→D: list my vaults                    */
    VW_IPC_VAULT_LIST_RESP    = 0x8028, /* D→C: error_code + count + entries      */
    VW_IPC_VAULT_UPLOAD_REQ   = 0x8029, /* C→D: encrypt+upload a local file       */
    VW_IPC_VAULT_UPLOAD_RESP  = 0x802A, /* D→C: error_code + file_id + version_id */
    VW_IPC_VAULT_DOWNLOAD_REQ = 0x802B, /* C→D: download+decrypt to a local path  */
    VW_IPC_VAULT_DOWNLOAD_RESP = 0x802C, /* D→C: error_code                       */

    /* Narrow lookup for the file browser's encrypted-item indicator: just
     * the vault_id, not a full FILE_STAT passthrough (which doesn't exist
     * over this IPC and isn't otherwise needed by any GUI view today). */
    VW_IPC_FILE_VAULT_ID_REQ  = 0x802D, /* C→D: look up one file's vault_id       */
    VW_IPC_FILE_VAULT_ID_RESP = 0x802E, /* D→C: error_code + vault_id             */

    /* TASK-106: add a sync folder rooted at a SHARED item (by file_id)
     * rather than an owned virtual path — a separate message pair rather
     * than an optional trailing field on FOLDER_ADD_REQ, since the two
     * cases need genuinely different validation (an owned virtual_root
     * the caller is free to invent vs. a remote_dir_id that must already
     * exist and be a directory the caller has at least VIEW access to). */
    VW_IPC_FOLDER_ADD_SHARED_REQ  = 0x802F, /* C→D: add shared-folder sync target */
    VW_IPC_FOLDER_ADD_SHARED_RESP = 0x8030, /* D→C: error_code                    */
} vw_ipc_msg_t;

/*
 * Payload layouts (all integers little-endian; strings = u16 len + UTF-8):
 *
 * VW_IPC_STATUS_RESP:
 *   u8  connected        1 = live server connection
 *   u8  syncing          1 = sync cycle in progress
 *   u8  paused           1 = all sync paused
 *   u8  _pad
 *   i64 last_sync_at     Unix timestamp of last completed sync; 0 = never
 *   u32 pending_uploads
 *   u32 pending_downloads
 *   u32 error_count      non-fatal errors since last sync
 *
 * VW_IPC_FOLDER_ADD_REQ:
 *   string local_root
 *   string virtual_root
 *
 * VW_IPC_FOLDER_REMOVE_REQ / VW_IPC_FILE_LIST_REQ:
 *   string path          local_root (folder remove) or virtual prefix (file list)
 *   u8     filter        sync_state filter; VW_IPC_FILTER_ALL (0xFF) = all
 *
 * VW_IPC_FOLDER_LIST_RESP per-entry:
 *   string local_root
 *   string virtual_root
 *   u8     paused
 *   u64    remote_dir_id  TASK-106: 0 = owned, path-addressed folder;
 *                         nonzero = a shared folder rooted at this server
 *                         file_id. Appended after every existing field —
 *                         no prior consumer of this message decoded past
 *                         `paused`, so this is a plain addition, not a
 *                         version-negotiated one (unlike the wire protocol
 *                         to the server, this IPC channel has no separate
 *                         client/daemon versions to keep in sync — they
 *                         ship from the same build).
 *

 * VW_IPC_FILE_LIST_RESP per-entry:
 *   string virtual_path
 *   string local_path
 *   u32    sync_state    vw_sync_state_t
 *   u8     entry_type    0=file, 1=dir
 *   i64    server_mtime
 *   i64    local_mtime
 *   u64    server_size
 *   u64    file_id       server file_id (vw_cache_entry_t already tracks
 *                        this; 0 = not yet uploaded — added for TASK-096,
 *                        which needs it to cross-reference SHARE_LIST/
 *                        LINK_LIST entries against browser rows). Internal
 *                        daemon↔client IPC only, not the wire protocol to
 *                        the server — no version negotiation needed.
 *
 * VW_IPC_FOLDER_ADD_RESP / VW_IPC_FOLDER_REMOVE_RESP / VW_IPC_SYNC_NOW_RESP /
 * VW_IPC_PAUSE_RESP / VW_IPC_RESUME_RESP / VW_IPC_SHUTDOWN_RESP:
 *   u32 error_code       vw_err_t; 0 = VW_OK
 *
 * VW_IPC_LOGIN_REQ:
 *   string password      RAW password — the daemon derives SHA-256(password)
 *                        itself via vw_client_connect(), same rationale as
 *                        the server admin IPC's USER_CREATE_REQ: this socket
 *                        is loopback-only (127.0.0.1), so sending the raw
 *                        password here is not a new exposure — see this
 *                        file's header comment for the peer-UID check's
 *                        per-platform coverage. The username comes from the daemon's own
 *                        already-configured daemon.conf, not from this
 *                        payload.
 *   string otp           TOTP/OTP code, if the caller already has one; empty
 *                        if not (first attempt on a 2FA-enabled account).
 * VW_IPC_LOGIN_RESP:
 *   u32 error_code       vw_err_t; 0 = VW_OK. VW_ERR_AUTH_2FA_REQUIRED means
 *                        retry with `otp` set (server requires 2FA and none
 *                        was supplied). On success the daemon persists the
 *                        new session token to state_dir/session.tok.
 *
 * VW_IPC_SHARE_GRANT_REQ:
 *   string virtual_path
 *   string target_username
 *   u8     permission     vw_perm_t: VW_PERM_VIEW (1) or VW_PERM_EDIT (2)
 *   i64    expires_at     0 = never
 * VW_IPC_SHARE_GRANT_RESP:
 *   u32 error_code
 *   u64 share_id          only meaningful if error_code == 0
 *
 * VW_IPC_SHARE_REVOKE_REQ / VW_IPC_LINK_REVOKE_REQ:
 *   u64 share_id
 * VW_IPC_SHARE_REVOKE_RESP / VW_IPC_LINK_REVOKE_RESP:
 *   u32 error_code
 *
 * VW_IPC_SHARE_LIST_REQ:
 *   u8  mode              0 = grants I created, 1 = grants granted to me
 * VW_IPC_SHARE_LIST_RESP:
 *   u32 error_code
 *   u32 count             0 if error_code != 0
 *   count * {
 *     u64    share_id
 *     u64    file_id
 *     string name              shared item's leaf name; display-only
 *     u8     share_type        0 = user grant, 1 = public link
 *     string target_username   empty for links
 *     u8     permission
 *     i64    created_at
 *     i64    expires_at        0 = never
 *     u8     revoked
 *   }
 *
 * VW_IPC_LINK_CREATE_REQ:
 *   string virtual_path
 *   u8     permission
 *   i64    expires_at
 * VW_IPC_LINK_CREATE_RESP:
 *   u32       error_code
 *   u64       share_id       only meaningful if error_code == 0
 *   bytes[32] link_token     raw token, returned exactly once; only
 *                            meaningful if error_code == 0
 *
 * VW_IPC_LINK_LIST_REQ:
 *   u64 file_id_filter    0 = all of my links
 * VW_IPC_LINK_LIST_RESP:
 *   u32 error_code
 *   u32 count             0 if error_code != 0
 *   count * {
 *     u64    share_id
 *     u64    file_id
 *     string name           display-only leaf name
 *     u8     permission
 *     i64    created_at
 *     i64    expires_at     0 = never
 *     u8     revoked
 *   }                       never includes the raw link_token
 *
 * VW_IPC_FILE_MKDIR_REQ:
 *   u64 new_parent_dir_id  0 = caller's own root
 *   string name            bare leaf name, no '/'
 * VW_IPC_FILE_MKDIR_RESP:
 *   u32 error_code
 *   u64 dir_id             only meaningful if error_code == 0
 *
 * VW_IPC_VAULT_CREATE_REQ:
 *   u64    folder_file_id  must already be a real directory (FILE_MKDIR
 *                          first) — see docs/PROTOCOL.md §7.2's FILE_STAT_RESP
 *                          note and TASK-099's own discovery of this
 *                          entry_type requirement.
 *   string passphrase      RAW encryption passphrase — same loopback-only
 *                          trust rationale as VW_IPC_LOGIN_REQ's password.
 *                          Uses the SEC.07-pinned Argon2id floor; no
 *                          custom-KDF-params path is exposed over IPC.
 * VW_IPC_VAULT_CREATE_RESP:
 *   u32 error_code
 *   u64 vault_id           only meaningful if error_code == 0. On success
 *                          the new vault is also added to the daemon's
 *                          unlocked-vault registry (no separate UNLOCK
 *                          call needed right after creating it).
 *
 * VW_IPC_VAULT_UNLOCK_REQ:
 *   u64    vault_id
 *   string passphrase      RAW; same rationale as above. Wrong passphrase
 *                          → error_code == VW_ERR_AUTH_BAD_CREDS.
 * VW_IPC_VAULT_UNLOCK_RESP:
 *   u32 error_code
 *
 * VW_IPC_VAULT_LIST_REQ: (no payload)
 * VW_IPC_VAULT_LIST_RESP:
 *   u32 error_code
 *   u32 count              0 if error_code != 0
 *   count * { u64 vault_id, u64 folder_file_id, i64 created_at }
 *
 * VW_IPC_VAULT_UPLOAD_REQ:
 *   u64    vault_id        must already be unlocked (VAULT_CREATE/_UNLOCK)
 *   u64    file_id         0 = create a new file named leaf_name
 *   string leaf_name       used only when file_id == 0; bare leaf, no '/'
 *   string local_path      local filesystem path to encrypt and upload
 * VW_IPC_VAULT_UPLOAD_RESP:
 *   u32 error_code
 *   u64 file_id            only meaningful if error_code == 0
 *   u64 version_id         only meaningful if error_code == 0
 *
 * VW_IPC_VAULT_DOWNLOAD_REQ:
 *   u64    vault_id        must already be unlocked
 *   u64    file_id
 *   string local_path      destination path for the decrypted plaintext
 * VW_IPC_VAULT_DOWNLOAD_RESP:
 *   u32 error_code
 *
 * VW_IPC_FILE_VAULT_ID_REQ:
 *   u64 file_id
 * VW_IPC_FILE_VAULT_ID_RESP:
 *   u32 error_code
 *   u64 vault_id           0 = unencrypted; only meaningful if error_code == 0
 *
 * VW_IPC_FOLDER_ADD_SHARED_REQ:
 *   string local_root      local filesystem directory to sync into
 *   string virtual_root    local display/bookkeeping name only (TASK-106
 *                          design: never sent to the server for a shared
 *                          folder) — shown in `ls`/status output the same
 *                          way an owned folder's virtual_root is.
 *   u64    remote_dir_id   the shared item's server file_id. Must already
 *                          be a directory (VW_ENTRY_DIR) the caller has at
 *                          least VIEW access to (checked via FILE_STAT_BY_ID
 *                          before the folder is added — VW_ERR_NOT_FOUND if
 *                          no access, VW_ERR_INVALID_ARG if it's a file, not
 *                          a directory).
 * VW_IPC_FOLDER_ADD_SHARED_RESP:
 *   u32 error_code       vw_err_t; 0 = VW_OK. Requires an active daemon
 *                        session (VW_ERR_AUTH_REQUIRED if none), same as
 *                        every other server-touching IPC request.
 */

/* ── Opaque types ────────────────────────────────────────────────────────── */

typedef struct vw_ipc_conn   vw_ipc_conn_t;
typedef struct vw_ipc_server vw_ipc_server_t;

/* ── IPC message framing ─────────────────────────────────────────────────── */

/*
 * Send a framed IPC message. payload may be NULL if payload_len == 0.
 * Blocks until all bytes are written or an error occurs.
 */
vw_err_t vw_ipc_send(vw_ipc_conn_t *conn, vw_ipc_msg_t type,
                      const void *payload, uint32_t payload_len);

/*
 * Receive one framed IPC message into out_buf.
 * buf_size must be at least the expected message payload size.
 * Returns VW_ERR_PROTO_TOO_LARGE if the incoming message exceeds buf_size
 * or VW_MAX_MSG_BYTES.
 */
vw_err_t vw_ipc_recv(vw_ipc_conn_t *conn, vw_ipc_msg_t *out_type,
                      void *out_buf, uint32_t buf_size,
                      uint32_t *out_payload_len);

/*
 * Close an IPC connection and free the object. Safe to call with NULL.
 */
void vw_ipc_conn_close(vw_ipc_conn_t *conn);

/*
 * Set a per-connection recv timeout. 0 = no timeout (block indefinitely).
 */
vw_err_t vw_ipc_conn_set_recv_timeout(vw_ipc_conn_t *conn, uint32_t timeout_ms);

/* ── Server-side API ─────────────────────────────────────────────────────── */

/*
 * Open a listening TCP socket on 127.0.0.1:port with SO_REUSEADDR, backlog 8.
 * Returns VW_ERR_NET_CONNECT if the port cannot be bound.
 */
vw_err_t vw_ipc_server_open(uint16_t port, vw_ipc_server_t **out);

/*
 * Close the listening socket and free the server object. Safe to call with NULL.
 */
void vw_ipc_server_close(vw_ipc_server_t *srv);

/*
 * Accept one client connection (blocking).
 *
 * On Linux, verifies the connecting process's uid via /proc/net/tcp
 * (TASK-093) and returns VW_ERR_AUTH_REQUIRED if it doesn't match ours (or
 * falls back to trusting loopback binding alone if /proc/net/tcp can't be
 * read in this environment — see vw_ipc.c for the full reasoning). On
 * Windows, verifies the connecting process's SID via GetExtendedTcpTable
 * (TASK-103) and returns VW_ERR_AUTH_REQUIRED only if a peer SID is
 * positively resolved and it doesn't match ours — any failure to resolve it
 * (table fetch failed, PID not found, insufficient privilege, a race
 * between accept() and the table snapshot) falls back to trusting loopback
 * binding alone, deliberately more permissive than the Linux path; see
 * vw_ipc.c for the full reasoning. On macOS, no peer-UID check is performed
 * — loopback binding (127.0.0.1) is the trust boundary there, and macOS
 * support is deferred project-wide so this isn't tracked further. See this
 * header's top comment for why SO_PEERCRED (used incorrectly here in an
 * earlier version) doesn't work for an AF_INET socket.
 */
vw_err_t vw_ipc_server_accept(vw_ipc_server_t *srv, vw_ipc_conn_t **out_conn);

/*
 * Non-blocking accept: polls the listen socket and returns VW_ERR_TIMEOUT
 * immediately if no connection is pending. Used by the daemon main loop to
 * drain all pending connections without blocking.
 */
vw_err_t vw_ipc_server_try_accept(vw_ipc_server_t *srv, vw_ipc_conn_t **out_conn);

/* ── Client-side API ─────────────────────────────────────────────────────── */

/*
 * Connect to the daemon IPC listener on 127.0.0.1:port.
 * Returns VW_ERR_IPC_NOT_RUNNING if the daemon is not listening.
 */
vw_err_t vw_ipc_connect(uint16_t port, vw_ipc_conn_t **out_conn);

/* ── Payload encode / decode helpers ─────────────────────────────────────── */

/*
 * Append a length-prefixed UTF-8 string (u16 len + bytes) at *offset in buf.
 * Returns VW_ERR_PROTO_TOO_LARGE if there is not enough space.
 */
vw_err_t vw_ipc_write_str(uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                            const char *str, uint16_t str_len);

/*
 * Read a length-prefixed string from buf at *offset.
 * *out_str points into buf (zero-copy, not NUL-terminated).
 * Returns VW_ERR_PROTO_TRUNCATED if the buffer ends prematurely.
 */
vw_err_t vw_ipc_read_str(const uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                           const char **out_str, uint16_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* VW_IPC_H */
