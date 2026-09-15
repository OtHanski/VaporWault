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
    /* 0x8013/0x8014 were VW_IPC_LOGIN_REQ/_RESP (single-account login) —
     * removed in TASK-161, superseded by VW_IPC_ACCOUNT_ADD_REQ/_RESP
     * below. Codes deliberately left unused rather than recycled (both IPC
     * ends always ship from the same build, so there's no compatibility
     * reason to recycle them — recycling would just make future git-log
     * archaeology on this range more confusing for no benefit). */

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
    VW_IPC_VAULT_DELETE_REQ   = 0x802D, /* C→D: soft-delete a vault (TASK-00278)  */
    VW_IPC_VAULT_DELETE_RESP  = 0x802E, /* D→C: error_code                        */

    /* TASK-106: add a sync folder rooted at a SHARED item (by file_id)
     * rather than an owned virtual path — a separate message pair rather
     * than an optional trailing field on FOLDER_ADD_REQ, since the two
     * cases need genuinely different validation (an owned virtual_root
     * the caller is free to invent vs. a remote_dir_id that must already
     * exist and be a directory the caller has at least VIEW access to). */
    VW_IPC_FOLDER_ADD_SHARED_REQ  = 0x802F, /* C→D: add shared-folder sync target */
    VW_IPC_FOLDER_ADD_SHARED_RESP = 0x8030, /* D→C: error_code                    */

    /* Multi-account (TASK-161). The daemon holds N concurrently-connected
     * accounts, each with its own server session, cache, and vault
     * registry under {state_dir}/accounts/<account_id>/ — see vw_daemon.c.
     * ACCOUNT_ADD_REQ replaces the old LOGIN_REQ/_RESP pair (removed
     * above): logging in IS adding (or re-authenticating) an account. */
    VW_IPC_ACCOUNT_LIST_REQ    = 0x8031, /* C→D: list configured accounts      */
    VW_IPC_ACCOUNT_LIST_RESP   = 0x8032, /* D→C: count + array of accounts     */
    VW_IPC_ACCOUNT_ADD_REQ     = 0x8033, /* C→D: add a new account, or re-authenticate an existing one */
    VW_IPC_ACCOUNT_ADD_RESP    = 0x8034, /* D→C: error_code + account_id       */
    VW_IPC_ACCOUNT_REMOVE_REQ  = 0x8035, /* C→D: log out and forget an account */
    VW_IPC_ACCOUNT_REMOVE_RESP = 0x8036, /* D→C: error_code                    */

    /* Version history (TASK-182). Server already supports VERSION_LIST/
     * VERSION_RESTORE (docs/PROTOCOL.md §7.3) and vw_client_core.c already
     * has working wrappers — this is the first daemon IPC exposure of
     * either. VERSION_LIST is a read (allowed on a read-only fallback
     * connection, same as SHARE_LIST/LINK_LIST above); VERSION_RESTORE is
     * write-shaped and gets the same account_is_read_only() rejection as
     * every other write-shaped request. */
    VW_IPC_VERSION_LIST_REQ    = 0x8037, /* C→D: list versions of a path       */
    VW_IPC_VERSION_LIST_RESP   = 0x8038, /* D→C: error_code + count + entries  */
    VW_IPC_VERSION_RESTORE_REQ = 0x8039, /* C→D: restore a version as HEAD     */
    VW_IPC_VERSION_RESTORE_RESP = 0x803A, /* D→C: error_code                   */

    /* Selective sync (TASK-192/193): replace (wholesale, not incremental)
     * one sync folder's exclude-pattern set. Entirely local to the
     * daemon — never touches the server (docs/PROTOCOL.md is unaffected,
     * see TASK-192's design). Persisted to account.conf and mirrored into
     * the live vw_sync_ctx_t immediately. */
    VW_IPC_FOLDER_SET_EXCLUDES_REQ  = 0x803B, /* C→D: local_root + new pattern list */
    VW_IPC_FOLDER_SET_EXCLUDES_RESP = 0x803C, /* D→C: error_code                    */

    /* TASK-199: filename search — thin passthrough to the server's
     * SEARCH/SEARCH_RESP (docs/PROTOCOL.md §7.12) via vw_client_search(). */
    VW_IPC_SEARCH_REQ  = 0x803D, /* C→D: account_id + query string     */
    VW_IPC_SEARCH_RESP = 0x803E, /* D→C: error_code + count + truncated + entries */

    /* TASK-209: notification preferences — thin passthrough to the
     * server's NOTIFY_PREFS_GET/SET (docs/PROTOCOL.md §7.13) via
     * vw_client_notify_prefs_get/_set(). _SET is write-shaped: rejected
     * with VW_ERR_READ_ONLY_FALLBACK while the account is on read-only
     * fallback, same as every other write-shaped request in this list;
     * _GET is a read and always works on fallback. */
    VW_IPC_NOTIFY_PREFS_GET_REQ  = 0x803F, /* C→D: account_id                    */
    VW_IPC_NOTIFY_PREFS_GET_RESP = 0x8040, /* D→C: error_code + prefs_bitmask    */
    VW_IPC_NOTIFY_PREFS_SET_REQ  = 0x8041, /* C→D: account_id + prefs_bitmask    */
    VW_IPC_NOTIFY_PREFS_SET_ACK  = 0x8042, /* D→C: error_code + prefs_bitmask    */

    /* TASK-222: account self-service email — thin passthrough to the
     * server's ACCOUNT_EMAIL_GET/SET (docs/PROTOCOL.md §7.14) via
     * vw_client_account_email_get/_set(). _SET is write-shaped: rejected
     * with VW_ERR_READ_ONLY_FALLBACK while the account is on read-only
     * fallback, same as NOTIFY_PREFS_SET above; _GET is a read and
     * always works on fallback. */
    VW_IPC_ACCOUNT_EMAIL_GET_REQ  = 0x8043, /* C→D: account_id                   */
    VW_IPC_ACCOUNT_EMAIL_GET_RESP = 0x8044, /* D→C: error_code + email string    */
    VW_IPC_ACCOUNT_EMAIL_SET_REQ  = 0x8045, /* C→D: account_id + email string    */
    VW_IPC_ACCOUNT_EMAIL_SET_ACK  = 0x8046, /* D→C: error_code + email string    */

    /* TASK-223: file_id-based version history — lets a grantee use
     * version history on a file shared with them, which they have no
     * owner-namespaced path for. Thin passthrough to
     * vw_client_version_list_by_id/_restore_by_id (docs/PROTOCOL.md
     * §7.3, TASK-214's server-side relaxation). Same shapes as
     * VW_IPC_VERSION_LIST_REQ/VW_IPC_VERSION_RESTORE_REQ above, minus
     * the virtual_path field. */
    VW_IPC_VERSION_LIST_BY_ID_REQ     = 0x8047, /* C→D: account_id + file_id     */
    VW_IPC_VERSION_LIST_BY_ID_RESP    = 0x8048, /* D→C: error_code + count + entries */
    VW_IPC_VERSION_RESTORE_BY_ID_REQ  = 0x8049, /* C→D: account_id + version_id  */
    VW_IPC_VERSION_RESTORE_BY_ID_RESP = 0x804A, /* D→C: error_code               */

    /* TASK-219: account self-service 2FA enrollment — thin passthrough to
     * the server's ACCOUNT_2FA_SET (docs/PROTOCOL.md §7.15) via
     * vw_client_account_2fa_set(). Write-shaped: rejected with
     * VW_ERR_READ_ONLY_FALLBACK while the account is on read-only
     * fallback, same as every other account-mutating request above. */
    VW_IPC_ACCOUNT_2FA_SET_REQ  = 0x804B, /* C→D: account_id + password + enable */
    VW_IPC_ACCOUNT_2FA_SET_ACK  = 0x804C, /* D→C: error_code + otp_enabled       */
    VW_IPC_ACCOUNT_2FA_GET_REQ  = 0x804D, /* C→D: account_id                    */
    VW_IPC_ACCOUNT_2FA_GET_RESP = 0x804E, /* D→C: error_code + otp_enabled      */

    /* TASK-00281/00282 (full-project review, TASK-00269): live, file_id-
     * addressed folder listing for a shared item the caller has no
     * owner-namespaced path for — the desktop GUI's "shared with me" view
     * has been flat-list-only for lack of exactly this, even though
     * nothing on the wire ever needed it: FILE_LIST's existing
     * `dir_file_id` field (TASK-106) plus `vw_share_resolve_permission`'s
     * ancestor-chain walk (`is_file_or_ancestor`, `vw_share.c`) already
     * let a grant-holder list ANY descendant directory of a shared folder,
     * to unbounded depth, with correct permission inheritance — the sync
     * engine already relies on exactly this (`vw_sync.c`'s shared-folder
     * BFS calls `vw_client_file_list_by_id` directly). The only real gap
     * was that no daemon IPC message exposed this live (non-cache) lookup
     * to a GUI/CLI caller — `VW_IPC_FILE_LIST_REQ` above only ever queries
     * the local sync *cache*, which has no entries for a shared folder the
     * user hasn't explicitly added as a sync target
     * (`VW_IPC_FOLDER_ADD_SHARED_REQ`). No `docs/PROTOCOL.md` change of
     * any kind was needed — same shape as `VW_IPC_VERSION_LIST_BY_ID_REQ`
     * above: a thin daemon-IPC passthrough to an already-existing,
     * already-used client-core function. `recursive` mirrors
     * `vw_client_file_list_by_id`'s own parameter — 0 for one directory
     * level (what a browsing UI wants per click), left available for a
     * future caller that wants a full subtree in one round trip. */
    VW_IPC_SHARED_FOLDER_LIST_REQ  = 0x804F, /* C→D: account_id + dir_file_id + recursive(u8) */
    VW_IPC_SHARED_FOLDER_LIST_RESP = 0x8050, /* D→C: error_code + count + vw_file_entry_t-shaped entries (see payload doc below) */
} vw_ipc_msg_t;

/*
 * Payload layouts (all integers little-endian; strings = u16 len + UTF-8):
 *
 * Multi-account scoping (TASK-161): every request below that operates on a
 * specific account's data — folder/file/vault/share/link operations — now
 * carries a leading `u32 account_id`, assigned by ACCOUNT_ADD_RESP and
 * reused thereafter exactly like `file_id` is already used instead of
 * repeating paths. An unknown `account_id` gets VW_ERR_INVALID_ARG; a known
 * one with no live session gets VW_ERR_AUTH_REQUIRED (same error used for
 * "no session at all" before this task). STATUS_REQ/_RESP, SYNC_NOW_REQ/
 * _RESP, and SHUTDOWN_REQ/_RESP remain account-agnostic — they report on or
 * act on the daemon as a whole, aggregating across every configured
 * account.
 *
 * VW_IPC_STATUS_RESP:
 *   u8  connected        1 = at least one account has a live server connection
 *   u8  syncing          1 = a sync cycle is in progress for at least one account
 *   u8  paused           1 = all sync paused (every account, every folder)
 *   u8  _pad
 *   i64 last_sync_at     Unix timestamp of the most recent completed sync
 *                        cycle across all accounts; 0 = never
 *   u32 pending_uploads      summed across all accounts
 *   u32 pending_downloads    summed across all accounts
 *   u32 error_count           non-fatal errors since last sync, summed across all accounts
 *   u32 permission_denied_count  TASK-113: permission-denied shared-folder
 *                                auto-mkdir attempts since last sync — kept
 *                                distinct from error_count above rather than
 *                                folded in, so a permission problem doesn't
 *                                read as a generic action error. Appended
 *                                after every existing field; client and
 *                                daemon ship from the same build (see the
 *                                FOLDER_LIST_RESP pause_reason field for the
 *                                same precedent). Summed across all accounts
 *                                (TASK-161) — see VW_IPC_ACCOUNT_LIST_RESP
 *                                for the per-account breakdown of every
 *                                field on this message.
 *   u8  any_on_fallback          TASK-173: 1 = at least one account is
 *                                currently connected to its read-only
 *                                fallback server rather than its primary.
 *                                Trailing field, same append convention as
 *                                permission_denied_count above.
 *
 * VW_IPC_ACCOUNT_LIST_REQ: (no payload)
 * VW_IPC_ACCOUNT_LIST_RESP:
 *   u32 count
 *   count * {
 *     u32    account_id
 *     string label
 *     string username
 *     string server_host
 *     u8     connected         1 = live server session right now (primary
 *                               or fallback -- see conn_mode below to tell
 *                               them apart)
 *     u32    pending_uploads
 *     u32    pending_downloads
 *     u8     conn_mode         TASK-173, trailing field: 0 = offline,
 *                               1 = primary, 2 = fallback (read-only).
 *                               Always 0 when `connected` above is 0.
 *   }
 *
 * VW_IPC_ACCOUNT_ADD_REQ:
 *   u32    account_id     0 = create a new account; nonzero = re-authenticate
 *                         an existing one (e.g. after a password change) —
 *                         its accounts/<id>/ subtree and cache are kept,
 *                         only the session/token/account.conf fields below
 *                         are refreshed.
 *   string label          display name; free-form, not sent to the server
 *   string server_host
 *   u16    server_port
 *   string ca_cert_pem_path   empty = system store
 *   string username
 *   string password       RAW — the daemon derives SHA-256(password) itself
 *                         via vw_client_connect(), same loopback-only trust
 *                         rationale the old LOGIN_REQ used (this socket is
 *                         127.0.0.1-only — see this file's header comment
 *                         for the peer-UID check's per-platform coverage).
 *                         The daemon also retains this derived value (never
 *                         the raw password) as this account's login_token,
 *                         for an unattended fallback connect later
 *                         (TASK-173) — see vw_daemon.c's login_token_save.
 *   string otp            TOTP/OTP code, if the caller already has one;
 *                         empty if not (first attempt on a 2FA-enabled
 *                         account).
 *   string fallback_host        TASK-173, optional trailing fields --
 *                                absent entirely (payload ends after `otp`)
 *                                means "leave fallback config as-is" on a
 *                                re-authentication, or "no fallback" on a
 *                                new account. Empty string explicitly
 *                                clears a previously configured fallback.
 *   u16    fallback_port
 *   string fallback_ca_cert_pem_path   empty = system store
 * VW_IPC_ACCOUNT_ADD_RESP:
 *   u32 error_code        vw_err_t; 0 = VW_OK. VW_ERR_AUTH_2FA_REQUIRED means
 *                         retry with `otp` set (and the same account_id, if
 *                         this was a re-authentication) — server requires
 *                         2FA and none was supplied.
 *   u32 account_id        only meaningful if error_code == 0 — the id to use
 *                         on every subsequent account-scoped request; equal
 *                         to the request's account_id if it was nonzero.
 *
 * VW_IPC_ACCOUNT_REMOVE_REQ:
 *   u32 account_id
 * VW_IPC_ACCOUNT_REMOVE_RESP:
 *   u32 error_code        vw_err_t; 0 = VW_OK. Logs out the account's server
 *                         session and deletes its accounts/<id>/ subtree
 *                         (cache + session token). Files already synced to
 *                         local disk are never touched by this call.
 *
 * VW_IPC_FOLDER_ADD_REQ:
 *   u32    account_id
 *   string local_root
 *   string virtual_root
 *
 * VW_IPC_FOLDER_REMOVE_REQ / VW_IPC_FILE_LIST_REQ:
 *   u32    account_id
 *   string path          local_root (folder remove) or virtual prefix (file list)
 *   u8     filter        sync_state filter; VW_IPC_FILTER_ALL (0xFF) = all
 *                        (FOLDER_REMOVE_REQ ignores this field)
 *
 * VW_IPC_FOLDER_LIST_REQ:
 *   u32 account_id
 * VW_IPC_FOLDER_LIST_RESP per-entry:
 *   string local_root
 *   string virtual_root
 *   u8     paused
 *   u8     pause_reason   TASK-111: VW_PAUSE_REASON_* (vw_cache.h); valid
 *                         iff paused. Inserted right after `paused` (not
 *                         appended) — both client and daemon ship from the
 *                         same build, so there is no version-skew risk from
 *                         changing a field's position rather than only ever
 *                         appending.
 *   u64    remote_dir_id  TASK-106: 0 = owned, path-addressed folder;
 *                         nonzero = a shared folder rooted at this server
 *                         file_id.
 *   u16    exclude_count  TASK-192/193, trailing field
 *   exclude_count * string exclude_pattern
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
 *   u64    vault_id      TASK-158: vw_cache_entry_t.vault_id (0 = unencrypted
 *                        or unknown). Lets the GUI browser show a per-file
 *                        encrypted-item indicator straight from the listing
 *                        it already fetched, replacing the removed
 *                        VW_IPC_FILE_VAULT_ID_REQ/_RESP one-round-trip-per-
 *                        file lookup this superseded.
 *
 * VW_IPC_FOLDER_ADD_RESP / VW_IPC_FOLDER_REMOVE_RESP / VW_IPC_SYNC_NOW_RESP /
 * VW_IPC_PAUSE_RESP / VW_IPC_RESUME_RESP / VW_IPC_SHUTDOWN_RESP:
 *   u32 error_code       vw_err_t; 0 = VW_OK
 *
 * VW_IPC_PAUSE_REQ / VW_IPC_RESUME_REQ:
 *   u32    account_id
 *   string local_root     empty = every folder under this account
 *
 * VW_IPC_SHARE_GRANT_REQ:
 *   u32    account_id
 *   string virtual_path
 *   string target_username
 *   u8     permission     vw_perm_t: VW_PERM_VIEW (1) or VW_PERM_EDIT (2)
 *   i64    expires_at     0 = never
 * VW_IPC_SHARE_GRANT_RESP:
 *   u32 error_code
 *   u64 share_id          only meaningful if error_code == 0
 *
 * VW_IPC_SHARE_REVOKE_REQ / VW_IPC_LINK_REVOKE_REQ:
 *   u32 account_id
 *   u64 share_id
 * VW_IPC_SHARE_REVOKE_RESP / VW_IPC_LINK_REVOKE_RESP:
 *   u32 error_code
 *
 * VW_IPC_SHARE_LIST_REQ:
 *   u32 account_id
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
 *   u32    account_id
 *   string virtual_path
 *   u8     permission
 *   i64    expires_at
 *   string password        TASK-186/188, optional trailing field — empty
 *                           or absent (payload ends after expires_at) =
 *                           no password.
 * VW_IPC_LINK_CREATE_RESP:
 *   u32       error_code
 *   u64       share_id       only meaningful if error_code == 0
 *   bytes[32] link_token     raw token, returned exactly once; only
 *                            meaningful if error_code == 0
 *
 * VW_IPC_LINK_LIST_REQ:
 *   u32 account_id
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
 *     u8     has_password   TASK-186/188, trailing field
 *   }                       never includes the raw link_token, the
 *                           password, or its hash
 *
 * VW_IPC_FILE_MKDIR_REQ:
 *   u32    account_id
 *   u64    new_parent_dir_id  0 = caller's own root
 *   string name            bare leaf name, no '/'
 * VW_IPC_FILE_MKDIR_RESP:
 *   u32 error_code
 *   u64 dir_id             only meaningful if error_code == 0
 *
 * VW_IPC_VAULT_CREATE_REQ:
 *   u32    account_id
 *   u64    folder_file_id  must already be a real directory (FILE_MKDIR
 *                          first) — see docs/PROTOCOL.md §7.2's FILE_STAT_RESP
 *                          note and TASK-099's own discovery of this
 *                          entry_type requirement.
 *   string passphrase      RAW encryption passphrase — same loopback-only
 *                          trust rationale as ACCOUNT_ADD_REQ's password.
 *                          Uses the SEC.07-pinned Argon2id floor; no
 *                          custom-KDF-params path is exposed over IPC.
 * VW_IPC_VAULT_CREATE_RESP:
 *   u32 error_code
 *   u64 vault_id           only meaningful if error_code == 0. On success
 *                          the new vault is also added to that account's
 *                          unlocked-vault registry (no separate UNLOCK
 *                          call needed right after creating it).
 *
 * VW_IPC_VAULT_UNLOCK_REQ:
 *   u32    account_id
 *   u64    vault_id
 *   string passphrase      RAW; same rationale as above. Wrong passphrase
 *                          → error_code == VW_ERR_AUTH_BAD_CREDS.
 * VW_IPC_VAULT_UNLOCK_RESP:
 *   u32 error_code
 *
 * VW_IPC_VAULT_LIST_REQ:
 *   u32 account_id
 * VW_IPC_VAULT_LIST_RESP:
 *   u32 error_code
 *   u32 count              0 if error_code != 0
 *   count * { u64 vault_id, u64 folder_file_id, i64 created_at }
 *
 * VW_IPC_VAULT_UPLOAD_REQ:
 *   u32    account_id
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
 *   u32    account_id
 *   u64    vault_id        must already be unlocked
 *   u64    file_id
 *   string local_path      destination path for the decrypted plaintext
 * VW_IPC_VAULT_DOWNLOAD_RESP:
 *   u32 error_code
 *
 * VW_IPC_VAULT_DELETE_REQ (TASK-00278):
 *   u32    account_id
 *   u64    vault_id        need not currently be unlocked — deletion only
 *                          needs ownership, not the unwrapped VK
 * VW_IPC_VAULT_DELETE_RESP:
 *   u32 error_code         VW_ERR_VAULT_NOT_EMPTY if any file version still
 *                          references this vault_id (docs/PROTOCOL.md
 *                          §7.11.4). On success, vault_id is also dropped
 *                          from this account's in-memory unlocked-vault
 *                          registry if it was present there.
 *
 * VW_IPC_FOLDER_ADD_SHARED_REQ:
 *   u32    account_id
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
 *                        session for that account (VW_ERR_AUTH_REQUIRED if
 *                        none), same as every other server-touching IPC
 *                        request.
 *
 * VW_IPC_VERSION_LIST_REQ:
 *   u32    account_id
 *   string virtual_path
 * VW_IPC_VERSION_LIST_RESP:
 *   u32 error_code
 *   u32 count             0 if error_code != 0
 *   count * {
 *     u64 version_id
 *     i64 created_at
 *     u64 size_bytes
 *   }
 *
 * VW_IPC_VERSION_RESTORE_REQ:
 *   u32    account_id
 *   string virtual_path
 *   u64    version_id
 * VW_IPC_VERSION_RESTORE_RESP:
 *   u32 error_code        vw_err_t; 0 = VW_OK. VW_ERR_READ_ONLY_FALLBACK if
 *                         the account is currently on its fallback
 *                         connection (TASK-173) — restoring is a write.
 *
 * VW_IPC_FOLDER_SET_EXCLUDES_REQ:
 *   u32    account_id
 *   string local_root     must already be a registered sync folder
 *                          (VW_ERR_NOT_FOUND if not)
 *   u16    count           0 = clear all exclude rules for this folder
 *   count * string pattern
 * VW_IPC_FOLDER_SET_EXCLUDES_RESP:
 *   u32 error_code        vw_err_t; 0 = VW_OK. VW_ERR_NOT_FOUND if
 *                         local_root isn't a registered folder for this
 *                         account. Entirely local to the daemon — never
 *                         VW_ERR_AUTH_REQUIRED/READ_ONLY_FALLBACK, since
 *                         this never touches the server.
 *
 * VW_IPC_SEARCH_REQ:
 *   u32    account_id
 *   string query           forwarded as-is to vw_client_search(); see
 *                          docs/PROTOCOL.md §7.12 for its own limits
 *                          (256-byte max, case-insensitive substring)
 * VW_IPC_SEARCH_RESP:
 *   u32 error_code         vw_err_t; 0 = VW_OK. Works while on fallback
 *                          (read-only) since SEARCH is a read.
 *   u32 count              0 if error_code != 0
 *   u8  truncated          1 = more matches existed than the server's
 *                          200-entry cap allowed; 0 if error_code != 0
 *   count * {
 *     u64    file_id
 *     string name          leaf name, display-only
 *     u8     is_dir
 *     u64    size_bytes
 *     i64    mtime_unix
 *     u64    vault_id      0 = unencrypted or a directory
 *     u8     is_shared     1 = visible via a grant, not owned
 *   }
 *
 * VW_IPC_ACCOUNT_EMAIL_GET_REQ:
 *   u32    account_id
 * VW_IPC_ACCOUNT_EMAIL_GET_RESP:
 *   u32    error_code      vw_err_t; 0 = VW_OK. Works while on fallback
 *                          (read-only) since this is a read.
 *   string email           "" if no email is on file (the default state)
 *
 * VW_IPC_ACCOUNT_EMAIL_SET_REQ:
 *   u32    account_id
 *   string email           forwarded as-is to vw_client_account_email_set();
 *                          "" clears the email back to unset. See
 *                          docs/PROTOCOL.md §7.14 for format validation.
 * VW_IPC_ACCOUNT_EMAIL_SET_ACK:
 *   u32    error_code      vw_err_t; 0 = VW_OK. VW_ERR_READ_ONLY_FALLBACK
 *                          if the account is currently on its fallback
 *                          connection (TASK-173) — setting is a write.
 *   string email           the stored value after this call (unchanged
 *                          from before on any error)
 *
 * VW_IPC_VERSION_LIST_BY_ID_REQ:
 *   u32    account_id
 *   u64    file_id         from vw_client_share_list, for content the
 *                          caller doesn't own
 * VW_IPC_VERSION_LIST_BY_ID_RESP: same shape as VW_IPC_VERSION_LIST_RESP.
 *
 * VW_IPC_VERSION_RESTORE_BY_ID_REQ:
 *   u32    account_id
 *   u64    version_id      from VW_IPC_VERSION_LIST_BY_ID_RESP above
 * VW_IPC_VERSION_RESTORE_BY_ID_RESP:
 *   u32 error_code         vw_err_t; 0 = VW_OK. VW_ERR_READ_ONLY_FALLBACK
 *                          if the account is currently on its fallback
 *                          connection (TASK-173) — restoring is a write.
 *
 * VW_IPC_ACCOUNT_2FA_SET_REQ:
 *   u32    account_id
 *   string password        plaintext current password — hashed to the
 *                          wire's password_token shape inside
 *                          vw_client_account_2fa_set(), same as
 *                          ACCOUNT_ADD_REQ's own plaintext password field
 *                          above; never touches disk or logs
 *   u8     enable           1 = enable, 0 = disable
 * VW_IPC_ACCOUNT_2FA_SET_ACK:
 *   u32 error_code         vw_err_t; 0 = VW_OK. VW_ERR_READ_ONLY_FALLBACK
 *                          if the account is currently on its fallback
 *                          connection (TASK-173). VW_ERR_AUTH_BAD_CREDS
 *                          if password didn't match. VW_ERR_INVALID_ARG
 *                          if enabling with no email on file.
 *   u8  otp_enabled        the stored value after this call
 *
 * VW_IPC_ACCOUNT_2FA_GET_REQ:
 *   u32    account_id
 * VW_IPC_ACCOUNT_2FA_GET_RESP:
 *   u32 error_code         vw_err_t; 0 = VW_OK. Works while on fallback
 *                          (read-only) since this is a read.
 *   u8  otp_enabled
 *
 * VW_IPC_SHARED_FOLDER_LIST_REQ (TASK-00281/00282):
 *   u32    account_id
 *   u64    dir_file_id     a shared folder's own file_id (from SHARE_LIST
 *                          mode=1 / VW_IPC_SHARE_LIST_RESP), or any
 *                          directory file_id previously returned by this
 *                          same message — the caller descends one level
 *                          at a time by re-issuing this with the clicked
 *                          subfolder's file_id.
 *   u8     recursive       0 = this directory's immediate children only
 *                          (what a browsing UI wants per click); 1 = the
 *                          whole subtree in one call (mirrors
 *                          vw_client_file_list_by_id's own parameter,
 *                          unused by the initial GUI consumer but free to
 *                          expose since the client-core function already
 *                          supports it).
 * VW_IPC_SHARED_FOLDER_LIST_RESP:
 *   u32    error_code      vw_err_t; 0 = VW_OK. VW_ERR_NOT_FOUND if the
 *                          caller has no access at all to dir_file_id;
 *                          VW_ERR_INVALID_ARG if dir_file_id names a file,
 *                          not a directory (same ordering/anti-enumeration
 *                          behavior as FILE_LIST's own dir_file_id path,
 *                          docs/PROTOCOL.md §7.2 — permission is checked
 *                          before entry_type). Works while on fallback
 *                          (read-only) since this is a read.
 *   u32    count
 *   count * entry, each:
 *     u8     entry_type    0=file, 1=dir
 *     u64    file_id
 *     u64    size_bytes
 *     i64    mtime_unix
 *     u64    version_id    current HEAD version; 0 if directory
 *     string name          leaf name
 *     u64    vault_id      0 = unencrypted or a directory
 *   (same field set as vw_file_entry_t, src/client/vw_client_core.h — a
 *   live remote listing, not a vw_cache_entry_t row, so it carries no
 *   virtual_path/local_path/sync_state/local_mtime: those describe this
 *   daemon's own local sync cache, which has no entries for a shared
 *   folder the caller hasn't explicitly added as a sync target via
 *   VW_IPC_FOLDER_ADD_SHARED_REQ)
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
