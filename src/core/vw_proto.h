#ifndef VW_PROTO_H
#define VW_PROTO_H

/*
 * vw_proto — VaporWault binary wire protocol.
 *
 * All integers are little-endian. Strings are length-prefixed: a uint16_t
 * byte count followed by UTF-8 bytes (no null terminator). Binary blobs
 * (hashes, tokens) are fixed-length raw bytes.
 *
 * Message framing:
 *   [u32 total_len][u16 msg_type][u16 proto_version][payload...]
 *
 * total_len includes the 8-byte header. Maximum message size is VW_MAX_MSG_BYTES.
 * The protocol version field carries the sender's negotiated version (set after
 * the HELLO / HELLO_OK exchange; use VW_PROTO_VERSION_CURRENT in HELLO).
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Version ─────────────────────────────────────────────────────────────── */

#define VW_PROTO_VERSION_CURRENT  ((uint16_t)6)
#define VW_PROTO_HEADER_SIZE      8u
#define VW_MAX_MSG_BYTES          (8u * 1024u * 1024u)   /* 8 MiB */
#define VW_MAX_PATH_BYTES         4096u
#define VW_MAX_USERNAME_BYTES     64u
#define VW_MAX_EMAIL_BYTES        256u
#define VW_HASH_BYTES             32u   /* SHA-256 */
#define VW_TOKEN_BYTES            32u   /* session / invite tokens */
#define VW_CHUNK_SIZE_DEFAULT     (4u * 1024u * 1024u)   /* 4 MiB */

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef enum {
    VW_OK                     = 0,

    /* Generic */
    VW_ERR_IO                 = 1,
    VW_ERR_OOM                = 2,
    VW_ERR_INVALID_ARG        = 3,
    VW_ERR_TIMEOUT            = 4,
    VW_ERR_NOT_FOUND          = 5,
    VW_ERR_ALREADY_EXISTS     = 6,
    VW_ERR_PERMISSION         = 7,
    VW_ERR_QUOTA_EXCEEDED     = 8,
    VW_ERR_NOT_IMPL           = 9,

    /* Network / TLS */
    VW_ERR_NET_CONNECT        = 100,
    VW_ERR_NET_TLS            = 101,
    VW_ERR_NET_CLOSED         = 102,
    VW_ERR_NET_TIMEOUT        = 103,

    /* Protocol */
    VW_ERR_PROTO_INVALID      = 200,
    VW_ERR_PROTO_VERSION      = 201,
    VW_ERR_PROTO_TOO_LARGE    = 202,
    VW_ERR_PROTO_TRUNCATED    = 203,

    /* Auth */
    VW_ERR_AUTH_BAD_CREDS     = 300,
    VW_ERR_AUTH_2FA_REQUIRED  = 301,
    VW_ERR_AUTH_2FA_INVALID   = 302,
    VW_ERR_AUTH_SESSION_EXPIRED = 303,
    VW_ERR_AUTH_LOCKED        = 304,   /* account locked (too many password attempts) */
    VW_ERR_AUTH_2FA_LOCKED    = 305,   /* 2FA locked (too many OTP attempts)          */
    VW_ERR_AUTH_REQUIRED      = 306,   /* file op sent without a valid session token   */

    /* Storage */
    VW_ERR_STORE_CORRUPT      = 400,
    VW_ERR_STORE_FULL         = 401,

    /* Crypto */
    VW_ERR_CRYPTO             = 500,

    /* File transfer */
    VW_ERR_CHUNK_HASH_MISMATCH = 600,  /* uploaded chunk SHA-256 != declared hash   */
    VW_ERR_PATH_INVALID        = 601,  /* virtual path fails validation rules        */
    VW_ERR_PATH_CONFLICT       = 602,  /* file/directory type collision at path      */
    VW_ERR_VERSION_NOT_FOUND   = 603,  /* version_id absent or belongs to other file */
    VW_ERR_DIR_NOT_EMPTY       = 604,  /* directory delete: children still exist     */
    VW_ERR_RATE_LIMITED        = 605,  /* TASK-094: scoped-session write-count cap hit */
    VW_ERR_READ_ONLY_REPLICA   = 606,  /* TASK-179: server rejected a write-shaped
                                          request because it is running as a
                                          cluster replica (cfg.cluster.is_replica);
                                          sent over the wire, defense-in-depth
                                          alongside the daemon's own client-side
                                          VW_ERR_READ_ONLY_FALLBACK (800s, below) */
    VW_ERR_LINK_PASSWORD_REQUIRED = 607, /* TASK-186: LINK_ACCESS against a
                                          password-protected link, no password
                                          supplied */
    VW_ERR_LINK_PASSWORD_WRONG = 608,  /* TASK-186: LINK_ACCESS against a
                                          password-protected link, wrong
                                          password supplied */

    /* IPC */
    VW_ERR_IPC_NOT_RUNNING     = 700,  /* daemon not listening on IPC port           */

    /* Client-local sync engine (TASK-111; never sent over the wire) */
    VW_ERR_SYNC_TREE_TOO_LARGE = 800,  /* shared-folder BFS exceeded the client's
                                          resource ceiling for one sync cycle       */
    VW_ERR_READ_ONLY_FALLBACK  = 801,  /* TASK-173: daemon rejected a write-shaped
                                          IPC request because this account is
                                          currently connected to its read-only
                                          fallback server, not the primary; never
                                          sent over the wire, IPC-response only  */
} vw_err_t;

/* ── Message types ───────────────────────────────────────────────────────── */

typedef enum {
    /* Connection / version */
    VW_MSG_HELLO              = 0x0001,
    VW_MSG_HELLO_OK           = 0x0002,
    VW_MSG_VERSION_REJECT     = 0x0003,
    VW_MSG_GOODBYE            = 0x000F,
    VW_MSG_KEEPALIVE          = 0x0010,
    VW_MSG_ERROR              = 0x00FF,

    /* Auth */
    VW_MSG_AUTH_REQUEST       = 0x0101,
    VW_MSG_AUTH_CHALLENGE     = 0x0102,  /* server → client: 2FA OTP needed */
    VW_MSG_AUTH_OTP           = 0x0103,  /* client → server: OTP response */
    VW_MSG_AUTH_OK            = 0x0104,
    VW_MSG_AUTH_FAIL          = 0x0105,
    VW_MSG_SESSION_RESUME       = 0x0106,  /* client sends stored session token */
    VW_MSG_AUTH_LOGOUT          = 0x0107,
    VW_MSG_AUTH_RECOVER_REQUEST = 0x0108,  /* client → server: initiate password recovery */
    VW_MSG_AUTH_RECOVER_CONFIRM = 0x0109,  /* client → server: confirm code + new password */
    VW_MSG_AUTH_RECOVER_OK      = 0x010A,  /* server → client: recovery successful */
    VW_MSG_AUTH_RECOVER_FAIL    = 0x010B,  /* server → client: recovery failed */

    /* File operations (client ↔ server) */
    VW_MSG_FILE_LIST          = 0x0201,
    VW_MSG_FILE_LIST_RESP     = 0x0202,
    VW_MSG_FILE_STAT          = 0x0203,
    VW_MSG_FILE_STAT_RESP     = 0x0204,
    VW_MSG_CHUNK_QUERY        = 0x0205,  /* "do you have these chunk hashes?" */
    VW_MSG_CHUNK_QUERY_RESP   = 0x0206,  /* bitmask of which hashes are present */
    VW_MSG_CHUNK_UPLOAD       = 0x0207,  /* send one chunk */
    VW_MSG_CHUNK_UPLOAD_ACK   = 0x0208,
    VW_MSG_CHUNK_DOWNLOAD_REQ = 0x0209,
    VW_MSG_CHUNK_DATA         = 0x020A,  /* server sends chunk bytes */
    VW_MSG_FILE_COMMIT        = 0x020B,  /* finalise upload: path + ordered chunk list */
    VW_MSG_FILE_COMMIT_ACK    = 0x020C,
    VW_MSG_FILE_DELETE        = 0x020D,
    VW_MSG_FILE_DELETE_ACK    = 0x020E,
    VW_MSG_FILE_MOVE          = 0x020F,
    VW_MSG_FILE_MOVE_ACK      = 0x0210,
    VW_MSG_FILE_MKDIR         = 0x0211,  /* create a single directory (TASK-104) */
    VW_MSG_FILE_MKDIR_ACK     = 0x0212,

    /* Version history */
    VW_MSG_VERSION_LIST        = 0x0301,
    VW_MSG_VERSION_LIST_RESP   = 0x0302,
    VW_MSG_VERSION_RESTORE     = 0x0303,
    VW_MSG_VERSION_RESTORE_ACK = 0x0304,
    VW_MSG_VERSION_CHUNKS      = 0x0305,  /* C → S: get ordered chunk hash list for a version */
    VW_MSG_VERSION_CHUNKS_RESP = 0x0306,  /* S → C: chunk_count + hash array */

    /* Sync */
    VW_MSG_SYNC_STATE         = 0x0401,  /* client sends local snapshot */
    VW_MSG_SYNC_DIFF          = 0x0402,  /* server sends delta ops to apply */
    VW_MSG_SYNC_ACK           = 0x0403,

    /* Sharing / permissions (TASK-094; see docs/PROTOCOL.md §7.5) */
    VW_MSG_SHARE_GRANT        = 0x0501,
    VW_MSG_SHARE_GRANT_ACK    = 0x0502,
    VW_MSG_SHARE_REVOKE       = 0x0503,
    VW_MSG_SHARE_REVOKE_ACK   = 0x0504,
    VW_MSG_SHARE_LIST         = 0x0505,
    VW_MSG_SHARE_LIST_RESP    = 0x0506,
    /* Repurposed from the never-implemented SUB_CREATE/SUB_DELETE
     * "subscription" skeleton — same numeric values, no wire compatibility
     * concern since no handler for the old names ever existed. */
    VW_MSG_LINK_CREATE        = 0x0507,  /* mint a public link for a file/folder */
    VW_MSG_LINK_CREATE_ACK    = 0x0508,
    VW_MSG_LINK_REVOKE        = 0x0509,
    VW_MSG_LINK_REVOKE_ACK    = 0x050A,
    VW_MSG_LINK_LIST          = 0x050B,  /* list public links I've created */
    VW_MSG_LINK_LIST_RESP     = 0x050C,
    VW_MSG_LINK_ACCESS        = 0x050D,  /* redeem a public link (**unauthenticated**) */
    VW_MSG_LINK_ACCESS_ACK    = 0x050E,

    /* Admin (admin session only) */
    VW_MSG_USER_CREATE        = 0x0601,
    VW_MSG_USER_CREATE_ACK    = 0x0602,
    VW_MSG_USER_MODIFY        = 0x0603,
    VW_MSG_USER_MODIFY_ACK    = 0x0604,
    VW_MSG_USER_SUSPEND       = 0x0605,
    VW_MSG_USER_SUSPEND_ACK   = 0x0606,
    VW_MSG_USER_LIST          = 0x0607,
    VW_MSG_USER_LIST_RESP     = 0x0608,
    VW_MSG_INVITE_CREATE      = 0x0609,
    VW_MSG_INVITE_CREATE_ACK  = 0x060A,
    VW_MSG_INVITE_REDEEM      = 0x060B,
    VW_MSG_INVITE_REDEEM_ACK  = 0x060C,
    VW_MSG_QUOTA_ADJUST       = 0x060D,
    VW_MSG_QUOTA_ADJUST_ACK   = 0x060E,
    VW_MSG_AUDIT_QUERY        = 0x060F,
    VW_MSG_AUDIT_RESP         = 0x0610,
    VW_MSG_DRIVE_CONFIG       = 0x0611,  /* set/get server-wide config */
    VW_MSG_DRIVE_CONFIG_RESP  = 0x0612,

    /* Cluster (server ↔ server) */
    VW_MSG_NODE_HELLO         = 0x0701,
    VW_MSG_NODE_HELLO_OK      = 0x0702,
    VW_MSG_OPLOG_PULL         = 0x0703,  /* replica → primary: give me entries from N */
    VW_MSG_OPLOG_DATA         = 0x0704,  /* primary → replica: batch of oplog entries */
    VW_MSG_OPLOG_ACK          = 0x0705,  /* replica confirms consumed up to entry_id */
    VW_MSG_CLUSTER_STATUS     = 0x0706,
    VW_MSG_CLUSTER_STATUS_RESP = 0x0707,

    /* Hot-standby data replication (TASK-169/170/172; docs/PROTOCOL.md
     * §7.7). Gives a replica genuinely queryable data — oplog entries
     * above are bare-id notifications only, never a data source; see
     * §7.7's own note. Cluster-connection-only (vw-cluster/1 ALPN),
     * authenticated by NODE_HELLO's auth_token, never reachable from the
     * normal vw/1 client listener. */
    VW_MSG_CLUSTER_FILE_SYNC_LIST      = 0x0708,  /* replica → primary: list syncable files + hashes */
    VW_MSG_CLUSTER_FILE_SYNC_LIST_RESP = 0x0709,  /* primary → replica: per-file size + sha256       */
    VW_MSG_CLUSTER_FILE_SYNC_FETCH     = 0x070A,  /* replica → primary: request one file's content   */
    VW_MSG_CLUSTER_FILE_SYNC_DATA      = 0x070B,  /* primary → replica: that file's full content      */
    VW_MSG_CLUSTER_CHUNK_QUERY         = 0x070C,  /* replica → primary: which of these hashes exist   */
    VW_MSG_CLUSTER_CHUNK_QUERY_RESP    = 0x070D,  /* primary → replica: bitmask (same shape as CHUNK_QUERY_RESP) */
    VW_MSG_CLUSTER_CHUNK_FETCH         = 0x070E,  /* replica → primary: request one chunk's bytes     */
    VW_MSG_CLUSTER_CHUNK_DATA          = 0x070F,  /* primary → replica: chunk bytes (same shape as CHUNK_DATA) */

    VW_MSG_NODE_HELLO_FAIL    = 0x07FF,  /* primary → replica: auth rejected */

    /* Vault / E2EE (TASK-098; docs/PROTOCOL.md §7.11). Server stores/returns
     * wrapped_vk and kdf_params as fully opaque bytes — no decryption, no
     * key material, ever server-side. */
    VW_MSG_VAULT_CREATE         = 0x0801,  /* register a new vault + wrapped VK   */
    VW_MSG_VAULT_CREATE_ACK     = 0x0802,
    VW_MSG_VAULT_KEY_FETCH      = 0x0803,  /* fetch wrapped VK (new-device unlock) */
    VW_MSG_VAULT_KEY_FETCH_RESP = 0x0804,
    VW_MSG_VAULT_LIST           = 0x0805,  /* list my vaults                       */
    VW_MSG_VAULT_LIST_RESP      = 0x0806,

    /* Filename search (TASK-196/197; docs/PROTOCOL.md §7.12). Server-side,
     * scoped to exactly what FILE_LIST/effective_permission() already let
     * the caller see (owned + shared-with-me). Filename/leaf-name
     * substring match only — no content search (vault contents are opaque
     * ciphertext by design; non-vault content search would need an index
     * this flat-file store doesn't have). */
    VW_MSG_SEARCH      = 0x0901,
    VW_MSG_SEARCH_RESP = 0x0902,

    /* Notification preferences (TASK-205/206; docs/PROTOCOL.md §7.13).
     * Account-scoped only — no user_id field, no VW_PERM_* concept, same
     * trust bar as a session changing its own password. Covers only the
     * four user-facing alert categories; admin-category alerts are
     * vapourwaultd.conf-only, never wire-visible. */
    VW_MSG_NOTIFY_PREFS_GET      = 0x0A01,
    VW_MSG_NOTIFY_PREFS_GET_RESP = 0x0A02,
    VW_MSG_NOTIFY_PREFS_SET      = 0x0A03,
    VW_MSG_NOTIFY_PREFS_SET_ACK  = 0x0A04,
} vw_msg_type_t;

/* ── Notification preference bitmask (TASK-205/206) ──────────────────────── */
/* One bit per user-facing alert category; bits 4-31 reserved for future
 * categories. A NOTIFY_PREFS_SET carrying any reserved bit is rejected
 * with VW_ERR_INVALID_ARG — see docs/PROTOCOL.md §7.13 for the rationale
 * and the note on revisiting this the day a second wave of categories
 * ships. */
#define VW_NOTIFY_SHARE_RECEIVED         ((uint32_t)0x00000001u)
#define VW_NOTIFY_QUOTA_WARNING          ((uint32_t)0x00000002u)
#define VW_NOTIFY_NEW_LOGIN              ((uint32_t)0x00000004u)
#define VW_NOTIFY_ACCOUNT_SECURITY_CHANGE ((uint32_t)0x00000008u)
#define VW_NOTIFY_ALL_KNOWN              (VW_NOTIFY_SHARE_RECEIVED | \
                                           VW_NOTIFY_QUOTA_WARNING | \
                                           VW_NOTIFY_NEW_LOGIN | \
                                           VW_NOTIFY_ACCOUNT_SECURITY_CHANGE)

/* ── Permission levels ───────────────────────────────────────────────────── */

typedef enum {
    VW_PERM_NONE  = 0,
    VW_PERM_VIEW  = 1,
    VW_PERM_EDIT  = 2,
    VW_PERM_OWNER = 3,
} vw_perm_t;

/* ── Admin capability bits (TASK-092) ───────────────────────────────────────
 *
 * Fine-grained admin roles, layered underneath vw_user_record_t.is_admin —
 * a record with is_admin == 0 has none of these regardless of admin_caps.
 *
 * admin_caps == 0 on an is_admin == 1 record means "full/legacy admin"
 * (equivalent to VW_CAP_ALL), not "no capabilities": this field reuses bytes
 * that were always-zero reserved padding before this feature existed, so
 * every admin account created before TASK-092 shipped reads back
 * admin_caps == 0 and must keep exactly the access it always had. To
 * delegate a narrower role, set an explicit nonzero subset. There is
 * deliberately no way to express "admin with zero capabilities" — that is a
 * meaningless state; unset is_admin instead. */
typedef enum {
    VW_CAP_USER_MGMT    = 1u << 0,  /* create/suspend/list users, invites */
    VW_CAP_QUOTA_MGMT   = 1u << 1,  /* set user storage quotas */
    VW_CAP_AUDIT_READ   = 1u << 2,  /* read the oplog/audit log */
    VW_CAP_CLUSTER_MGMT = 1u << 3,  /* view/manage cluster replication status */
    VW_CAP_CERT_RELOAD  = 1u << 4,  /* reload the TLS certificate */
    VW_CAP_ALL          = 0x1Fu,    /* all bits above */
} vw_admin_cap_t;

/* ── 2FA challenge types ─────────────────────────────────────────────────── */

typedef enum {
    VW_2FA_EMAIL_OTP = 1,
    VW_2FA_TOTP      = 2,   /* future: TOTP app (Google Authenticator, etc.) */
} vw_2fa_type_t;

/* ── Message header ──────────────────────────────────────────────────────── */

/*
 * On-wire layout (all LE):
 *   bytes 0-3: total message length (including this 8-byte header)
 *   bytes 4-5: message type (vw_msg_type_t)
 *   bytes 6-7: protocol version
 */
typedef struct {
    uint32_t total_len;
    uint16_t msg_type;
    uint16_t proto_version;
} vw_msg_header_t;

/* ── Payload structs ─────────────────────────────────────────────────────── */
/*
 * These are in-memory representations. Serialisation functions handle
 * endian conversion and length-prefixed string encoding. Do NOT memcpy
 * these structs directly onto the wire — always use vw_proto_encode_*.
 */

typedef struct {
    uint16_t max_version;   /* sender's maximum supported protocol version */
} vw_payload_hello_t;

typedef struct {
    uint16_t negotiated_version;
    uint8_t  server_id[16];  /* server UUID */
} vw_payload_hello_ok_t;

typedef struct {
    uint16_t min_version;
    uint16_t max_version;
} vw_payload_version_reject_t;

typedef struct {
    uint32_t error_code;     /* vw_err_t */
    /* variable: string message */
} vw_payload_error_t;

/* Auth */

/*
 * String pointers (username, otp_code, hint) are zero-copy borrows from the
 * caller's buffer. They must remain valid for the duration of any encode call,
 * and point into the receive buffer after any decode call.
 */
typedef struct {
    const char *username;              /* UTF-8, not null-terminated */
    uint16_t    username_len;
    uint8_t     auth_token[VW_TOKEN_BYTES];  /* Argon2id-derived on client, see PROTOCOL.md */
} vw_payload_auth_request_t;

typedef struct {
    uint8_t     challenge_type;        /* vw_2fa_type_t */
    const char *hint;                  /* e.g. "Code sent to o***@example.com" */
    uint16_t    hint_len;
} vw_payload_auth_challenge_t;

typedef struct {
    const char *otp_code;              /* UTF-8 digit string, not null-terminated */
    uint16_t    otp_len;
} vw_payload_auth_otp_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    int64_t  expires_at;     /* Unix timestamp */
    uint8_t  is_admin;
    uint64_t quota_bytes;
    uint64_t used_bytes;
    uint64_t user_id;
} vw_payload_auth_ok_t;

typedef struct {
    uint32_t error_code;     /* VW_ERR_AUTH_* */
    uint16_t lockout_remaining_secs;  /* 0 = not locked; max 65535s */
} vw_payload_auth_fail_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
} vw_payload_session_resume_t;

/* File operations
 *
 * Security: every C→S file operation payload begins with session_token[32].
 * The server validates the token before processing; an invalid or expired token
 * returns VW_MSG_ERROR with VW_ERR_AUTH_REQUIRED without further processing.
 *
 * Path validation (enforced by vw_server_core before any store call):
 *   - Must begin with '/'.
 *   - No '..' components.
 *   - No null bytes or backslashes.
 *   - No empty components (no '//').
 *   - Encoded length ≤ VW_MAX_PATH_BYTES (4096).
 * Violations return VW_ERR_PATH_INVALID.
 */

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint8_t  recursive;       /* 0=shallow, 1=recursive */
    uint8_t  include_deleted;
    /* variable: string path (virtual path; empty = drive root) */
} vw_payload_file_list_t;

typedef struct {
    uint32_t count;
    /* repeated count times:
     *   string  name
     *   uint64  file_id
     *   uint64  size_bytes
     *   int64   mtime_unix
     *   uint8   entry_type  (0=file, 1=folder)
     *   uint8   perm        (vw_perm_t as seen by requesting user)
     */
} vw_payload_file_list_resp_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint64_t file_id;         /* 0 = look up by path instead */
    /* variable: string path (if file_id == 0) */
} vw_payload_file_stat_t;

typedef struct {
    uint8_t  entry_type;      /* 0=file, 1=folder */
    uint64_t file_id;
    uint64_t size_bytes;
    int64_t  mtime_unix;
    uint64_t version_id;      /* current version */
    uint64_t owner_id;
    uint8_t  perm;            /* vw_perm_t as seen by requesting user */
    /* variable: string virtual_path */
} vw_payload_file_stat_resp_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint16_t count;           /* max 1024; server rejects larger with VW_ERR_PROTO_INVALID */
    /* raw bytes: count * VW_HASH_BYTES chunk hashes (in chunk order) */
} vw_payload_chunk_query_t;

typedef struct {
    uint16_t count;           /* mirrors request count */
    /* raw bytes: ceil(count/8) bytes bitmask; bit i (big-endian within byte) = chunk i present */
} vw_payload_chunk_query_resp_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint8_t  chunk_hash[VW_HASH_BYTES];
    uint32_t chunk_len;       /* actual bytes in this chunk; ≤ VW_CHUNK_SIZE_DEFAULT */
    /* raw bytes: chunk_len bytes of chunk data */
} vw_payload_chunk_upload_t;

typedef struct {
    uint8_t  chunk_hash[VW_HASH_BYTES];
    uint32_t error_code;      /* vw_err_t; 0 = VW_OK */
} vw_payload_chunk_upload_ack_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint8_t  chunk_hash[VW_HASH_BYTES];
} vw_payload_chunk_download_req_t;

typedef struct {
    uint8_t  chunk_hash[VW_HASH_BYTES];
    uint32_t chunk_len;       /* ≤ VW_CHUNK_SIZE_DEFAULT */
    /* raw bytes: chunk_len bytes */
} vw_payload_chunk_data_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint64_t file_id;         /* 0 = create new file */
    uint64_t logical_size;
    uint32_t chunk_count;     /* max 65535 (~256 GiB at 4 MiB/chunk) */
    /* variable:
     *   string  virtual_path
     *   bytes   chunk_count * VW_HASH_BYTES (ordered chunk hashes)
     */
} vw_payload_file_commit_t;

typedef struct {
    uint64_t file_id;
    uint64_t version_id;
    uint32_t error_code;      /* vw_err_t; 0 = VW_OK */
} vw_payload_file_commit_ack_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint64_t file_id;         /* 0 = look up by path */
    /* variable: string path (if file_id == 0) */
} vw_payload_file_delete_t;

typedef struct {
    uint32_t error_code;      /* vw_err_t; 0 = VW_OK */
} vw_payload_file_delete_ack_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint64_t file_id;
    uint32_t offset;          /* pagination start (0-based) */
    uint32_t limit;           /* max entries; 0 = server default (50) */
} vw_payload_version_list_t;

/* VERSION_LIST_RESP: see §7.3 of docs/PROTOCOL.md for the repeated-entry layout */

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint64_t version_id;
    /* variable: string virtual_path */
} vw_payload_version_restore_t;

typedef struct {
    uint64_t version_id;      /* newly created version */
    uint32_t error_code;      /* vw_err_t; 0 = VW_OK */
} vw_payload_version_restore_ack_t;

typedef struct {
    uint8_t  session_token[VW_TOKEN_BYTES];
    uint64_t version_id;
} vw_payload_version_chunks_t;

typedef struct {
    uint32_t chunk_count;
    /* raw bytes: chunk_count * VW_HASH_BYTES (ordered SHA-256 chunk hashes) */
} vw_payload_version_chunks_resp_t;

/* Sharing (TASK-094): all SHARE_ and LINK_ payloads are hand-decoded
 * directly in vw_file_handlers.c, following the same convention already
 * used for FILE_LIST/FILE_STAT/etc. below rather than dedicated
 * vw_proto_encode/decode_* helpers (those exist only for the Auth message
 * family above). See docs/PROTOCOL.md section 7.5 for the exact wire
 * layout of each message. */

/* Cluster (v6) */

typedef struct {
    uint64_t node_id;
    uint8_t  auth_token[VW_TOKEN_BYTES]; /* 256-bit pre-shared node secret */
    uint64_t sync_watermark;             /* last oplog entry_id applied (0 = none) */
    uint16_t proto_version;
    const char *hostname;                /* UTF-8; zero-copy borrow from caller/buf */
    uint16_t    hostname_len;
} vw_payload_node_hello_t;

typedef struct {
    uint64_t primary_node_id;
    uint64_t current_last_entry_id;
} vw_payload_node_hello_ok_t;

typedef struct {
    uint32_t error_code;  /* always 0 — prevents node_id enumeration */
} vw_payload_node_hello_fail_t;

typedef struct {
    uint64_t from_entry_id;   /* exclusive lower bound; 0 = from the start */
    uint32_t max_entries;
} vw_payload_oplog_pull_t;

typedef struct {
    uint32_t count;           /* 0 = caught up; no entries bytes follow */
    uint64_t last_entry_id;   /* 0 if count == 0 */
    /* raw bytes: count serialised vw_oplog_entry_t records (header + payload) */
} vw_payload_oplog_data_t;

typedef struct {
    uint64_t confirmed_entry_id;  /* last entry_id durably applied by this replica */
} vw_payload_oplog_ack_t;

/* CLUSTER_STATUS_RESP: no fixed struct — role (u8) + node_count (u32) +
 * repeated node entries.  Each entry: node_id (u64), is_active (u8),
 * sync_watermark (u64), lag_entries (u64), hostname (string).
 * auth_token is NEVER included. */

/* ── Forward declare connection type (defined in vw_net.h) ───────────────── */

typedef struct vw_conn vw_conn_t;

/* ── API ──────────────────────────────────────────────────────────────────── */

/*
 * Send a framed message. payload may be NULL if payload_len == 0.
 * Blocks until all bytes are written or an error occurs.
 */
vw_err_t vw_proto_send(vw_conn_t *conn, vw_msg_type_t type,
                        const void *payload, uint32_t payload_len);

/*
 * Receive one framed message into *out_buf (must be at least VW_MAX_MSG_BYTES).
 * On return, *out_type and *out_payload_len are set; payload begins at out_buf.
 * Returns VW_ERR_PROTO_TOO_LARGE if the message exceeds VW_MAX_MSG_BYTES.
 */
vw_err_t vw_proto_recv(vw_conn_t *conn, vw_msg_type_t *out_type,
                        void *out_buf, uint32_t buf_size,
                        uint32_t *out_payload_len);

/*
 * Version negotiation. Server: is_server=1. Client: is_server=0.
 * After calling this, both sides have agreed on *out_version.
 * Returns VW_ERR_PROTO_VERSION if no common version exists.
 */
vw_err_t vw_proto_negotiate(vw_conn_t *conn, int is_server,
                             uint16_t *out_version);

/* ── Serialisation helpers (write into a caller-provided buffer) ──────────── */

/*
 * Append a length-prefixed UTF-8 string to buf at *offset.
 * Returns VW_ERR_PROTO_TOO_LARGE if the string exceeds remaining space.
 */
vw_err_t vw_proto_write_str(uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                             const char *str, uint16_t str_len);

/*
 * Read a length-prefixed string from buf at *offset.
 * *out_str is set to point inside buf (not null-terminated).
 * Returns VW_ERR_PROTO_TRUNCATED if the buffer ends prematurely.
 */
vw_err_t vw_proto_read_str(const uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                            const char **out_str, uint16_t *out_len);

/* Little-endian write helpers */
static inline void vw_write_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}
static inline void vw_write_u32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static inline void vw_write_u64le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

/* ── Auth payload encode / decode ────────────────────────────────────────── */
/*
 * Encode functions write into a caller-provided buffer and set *out_len to
 * the number of bytes written. Return VW_ERR_PROTO_TOO_LARGE if buf_size is
 * insufficient.
 *
 * Decode functions borrow string pointers directly from buf (zero-copy). The
 * pointers in the output struct are only valid as long as buf is live.
 */

vw_err_t vw_proto_encode_auth_request(
    const vw_payload_auth_request_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

/* Decoded string pointers alias buf; valid only while buf remains live. */
vw_err_t vw_proto_decode_auth_request(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_request_t *out);

vw_err_t vw_proto_encode_auth_challenge(
    const vw_payload_auth_challenge_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

/* Decoded string pointers alias buf; valid only while buf remains live. */
vw_err_t vw_proto_decode_auth_challenge(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_challenge_t *out);

vw_err_t vw_proto_encode_auth_otp(
    const vw_payload_auth_otp_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

/* Decoded string pointers alias buf; valid only while buf remains live. */
vw_err_t vw_proto_decode_auth_otp(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_otp_t *out);

vw_err_t vw_proto_encode_auth_ok(
    const vw_payload_auth_ok_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_auth_ok(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_ok_t *out);

vw_err_t vw_proto_encode_auth_fail(
    const vw_payload_auth_fail_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_auth_fail(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_fail_t *out);

/*
 * Encode / decode VW_MSG_ERROR (0x00FF).
 *
 * SECURITY: msg must never contain a password hash, salt, session token, or
 * internal file-system path. Callers must sanitise before passing msg.
 */
vw_err_t vw_proto_encode_error(
    uint32_t error_code, const char *msg, uint16_t msg_len,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

/* out_msg aliases buf; valid only while buf remains live. */
vw_err_t vw_proto_decode_error(
    const uint8_t *buf, uint32_t len,
    uint32_t *out_code, const char **out_msg, uint16_t *out_msg_len);

/* Little-endian read helpers */
static inline uint16_t vw_read_u16le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline uint32_t vw_read_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t vw_read_u64le(const uint8_t *p) {
    return (uint64_t)p[0]        | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

#ifdef __cplusplus
}
#endif

#endif /* VW_PROTO_H */
