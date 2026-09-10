#ifndef VW_ADMIN_H
#define VW_ADMIN_H

/*
 * vw_admin — lightweight admin IPC channel for VaporWault server.
 *
 * Listens on a Unix domain socket (AF_UNIX). Uses the same 8-byte framing as
 * vw_proto.h with message types in the 0x9000–0x9FFF range.
 *
 * Security: the socket is created with mode 0600 so only the server operator
 * (same UID) can connect. SO_PEERCRED on Linux verifies the connecting UID
 * at accept time. Admin server is POSIX-only; on Windows, start returns VW_OK
 * with *out = NULL (admin disabled).
 *
 * SEC.07 [2026-07-12]: Switched from AF_INET to AF_UNIX. SO_PEERCRED only
 * works on AF_UNIX sockets; on AF_INET it always fails (ENODATA) so the
 * previous TCP implementation rejected every connection on Linux.
 *
 * SRV.01 [2026-07-12]: See TASK-040.
 */

#include "../core/vw_proto.h"
#include "vw_store.h"
#include "vw_oplog.h"
#include "vw_cluster.h"
#include "vw_conn_registry.h"
#include "vw_scrub.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VW_ADMIN_DEFAULT_SOCKET "/var/run/vapourwaultd/admin.sock"

/* Admin message types: 0x9000–0x9FFF */
typedef enum {
    VW_ADMIN_USER_CREATE_REQ  = 0x9001,
    VW_ADMIN_USER_CREATE_RESP = 0x9002,
    VW_ADMIN_USER_LIST_REQ    = 0x9003,
    VW_ADMIN_USER_LIST_RESP   = 0x9004,
    VW_ADMIN_SET_QUOTA_REQ    = 0x9005,
    VW_ADMIN_SET_QUOTA_RESP   = 0x9006,
    VW_ADMIN_OPLOG_TAIL_REQ   = 0x9007,
    VW_ADMIN_OPLOG_TAIL_RESP  = 0x9008,
    VW_ADMIN_CONN_LIST_REQ    = 0x9009,
    VW_ADMIN_CONN_LIST_RESP   = 0x900A,
    VW_ADMIN_RELOAD_CERT_REQ  = 0x900B,
    VW_ADMIN_RELOAD_CERT_RESP = 0x900C,
    VW_ADMIN_NODE_ADD_REQ            = 0x900D,
    VW_ADMIN_NODE_ADD_RESP           = 0x900E,
    VW_ADMIN_CLUSTER_STATUS_REQ      = 0x900F,
    VW_ADMIN_CLUSTER_STATUS_RESP     = 0x9010,
    VW_ADMIN_NODE_REGISTER_SELF_REQ  = 0x9011,
    VW_ADMIN_NODE_REGISTER_SELF_RESP = 0x9012,
    VW_ADMIN_LIST_DELETED_REQ  = 0x9013,
    VW_ADMIN_LIST_DELETED_RESP = 0x9014,
    VW_ADMIN_RESTORE_FILE_REQ  = 0x9015,
    VW_ADMIN_RESTORE_FILE_RESP = 0x9016,
    VW_ADMIN_SET_CAPS_REQ      = 0x9017,
    VW_ADMIN_SET_CAPS_RESP     = 0x9018,
    VW_ADMIN_SCRUB_RUN_REQ     = 0x9019,
    VW_ADMIN_SCRUB_RUN_RESP    = 0x901A,
    VW_ADMIN_SCRUB_STATUS_REQ  = 0x901B,
    VW_ADMIN_SCRUB_STATUS_RESP = 0x901C,
} vw_admin_msg_t;

/*
 * Payload wire formats (all integers little-endian):
 *
 * USER_CREATE_REQ:   u8 is_admin, u16 uname_len, uname[], u16 pw_len, pw[]
 *                    pw[] is the RAW operator-supplied password, not
 *                    pre-hashed by the caller — safe since this socket is
 *                    local-only (AF_UNIX, mode 0600, SO_PEERCRED-verified).
 *                    The server SHA-256s pw[] internally before Argon2id,
 *                    matching the Argon2id(SHA-256(password)) derivation
 *                    used everywhere else (see docs/PROTOCOL.md). Callers
 *                    must NOT pre-hash pw[] themselves.
 * USER_CREATE_RESP:  u32 error_code, u64 user_id (user_id valid only if code==0)
 *
 * USER_LIST_REQ:     (no payload)
 * USER_LIST_RESP:    u32 count, then count × entry:
 *                      u64 user_id, u8 is_admin, u8 is_active, u8[2] pad,
 *                      u8[64] username (NUL-padded), u64 quota_bytes, u64 used_bytes
 *
 * SET_QUOTA_REQ:     u16 uname_len, uname[], u64 quota_bytes
 * SET_QUOTA_RESP:    u32 error_code
 *
 * OPLOG_TAIL_REQ:    u32 count (max 100)
 * OPLOG_TAIL_RESP:   u32 count, then count × entry:
 *                      u64 entry_id, u8 op_type, u8[7] pad
 *
 * CONN_LIST_REQ:     (no payload)
 * CONN_LIST_RESP:    u32 count, then count × entry:
 *                      u64 conn_id, u64 user_id (0 = not yet authenticated),
 *                      i64 connected_since (Unix timestamp),
 *                      u8[64] peer_addr (NUL-padded)
 *                    count is 0 if connection tracking is unavailable
 *                    (vw_conn_registry_open failed at server startup).
 *
 * RELOAD_CERT_REQ:   (no payload)
 * RELOAD_CERT_RESP:  u32 error_code
 *
 * NODE_ADD_REQ:      u16 hostname_len, hostname[]
 *                    Run on the PRIMARY to register a new replica. Always
 *                    creates a VW_NODE_ROLE_REPLICA record with a freshly
 *                    generated auth_token — there is no way to supply your
 *                    own token here (see NODE_REGISTER_SELF_REQ for the
 *                    other half of pairing).
 * NODE_ADD_RESP:     u32 error_code, u64 node_id, u8[32] auth_token
 *                    auth_token is valid only if error_code==0. It is
 *                    returned exactly once here — record it immediately;
 *                    it is never retrievable again (vw_cluster_node_get
 *                    zeroes it in every other response). Returns
 *                    VW_ERR_INVALID_ARG if cluster mode is not enabled
 *                    (cluster_port == 0 and is_replica == 0 in server.conf).
 *
 * CLUSTER_STATUS_REQ:  (no payload)
 * CLUSTER_STATUS_RESP: u32 error_code, u32 count, then count × entry:
 *                       u64 node_id, u8 role, u8 is_active, u8[2] pad,
 *                       u8[128] hostname (NUL-padded), u64 sync_watermark
 *                       count is 0 if error_code != 0.
 *
 * NODE_REGISTER_SELF_REQ:  u64 node_id, u8[32] auth_token, u16 hostname_len, hostname[]
 *                    Run on the REPLICA to complete pairing, using the
 *                    node_id/auth_token that NODE_ADD_REQ printed on the
 *                    primary. Always creates a VW_NODE_ROLE_SELF record.
 *                    Returns VW_ERR_ALREADY_EXISTS if node_id is already
 *                    registered locally, VW_ERR_INVALID_ARG if cluster mode
 *                    is not enabled.
 * NODE_REGISTER_SELF_RESP: u32 error_code
 *
 * LIST_DELETED_REQ:  u16 uname_len, uname[]
 *                    Lists soft-deleted (trashed) files owned by the given
 *                    user that are still within the GC retention window
 *                    (server.conf trash_retention_days).
 * LIST_DELETED_RESP: u32 error_code, u32 count, then count × entry:
 *                      u64 file_id, i64 deleted_at, u8[64] name (NUL-padded)
 *                    count is 0 if error_code != 0 (e.g. unknown username).
 *
 * RESTORE_FILE_REQ:  u64 file_id
 *                    Undoes a soft-delete (from LIST_DELETED_RESP's file_id),
 *                    making the file visible/usable again. Must be called
 *                    before the retention window elapses and GC hard-deletes
 *                    it. Returns VW_ERR_NOT_FOUND if file_id doesn't exist at
 *                    all, VW_ERR_INVALID_ARG if it exists but isn't deleted.
 * RESTORE_FILE_RESP: u32 error_code
 *
 * SET_CAPS_REQ:      u16 uname_len, uname[], u32 caps (vw_admin_cap_t bitmask)
 *                    Sets the target user's fine-grained admin capabilities
 *                    (TASK-092), replacing whatever was there before —
 *                    this is a full replace, not an incremental grant/
 *                    revoke of individual bits. Only meaningful for users
 *                    with is_admin == 1; has no effect on access for a
 *                    non-admin (is_admin == 0) target, since
 *                    vw_admin_has_cap() always returns false for those
 *                    regardless of admin_caps.
 *                    caps == 0 means "full/legacy admin" (VW_CAP_ALL) — see
 *                    vw_admin_cap_t in vw_proto.h. To explicitly restrict an
 *                    admin, pass a real nonzero subset of the capability
 *                    bits. Returns VW_ERR_NOT_FOUND if the username doesn't
 *                    exist.
 *                    This request only ever runs over the local, operator-
 *                    trusted admin.sock (SO_PEERCRED-verified, same UID as
 *                    the server process) — it is how the trusted operator
 *                    delegates a narrower role to a *different*, less-
 *                    trusted admin account that authenticates remotely over
 *                    the network wire protocol (docs/PROTOCOL.md §7.6).
 *                    admin.sock itself remains all-or-nothing by design;
 *                    see TASK-092's notes for why that channel is not
 *                    itself capability-gated.
 * SET_CAPS_RESP:     u32 error_code
 *
 * SCRUB_RUN_REQ:     (no payload)
 *                    Runs one full chunk-store integrity scan synchronously
 *                    (TASK-255/256) — re-hashes every chunk on disk against
 *                    its own filename and reports what it found. Blocks
 *                    until the pass completes (a full chunk store can take
 *                    a while to re-read); this is why it is separate from
 *                    SCRUB_STATUS_REQ rather than folded into it. Detection
 *                    only — corrupt chunks are logged, not yet repaired
 *                    (Phase 22's repair pipeline is TASK-260, not
 *                    implemented yet). Returns VW_ERR_INVALID_ARG if the
 *                    scrub module is unavailable (chunk store failed to
 *                    open at server startup).
 * SCRUB_RUN_RESP:    u32 error_code, u64 scanned, u64 corrupt, u64 tombstoned
 *                    Counts are valid only if error_code==0.
 *
 * SCRUB_STATUS_REQ:  (no payload)
 *                    Reports the results of the most recently completed
 *                    pass (background or admin-triggered) without running
 *                    a new one.
 * SCRUB_STATUS_RESP: u32 error_code, i64 last_run_unix (0 = never run),
 *                    u64 scanned, u64 corrupt, u64 tombstoned
 *                    Fields are all-zero (last_run_unix==0) if no pass has
 *                    ever completed, or if error_code != 0.
 */

typedef struct {
    vw_store_t         *store;         /* for user / quota operations */
    vw_oplog_t         *oplog;         /* for oplog tail               */
    vw_cluster_t       *cluster;       /* for node-add / cluster-status; NULL if cluster mode is disabled */
    vw_conn_registry_t *conn_registry; /* for list-connections; NULL if unavailable */
    vw_file_store_t    *file_store;    /* for list-deleted / restore-file; NULL if unavailable */
    vw_scrub_ctx_t     *scrub;         /* for scrub run/status (TASK-256); NULL if unavailable */
} vw_admin_ctx_t;

typedef struct vw_admin_server vw_admin_server_t;

/* Start the admin listener thread on the given AF_UNIX socket path.
 * NULL or empty path → disabled (*out=NULL, returns VW_OK). */
vw_err_t vw_admin_server_start(const char *socket_path, const vw_admin_ctx_t *ctx,
                                vw_admin_server_t **out);

/* Signal stop and join thread. Safe with NULL. */
void vw_admin_server_stop(vw_admin_server_t *srv);

#ifdef __cplusplus
}
#endif

#endif /* VW_ADMIN_H */
