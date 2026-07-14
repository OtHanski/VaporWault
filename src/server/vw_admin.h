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
} vw_admin_msg_t;

/*
 * Payload wire formats (all integers little-endian):
 *
 * USER_CREATE_REQ:   u8 is_admin, u16 uname_len, uname[], u16 pw_len, pw[]
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
 * CONN_LIST_REQ:     (no payload) — Phase 5 returns empty list
 * CONN_LIST_RESP:    u32 count (always 0 in Phase 5)
 *
 * RELOAD_CERT_REQ:   (no payload)
 * RELOAD_CERT_RESP:  u32 error_code
 */

typedef struct {
    vw_store_t  *store;   /* for user / quota operations */
    vw_oplog_t  *oplog;   /* for oplog tail              */
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
