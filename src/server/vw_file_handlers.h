#ifndef VW_FILE_HANDLERS_H
#define VW_FILE_HANDLERS_H

/*
 * vw_file_handlers — Phase 2 file-transfer message dispatcher.
 *
 * After a successful auth handshake (vw_server_conn_handle), the accept
 * loop receives each subsequent message and calls vw_server_dispatch_file_op.
 *
 * Return values:
 *   VW_OK            — message handled; response sent; loop may continue.
 *   VW_ERR_PROTO_*   — protocol violation; caller must close connection.
 *   VW_ERR_AUTH_*    — session invalid; AUTH_REQUIRED sent; close connection.
 *   VW_ERR_NOT_IMPL  — unrecognised message type; caller may close or ignore.
 */

#include "vw_server_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Validate the virtual path string.
 * Rules: starts with '/', no '..' components, no null bytes, no '\\',
 *        no empty components (no '//'), len <= VW_MAX_PATH_BYTES.
 * Returns VW_OK or VW_ERR_PATH_INVALID.
 */
vw_err_t vw_path_validate(const char *path, uint32_t len);

/*
 * Dispatch one post-auth message.
 *
 * ctx    — server context (must have file stores set via
 *          vw_server_ctx_set_file_stores before any file op).
 * conn   — live TLS connection.
 * type   — message type from vw_proto_recv.
 * payload — raw payload bytes (token is at byte 0).
 * plen   — payload byte count.
 */
vw_err_t vw_server_dispatch_file_op(vw_server_ctx_t *ctx,
                                     vw_conn_t       *conn,
                                     vw_msg_type_t    type,
                                     const uint8_t   *payload,
                                     uint32_t         plen);

#ifdef __cplusplus
}
#endif

#endif /* VW_FILE_HANDLERS_H */
