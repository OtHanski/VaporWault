#ifndef VW_SERVER_CORE_H
#define VW_SERVER_CORE_H

/*
 * vw_server_core — server-side connection handler for VaporWault.
 *
 * Handles one accepted TLS connection through the complete auth handshake
 * (HELLO → AUTH_REQUEST or SESSION_RESUME → AUTH_OK / AUTH_FAIL).
 *
 * After a successful auth handshake, the accept loop passes subsequent
 * messages to vw_server_dispatch_file_op (vw_file_handlers.h) which
 * dispatches Phase 2 file-transfer operations.
 *
 * The caller is responsible for accepting the TLS connection
 * (vw_net_accept) and closing it after this function returns.
 */

#include "../core/vw_net.h"
#include "../core/vw_proto.h"
#include "vw_auth.h"
#include "vw_cluster.h"
#include "vw_conn_registry.h"
#include "vw_invite.h"
#include "vw_recovery.h"
#include "vw_share.h"
#include "vw_smtp.h"
#include "vw_notify.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_oplog.h"
#include "vw_vault.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Session info ────────────────────────────────────────────────────────── */

/*
 * Populated by vw_server_conn_handle on successful auth.
 * The accept loop passes this to subsequent message handlers so they know
 * which user is authenticated (Phase 2).
 */
typedef struct {
    uint64_t user_id;
    uint8_t  session_token[VW_TOKEN_BYTES];
    int64_t  expires_at;
    uint8_t  is_admin;
} vw_session_info_t;

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_server_ctx vw_server_ctx_t;

/* ── Config ──────────────────────────────────────────────────────────────── */

typedef struct {
    uint32_t auth_timeout_ms;  /* recv timeout during the auth phase; 0 = 10 000 ms */
} vw_server_cfg_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Create a server context.  Borrows auth and store (caller keeps them alive
 * until vw_server_ctx_close).  cfg may be NULL to use defaults.
 * Returns VW_OK and sets *out_ctx on success; VW_ERR_OOM on failure.
 */
vw_err_t vw_server_ctx_open(vw_auth_ctx_t *auth, vw_store_t *store,
                              const vw_server_cfg_t *cfg,
                              vw_server_ctx_t **out_ctx);

/*
 * Attach Phase 2 file and chunk stores.  Must be called before any
 * file-operation messages are dispatched.  Both pointers are borrowed;
 * caller keeps them alive until vw_server_ctx_close.
 */
void vw_server_ctx_set_file_stores(vw_server_ctx_t *ctx,
                                    vw_file_store_t *file_store,
                                    vw_storage_t    *chunk_store);

/*
 * Attach the invite store.  Borrowed; caller keeps it alive until
 * vw_server_ctx_close.  May be NULL when invites are disabled.
 */
void vw_server_ctx_set_invite_store(vw_server_ctx_t  *ctx,
                                     vw_invite_store_t *invite_store);

/*
 * Attach the recovery store and SMTP config for password-reset flows.
 * Both are borrowed; caller keeps them alive until vw_server_ctx_close.
 * smtp_cfg may be NULL to disable email sending (requests will be silently
 * accepted but no code is emailed).
 */
void vw_server_ctx_set_recovery(vw_server_ctx_t       *ctx,
                                 vw_recovery_store_t   *recovery_store,
                                 const vw_smtp_cfg_t   *smtp_cfg);

/* Accessors used by vw_file_handlers.c (opaque struct). */
vw_store_t        *vw_server_ctx_store(const vw_server_ctx_t *ctx);
vw_file_store_t   *vw_server_ctx_file_store(const vw_server_ctx_t *ctx);
vw_storage_t      *vw_server_ctx_chunk_store(const vw_server_ctx_t *ctx);
vw_invite_store_t *vw_server_ctx_invite_store(const vw_server_ctx_t *ctx);

/*
 * Create (or replace) the notification dispatch context (TASK-205/207)
 * and register it as vw_store's quota_warning hook. smtp_cfg is
 * borrowed; may be NULL to disable all outbound notification email
 * (every trigger becomes a silent no-op). Safe to call again later (e.g.
 * after a config reload changes SMTP settings) — replaces the previous
 * notify context and re-registers the hook.
 */
void vw_server_ctx_set_notify(vw_server_ctx_t *ctx, const vw_smtp_cfg_t *smtp_cfg);
vw_notify_ctx_t *vw_server_ctx_notify(const vw_server_ctx_t *ctx);

/*
 * Attach the share store (TASK-094). Borrowed; caller keeps it alive until
 * vw_server_ctx_close. May be NULL — sharing messages return VW_ERR_NOT_IMPL
 * and LINK_ACCESS in the pre-auth phase is rejected like an unknown token.
 */
void              vw_server_ctx_set_share_store(vw_server_ctx_t *ctx,
                                                 vw_share_store_t *share_store);
vw_share_store_t *vw_server_ctx_share_store(const vw_server_ctx_t *ctx);

/*
 * Attach the vault store (TASK-098). Borrowed; caller keeps it alive until
 * vw_server_ctx_close. May be NULL — VAULT_* messages return VW_ERR_NOT_IMPL.
 */
void              vw_server_ctx_set_vault_store(vw_server_ctx_t *ctx,
                                                 vw_vault_store_t *vault_store);
vw_vault_store_t *vw_server_ctx_vault_store(const vw_server_ctx_t *ctx);

/*
 * Attach the oplog for AUDIT_QUERY support over TLS.
 * Borrowed; caller keeps it alive until vw_server_ctx_close.
 * May be NULL — AUDIT_QUERY will return an empty result.
 */
void        vw_server_ctx_set_oplog(vw_server_ctx_t *ctx, vw_oplog_t *oplog);
vw_oplog_t *vw_server_ctx_oplog(const vw_server_ctx_t *ctx);

/*
 * Attach the cluster context for CLUSTER_STATUS support over TLS.
 * Borrowed; caller keeps it alive until vw_server_ctx_close.
 * May be NULL — CLUSTER_STATUS will return an empty node list.
 */
void          vw_server_ctx_set_cluster(vw_server_ctx_t *ctx, vw_cluster_t *cluster);
vw_cluster_t *vw_server_ctx_cluster(const vw_server_ctx_t *ctx);

/*
 * Attach the connection registry for admin CONN_LIST support.
 * Borrowed; caller keeps it alive until vw_server_ctx_close.
 * May be NULL — CONN_LIST will return an empty list.
 */
void                vw_server_ctx_set_conn_registry(vw_server_ctx_t *ctx,
                                                      vw_conn_registry_t *reg);
vw_conn_registry_t *vw_server_ctx_conn_registry(const vw_server_ctx_t *ctx);

void vw_server_ctx_close(vw_server_ctx_t *ctx);

/* ── Connection handler ──────────────────────────────────────────────────── */

/*
 * Handle one accepted connection through the auth handshake.
 *
 * Steps:
 *   1. Apply auth-phase recv timeout (slow-loris guard).
 *   2. vw_proto_negotiate — sends HELLO_OK or VERSION_REJECT; returns error
 *      if the client's protocol version is incompatible.
 *   3. Receive AUTH_REQUEST or SESSION_RESUME.
 *      AUTH_REQUEST:    verify credentials via vw_auth_begin_login.
 *                       If 2FA is required: send AUTH_CHALLENGE, wait for
 *                       AUTH_OTP, call vw_auth_verify_2fa.
 *      SESSION_RESUME:  validate token, replace it (single-use per spec),
 *                       send AUTH_OK with the new token.
 *   4. Send AUTH_OK or AUTH_FAIL.
 *
 * Return values:
 *   VW_OK              — auth succeeded; *out_info is populated.
 *   VW_ERR_AUTH_*      — auth failed; AUTH_FAIL was sent to client.
 *   VW_ERR_PROTO_*     — malformed message; connection must be closed.
 *   VW_ERR_NET_*       — I/O or TLS error.
 *
 * out_info may be NULL if the caller does not need session details.
 */
vw_err_t vw_server_conn_handle(vw_server_ctx_t *ctx,
                                 vw_conn_t *conn,
                                 vw_session_info_t *out_info);

/*
 * TASK-237: handle AUTH_LOGOUT on an already-authenticated connection.
 * Revokes session_token (the token this connection authenticated with —
 * AUTH_LOGOUT itself carries no payload, so the caller must supply the
 * token from the vw_session_info_t populated by vw_server_conn_handle)
 * so it is rejected by any subsequent request, on this connection or any
 * other. Best-effort by design, matching the fire-and-forget client
 * contract (vw_client_logout does not wait for a response): VW_ERR_NOT_FOUND
 * (token already revoked/expired) is not an error worth surfacing to a
 * client that is already on its way out.
 */
vw_err_t vw_server_handle_auth_logout(vw_server_ctx_t *ctx,
                                        const uint8_t session_token[VW_TOKEN_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VW_SERVER_CORE_H */
