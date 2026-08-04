#ifndef VW_FILE_HANDLERS_INTERNAL_H
#define VW_FILE_HANDLERS_INTERNAL_H

/*
 * vw_file_handlers_internal.h — TASK-115: internal functions from
 * vw_file_handlers.c, exposed ONLY for unit testing.
 *
 * This is NOT a public API. Never include it outside vw_file_handlers.c
 * itself and its unit test (tests/unit/test_vw_file_handlers.c). Every
 * function declared below is `static` in vw_file_handlers.c in every
 * production build — VW_FH_TESTABLE (defined in vw_file_handlers.c)
 * resolves to `static` unless VW_FILE_HANDLERS_TEST_HOOKS is defined, the
 * same pattern TASK-114 established for vw_sync.c (see
 * src/client/vw_sync_internal.h). vw_file_handlers.h — the real public API
 * (vw_path_validate, vw_server_dispatch_file_op) — is untouched; that
 * header is already sufficient for testing vw_path_validate directly, so
 * this file only needs to add the two permission-resolution helpers below.
 *
 * Why these two specifically: every mutating/reading handler in
 * vw_file_handlers.c makes its access-control decision by calling one of
 * these, then immediately hands the result to require_permission() (which
 * sends the actual wire response — untestable without a live vw_conn_t,
 * which is fully opaque outside vw_net.c and constructible only via a real
 * TLS accept/connect). Testing effective_permission()/
 * permission_on_dir_or_root() directly exercises the actual per-caller-
 * class access decision (owner / grantee / scoped-link-session / no
 * access) that TASK-115 is about, without needing a socket. The wire-level
 * response each handler sends for a given decision (VW_ERR_PERMISSION vs.
 * VW_ERR_NOT_FOUND vs. success) remains covered by the existing integration
 * suite (tests/integration/test_sharing.py, test_file_ops.py,
 * run_integration.py) — require_permission()'s own mapping from decision
 * to error code is a two-line, already-reviewed function, not re-derived
 * here.
 */

#include "vw_store.h"
#include "vw_share.h"
#include "../core/vw_proto.h"

#ifdef VW_FILE_HANDLERS_TEST_HOOKS

vw_perm_t effective_permission(vw_share_store_t *ss, vw_file_store_t *fs,
                                const vw_file_record_t *file_rec,
                                uint64_t user_id, uint64_t scope_share_id);

vw_perm_t permission_on_dir_or_root(vw_share_store_t *ss, vw_file_store_t *fs,
                                     uint64_t dir_id, uint64_t root_owner_id,
                                     uint64_t user_id, uint64_t scope_share_id);

#endif /* VW_FILE_HANDLERS_TEST_HOOKS */

#endif /* VW_FILE_HANDLERS_INTERNAL_H */
