#ifndef VW_CONN_REGISTRY_H
#define VW_CONN_REGISTRY_H

/*
 * vw_conn_registry — tracks currently-active client connections.
 *
 * Used by the admin CONN_LIST query (vw_admin.c) to report real connection
 * data instead of the Phase 5 stub (always-empty list). Entries are added
 * when a connection is accepted (peer address known, user_id unset), updated
 * with the authenticated user_id once the auth handshake completes, and
 * removed when the connection closes. Thread-safe — the main server runs a
 * worker-thread pool (vw_server_main.c) that calls into this concurrently.
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vw_conn_registry vw_conn_registry_t;

typedef struct {
    uint64_t conn_id;
    uint64_t user_id;         /* 0 = not yet authenticated */
    char     peer_addr[64];   /* NUL-terminated */
    int64_t  connected_since; /* Unix timestamp */
} vw_conn_info_t;

/* Returns VW_OK and sets *out on success; VW_ERR_OOM on allocation failure. */
vw_err_t vw_conn_registry_open(vw_conn_registry_t **out);

/* Safe to call with NULL. */
void vw_conn_registry_close(vw_conn_registry_t *reg);

/*
 * Register a new connection. Returns a unique conn_id via *out_conn_id
 * (monotonically increasing; never reused, so a stale id from a since-closed
 * connection can never collide with a new one).
 * Returns VW_ERR_OOM if the table needs to grow and allocation fails.
 */
vw_err_t vw_conn_registry_add(vw_conn_registry_t *reg, const char *peer_addr,
                               uint64_t *out_conn_id);

/* Update user_id once the auth handshake completes. No-op if conn_id is unknown
 * (e.g. the connection already closed). */
void vw_conn_registry_set_user(vw_conn_registry_t *reg, uint64_t conn_id,
                                uint64_t user_id);

/* Remove a connection on close. Safe to call with an unknown conn_id. */
void vw_conn_registry_remove(vw_conn_registry_t *reg, uint64_t conn_id);

/*
 * Snapshot all current entries. *out_entries is malloc'd; caller frees.
 * *out_entries is NULL and *out_count is 0 if there are no active connections.
 */
vw_err_t vw_conn_registry_list(vw_conn_registry_t *reg,
                                vw_conn_info_t **out_entries, uint32_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* VW_CONN_REGISTRY_H */
