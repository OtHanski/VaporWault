#ifndef VW_CLUSTER_H
#define VW_CLUSTER_H

/*
 * vw_cluster — node record store and cluster handshake handler.
 *
 * Responsibilities (TASK-048):
 *   - vw_node_record_t flat-file store: {data_dir}/cluster/nodes.db
 *   - In-memory nid_to_slot index (same pattern as fid_to_slot in vw_store)
 *   - ALPN "vw-cluster/1" accept loop running in its own thread
 *   - NODE_HELLO / NODE_HELLO_OK handshake with constant-time token comparison
 *   - IP-based rate-limiting: 5 failures / 60 s → silent drop
 *
 * Responsibilities (TASK-049, added in that task):
 *   - Oplog replication loop on the accepted cluster connection
 *
 * Responsibilities (TASK-050, added in that task):
 *   - vw_cluster_min_sync_watermark, vw_cluster_has_active_replicas (used by GC)
 *   - CLUSTER_STATUS handler
 */

#include "../core/vw_proto.h"
#include "../core/vw_fs.h"
#include "vw_oplog.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── On-disk node record ────────────────────────────────────────────────────── */

/*
 * Fixed-size node record. 256 bytes, _Static_assert enforced.
 * node_id == 0 marks a free slot.
 *
 * SECURITY: auth_token is a 256-bit pre-shared secret.
 * vw_cluster_node_get() zeroes auth_token in the returned copy.
 * Never log auth_token; never include it in any response payload.
 */
typedef struct {
    uint64_t node_id;           /* assigned at registration; 0 = free slot */
    uint8_t  auth_token[32];    /* 256-bit secret — NEVER log or return    */
    uint8_t  hostname[128];     /* NUL-terminated, max 127 bytes           */
    uint64_t sync_watermark;    /* last confirmed oplog entry_id from this node */
    uint8_t  is_active;         /* 1 = enabled; 0 = deregistered/disabled */
    uint8_t  role;              /* VW_NODE_ROLE_REPLICA or VW_NODE_ROLE_SELF */
    uint8_t  _pad[62];          /* reserved; zero on write                 */
} vw_node_record_t;

/*
 * role field values. The meaning is context-dependent:
 *   On the PRIMARY's nodes.db: REPLICA (0) marks a registered replica node.
 *   On a REPLICA's nodes.db: SELF (1) marks the node's own self-registration record.
 */
#define VW_NODE_ROLE_REPLICA  0u   /* primary-side: this is a known replica */
#define VW_NODE_ROLE_SELF     1u   /* replica-side: this is our own record */

_Static_assert(sizeof(vw_node_record_t) == 256,
               "vw_node_record_t must be exactly 256 bytes");

/* ── Opaque cluster context ──────────────────────────────────────────────────── */

typedef struct vw_cluster_ctx vw_cluster_t;

/* ── Configuration ────────────────────────────────────────────────────────────── */

typedef struct {
    uint16_t cluster_port;              /* listen port for cluster connections; default 9010 */
    /* Replica-mode fields (used by TASK-049). */
    uint8_t  is_replica;
    char     primary_host[256];
    uint16_t primary_cluster_port;
    uint32_t replica_poll_interval_secs;
} vw_cluster_cfg_t;

/* ── Lifecycle ────────────────────────────────────────────────────────────────── */

/*
 * Open (or create) the node store under {data_dir}/cluster/nodes.db.
 * Scans records to build the nid_to_slot in-memory index.
 * Does NOT start the accept thread — call vw_cluster_start() for that.
 *
 * cert_pem_path and key_pem_path are the same TLS credentials used by the
 * main server; they are used for the cluster TLS listener.
 *
 * oplog must remain valid for the lifetime of the cluster context.
 *
 * Returns VW_OK and sets *out on success; VW_ERR_IO on file errors;
 * VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_cluster_open(const char *data_dir,
                          const vw_cluster_cfg_t *cfg,
                          const char *cert_pem_path,
                          const char *key_pem_path,
                          vw_oplog_t *oplog,
                          vw_cluster_t **out);

/*
 * Stop the accept thread (if running) and release all resources.
 * Safe to call with NULL.
 */
void vw_cluster_close(vw_cluster_t *ctx);

/*
 * Start the cluster accept thread. Begins listening on cfg.cluster_port.
 * Returns VW_ERR_IO if the listen socket cannot be created or the thread
 * fails to start.
 * No-op (VW_OK) if cfg.cluster_port == 0.
 */
vw_err_t vw_cluster_start(vw_cluster_t *ctx);

/*
 * Signal the accept thread to stop and block until it exits.
 * Safe to call when the thread was never started.
 */
void vw_cluster_stop(vw_cluster_t *ctx);

/* ── Node record API ────────────────────────────────────────────────────────── */

/*
 * Register a new node. Generates a 256-bit auth_token via vw_crypto_random.
 * Returns the new node_id in *out_node_id and the token in *out_token (32 bytes).
 * The token is returned to the caller once; it is never readable again via
 * vw_cluster_node_get (that function zeroes the token in returned copies).
 *
 * Returns VW_OK on success; VW_ERR_OOM on allocation failure; VW_ERR_IO on
 * disk failure.
 */
vw_err_t vw_cluster_node_add(vw_cluster_t *ctx,
                              const char *hostname,
                              uint8_t role,
                              uint64_t *out_node_id,
                              uint8_t  out_token[32]);

/*
 * Look up a node by node_id and copy the record into *out_rec.
 * Zeroes out_rec->auth_token before returning (security invariant).
 * Returns VW_ERR_NOT_FOUND if node_id does not exist.
 */
vw_err_t vw_cluster_node_get(vw_cluster_t *ctx,
                              uint64_t node_id,
                              vw_node_record_t *out_rec);

/*
 * Update the sync_watermark for node_id in-place (single pwrite, 8 bytes,
 * naturally aligned — POSIX-atomic). Returns VW_ERR_NOT_FOUND if absent.
 */
vw_err_t vw_cluster_node_update_watermark(vw_cluster_t *ctx,
                                           uint64_t node_id,
                                           uint64_t watermark);

/*
 * Set is_active for node_id. Updates the record on disk (pwrite + sync).
 * Returns VW_ERR_NOT_FOUND if absent.
 */
vw_err_t vw_cluster_node_set_active(vw_cluster_t *ctx,
                                     uint64_t node_id,
                                     uint8_t is_active);

/*
 * Return an array of all node records in *out_recs (caller frees).
 * auth_token is zeroed in every entry in the returned array.
 */
vw_err_t vw_cluster_node_list(vw_cluster_t *ctx,
                               vw_node_record_t **out_recs,
                               uint32_t *out_count);

/* ── GC helpers (used by vw_gc, TASK-050) ────────────────────────────────────── */

/*
 * Return the minimum sync_watermark across all nodes with
 * is_active == 1 && role == 0 (replicas).
 * Returns UINT64_MAX if no active replicas exist (safe to truncate freely).
 */
uint64_t vw_cluster_min_sync_watermark(vw_cluster_t *ctx);

/*
 * Return 1 if at least one node has is_active == 1 && role == 0.
 */
int vw_cluster_has_active_replicas(vw_cluster_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VW_CLUSTER_H */
