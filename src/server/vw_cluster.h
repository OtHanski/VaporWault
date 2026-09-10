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

/* Forward declarations — TASK-172 (replica hot-standby data replication):
 * vw_cluster_open needs each store module's live handle so a replica can
 * reload its in-memory state after CLUSTER_FILE_SYNC_DATA/CLUSTER_CHUNK_DATA
 * writes new bytes to disk (see vw_*_reload() in each module's own header).
 * Forward-declared rather than included so this header stays a thin
 * dependency for callers that only need the node-record/handshake API. */
struct vw_store;        typedef struct vw_store vw_store_t;
struct vw_file_store;   typedef struct vw_file_store vw_file_store_t;
struct vw_storage;      typedef struct vw_storage vw_storage_t;
struct vw_share_store;  typedef struct vw_share_store vw_share_store_t;
struct vw_vault_store;  typedef struct vw_vault_store vw_vault_store_t;

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
    uint8_t  _pad[78];          /* reserved; zero on write                 */
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
 * store, file_store, chunks, share_store, vault_store (TASK-172): this
 * server's own already-opened live store handles. Used two ways:
 *   - On either role, `chunks` backs CLUSTER_CHUNK_QUERY/CLUSTER_CHUNK_FETCH
 *     (primary side, reusing vw_storage_chunk_query/vw_storage_chunk_get
 *     exactly like the client-facing CHUNK_QUERY/CHUNK_DOWNLOAD_REQ
 *     handlers) and vw_storage_chunk_put_replicated (replica side).
 *   - On a replica, the other four back each module's vw_*_reload() call
 *     after CLUSTER_FILE_SYNC_DATA writes fresh bytes for that module's
 *     file(s) to disk (docs/PROTOCOL.md §7.7).
 * share_store and vault_store may be NULL if the caller's own open call for
 * that optional subsystem failed — the corresponding sync/reload is then
 * skipped (that module stays whatever it already was, matching how the
 * rest of the server already runs with sharing/vaults disabled). store,
 * file_store, and chunks must be non-NULL — they are load-bearing for the
 * base feature set on every server regardless of cluster role.
 *
 * Returns VW_OK and sets *out on success; VW_ERR_IO on file errors;
 * VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_cluster_open(const char *data_dir,
                          const vw_cluster_cfg_t *cfg,
                          const char *cert_pem_path,
                          const char *key_pem_path,
                          vw_oplog_t *oplog,
                          vw_store_t *store,
                          vw_file_store_t *file_store,
                          vw_storage_t *chunks,
                          vw_share_store_t *share_store,
                          vw_vault_store_t *vault_store,
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
 * Register THIS node's own self-record (role forced to VW_NODE_ROLE_SELF)
 * using a node_id and auth_token already issued by the primary's call to
 * vw_cluster_node_add() for this node. The primary and replica must agree on
 * both values — the NODE_HELLO handshake authenticates by comparing them —
 * so this does not generate a new token; it stores the one given.
 *
 * This is the second half of node pairing: run vw_cluster_node_add() once on
 * the primary, then this once on the replica with the node_id/token it
 * printed.
 *
 * Returns VW_ERR_ALREADY_EXISTS if node_id is already registered locally;
 * VW_ERR_OOM on allocation failure; VW_ERR_IO on disk failure.
 */
vw_err_t vw_cluster_node_add_self(vw_cluster_t *ctx,
                                   uint64_t node_id,
                                   const uint8_t token[32],
                                   const char *hostname);

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

/*
 * Return 1 if this server was configured with cluster_is_replica = 1
 * (cfg.is_replica at vw_cluster_open time), 0 otherwise. ctx may be NULL
 * (a non-clustered server) — returns 0 in that case. TASK-179: lets the
 * client-facing dispatcher (vw_file_handlers.c) reject write-shaped
 * requests on a replica without needing its own copy of the cluster cfg.
 */
int vw_cluster_is_replica(const vw_cluster_t *ctx);

/* ── Chunk repair-fetch (Phase 22, TASK-259) ─────────────────────────────── */

/*
 * Ask a specific, currently-connected replica node for a clean copy of
 * chunk_hash, over its existing authenticated cluster connection, for
 * local corruption repair on this (primary) server. A primary cannot
 * originate unprompted traffic on this connection — the replica opened
 * it — so this queues the request and blocks, polling in 100ms steps up
 * to timeout_ms, until that replica's own next OPLOG_PULL check-in
 * actually carries it (docs/PROTOCOL.md §7.7's "Direction is genuinely
 * reversed" note). Recommend a timeout comfortably above
 * cfg.replica_poll_interval_secs * 1000 (default poll interval 5 s) so a
 * normally-connected replica has time to check in — e.g. 15000.
 *
 * Returns VW_OK and fills *out_data (malloc'd, caller frees) and
 * *out_len on success; this function re-verifies the returned bytes' hash itself
 * before accepting them, so a caller never receives unverified bytes
 * from the wire even if the replica misbehaves.
 * Returns VW_ERR_NOT_FOUND if the replica responded that it doesn't have
 * a clean copy either (or responded with some other ERROR code, passed
 * through as-is — e.g. VW_ERR_CHUNK_CORRUPT if the replica's own copy
 * also failed its hash check).
 * Returns VW_ERR_TIMEOUT if no primary_repl_loop thread for node_id
 * checks in within timeout_ms — e.g. the replica is currently
 * disconnected. Not distinguished on the wire from "the replica exists
 * but is currently unreachable"; callers that need to know which should
 * check vw_cluster_node_list's is_active/liveness state separately.
 * Returns VW_ERR_ALREADY_EXISTS if a repair-fetch is already outstanding
 * for node_id (one at a time per node in this MVP) or the small
 * pending-request table (VW_CLUSTER_REPAIR_SLOTS) is full.
 */
vw_err_t vw_cluster_repair_fetch(vw_cluster_t *ctx, uint64_t node_id,
                                  const uint8_t hash[VW_HASH_BYTES],
                                  uint32_t timeout_ms,
                                  uint8_t **out_data, uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* VW_CLUSTER_H */
