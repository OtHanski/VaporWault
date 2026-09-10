/*
 * vw_repair.c — Phase 22 (TASK-260) repair pipeline orchestration.
 *
 * See vw_repair.h for the design description.
 */

#include "vw_repair.h"

#include <stdlib.h>

/* Generous relative to cfg.replica_poll_interval_secs's 5s default (see
 * vw_cluster_repair_fetch's own doc comment) — repair is a background
 * operation, not latency-sensitive, so erring toward "wait long enough
 * for a normally-connected replica to check in" costs nothing here. */
#define VW_REPAIR_FETCH_TIMEOUT_MS 15000u

vw_err_t vw_repair_chunk(vw_storage_t *chunks, vw_cluster_t *cluster,
                          const uint8_t hash[VW_HASH_BYTES])
{
    if (!chunks || !hash) return VW_ERR_INVALID_ARG;

    uint8_t *data = NULL;
    uint32_t len  = 0;

    /* Step 1: local Reed-Solomon reconstruction — cheap, no network. */
    if (vw_storage_repair_local(chunks, hash, &data, &len) == VW_OK) {
        vw_err_t wrc = vw_storage_chunk_repair_write(chunks, hash, data, len);
        free(data);
        return wrc;
    }

    /* Step 2: replica-fetch fallback, one active replica at a time. */
    if (cluster) {
        vw_node_record_t *nodes = NULL;
        uint32_t node_count = 0;
        if (vw_cluster_node_list(cluster, &nodes, &node_count) == VW_OK) {
            uint32_t i;
            for (i = 0; i < node_count; i++) {
                if (nodes[i].role != VW_NODE_ROLE_REPLICA || !nodes[i].is_active)
                    continue;

                data = NULL;
                len  = 0;
                vw_err_t frc = vw_cluster_repair_fetch(cluster, nodes[i].node_id, hash,
                                                        VW_REPAIR_FETCH_TIMEOUT_MS,
                                                        &data, &len);
                if (frc == VW_OK) {
                    vw_err_t wrc = vw_storage_chunk_repair_write(chunks, hash, data, len);
                    free(data);
                    free(nodes);
                    return wrc;
                }
                /* frc != VW_OK: this replica doesn't have a clean copy
                 * either, or is unreachable (VW_ERR_TIMEOUT) — try the
                 * next one, same posture docs/PROTOCOL.md §7.7 documents
                 * for this pipeline. */
            }
            free(nodes);
        }
    }

    /* Step 3: give up — the chunk is still corrupt on disk. */
    return VW_ERR_NOT_FOUND;
}
