#ifndef VW_REPAIR_H
#define VW_REPAIR_H

/*
 * vw_repair — Phase 22 (TASK-260) repair pipeline orchestration.
 *
 * Ties vw_storage's local Reed-Solomon reconstruction (TASK-258) and
 * vw_cluster's replica-fetch (TASK-259) together into the repair
 * ordering from the Phase 22 design (ARCHITECTURE.md): local
 * reconstruction first (cheap, no network), replica-fetch fallback
 * second, give up third. Neither vw_storage.c nor vw_cluster.c reference
 * each other directly (vw_storage stays cluster-agnostic, matching its
 * existing design) — this module is the one place that needs both.
 */

#include "../core/vw_proto.h"
#include "vw_storage.h"
#include "vw_cluster.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Attempt to repair a chunk found corrupt (ref_count > 0, on-disk bytes
 * no longer hash to `hash`):
 *   1. Local Reed-Solomon reconstruction (vw_storage_repair_local).
 *   2. If that fails (not enough redundancy left in its parity group —
 *      see that function's own doc comment on the single-fault limit),
 *      ask each active replica in turn (vw_cluster_repair_fetch) until
 *      one returns a hash-verified copy.
 *   3. If neither succeeds, do nothing further — the chunk is still
 *      corrupt on disk.
 *
 * On success (VW_OK), the corrected bytes are already durably written
 * back to the chunk store (vw_storage_chunk_repair_write) before this
 * returns — callers never need to write anything themselves.
 *
 *   chunks  : the local chunk store (required)
 *   cluster : this server's cluster context, or NULL if clustering is
 *             disabled — step 2 is simply skipped in that case
 *   hash    : the corrupted chunk's hash
 *
 * Returns VW_ERR_NOT_FOUND if neither step produced a hash-verified
 * copy — the caller should treat this like any other unrepairable-
 * corruption case (TASK-261's alert, once wired in).
 */
vw_err_t vw_repair_chunk(vw_storage_t *chunks, vw_cluster_t *cluster,
                          const uint8_t hash[VW_HASH_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VW_REPAIR_H */
