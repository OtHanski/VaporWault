#ifndef VW_STORAGE_H
#define VW_STORAGE_H

/*
 * vw_storage — SHA-256-keyed chunk content store with ref-counted deduplication.
 *
 * On-disk layout under {data_dir}/chunks/:
 *   {hex[0:2]}/             — two-hex-char sharding prefix directories
 *     {sha256hex}.chunk     — raw chunk data (up to 4 MiB)
 *   refcounts.db            — flat array of refcount_record_t (40 bytes/slot)
 *
 * refcounts.db slot 0 is a guard (all-zero hash == free).
 * The in-memory HT is rebuilt by scanning refcounts.db on open.
 *
 * Security:
 *   vw_storage_chunk_get does NOT verify the SHA-256 of the returned data.
 *   The hash is verified by vw_storage_chunk_put at write time (using the
 *   atomic rename approach: temp file + SHA-256 verify + rename).
 *   Callers that receive chunk data from the wire (TASK-024 CHUNK_DOWNLOAD
 *   handler) must re-verify the hash before sending to clients, since the
 *   on-disk data is considered trusted after a successful put.
 *
 * Thread safety: all public functions are thread-safe (single rwlock).
 */

#include "../core/vw_proto.h"
#include <stdint.h>
#include <stddef.h>

/* Forward-declare vw_store_t for the quota callback (defined in vw_store.h). */
struct vw_store;
typedef struct vw_store vw_store_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_storage vw_storage_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Open or create the chunk store under {data_dir}/chunks/.
 * Creates directories and refcounts.db if they do not exist.
 * Scans refcounts.db to build the in-memory ref-count table.
 * Runs a dark-orphan scan: chunk files with no refcounts.db entry are added
 * as ref_count=0 and will be reclaimed on the next vw_storage_gc_run().
 *
 * Returns VW_OK and sets *out on success.
 * Returns VW_ERR_IO on filesystem failure; VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_storage_open(const char *data_dir, vw_storage_t **out);

/*
 * Flush and free the storage context. Safe to call with NULL.
 */
void vw_storage_close(vw_storage_t *st);

/*
 * Associate a vw_store_t with this storage context so that GC can decrement
 * the owner's used_bytes when a chunk is deleted. Call after vw_storage_open
 * and before vw_storage_gc_run. Optional — if not called, GC skips quota
 * decrement (safe but leaves used_bytes over-counted until next store_open).
 */
void vw_storage_set_store(vw_storage_t *st, vw_store_t *store);

/* ── Chunk operations ────────────────────────────────────────────────────── */

/*
 * Store a chunk (or increment its ref_count if it already exists).
 *
 *   hash    : caller-supplied SHA-256 of `data`
 *   data    : raw chunk bytes
 *   len     : byte count (max 4 MiB = 4194304)
 *
 * If the chunk is NEW:
 *   1. Verifies SHA-256(data) == hash; returns VW_ERR_CHUNK_HASH_MISMATCH
 *      if not.
 *   2. Writes data to a temp file; fsyncs; renames to the canonical path
 *      (atomic on POSIX; MOVEFILE_REPLACE_EXISTING on Windows).
 *   3. Sets ref_count = 1 in the in-memory table and on disk.
 *
 * If the chunk already exists (ref_count > 0): increments ref_count in-memory
 * and on disk. The data bytes are not re-written.
 *
 * INVARIANT (TASK-023 §1): ref_count must be set/incremented BEFORE the
 * chunk is considered committed. GC only deletes chunks with ref_count == 0.
 */
/*
 * owner_user_id is stored in the refcount record for GC quota attribution.
 * Pass the uploading user's user_id. On a dedup hit the owner_user_id is
 * not changed (cross-user dedup: quota is charged to the first uploader only).
 *
 * Quota enforcement: if a vw_store_t is associated via vw_storage_set_store,
 * vw_storage_chunk_put charges the user's quota atomically under its write lock
 * on new-chunk paths only (dedup hits do not charge).  Returns
 * VW_ERR_QUOTA_EXCEEDED without writing if the limit would be breached.
 */
vw_err_t vw_storage_chunk_put(vw_storage_t *st,
                               const uint8_t hash[VW_HASH_BYTES],
                               const uint8_t *data, uint32_t len,
                               uint64_t owner_user_id);

/*
 * TASK-172 (replica hot-standby data replication, docs/PROTOCOL.md §7.7):
 * apply a chunk fetched via CLUSTER_CHUNK_FETCH. Same hash-verify +
 * atomic-write + ref_count-set behavior as vw_storage_chunk_put, but never
 * charges quota (the primary already charged this content when its own
 * client uploaded it — replication must never fail with
 * VW_ERR_QUOTA_EXCEEDED against this replica's own, possibly not-yet-synced
 * quota state) and has no owner_user_id, for the same reason.
 */
vw_err_t vw_storage_chunk_put_replicated(vw_storage_t *st,
                                          const uint8_t hash[VW_HASH_BYTES],
                                          const uint8_t *data, uint32_t len);

/*
 * Retrieve a chunk by its SHA-256 hash.
 * *out_data receives a malloc'd buffer; caller frees.
 * *out_len receives the byte count.
 * Returns VW_ERR_NOT_FOUND if the chunk is absent or ref_count == 0.
 */
vw_err_t vw_storage_chunk_get(vw_storage_t *st,
                               const uint8_t hash[VW_HASH_BYTES],
                               uint8_t **out_data, uint32_t *out_len);

/*
 * Increment ref_count for an already-stored chunk without re-supplying the
 * data. Used by FILE_COMMIT when creating a new version that references
 * chunks already present in the store.
 * Returns VW_ERR_NOT_FOUND if the chunk is absent or ref_count == 0.
 */
vw_err_t vw_storage_chunk_addref(vw_storage_t *st,
                                   const uint8_t hash[VW_HASH_BYTES]);

/*
 * Decrement ref_count for a chunk.
 * If ref_count reaches 0, marks the chunk as GC-eligible (does not delete
 * the chunk file immediately — that is done by vw_storage_gc_run).
 * Returns VW_ERR_NOT_FOUND if the chunk is not in the table.
 */
vw_err_t vw_storage_chunk_decref(vw_storage_t *st,
                                  const uint8_t hash[VW_HASH_BYTES]);

/*
 * TASK-181: authoritatively overwrite a chunk's ref_count to exactly
 * `refcount`, unlike addref/decref's +1/-1 semantics. For a replica
 * reconciling its own refcounts.db against the true occurrence count
 * computed from its own current versions.dat/versions.blob (see
 * vw_cluster.c's replica_run_chunk_sync_pass) — never for primary-side
 * incremental tracking, which must keep using addref/decref/chunk_put's
 * own increment-on-write.
 *
 * Does not create the chunk if absent: returns VW_ERR_NOT_FOUND if the
 * hash has no entry at all (the caller must vw_storage_chunk_put_replicated
 * it first so the content and its ref_count == 1 baseline both exist).
 * Passing refcount == 0 is valid and marks the chunk GC-eligible, same as
 * decref reaching 0.
 */
vw_err_t vw_storage_chunk_set_refcount(vw_storage_t *st,
                                        const uint8_t hash[VW_HASH_BYTES],
                                        uint32_t refcount);

/*
 * TASK-094: move a chunk's quota attribution from from_user_id to
 * to_user_id, if and only if the chunk's currently-recorded owner_user_id
 * (the party charged for its bytes) is exactly from_user_id. A no-op
 * (returns VW_OK) if the chunk's owner is anyone else — e.g. a dedup hit
 * against a chunk some third party uploaded long ago, which from_user_id
 * was never charged for in the first place, so there is nothing to move.
 *
 * Used by FILE_COMMIT to correct quota attribution when the acting session
 * (from_user_id — the uploader, possibly an EDIT grantee or an anonymous
 * scoped-link session with user_id 0) differs from the file's resolved
 * real owner (to_user_id): every chunk-level charge that CHUNK_UPLOAD made
 * against the uploader is transferred to the owner, exactly for the bytes
 * that upload actually put on disk (looked up via vw_fs_file_size on the
 * chunk file, not the wire-supplied logical_size, so dedup'd chunks that
 * were never charged to from_user_id are correctly excluded).
 *
 * Updates the refcount record's owner_user_id to to_user_id so future GC
 * decrements (and any later reattribution) charge the correct party.
 * Returns VW_ERR_NOT_FOUND if the chunk is absent or ref_count == 0.
 */
vw_err_t vw_storage_chunk_reattribute(vw_storage_t *st,
                                       const uint8_t hash[VW_HASH_BYTES],
                                       uint64_t from_user_id,
                                       uint64_t to_user_id);

/*
 * Batch chunk-exists query (used by CHUNK_QUERY handler).
 *
 *   hashes      : array of `count` SHA-256 hashes (each VW_HASH_BYTES bytes)
 *   count       : number of hashes; max 1024 (returns VW_ERR_INVALID_ARG if larger)
 *   out_bitmask : caller provides ceil(count/8) bytes; bit i is set if chunk i
 *                 is present (ref_count > 0). Bit 0 of byte 0 = chunk 0
 *                 (big-endian bit order within each byte, PROTOCOL.md §7.2).
 */
vw_err_t vw_storage_chunk_query(vw_storage_t *st,
                                 const uint8_t (*hashes)[VW_HASH_BYTES],
                                 uint16_t count,
                                 uint8_t *out_bitmask);

/* ── Garbage collection ──────────────────────────────────────────────────── */

/*
 * Run a GC pass:
 *   Phase A — collect: delete chunk files for all in-memory entries with
 *              ref_count == 0; zero those entries in refcounts.db.
 *   Phase B — dark-orphan scan: walk data/chunks/ for .chunk files with
 *              no in-memory entry; add them as ref_count=0 (they will be
 *              collected on the next GC pass). This handles crash recovery
 *              for chunks written before the ref_count was set.
 *
 * Called periodically by the server (default: every hour). Thread-safe;
 * holds exclusive lock during Phase A removal. Phase B (directory walk)
 * is done under a temporary shared lock per shard to reduce contention.
 */
vw_err_t vw_storage_gc_run(vw_storage_t *st);

#ifdef __cplusplus
}
#endif

#endif /* VW_STORAGE_H */
