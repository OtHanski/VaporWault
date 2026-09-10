#ifndef VW_STORAGE_H
#define VW_STORAGE_H

/*
 * vw_storage — SHA-256-keyed chunk content store with ref-counted deduplication.
 *
 * On-disk layout under {data_dir}/chunks/:
 *   {hex[0:2]}/             — two-hex-char sharding prefix directories
 *     {sha256hex}.chunk     — raw chunk data (up to 4 MiB)
 *   refcounts.db            — flat array of refcount_record_t (40 bytes/slot)
 *   parity_groups.db        — Phase 22 (TASK-258): flat array of
 *                             pg_member_record_t (64 bytes/slot), mapping
 *                             each chunk hash to its parity group + slot
 *   parity/{group_id}.parity — Phase 22 (TASK-258): one sealed group's
 *                             Reed-Solomon parity shard (1-byte format
 *                             version + VW_CHUNK_SIZE_DEFAULT bytes);
 *                             existence of this file IS the group's
 *                             "sealed" flag, no separate index needed
 *
 * refcounts.db slot 0 is a guard (all-zero hash == free).
 * The in-memory HT is rebuilt by scanning refcounts.db on open.
 * parity_groups.db follows the identical guard/scan-on-open convention.
 *
 * Security:
 *   vw_storage_chunk_get does NOT verify the SHA-256 of the returned data —
 *   it is a hot path and stays that way. The hash is verified by
 *   vw_storage_chunk_put at write time (temp file + SHA-256 verify +
 *   atomic rename), and on-disk data is trusted between then and its next
 *   check. Two chokepoints do re-verify after that, to catch corruption at
 *   rest (bit rot, filesystem bugs) rather than trust it forever:
 *     - handle_chunk_download (vw_file_handlers.c, TASK-254) re-hashes
 *       before ever sending CHUNK_DATA to a client, returning
 *       VW_ERR_CHUNK_CORRUPT on mismatch instead of serving bad bytes.
 *     - vw_storage_scrub_run (TASK-255) periodically walks the whole
 *       chunk store re-hashing every chunk, for detection before a client
 *       ever requests the corrupted one.
 *   Neither chokepoint repairs a corrupt chunk yet. TASK-258 (this file's
 *   parity-group API below, plus vw_ecc.h's codec) makes local
 *   reconstruction *possible*; TASK-259/260 (cluster replica-fetch repair
 *   and wiring scrub/download's corruption detection to actually call
 *   these) are filed but not yet implemented — a corrupt chunk is still
 *   only detected and reported today, never auto-repaired.
 *
 * Thread safety: all public functions are thread-safe (single rwlock).
 */

#include "../core/vw_proto.h"
#include "vw_ecc.h" /* VW_ECC_MAX_DATA_SHARDS — sizes the parity-group API's caller-allocated arrays below */
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
 * Overwrite the on-disk bytes for an EXISTING, already-referenced chunk
 * with verified-correct content — Phase 22 (TASK-260), used by the
 * repair pipeline (vw_repair.c) after local Reed-Solomon reconstruction
 * or a cluster replica-fetch recovers a clean copy. Does NOT touch
 * ref-counting, quota, or parity-group membership — this hash already
 * has all of those from whenever it was first written; this is purely a
 * corrected-bytes write, atomic (temp + rename, same primitive
 * vw_storage_chunk_put uses internally).
 *
 * Verifies SHA-256(data) == hash before writing — defense in depth, the
 * last check before anything touches disk, even though every caller is
 * expected to have already verified this itself.
 *
 * Returns VW_ERR_CHUNK_HASH_MISMATCH if the hash doesn't match.
 * Returns VW_ERR_NOT_FOUND if this hash has no existing live entry
 * (ref_count > 0) at all — repair only ever replaces already-known,
 * still-referenced content, never creates new chunks or resurrects a
 * tombstone.
 */
vw_err_t vw_storage_chunk_repair_write(vw_storage_t *st,
                                        const uint8_t hash[VW_HASH_BYTES],
                                        const uint8_t *data, uint32_t len);

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

/* ── Scrub (TASK-255, Phase 22 detection foundation) ─────────────────────── */

typedef struct {
    uint64_t scanned;     /* .chunk files examined */
    uint64_t corrupt;     /* ref_count > 0 but bytes no longer hash to filename */
    uint64_t tombstoned;  /* ref_count == 0 mismatch/unreadable — skipped, not an error */
} vw_storage_scrub_stats_t;

/*
 * Invoked once per chunk found genuinely corrupt (ref_count > 0, bytes no
 * longer hash to their own filename). Repair is not wired yet — TASK-260
 * will call this to drive local Reed-Solomon reconstruction / cluster
 * replica-fetch repair. May be NULL (stats-only run).
 */
typedef void (*vw_storage_scrub_cb)(const uint8_t hash[VW_HASH_BYTES], void *ud);

/*
 * Walk every shard directory (data/chunks/XX/ for XX in 00..ff — a shard
 * that has never received a chunk simply doesn't exist yet and is skipped,
 * not an error), re-hash every *.chunk file, and compare against its own
 * filename.
 *
 * A hash mismatch (or unreadable file) for a chunk whose in-memory
 * ref_count is 0 is a legitimate tombstone — GC (vw_storage_gc_run) may be
 * about to unlink it, or it's a dark orphan from a crash between chunk
 * write and ref_count set (see vw_storage_gc_run's own doc comment) — and
 * is silently counted in out_stats->tombstoned, never passed to cb.
 *
 * A mismatch for a chunk with ref_count > 0 is real corruption: cb (if
 * non-NULL) is invoked once with that hash, and out_stats->corrupt is
 * incremented.
 *
 * Each shard is read under a shared lock (like vw_storage_gc_run's Phase B)
 * so this never blocks normal chunk reads/writes for long; the directory
 * walk itself runs unlocked.
 *
 * out_stats may be NULL. Returns VW_OK; per-file I/O errors are logged
 * internally and skipped, not fatal to the overall scan (same convention
 * as vw_storage_gc_run's Phase B).
 */
vw_err_t vw_storage_scrub_run(vw_storage_t *st,
                               vw_storage_scrub_cb cb, void *ud,
                               vw_storage_scrub_stats_t *out_stats);

/* ── Parity groups (TASK-258, Phase 22 local-reconstruction foundation) ──── */
/*
 * Chunks are grouped into fixed-size parity groups, each member assigned
 * the next open slot the first time it gets a genuine, permanent
 * reference — for a real client upload, that's its first
 * vw_storage_chunk_addref (called from FILE_COMMIT), not its earlier
 * vw_storage_chunk_put; for a replicated write, ref_count is established
 * at put time already, so that's when it's registered instead. (Revised
 * after TASK-258 originally registered every real upload at put time —
 * see register_parity_member's own doc comment in vw_storage.c for the
 * GC race that fixed. A dedup hit against an already-registered hash is
 * always a no-op, regardless of which path re-encounters it.) When a
 * group reaches VW_ECC_MAX_DATA_SHARDS (vw_ecc.h) members it is sealed —
 * its parity shard computed via vw_ecc_encode and written to
 * {data_dir}/chunks/parity/{group_id}.parity — and a fresh group opens.
 * A still-open (< VW_ECC_MAX_DATA_SHARDS members) group has no parity
 * coverage yet; this is a disclosed, accepted gap, not a bug — the next
 * VW_ECC_MAX_DATA_SHARDS registrations close it. Group formation happens
 * automatically inside vw_storage_chunk_put/_put_replicated/_addref;
 * there is no separate "form a group" entry point.
 *
 * Reconstruction itself (calling vw_ecc_decode_single with a group's
 * members) is not wired up by this task — TASK-260 drives that from
 * vw_storage_scrub_run's/handle_chunk_download's corruption findings.
 * The four functions below are what that future wiring (and this task's
 * own tests) build on: look up a hash's group, read a sealed group's
 * parity shard, and enumerate a group's members to gather the other
 * VW_ECC_MAX_DATA_SHARDS-1 shards needed to reconstruct one.
 */

typedef struct {
    uint64_t group_id;
    uint32_t slot_index;  /* 0..VW_ECC_MAX_DATA_SHARDS-1 */
    uint32_t chunk_len;   /* real on-disk length of this member */
} vw_parity_membership_t;

/*
 * Look up which parity group (if any) a chunk hash belongs to.
 * Returns VW_ERR_NOT_FOUND if this hash was never assigned a group slot
 * (e.g. it predates this feature, or is genuinely unknown to this store).
 * A stale membership for a hash later GC'd to ref_count 0 is not an
 * error here — the caller (repair logic) is responsible for checking the
 * chunk's live ref_count in refcounts.db to distinguish a tombstone from
 * real corruption, exactly as vw_storage_scrub_run already does.
 */
vw_err_t vw_storage_parity_lookup(vw_storage_t *st,
                                   const uint8_t hash[VW_HASH_BYTES],
                                   vw_parity_membership_t *out);

/*
 * Return 1 if group_id has been sealed (its parity shard file exists on
 * disk), 0 otherwise (still open, or a crash left it at
 * VW_ECC_MAX_DATA_SHARDS members with no parity file yet — the latter is
 * corrected automatically at the next vw_storage_open, which finishes
 * sealing any such group before returning).
 */
int vw_storage_parity_group_is_sealed(vw_storage_t *st, uint64_t group_id);

/*
 * Enumerate group_id's members. out_hashes/out_memberships are
 * caller-allocated arrays of VW_ECC_MAX_DATA_SHARDS entries; a member is
 * written at out_hashes[i]/out_memberships[i] where i ==
 * out_memberships[i].slot_index, so results are deterministic regardless
 * of internal iteration order — entries past *out_count are untouched
 * (garbage), not zeroed. *out_count < VW_ECC_MAX_DATA_SHARDS means the
 * group is still open.
 *
 * O(chunks ever assigned a parity slot in this store) — a full scan of
 * the in-memory index, same "acceptable at this project's personal
 * self-hosted scale" tradeoff already made for e.g. filename search's
 * full-table scan and vw_admin's list-deleted. Not on any hot path: only
 * called once per group seal (using this store's own fast in-memory
 * open-group accumulator, not this scan) is the frequent case — this
 * function itself is for the rare cases (startup crash-recovery, a
 * future repair lookup, this task's own tests).
 */
vw_err_t vw_storage_parity_group_members(vw_storage_t *st, uint64_t group_id,
                                          uint8_t out_hashes[][VW_HASH_BYTES],
                                          vw_parity_membership_t *out_memberships,
                                          uint32_t *out_count);

/*
 * Read a sealed group's parity shard: *out_data receives a malloc'd
 * VW_CHUNK_SIZE_DEFAULT-byte buffer (caller frees), *out_len is always
 * VW_CHUNK_SIZE_DEFAULT on success (the format-version byte is validated
 * and stripped, not included in *out_len).
 * Returns VW_ERR_NOT_FOUND if the group isn't sealed. Returns
 * VW_ERR_STORE_CORRUPT if the parity file exists but its format-version
 * byte is unrecognized or its size doesn't match the expected
 * 1 + VW_CHUNK_SIZE_DEFAULT bytes.
 */
vw_err_t vw_storage_parity_shard_read(vw_storage_t *st, uint64_t group_id,
                                       uint8_t **out_data, uint32_t *out_len);

/*
 * Enumerate "stuck" parity groups (Phase 22, TASK-264): a group_id with
 * exactly VW_ECC_MAX_DATA_SHARDS members recorded but no parity file on
 * disk, and which is NOT the store's currently-open group (that one is
 * expected to have fewer members, or — for the brief moment between
 * filling and register_parity_member's own deferred seal — is no longer
 * "current" by the time this scan can observe it; see that function's
 * own comment). This happens when a seal attempt fails and its failure
 * is silently discarded (register_parity_member advances past the
 * failing group before attempting to seal it, so concurrent uploads
 * aren't blocked on a potentially slow multi-chunk I/O operation) —
 * unlike the analogous crash-recovery path in vw_storage_open, which
 * only ever notices this for the single highest group_id, this call
 * finds every older group left in this state too.
 *
 * out_group_ids is a caller-allocated array of max_count uint64_t
 * entries; *out_count receives however many were found, up to
 * max_count (silently capped if there are more — a pathological case
 * this project doesn't expect to actually hit; a caller wanting to be
 * sure nothing is missed should just size the array generously, e.g.
 * vw_scrub.c's own caller).
 *
 * O(chunks ever assigned a parity slot in this store) plus O(group
 * count), same non-hot-path scan-cost tradeoff as
 * vw_storage_parity_group_members — called only from vw_scrub's own
 * periodic pass, never inline with a chunk write/read.
 */
vw_err_t vw_storage_parity_stuck_groups(vw_storage_t *st,
                                         uint64_t *out_group_ids,
                                         uint32_t max_count,
                                         uint32_t *out_count);

/*
 * Retry sealing a stuck group (Phase 22, TASK-264) — see
 * vw_storage_parity_stuck_groups's own comment for how a group ends up
 * here. Idempotent: returns VW_OK immediately, without redoing any work,
 * if group_id is already sealed. Returns VW_ERR_INVALID_ARG if group_id
 * doesn't actually have exactly VW_ECC_MAX_DATA_SHARDS members recorded
 * (not stuck — just not full yet, or not a real group at all).
 *
 * A transient original cause (a momentary I/O hiccup, a since-freed-up
 * full disk) heals silently on a successful retry. A permanent cause
 * (a member's chunk file is genuinely gone forever — see the
 * "Corruption detection & repair: registration timing" decision in
 * ARCHITECTURE.md for the residual race that can cause this) keeps
 * returning the same underlying failure every time this is called —
 * the caller (vw_scrub.c) logs that outcome each pass rather than the
 * silence this task fixes; it is never treated as fatal here.
 */
vw_err_t vw_storage_parity_group_reseal(vw_storage_t *st, uint64_t group_id);

/*
 * Attempt local Reed-Solomon reconstruction of a corrupted chunk from its
 * parity group's other members (Phase 22, TASK-260) — the first step of
 * vw_repair.c's repair pipeline. Pure read: does NOT write the result
 * back to disk (the caller does that, via vw_storage_chunk_repair_write,
 * only after deciding reconstruction actually succeeded).
 *
 * Important limitation, inherent to single-parity (m=1) redundancy, not
 * a bug: once ANY member of a group has been legitimately deleted (its
 * ref_count reached 0 and vw_storage_gc_run collected it — an entirely
 * ordinary consequence of normal file deletion), that group has already
 * spent its one allowed "gap". No other member of that same group can
 * ever be locally reconstructed after that, forever — this function
 * will correctly return VW_ERR_INVALID_ARG for every future call
 * against any of that group's remaining members, and the repair
 * pipeline falls through to cluster replica-fetch instead.
 *
 * Returns VW_ERR_NOT_FOUND if hash has no parity-group membership at all
 * (predates Phase 22, or is genuinely unknown) or its group isn't sealed
 * yet — nothing to reconstruct from.
 * Returns VW_ERR_INVALID_ARG if the group has more than one simultaneous
 * gap (this hash plus at least one sibling also unreadable or
 * hash-mismatched, including a sibling tombstoned by GC — see the
 * limitation above) — single-parity redundancy can't cover it.
 * Returns VW_ERR_CHUNK_CORRUPT in the (should-be-impossible) case where
 * reconstruction completed but the result doesn't actually hash-verify
 * against `hash` — the group's own data was somehow inconsistent.
 * Returns VW_OK and fills *out_data (malloc'd, caller frees) and
 * *out_len (trimmed to this member's real recorded length, not the full
 * VW_CHUNK_SIZE_DEFAULT shard size) on success.
 */
vw_err_t vw_storage_repair_local(vw_storage_t *st,
                                  const uint8_t hash[VW_HASH_BYTES],
                                  uint8_t **out_data, uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* VW_STORAGE_H */
