#ifndef VW_ECC_H
#define VW_ECC_H

/*
 * vw_ecc — GF(256) Reed-Solomon erasure coding primitives.
 *
 * Phase 22 (corruption detection & repair), TASK-258. See ARCHITECTURE.md's
 * Phase 22 row / "Corruption detection & repair data layout" decision for
 * the full design. This module is pure, storage-agnostic math: it knows
 * nothing about chunks, hashes, or files — vw_storage.c (TASK-258's other
 * half) owns forming parity groups from the chunk store and calling into
 * this module with plain byte buffers.
 *
 * MVP scope: single-parity-shard groups (k data shards -> 1 parity shard,
 * ~1/k storage overhead, tolerates exactly one missing/corrupt shard per
 * group — data or parity). This is a genuine, valid systematic
 * Reed-Solomon code, not an approximation of one: the parity row's
 * coefficient is 1 for every data shard (gf256_mul(1, x) == x for all x),
 * which is a valid, MDS (maximum-distance-separable) row for a
 * Vandermonde/Cauchy-style RS generator matrix — the k-data + 1-parity
 * case is the well-known degenerate single-parity RS code, mathematically
 * identical to what "RAID 5" / plain XOR parity computes, arrived at here
 * via real GF(256) arithmetic rather than a disguised XOR helper. A future
 * second parity shard (not implemented — Phase 22 MVP is m=1) would need a
 * second, linearly-independent coefficient row (e.g. gf256_pow(2, i) for
 * shard i) so the resulting (k+2) x k matrix stays MDS; the GF(256)
 * primitives below are exposed and independently tested specifically so
 * that extension doesn't need new field arithmetic, only a new coefficient
 * row and (unlike the single-parity case) real Gaussian elimination in
 * decode to solve for 2 simultaneous unknowns.
 *
 * Usage:
 *   vw_ecc_init();  // idempotent, call once at startup (see vw_crypto_init)
 *   vw_ecc_encode(shards, k, shard_size, parity_out);
 *   ...later, shard i lost/corrupted...
 *   vw_ecc_decode_single(shards, k, parity, i, shard_size, out);
 */

#include "../core/vw_proto.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Data shards per parity group (Phase 22 MVP). Overridable at compile time
 * for fast unit tests (mirrors VW_OPLOG_SEGMENT_MAX's existing pattern,
 * tests/unit/CMakeLists.txt) — production code must never override this. */
#ifndef VW_ECC_MAX_DATA_SHARDS
#define VW_ECC_MAX_DATA_SHARDS 16u
#endif

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Build the GF(256) log/exp tables. Idempotent; safe to call more than
 * once or concurrently from multiple threads (the tables are deterministic
 * and a redundant rebuild just overwrites identical values — no lock
 * needed, unlike vw_crypto_init's RNG state). Must be called before any
 * other vw_ecc_* function; every server entry point that calls
 * vw_crypto_init() (main, vw_daemon, the Android JNI_OnLoad hook, etc.)
 * must call this too once Phase 22's chunk store integration (this task)
 * is wired into server startup.
 */
void vw_ecc_init(void);

/* ── GF(256) primitives ──────────────────────────────────────────────────── */
/*
 * Field: GF(2^8) with reduction polynomial x^8+x^4+x^3+x^2+1 (0x11D),
 * generator/primitive element 2 — the standard choice for Reed-Solomon
 * erasure coding (same field used by CDs, QR codes, and most published
 * RS erasure-coding references). Exposed for independent review and
 * testing, and for a future multi-parity-shard extension; the
 * single-parity MVP encode/decode below only ever multiply by 1 (a no-op
 * special-cased for speed — see vw_ecc.c), so these are not otherwise
 * exercised by this task's own storage-integration path today.
 */
uint8_t vw_gf256_mul(uint8_t a, uint8_t b);
uint8_t vw_gf256_div(uint8_t a, uint8_t b); /* b == 0 is a caller bug: returns 0, never crashes */
uint8_t vw_gf256_pow(uint8_t base, uint8_t exp);
uint8_t vw_gf256_inv(uint8_t a);            /* a == 0 is a caller bug: returns 0, never crashes */

/* ── Erasure coding ──────────────────────────────────────────────────────── */

/*
 * Compute one parity shard from k data shards.
 *
 *   shards      : k pointers to shard_size-byte buffers. A logical shard
 *                 shorter than shard_size (e.g. a chunk smaller than
 *                 VW_CHUNK_SIZE_DEFAULT) must be zero-padded by the caller
 *                 up to shard_size first — vw_ecc has no concept of "real"
 *                 vs "padding" length, that bookkeeping is the caller's
 *                 (vw_storage.c stores each member's real length
 *                 separately, in parity_groups.db).
 *   k           : 1..VW_ECC_MAX_DATA_SHARDS
 *   shard_size  : byte length of every shard and of parity_out
 *   parity_out  : caller-provided shard_size-byte buffer
 *
 * Returns VW_ERR_INVALID_ARG if k==0, k > VW_ECC_MAX_DATA_SHARDS,
 * shard_size==0, or any required pointer is NULL.
 */
vw_err_t vw_ecc_encode(const uint8_t *const *shards, uint32_t k,
                        size_t shard_size, uint8_t *parity_out);

/*
 * Reconstruct exactly one missing shard — a data shard, or the parity
 * shard itself — from the rest of a k-data + 1-parity group. Single-parity
 * redundancy can only ever cover one missing/corrupt shard among the k+1
 * total; this function rejects (VW_ERR_INVALID_ARG) rather than silently
 * guessing whenever more than one is absent.
 *
 *   shards        : k pointers. shards[missing_index] is ignored and may
 *                   be NULL when missing_index < k (that's the one
 *                   allowed gap); every other entry must be a valid,
 *                   non-NULL shard_size-byte buffer.
 *   k             : the group's original data-shard count
 *   parity        : the group's parity shard (shard_size bytes). Must be
 *                   non-NULL unless missing_index == k (reconstructing
 *                   the parity shard itself, in which case it's ignored
 *                   and may be NULL).
 *   missing_index : 0..k-1 to reconstruct that data shard, or k to
 *                   reconstruct the parity shard.
 *   shard_size    : byte length of every shard (and of *out)
 *   out           : caller-provided shard_size-byte buffer for the result
 *
 * Returns VW_OK and fills *out on success. Returns VW_ERR_INVALID_ARG for
 * a bad k/missing_index/shard_size, a NULL out, or — the actual "can't
 * cover this many faults" case — any required shard/parity pointer being
 * NULL in addition to the one gap missing_index already allows (i.e. two
 * or more simultaneous faults in the same group).
 */
vw_err_t vw_ecc_decode_single(const uint8_t *const *shards, uint32_t k,
                               const uint8_t *parity, uint32_t missing_index,
                               size_t shard_size, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VW_ECC_H */
