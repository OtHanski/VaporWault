#ifndef VW_RECOVERY_H
#define VW_RECOVERY_H

/*
 * vw_recovery — password-recovery token flat-file store.
 *
 * A recovery record holds a SHA-256 hash of the 6-digit one-time code
 * emailed to the user. Plaintext codes are never stored.
 *
 * Storage: {data_dir}/store/recovery.db
 * Record layout: vw_recovery_record_t (64 bytes per slot).
 * A slot with user_id == 0 is free.
 *
 * No in-memory index — lookup is always by user_id via linear scan.
 * The expected record count is small (≤ a few hundred) and TTL is 10 minutes,
 * so a hash table would not add meaningful performance.
 *
 * Thread safety: single rwlock guards all operations.
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Record ──────────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t user_id;       /* 0 = free slot                                  */
    uint8_t  code_hash[32]; /* SHA-256 of the 6-digit code; NEVER store plain */
    uint64_t expires_at;    /* Unix timestamp; record is invalid after this   */
    uint8_t  is_used;       /* 1 = already confirmed; prevents replay         */
    uint8_t  _pad[15];      /* reserved; must be zero on write                */
} vw_recovery_record_t;

_Static_assert(sizeof(vw_recovery_record_t) == 64,
               "vw_recovery_record_t must be exactly 64 bytes");

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_recovery_store vw_recovery_store_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Open or create the recovery store under {data_dir}/store/.
 * Returns VW_OK and sets *out on success.
 */
vw_err_t vw_recovery_store_open(const char *data_dir, vw_recovery_store_t **out);

/* Close and free the store. Safe to call with NULL. */
void vw_recovery_store_close(vw_recovery_store_t *s);

/* ── Operations ──────────────────────────────────────────────────────────── */

/*
 * Append a new recovery record for user_id.
 * code_hash[32] must be SHA-256(plaintext_code) — the caller computes it.
 * ttl_secs is added to now() to set expires_at.
 */
vw_err_t vw_recovery_write(vw_recovery_store_t *s,
                            uint64_t user_id,
                            const uint8_t code_hash[32],
                            uint32_t ttl_secs);

/*
 * Count unexpired, unused recovery records for user_id.
 * Used to enforce the 3-per-hour rate limit before writing a new record.
 */
vw_err_t vw_recovery_count_unexpired(vw_recovery_store_t *s,
                                      uint64_t user_id,
                                      uint64_t now_unix,
                                      uint32_t *out_count);

/*
 * Find the most recent unexpired, unused recovery record for user_id.
 * Returns VW_ERR_NOT_FOUND if no matching record exists.
 * On success *out_slot receives the 0-based slot index for vw_recovery_mark_used.
 */
vw_err_t vw_recovery_find_latest(vw_recovery_store_t *s,
                                  uint64_t user_id,
                                  uint64_t now_unix,
                                  vw_recovery_record_t *out,
                                  uint64_t *out_slot);

/*
 * Write is_used=1 for the record at slot (from vw_recovery_find_latest).
 * Returns VW_ERR_NOT_FOUND if slot is out of range.
 */
vw_err_t vw_recovery_mark_used(vw_recovery_store_t *s, uint64_t slot);

#ifdef __cplusplus
}
#endif

#endif /* VW_RECOVERY_H */
