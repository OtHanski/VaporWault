#ifndef VW_INVITE_H
#define VW_INVITE_H

/*
 * vw_invite — invite token flat-file store.
 *
 * Invites are admin-generated, single-use tokens that allow a user to
 * self-register without an admin creating the account directly.
 *
 * Storage: {data_dir}/store/invites.db
 * Record layout: vw_invite_record_t (64 bytes per slot).
 * A slot with code[0] == 0 is free/unused.
 * Invites are appended on creation; is_used is updated in-place.
 *
 * Wire payload (INVITE_CREATE_ACK / INVITE_REDEEM):
 *   code[32] — base32-encoded 128-bit random token (26 ASCII chars, NUL-padded to 32).
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Record ──────────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  code[32];       /* base32 code (26 chars), NUL-padded; [0]==0 → free */
    uint64_t created_by;     /* admin user_id                                     */
    uint64_t quota_bytes;    /* initial quota for redeemed account; 0 = unlimited */
    uint64_t expires_at;     /* Unix timestamp; 0 = no expiry                     */
    uint8_t  is_used;        /* 1 = already redeemed                              */
    uint8_t  _pad[7];        /* reserved; must be zero on write                   */
} vw_invite_record_t;

_Static_assert(sizeof(vw_invite_record_t) == 64,
               "vw_invite_record_t must be exactly 64 bytes");

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_invite_store vw_invite_store_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Open or create the invite store under {data_dir}/store/.
 * Scans existing records and builds the in-memory code index.
 * Returns VW_OK and sets *out on success.
 */
vw_err_t vw_invite_store_open(const char *data_dir, vw_invite_store_t **out);

/* Close and free the store. Safe to call with NULL. */
void vw_invite_store_close(vw_invite_store_t *s);

/* ── Operations ──────────────────────────────────────────────────────────── */

/*
 * Generate a random invite code and write the record.
 * out_code[32] receives the base32 code (26 ASCII chars, NUL-padded to 32).
 * ttl_secs == 0 means no expiry.
 * Returns VW_OK or VW_ERR_IO / VW_ERR_OOM.
 */
vw_err_t vw_invite_create(vw_invite_store_t *s,
                           uint64_t created_by,
                           uint64_t quota_bytes,
                           uint32_t ttl_secs,
                           uint8_t  out_code[32]);

/*
 * Atomically validate and consume an invite in a single write-locked operation.
 * Checks that the invite exists, is unused, and is not expired. If valid,
 * writes is_used=1 to disk and populates *out.
 *
 * TASK-00045: this replaced an earlier separate get-then-mark-used pair
 * (vw_invite_get + vw_invite_mark_used) that had a TOCTOU window where two
 * concurrent INVITE_REDEEM requests could both observe is_used=0 before
 * either marked the invite used. Both were removed entirely (TASK-00270)
 * once confirmed to have zero remaining call sites — this is the only way
 * to read or consume an invite.
 *
 * Returns VW_ERR_NOT_FOUND if the code is unknown, already used, or expired.
 */
vw_err_t vw_invite_claim(vw_invite_store_t *s,
                          const uint8_t code[32],
                          vw_invite_record_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VW_INVITE_H */
