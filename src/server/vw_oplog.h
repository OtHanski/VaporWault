#ifndef VW_OPLOG_H
#define VW_OPLOG_H

/*
 * vw_oplog — append-only, segmented, crash-safe operation log.
 *
 * Serves two purposes:
 *   1. Crash recovery: replay uncommitted multi-table writes on server restart.
 *   2. Cluster replication: replicas pull entries from primary via OPLOG_PULL.
 *
 * On-disk entry format (all little-endian, packed, no padding):
 *   [uint32 crc32][uint32 payload_len][uint64 entry_id][uint8 confirmed][uint8 op_type][uint8... op_payload]
 *
 *   Offset  Size  Field
 *   0       4     crc32         (covers bytes 4..end of entry)
 *   4       4     payload_len   (= 1 + caller's payload_len; includes op_type byte)
 *   8       8     entry_id
 *   16      1     confirmed     (NOT CRC-covered; 0 = pending, 1 = committed)
 *   17      1     op_type
 *   18      N     op_payload    (N = payload_len - 1)
 *
 *   total entry size = 4 + 4 + 8 + 1 + payload_len = 17 + payload_len bytes
 *
 *   crc32 covers bytes 4..15 (payload_len + entry_id) plus the payload bytes:
 *     payload_len + entry_id + op_type + op_payload
 *
 *   The confirmed byte (offset 16) is intentionally excluded from the CRC so it
 *   can be updated in-place by vw_oplog_confirm() without CRC recalculation.
 *
 * Two-phase commit:
 *   vw_oplog_append() writes entries with confirmed=0.
 *   vw_oplog_confirm() seeks to the confirmed byte and writes 1.
 *   On crash recovery, seg_scan() truncates all unconfirmed tail entries.
 *   vw_oplog_replay_from() skips confirmed=0 entries (cluster replication).
 *
 * Segment files live in <data_dir>/oplog/.
 * Filename = first entry_id of the segment, zero-padded 16 hex digits: %016llx.log
 * A new segment is started when the current segment reaches VW_OPLOG_SEGMENT_MAX bytes.
 */

#include "../core/vw_proto.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum segment size before rotation (64 MiB). */
#ifndef VW_OPLOG_SEGMENT_MAX
#define VW_OPLOG_SEGMENT_MAX ((uint64_t)(64u * 1024u * 1024u))
#endif

/* ── Op types ──────────────────────────────────────────────────────────────── */

typedef enum {
    VW_OPLOG_USER_WRITE    = 0x01,  /* user record created/modified  */
    VW_OPLOG_FILE_WRITE    = 0x02,  /* file metadata created/modified */
    VW_OPLOG_FILE_DELETE   = 0x03,  /* file deleted                  */
    VW_OPLOG_PERM_WRITE    = 0x04,  /* permission record changed     */
    VW_OPLOG_SESSION_WRITE = 0x05,  /* session created/invalidated   */
    VW_OPLOG_CHUNK_WRITE   = 0x06,  /* chunk ref-count changed (GC)  */
} vw_oplog_op_t;

/* ── Opaque context ────────────────────────────────────────────────────────── */

typedef struct vw_oplog vw_oplog_t;

/* ── API ───────────────────────────────────────────────────────────────────── */

/*
 * Open or create the oplog under <data_dir>/oplog/.
 * On open, scans the latest segment to find the last entry with a valid CRC
 * (crash recovery). Any partial entry at the end is truncated.
 *
 * Returns VW_OK on success; *out_ctx is set to a heap-allocated context that
 * the caller must eventually pass to vw_oplog_close().
 */
vw_err_t vw_oplog_open(const char *data_dir, vw_oplog_t **out_ctx);

/*
 * Flush pending writes and close the oplog. Safe to call with NULL.
 * After this call *ctx is invalid.
 */
void vw_oplog_close(vw_oplog_t *ctx);

/*
 * Append one entry to the log.
 *
 *   op_type     : one of the VW_OPLOG_* constants
 *   payload     : op-specific bytes (does NOT include op_type itself)
 *   payload_len : byte length of payload; must be >= 1 (at least the op_type
 *                 byte is always written, so the on-disk payload_len field
 *                 stores payload_len + 1)
 *   out_entry_id: if non-NULL, receives the assigned monotonic entry_id
 *
 * The entry is written with confirmed=0. Callers MUST call either
 * vw_oplog_confirm() on success or vw_oplog_abort() on failure for every
 * entry_id returned, or the pending-confirm slot leaks permanently.
 *
 * Calls fdatasync / FlushFileBuffers after each append for crash durability.
 * Thread-safe (internally serialised by a mutex).
 */
vw_err_t vw_oplog_append(vw_oplog_t *ctx,
                          vw_oplog_op_t op_type,
                          const void *payload, uint32_t payload_len,
                          uint64_t *out_entry_id);

/*
 * Mark a previously appended entry as committed (two-phase commit).
 *
 *   entry_id: the ID returned by vw_oplog_append()
 *
 * Seeks to the confirmed byte of the entry in its segment file and writes 1,
 * then calls fdatasync / FlushFileBuffers. The entry must still be in the
 * pending-confirm set (i.e., this is the first confirm call for entry_id).
 *
 * After vw_oplog_confirm() returns VW_OK, the entry will survive crash
 * recovery and be visible to vw_oplog_replay_from(). If the server crashes
 * between vw_oplog_append() and vw_oplog_confirm(), the entry is truncated
 * on the next vw_oplog_open() and is not replayed.
 *
 * Thread-safe. Returns VW_ERR_NOT_FOUND if entry_id is not a pending entry.
 */
vw_err_t vw_oplog_confirm(vw_oplog_t *ctx, uint64_t entry_id);

/*
 * Abort a previously appended entry that was never committed (two-phase rollback).
 *
 *   entry_id: the ID returned by vw_oplog_append()
 *
 * Removes the entry from the pending-confirm set without touching the segment
 * file. The on-disk confirmed=0 entry becomes an inert hole: it is skipped by
 * vw_oplog_replay_from() and cleaned by seg_scan() on next open if it is the
 * last entry in the segment.
 *
 * MUST be called when the data-table write fails after vw_oplog_append()
 * succeeds. Failure to call either vw_oplog_confirm or vw_oplog_abort for
 * every appended entry will exhaust the pending-confirm slots (VW_OPLOG_MAX_PENDING)
 * and stall all subsequent appends.
 *
 * Thread-safe. Returns VW_ERR_NOT_FOUND if entry_id is not a pending entry.
 */
vw_err_t vw_oplog_abort(vw_oplog_t *ctx, uint64_t entry_id);

/*
 * Iterate entries starting at from_entry_id (inclusive) through the end of
 * the log, reading all segments whose last entry_id >= from_entry_id.
 *
 * For each valid entry the callback is invoked:
 *   entry_id   : monotonic ID of this entry
 *   op_type    : op type byte
 *   payload    : pointer to op-specific bytes (valid only during callback)
 *   payload_len: byte count of payload (not including op_type)
 *   userdata   : value passed to vw_oplog_replay_from()
 *
 * Callback return value: 0 = continue, non-zero = stop iteration (returns
 * VW_OK from vw_oplog_replay_from to the caller regardless).
 *
 * Entries before from_entry_id are skipped but the segments are still opened
 * (binary-level skip only — no callback).
 */
vw_err_t vw_oplog_replay_from(vw_oplog_t *ctx,
                               uint64_t from_entry_id,
                               int (*callback)(uint64_t entry_id,
                                               vw_oplog_op_t op_type,
                                               const void *payload,
                                               uint32_t payload_len,
                                               void *userdata),
                               void *userdata);

/*
 * Garbage-collect segments whose LAST entry_id is strictly less than
 * min_entry_id.  An entire segment is deleted only when every entry in it
 * precedes the cutoff (i.e. it has been consumed by all replicas).
 *
 * The active (write) segment is never deleted.
 */
vw_err_t vw_oplog_truncate_before(vw_oplog_t *ctx, uint64_t min_entry_id);

/*
 * Return the entry_id of the last successfully appended entry.
 * Returns 0 if the log is empty.
 */
uint64_t vw_oplog_last_entry_id(const vw_oplog_t *ctx);

/*
 * Read confirmed oplog entries with entry_id > from_entry_id, up to
 * max_entries entries.  Each entry is serialised as its raw on-disk bytes
 * (header + payload, confirmed byte set to 1) and concatenated into a single
 * heap-allocated buffer returned in *out_buf.  The caller must free *out_buf.
 *
 * *out_count receives the number of entries returned; *out_last_entry_id
 * receives the entry_id of the last entry in the buffer (0 if count == 0).
 *
 * Returns VW_OK; VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_oplog_read_range(vw_oplog_t *oplog,
                              uint64_t    from_entry_id,
                              uint32_t    max_entries,
                              uint8_t   **out_buf,
                              uint32_t   *out_count,
                              uint64_t   *out_last_entry_id);

/*
 * Append a pre-encoded oplog entry received from the primary.
 *
 *   entry_bytes / entry_len — raw on-disk bytes (header + payload).
 *   expected_entry_id       — the entry_id the caller expects to apply.
 *
 * - Verifies the CRC32 embedded in entry_bytes before applying.
 * - Returns VW_OK without applying if expected_entry_id <= last_entry_id
 *   (idempotent re-delivery after reconnect).
 * - Returns VW_ERR_PROTO_INVALID if: CRC mismatch, malformed entry, or
 *   expected_entry_id != next expected sequence number (gap detected).
 * - On success, the entry is written with confirmed=1 (pre-committed from
 *   primary) and fdatasync'd before VW_OK is returned.
 *
 * MUST NOT be called when cfg.is_replica == 0 (assert in implementation).
 */
vw_err_t vw_oplog_append_raw(vw_oplog_t    *oplog,
                              const uint8_t *entry_bytes,
                              uint32_t       entry_len,
                              uint64_t       expected_entry_id);

#ifdef __cplusplus
}
#endif

#endif /* VW_OPLOG_H */
