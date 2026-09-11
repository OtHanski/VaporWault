#ifndef VW_OPLOG_H
#define VW_OPLOG_H

/*
 * vw_oplog — append-only, segmented, crash-safe operation log.
 *
 * Serves two purposes:
 *   1. Crash recovery: replay uncommitted multi-table writes on server restart.
 *   2. Cluster replication: replicas pull entries from primary via OPLOG_PULL.
 *
 * On-disk entry format (all little-endian, packed, no padding) — protocol v17,
 * see docs/PROTOCOL.md §7.7 for the normative wire-level spec (this format is
 * also what AUDIT_RESP and OPLOG_DATA carry, since both serialise raw entry
 * bytes):
 *   [uint32 crc32][uint32 payload_len][uint64 entry_id][uint64 ts_unix_secs][uint8 confirmed][uint8 op_type][uint8... op_payload]
 *
 *   Offset  Size  Field
 *   0       4     crc32         (covers bytes 4..end of entry, excluding confirmed)
 *   4       4     payload_len   (= 1 + caller's payload_len; includes op_type byte)
 *   8       8     entry_id
 *   16      8     ts_unix_secs  (wall-clock append time; ADVISORY ONLY — never used
 *                                for ordering, dedup, GC cutoff, or any replication
 *                                decision; entry_id remains the sole authority for
 *                                those. Exists so AUDIT_RESP consumers can filter by
 *                                date/time.)
 *   24      1     confirmed     (NOT CRC-covered; 0 = pending, 1 = committed)
 *   25      1     op_type
 *   26      N     op_payload    (N = payload_len - 1)
 *
 *   total entry size = 4 + 4 + 8 + 8 + 1 + payload_len = VW_OPLOG_ENTRY_HDR_BYTES + payload_len bytes
 *
 *   crc32 covers bytes 4..23 (payload_len + entry_id + ts_unix_secs) plus the payload bytes:
 *     payload_len + entry_id + ts_unix_secs + op_type + op_payload
 *
 *   The confirmed byte (offset 24) is intentionally excluded from the CRC so it
 *   can be updated in-place by vw_oplog_confirm() without CRC recalculation.
 *
 *   ts_unix_secs is stamped exactly once, by vw_oplog_append() on the node
 *   where the entry originates (always the primary in a cluster).
 *   vw_oplog_append_raw() (a replica applying an entry received from the
 *   primary) does NOT re-derive it — the field rides through verbatim as part
 *   of the already-CRC-verified received bytes, so a given entry_id carries
 *   the same timestamp on every node regardless of clock skew.
 *
 *   Pre-v17 entries used a 17-byte header (no ts_unix_secs) and a single
 *   ambiguous VW_OPLOG_FILE_WRITE op_type — see that enumerator's comment
 *   below. This is a hard cutover: this code does not read pre-v17 segments;
 *   see docs/PROTOCOL.md §7.7's upgrade note for the required operator step
 *   (clear <data_dir>/oplog/ per node before starting the new binary).
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

/*
 * Fixed non-payload header size for the protocol-v17 entry format (see the
 * format comment above): crc32(4) + payload_len(4) + entry_id(8) +
 * ts_unix_secs(8) + confirmed(1) = 25 bytes. op_type/op_payload follow.
 *
 * Public so callers that must split a concatenated buffer of raw entries
 * into individual entries (AUDIT_RESP parsing in vw_view_audit.cpp;
 * OPLOG_DATA batch-splitting in vw_cluster.c) use this instead of each
 * hardcoding their own private copy of the header size — TASK-121/TASK-122's
 * v17 migration found three divergent hardcoded copies of the pre-v17 value,
 * one of which (vw_cluster.c) had been missed when the format first changed.
 */
#define VW_OPLOG_ENTRY_HDR_BYTES 25u

/* ── Op types ──────────────────────────────────────────────────────────────── */

typedef enum {
    VW_OPLOG_USER_WRITE    = 0x01,  /* user record created/modified  */
    VW_OPLOG_FILE_WRITE    = 0x02,  /* RETIRED as of protocol v17 (docs/PROTOCOL.md §7.7).
                                        Payload was a bare owner_id/file_id uint64 whose
                                        meaning depended on call site (create vs.
                                        rename/update vs. version-write) with no way for a
                                        reader to tell which — see TASK-122. Superseded by
                                        VW_OPLOG_FILE_CREATE/_UPDATE/_VERSION below. Do not
                                        reuse this value for a new op type and do not emit
                                        it from new code; kept defined only so old
                                        comments/history referencing 0x02 stay meaningful. */
    VW_OPLOG_FILE_DELETE   = 0x03,  /* file deleted                  */
    VW_OPLOG_PERM_WRITE    = 0x04,  /* permission record changed     */
    VW_OPLOG_SESSION_WRITE = 0x05,  /* session created/invalidated   */
    VW_OPLOG_CHUNK_WRITE   = 0x06,  /* chunk ref-count changed (GC)  */
    VW_OPLOG_VAULT_WRITE   = 0x07,  /* vault (TASK-098) registered   */
    VW_OPLOG_FILE_CREATE   = 0x08,  /* file created; payload = owner_id (uint64 LE)  */
    VW_OPLOG_FILE_UPDATE   = 0x09,  /* file renamed/metadata updated; payload = file_id (uint64 LE) */
    VW_OPLOG_FILE_VERSION  = 0x0A,  /* new file version written; payload = file_id (uint64 LE) */
    VW_OPLOG_VAULT_DELETE  = 0x0B,  /* vault (TASK-00277) deleted; payload = owner_id (uint64 LE).
                                        Deliberately a distinct op type from VW_OPLOG_VAULT_WRITE
                                        rather than reusing it for both create and delete — see
                                        VW_OPLOG_FILE_WRITE's own retirement above for why an
                                        ambiguous shared op type is the mistake this avoids. */
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
 *   entry_id     : monotonic ID of this entry
 *   op_type      : op type byte
 *   ts_unix_secs : wall-clock append time recorded for this entry (advisory
 *                  only — see vw_oplog.h's format comment); passed through
 *                  unchanged from the on-disk/received bytes
 *   payload      : pointer to op-specific bytes (valid only during callback)
 *   payload_len  : byte count of payload (not including op_type)
 *   userdata     : value passed to vw_oplog_replay_from()
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
                                               uint64_t ts_unix_secs,
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
 * TASK-208: returns non-zero if vw_oplog_open's recovery scan had to
 * truncate a corrupt/unconfirmed tail entry from the active segment —
 * i.e. the server did not shut down cleanly last time. Reflects the
 * state captured at open time; query once at startup. Always 0 for a
 * brand-new log (nothing to recover from).
 */
int vw_oplog_did_recover_from_crash(const vw_oplog_t *ctx);

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
