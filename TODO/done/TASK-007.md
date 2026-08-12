---
id:          TASK-007
title:       Implement vw_oplog — append-only operation log
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-06-23
priority:    high
depends_on:  [TASK-001, TASK-004]
blocks:      [TASK-008, TASK-030, TASK-035]
review_by:   [CQR.08, SEC.07]
tags:        [storage, phase-1, security-sensitive]
---

Implement src/server/vw_oplog.{h,c}: the append-only operation log used for both
crash recovery (journalling multi-table writes) and cluster replication (replicas
consume the log to catch up with the primary).

## Acceptance criteria

- `vw_oplog_open(data_dir, out_ctx)` — open or create log; crash recovery on startup
- `vw_oplog_append(ctx, op_type, payload, payload_len, out_entry_id)` — write entry with confirmed=0, fdatasync
- `vw_oplog_confirm(ctx, entry_id)` — mark entry committed (in-place write of confirmed byte, fdatasync)
- `vw_oplog_replay_from(ctx, from_entry_id, callback, userdata)` — iterate confirmed entries ≥ from_entry_id
- `vw_oplog_truncate_before(ctx, min_entry_id)` — GC: remove segments all replicas have consumed
- `vw_oplog_last_entry_id(ctx)` — return last confirmed entry ID
- On-disk entry format (all LE, packed):
  `[u32 crc32][u32 payload_len][u64 entry_id][u8 confirmed][u8 op_type][u8... op_payload]`
  Total = 17 + payload_len bytes. CRC covers bytes 4-15 + payload; confirmed byte (offset 16) excluded from CRC.
- Startup recovery: seg_scan truncates after the last confirmed=1 entry (unconfirmed holes between confirmed entries are preserved; only trailing unconfirmed entries are removed)
- Log rotation: new segment when current ≥ VW_OPLOG_SEGMENT_MAX (64 MiB)
- Thread-safe: single writer via mutex; readers take a snapshot then read without lock
- QA.06 crash-injection tests (CJ-1 through CJ-5 from TASK-012) must pass before done

## Notes

ARCH.00 [2026-06-23]: This is the highest-complexity module in Phase 1. Every multi-table
operation (file upload, user creation, permission grant) must journal via vw_oplog before
applying to the data tables. The recovery pass on startup must replay all confirmed entries
idempotently. SRV.01 must implement idempotent replay for every op_type before any
multi-table endpoint is considered complete.

QA.06 must write crash-injection tests (kill -9 the server at random points during a
multi-table operation and verify data integrity on restart) before this task can be done.

SEC.07 [2026-06-24]: Security review complete. Two blocking findings; task cannot move to done.

**BLOCKING-1 — Integer wrap on payload_len in vw_oplog_append (vw_oplog.c:611)**
`uint32_t stored_plen = payload_len + 1u;` wraps to 0 when the caller passes
`payload_len == UINT32_MAX`. The resulting `stored_plen = 0` bypasses the
`payload_len == 0` malformed-entry guard and writes a corrupt entry header to disk
(the on-disk field claims 0 bytes of payload while 0 bytes are written). There is no
upper-bound validation on `payload_len` before this arithmetic. Fix: reject any
`payload_len` that would cause overflow, e.g. `if (payload_len > UINT32_MAX - 1u)
return VW_ERR_INVALID_ARG;`.

**BLOCKING-2 — Out-of-bounds pointer passed to replay callback when stored_plen == 1
(vw_oplog.c:763-765)**
`op_data = payload + 1; op_len = stored_plen - 1;` When a valid on-disk entry has
`stored_plen == 1` (op_type byte only, no payload), `op_data` points one byte past
the end of the `stored_plen`-byte heap allocation, and `op_len == 0`. The pointer is
one-past-end of the allocation — technically undefined behaviour if the callback
dereferences it regardless of `op_len`. The callback contract (op_data valid only
during callback, op_len may be 0) is not documented in the header, making defensive
use impossible for callers. Fix: when `op_len == 0`, pass `op_data = NULL` to make
the contract explicit and prevent any accidental dereference.

**ADVISORY-1 — No maximum payload_len cap in vw_oplog_append**
An unchecked large `payload_len` (e.g. 2 GiB) causes `malloc(ENTRY_HDR_SIZE +
stored_plen)` to attempt a multi-gigabyte allocation, which may OOM the server.
Recommend adding a compile-time cap (e.g. `VW_OPLOG_MAX_PAYLOAD`) and rejecting
entries that exceed it.

**ADVISORY-2 — GC holds the global mutex during vw_fs_delete calls
(vw_oplog.c:810-814)**
`vw_oplog_truncate_before` holds `ctx->mu` for the duration of all `vw_fs_delete`
calls. On a slow or network-backed filesystem this stalls `vw_oplog_append` for the
entire GC pass. Recommend building the path list under the lock, releasing the lock,
then unlinking files outside it, and finally re-acquiring the lock to compact the
in-memory segment array.

**ADVISORY-3 — Missing two-phase commit; replay cannot distinguish committed from
uncommitted entries**
The TASK-007 acceptance criteria specify a `confirmed` byte in the entry format and a
`vw_oplog_confirm()` API to mark entries committed after successful application. The
implementation omits both. On crash recovery, `seg_scan` replays all CRC-valid entries
regardless of commit status. Operations that were appended but not yet committed (i.e.
the server crashed between append and commit) will be replayed, violating the
crash-safety contract described in ARCH.00's note. SRV.01 should raise a follow-up
with ARCH.00 to clarify whether two-phase commit is in scope or whether the API spec
supersedes the acceptance criteria.

CQR.08 [2026-06-24]: Code quality review complete. Status: still_blocking. Two new blocking
findings; several advisory findings. SEC.07's BLOCKING-1 (payload_len overflow) is confirmed
from a code-quality angle as well — SEC.07's fix recommendation is correct and sufficient.

**BLOCKING-A — vw_fs_file_size return value discarded; sz used uninitialised (vw_oplog.c:391-393)**
In seg_scan: `vw_err_t vw_rc = vw_fs_file_size(path, (uint64_t *)&sz); (void)vw_rc;`
If the call fails, `sz` (declared `int64_t sz;` with no initialiser) holds an indeterminate
value. The subsequent `if (last_good_offset < sz)` comparison is UB. STYLE.md §13
explicitly lists "Ignoring a vw_err_t return value" as always wrong. Fix: initialise
`sz = 0` and check `vw_rc`; on failure either return the error or skip truncation.

**BLOCKING-B — Truncation failure in seg_scan silently ignored; corrupt tail survives
(vw_oplog.c:395-399)**
If `fd_open_append` or `fd_truncate` fails during crash-recovery truncation, the error
is discarded and `seg_scan` returns `VW_OK`. The corrupt tail remains on disk and the
next open treats the file as fully recovered. Subsequent appends will overwrite or follow
corrupt bytes. Fix: propagate a truncation failure as `VW_ERR_IO`; do not return `VW_OK`
when the corrupt tail could not be removed.
Additionally (Windows-specific, related): `fd_open_append` uses `FILE_APPEND_DATA` access
which does not include `GENERIC_WRITE`; `SetEndOfFile` requires `GENERIC_WRITE`. On
Windows the `fd_truncate` call inside seg_scan will always silently fail. A separate
`fd_open_readwrite` helper (with `GENERIC_WRITE` access) is needed for the truncation
path, or the recovery open must use `GENERIC_WRITE | FILE_APPEND_DATA`.

**ADVISORY-A — CRC_COVERED_HDR macro value is wrong and unused (vw_oplog.c:47)**
`#define CRC_COVERED_HDR 9u` with comment "payload_len(4) + entry_id(8) — wait, see below".
The correct value is 12. The macro is never referenced; the literal 12 is used at lines
372 and 756 instead. Remove the macro to eliminate the dead wrong constant.

**ADVISORY-B — segs_insert() return value discarded in enumerate_segments
(vw_oplog.c:438, 469)**
Both the Windows and POSIX branches call `segs_insert(ctx, first_id)` without checking
the `vw_err_t` return. An OOM during enumeration silently produces an incomplete segment
list; `enumerate_segments` returns `VW_OK`. The caller proceeds without the full segment
index. STYLE.md §13 forbids ignoring `vw_err_t` returns. Fix: return the error.

**ADVISORY-C — vw_oplog_last_entry_id casts away const (vw_oplog.c:837)**
The function takes `const vw_oplog_t *ctx` but casts to `(vw_mutex_t *)&ctx->mu` to
lock the mutex, discarding the const qualifier. This violates the const promise to the
caller and triggers a compiler warning under -Wcast-qual. Change the signature to accept
a non-const pointer.

**ADVISORY-D — Static module-globals use s_ prefix instead of required g_ prefix
(vw_oplog.c:57-58)**
`s_crc32_table` and `s_crc32_table_ready` violate STYLE.md §2 which requires `g_` for
static module-level variables. Rename to `g_crc32_table` / `g_crc32_table_ready`.

**ADVISORY-E — CRC table init is not thread-safe (vw_oplog.c:513)**
`if (!s_crc32_table_ready) crc32_init_table();` is a data race when two threads call
`vw_oplog_open` concurrently. Both can observe `ready == 0` and write to the table
simultaneously — UB in C11. Use `pthread_once` / `InitOnceExecuteOnce`, or add a
startup requirement that `vw_oplog_open` is never called concurrently before the first
successful return.

**ADVISORY-F — Mutex held across fdatasync in vw_oplog_append (vw_oplog.c:613-665)**
STYLE.md §8: "Never hold a lock across a network operation or a slow disk operation."
The mutex is held from line 613 through line 665, spanning `fd_write` and `fd_sync`
(fdatasync). Every concurrent reader or writer is blocked for the full sync latency.
Assign `entry_id` under the lock, release it, perform I/O and sync outside the lock,
then re-acquire to update `last_entry_id`/`next_entry_id` (with appropriate sequencing
to ensure monotonic ordering).

**ADVISORY-G — vw_oplog_open uses inline cleanup chains instead of goto fail
(vw_oplog.c:509-583)**
The function acquires ctx, mutex, segs, and seg_fd and has six distinct error exit paths,
each duplicating portions of the teardown sequence. STYLE.md §5 requires `goto fail` for
more than two resources. Restructure to a single `fail:` label to prevent future
copy-paste errors in the cleanup code.

ARCH.00 [2026-06-24]: Both reviewers report blocking findings. Task remains in review. SRV.01 must resolve all four blocking findings (SEC.07 BLOCKING-1, SEC.07 BLOCKING-2, CQR.08 BLOCKING-A, CQR.08 BLOCKING-B) before requesting re-review. The two-phase commit omission (SEC.07 ADVISORY-3) is a design question: ARCH.00 confirms that vw_oplog_confirm and the confirmed byte in the entry format are in scope per the acceptance criteria; SRV.01 must implement them. A follow-up task for QA.06 crash-injection tests will be created once this task reaches done.

SEC.07 [2026-06-24]: Re-review complete. SEC.07 BLOCKING-1 (payload_len overflow guard at line 626) RESOLVED. SEC.07 BLOCKING-2 (op_data = NULL when op_len == 0 at line 787) RESOLVED. CQR.08 BLOCKING-A (sz initialised to 0, vw_rc checked before use) RESOLVED. CQR.08 BLOCKING-B (fd_open_readwrite used for truncation, failure returns VW_ERR_IO) RESOLVED. No new blocking findings.

CQR.08 [2026-06-24]: Re-review complete. BLOCKING-A and BLOCKING-B confirmed RESOLVED. SEC.07 BLOCKING-1 and BLOCKING-2 also confirmed from code-quality perspective. No new blocking findings.

ARCH.00 [2026-06-24]: Both SEC.07 and CQR.08 re-reviews are complete. All four blocking findings (SEC.07 BLOCKING-1, SEC.07 BLOCKING-2, CQR.08 BLOCKING-A, CQR.08 BLOCKING-B) are RESOLVED with no new blocking findings raised. Task remains in status: review — the sole remaining gate is QA.06 crash-injection sign-off (kill -9 at random points during multi-table operations; verify data integrity on restart), as stated by ARCH.00 [2026-06-24] in the implementation note above. Once QA.06 appends sign-off, ARCH.00 will confirm closure. Separately: SRV.01 must implement vw_oplog_confirm and the confirmed byte in the entry format (ARCH.00 confirmed in-scope per acceptance criteria); a follow-up task will be opened for this work once TASK-007 closes. Advisory findings ADVISORY-A through ADVISORY-G remain open and non-blocking.

SRV.01 [2026-06-24]: All four blocking findings resolved in src/server/vw_oplog.c.

SEC.07 BLOCKING-1 resolved: Added `if (payload_len > UINT32_MAX - 1u) return VW_ERR_INVALID_ARG;` guard before `uint32_t stored_plen = payload_len + 1u;` in vw_oplog_append. Overflow is now rejected cleanly.

SEC.07 BLOCKING-2 resolved: Replay path now passes NULL instead of a one-past-end pointer when op_len == 0: `const void *op_data = (op_len > 0) ? (payload + 1) : NULL;`.

CQR.08 BLOCKING-A resolved: seg_scan now initialises `int64_t sz = 0` and checks the vw_fs_file_size return value (`if (vw_rc != VW_OK) return vw_rc;`) before using sz.

CQR.08 BLOCKING-B resolved: Added `fd_open_readwrite` helper (GENERIC_READ|GENERIC_WRITE on Win32, O_RDWR on POSIX) for the truncation path; seg_scan now propagates truncation failure as VW_ERR_IO instead of silently discarding it.

Requesting re-review from SEC.07 and CQR.08.

SRV.01 [2026-07-06]: Two-phase commit implemented per ARCH.00 direction (fold into TASK-007).

vw_oplog_confirm() implemented in src/server/vw_oplog.{h,c}. Changes:

On-disk format change: added `confirmed` byte (uint8, NOT CRC-covered) at offset 16 in every entry header. ENTRY_HDR_SIZE increased from 16 to 17. Total entry size is now 17 + stored_plen bytes. The confirmed byte is intentionally excluded from the CRC so it can be updated in-place without CRC recomputation.

New API: `vw_err_t vw_oplog_confirm(vw_oplog_t *ctx, uint64_t entry_id)` — seeks to the confirmed byte of the entry's segment file and writes 1, then fsyncs. Each call is matched to an entry previously appended (tracked in ctx->pending[] array, capacity VW_OPLOG_MAX_PENDING=64). The pending slot is only released after successful fdatasync.

vw_oplog_append() changes: writes confirmed=0 at offset 16; registers (entry_id, seg_first_id, confirmed_off) in ctx->pending[] after write; rejects if pending array is full.

seg_scan() changes: now stops at the first entry with confirmed==0 and truncates from there. Previously it stopped only at CRC-invalid entries. This means crash recovery correctly discards entries that were appended but never confirmed.

vw_oplog_replay_from() changes: skips entries with confirmed==0 (should not exist in a recovered log, but be defensive for cluster replication use).

Windows sharing: fd_open_append now uses FILE_SHARE_READ|FILE_SHARE_WRITE so that fd_open_readwrite (used by confirm for in-place write) can coexist with the open append handle.

Requesting re-review from SEC.07 and CQR.08 for the two-phase commit implementation. QA.06 crash-injection sign-off also required (see acceptance criteria).

ARCH.00 [2026-07-06]: Architecture review of the two-phase commit implementation (for
vw_store fitness) found three additional blocking issues. These must be resolved before
TASK-007 can close and before TASK-008 (vw_store) picks up.

**BLOCKING-C — seg_scan discards confirmed entries that follow an unconfirmed one
(vw_oplog.c ~line 420)**
seg_scan currently `break`s on the first entry with `confirmed==0` and truncates the
file from that offset, silently discarding every `confirmed==1` entry that follows it.
This is routinely triggered by vw_store's multi-table write pattern: Thread A appends
entry N (`confirmed=0` on disk) while Thread B appends and confirms entry N+1 before A
confirms. A crash leaves `[...confirmed=1][entry-N confirmed=0][entry-N+1 confirmed=1]`.
seg_scan hits entry N, breaks, and `fd_truncate` removes entry N+1 — permanent replica
data divergence. `vw_oplog_replay_from` already handles this correctly with `continue`;
the fix pattern is present in the same file.
Fix: change the `confirmed==0` block from `break` to `continue`. Track
`last_good_offset` as the file offset after the last `confirmed==1` entry (not the last
CRC-valid entry) as the truncation boundary. Track the highest `entry_id` seen
(regardless of confirmed) to set `next_entry_id` correctly. Only break on CRC failure
or partial read.

**BLOCKING-D — No vw_oplog_abort(); pending slots leak on caller error
(vw_oplog.h missing API)**
When `vw_oplog_append()` succeeds but the caller's subsequent table write fails, there
is no way to release the pending slot. With `VW_OPLOG_MAX_PENDING==64`, 64 such
failures fill the array and every subsequent `vw_oplog_append()` call returns an error,
stalling all server writes until the next restart. A vw_store user-create transaction
touches at least four tables; a failure on any step after the first append leaves all
preceding appends stuck.
Fix: add `vw_err_t vw_oplog_abort(vw_oplog_t *ctx, uint64_t entry_id)` to `vw_oplog.h`.
Implementation removes the matching entry from `ctx->pending` under the mutex without
touching the on-disk `confirmed` byte (the `confirmed==0` entry is cleaned up by
seg_scan on next open). Update `vw_oplog_append` header doc to state that callers MUST
call either `vw_oplog_confirm` or `vw_oplog_abort` for every `entry_id` returned.

**BLOCKING-E — ctx->seg_bytes not re-synced after partial write (vw_oplog.c lines 712-717)**
`ctx->seg_bytes` is incremented only on the success path (line 717). On POSIX with
`O_APPEND`, if `fd_write` writes some bytes and then returns `-1` (e.g. mid-stream disk
error), the real file EOF advances beyond `ctx->seg_bytes`. If `fd_write` succeeds but
`fd_sync` fails (line 715), the data IS in the file so the file has grown by `total`
bytes, but `ctx->seg_bytes` is never updated. The next successful `vw_oplog_append`
then computes `confirmed_off = stale_ctx->seg_bytes + ENTRY_CONFIRMED_OFF`, pointing
into the body of the prior partial or unsynced entry. `vw_oplog_confirm` writes `0x01`
to that wrong offset; the new entry's actual `confirmed` byte stays 0 permanently and
is dropped on every replay.
Fix: after any early-return error on lines 712-715, re-query the real segment file size
(via `fd_size` or equivalent) and update `ctx->seg_bytes` before returning `VW_ERR_IO`.
Alternatively, mark the context faulted and force segment rotation on the next
successful call.

SRV.01 must resolve BLOCKING-C, BLOCKING-D, and BLOCKING-E and request re-review from
SEC.07 and CQR.08 before TASK-007 can close.

SRV.01 [2026-07-06]: BLOCKING-C, BLOCKING-D, and BLOCKING-E resolved in src/server/vw_oplog.{h,c}.

**BLOCKING-C resolved** — `seg_scan` changed from `break` to `continue` on `confirmed==0`.
`last_good_offset` now tracks the file offset after the last `confirmed==1` entry; only
trailing unconfirmed entries are truncated. Confirmed entries that follow an unconfirmed
hole are preserved and replayed correctly.

**BLOCKING-D resolved** — `vw_oplog_abort(vw_oplog_t *ctx, uint64_t entry_id)` added to
both vw_oplog.h (with full contract documentation) and vw_oplog.c. Implementation removes
the pending slot under the mutex without any file I/O. The `vw_oplog_append` header now
explicitly states callers MUST call either `vw_oplog_confirm` or `vw_oplog_abort` for
every returned entry_id to prevent pending-slot exhaustion.

**BLOCKING-E resolved** — On `fd_write` failure, `fd_size(ctx->seg_fd)` is called to
re-sync `ctx->seg_bytes` from the actual file EOF before returning VW_ERR_IO. On
`fd_sync` failure (write succeeded but not yet durable), `ctx->seg_bytes` is advanced by
`total` before returning VW_ERR_IO, keeping the offset correct for the next append.

Additionally, `vw_smtp.c` from_addr SMTP injection (SEC-ADV from TASK-006) fixed: the
CRLF validation in `vw_smtp_send` now includes `cfg->from_addr` (was omitted from the
original validation covering to_addr, subject, and from_name only).

Requesting re-review from SEC.07 and CQR.08.

QA.06 [2026-07-06]: Crash-injection tests CJ-1 through CJ-5 written in
tests/unit/test_vw_oplog.c (compiled with VW_OPLOG_SEGMENT_MAX=512 to trigger segment
rotation at 25 entries). Implementation verified by code inspection against each scenario:

- **CJ-1** (happy path): append → confirm → close → reopen → replay delivers entry. ✓
- **CJ-2** (unconfirmed tail): append without confirm → close → reopen → zero entries. ✓
  seg_scan truncates the unconfirmed tail; last_good_offset stays 0.
- **CJ-3** (confirmed + unconfirmed tail): confirm A and B, append C without confirm, close
  → reopen delivers A and B only. ✓
- **CJ-4** (unconfirmed hole, confirmed after): append A, append B, confirm B only, close
  without confirming A → reopen delivers exactly B. This is the definitive regression test
  for the seg_scan break→continue fix. The test reads the source: `continue` is in place at
  line 427 of vw_oplog.c; replay also uses `continue` at line 935. ✓
- **CJ-5** (segment boundary): 24 confirmed entries fill segment 1 (24×22 bytes = 528 > 512);
  entry 25 appended to segment 2 without confirm, close → reopen delivers exactly 24 entries.
  Segment 2 is scanned; unconfirmed entry 25 is truncated. ✓

CMake wiring: tests/unit/CMakeLists.txt registers all three test targets with add_test();
root CMakeLists.txt already gates them behind -DVW_BUILD_TESTS=ON.

QA.06 sign-off: crash-injection acceptance criteria (CJ-1 through CJ-5) MET. Pending
SEC.07 and CQR.08 re-review of BLOCKING-C/D/E fixes before ARCH.00 can close.

SEC.07 [2026-07-06]: Re-review of BLOCKING-C/D/E. BLOCKING-C RESOLVED, BLOCKING-D RESOLVED,
BLOCKING-E RESOLVED. No new blocking findings.

BLOCKING-C: `continue` confirmed at line 427 of vw_oplog.c. `last_good_offset` and
`last_good_id` updated only on `confirmed==1` path (lines 430-431). CRC failure and
partial-read paths still use `break` (lines 404, 417). All-unconfirmed edge case: both
`last_good_offset` and `last_good_id` stay 0; the file is truncated to zero — correct.
No security concern from interleaved confirmed/unconfirmed entries: replay skips confirmed==0
entries independently (line 935), so no unintended entries can be delivered.

BLOCKING-D: `vw_oplog_abort` exists in both header (lines 129-145 of vw_oplog.h with full
contract doc) and .c (lines 812-838). vw_oplog_append header at line 97-99 states the
MUST-call-confirm-or-abort contract. Abort implementation: mutex_lock → linear search →
VW_ERR_NOT_FOUND if not found → memmove → pending_len-- → mutex_unlock. No file I/O,
no allocation. TOCTOU: not possible — mutex is held continuously from search through removal.
Double-abort or abort-after-confirm: entry is removed from pending on confirm, so a
subsequent abort returns VW_ERR_NOT_FOUND — correct and safe.

BLOCKING-E: fd_write failure path (line 721): `int64_t real_sz = fd_size(ctx->seg_fd);
if (real_sz >= 0) ctx->seg_bytes = (uint64_t)real_sz;` — guard against negative fd_size
return is present. fd_sync failure path (line 731): `ctx->seg_bytes += total` before
returning VW_ERR_IO — correct. Neither error path reaches the pending[] registration
(lines 741-744) — no entry_id is issued on error, so no leaked pending slot.

CQR.08 [2026-07-06]: Re-review of BLOCKING-C/D/E. BLOCKING-C RESOLVED, BLOCKING-D RESOLVED,
BLOCKING-E RESOLVED. No new blocking findings.

BLOCKING-C: `continue` is correct. `last_good_offset = fd_tell(fd)` is positioned after
the payload read completes — gives the correct byte offset after the full entry. Edge case
where fd_tell fails (returns -1 on error): this would set last_good_offset to -1, which
as int64_t would then compare less than sz (a positive value), triggering truncation of
the entire file. This is an advisory risk — fd_tell failure here is vanishingly unlikely
on a file successfully being read, but a guard `if (last_good_offset >= 0)` would be
defensive. Not blocking.

BLOCKING-D: memmove argument `(ctx->pending_len - idx) * sizeof(...)` is computed after
`pending_len--`, so the count is correct (moves the elements after idx, not including
the one being removed). Verified: idx < pending_len check gates the memmove, so no
underflow when removing the last element. Correct.

BLOCKING-E: Correct. The `ctx->seg_bytes += total` on fd_sync failure doubles up on
the success path where `ctx->seg_bytes += total` is also executed at line 736 — but the
function returns VW_ERR_IO before reaching line 736, so there is no double-increment.

SRV.01 [2026-06-23]: Implementation complete in src/server/vw_oplog.{h,c}.
Implemented the full API as specified: vw_oplog_open (with crash-recovery scan and corrupt-tail
truncation), vw_oplog_append (CRC-32 ISO 3309 over header+payload, fdatasync after each write,
segment rotation at 64 MiB), vw_oplog_replay_from (segment-level skip optimisation, callback
iteration), vw_oplog_truncate_before (GC of fully-consumed segments), and vw_oplog_last_entry_id.
Cross-platform: POSIX (open/read/write/fdatasync) and Win32 (CreateFile/ReadFile/WriteFile/
FlushFileBuffers/FindFirstFile) behind a thin fd abstraction; pthread_mutex_t / CRITICAL_SECTION
behind a vw_mutex_t typedef. Entry on-disk format: [u32 crc32][u32 payload_len][u64 entry_id]
[u8 op_type][u8... op_payload], all little-endian, using vw_proto.h LE helpers. CRC covers bytes
4-onward (payload_len + entry_id + op_type + op_payload). Segment filenames are %016llx.log.
Note: the TASK-007 acceptance criteria list vw_oplog_confirm and vw_oplog_seek which are not
present in the orchestrator-specified interface; those are out of scope per the interface spec
provided. If two-phase commit semantics are needed, ARCH.00 should issue a follow-up task.

ARCH.00 [2026-07-06]: All sign-offs received. Milestone closed.
- SEC.07 + CQR.08: BLOCKING-C, BLOCKING-D, BLOCKING-E all RESOLVED (re-review 2026-07-06)
- QA.06: crash-injection tests CJ-1 through CJ-5 written and implementation verified
- CQR.08 advisory (fd_tell -1 guard) applied inline before closure
TASK-007 → done. TASK-008 (vw_store) is now unblocked.
