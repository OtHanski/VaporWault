---
id:          TASK-123
title:       Implement oplog v17 entry format (append timestamp + FILE_WRITE split)
status:      done
assignee:    SRV.01
created_by:  PRT.04
created:     2026-08-04
priority:    normal
depends_on:  [TASK-121, TASK-122]
blocks:      [TASK-124]
review_by:   [SEC.07, CQR.08]
tags:        [server, oplog, security-sensitive]
---

Implement the oplog entry format change published in `docs/PROTOCOL.md` §7.7
("Oplog entry format (v17)"), resolving `TASK-121` (timestamp) and
`TASK-122` (FILE_WRITE disambiguation) together as one migration, per that
spec's suggestion.

New on-disk entry layout (see §7.7 for the full table):

```
[crc32(4)][payload_len(4)][entry_id(8)][ts_unix_ms(8)][confirmed(1)][op_type(1)][op_payload(N)]
```

Total entry size = `25 + payload_len` (was `17 + payload_len`).

## Acceptance criteria

- `src/server/vw_oplog.h`: update the file-header format comment to the new
  layout; add `VW_OPLOG_FILE_CREATE = 0x08`, `VW_OPLOG_FILE_UPDATE = 0x09`,
  `VW_OPLOG_FILE_VERSION = 0x0A` to `vw_oplog_op_t`; mark `VW_OPLOG_FILE_WRITE`
  (0x02) retired (comment only — do not delete the enumerator, other code/log
  archives may still reference the numeric value in comments/history). Also
  expose the entry header size as a public constant here (e.g.
  `VW_OPLOG_ENTRY_HDR_BYTES = 25`) — see the last bullet below for why.
- `src/server/vw_oplog.c`: currently defines three private constants at the
  top of the file — `ENTRY_HDR_SIZE` (17), `ENTRY_CONFIRMED_OFF` (16),
  `CRC_HEADER_BYTES` (12) — these become 25, 24, and 20 respectively.
  `vw_oplog_append()` additionally stamps `ts_unix_ms` (wall-clock write
  time) into the new header field. `vw_oplog_append_raw()` must **not**
  independently derive/overwrite `ts_unix_ms` — it already copies
  `entry_bytes` through verbatim (only forcing `confirmed=1`), so simply
  widening `ENTRY_HDR_SIZE`/`CRC_HEADER_BYTES` there is sufficient; the
  received `ts_unix_ms` rides through unchanged as part of the CRC-covered
  bytes already verified. `vw_oplog_replay_from` and `vw_oplog_read_range`
  (and the crash-recovery segment scanner, `seg_scan`) all key off these
  same constants and need no other changes once they're widened.
- `src/server/vw_store_files.c`: split the three `VW_OPLOG_FILE_WRITE`
  call sites into the new codes:
  - create path (currently ~line 471, payload `rec->owner_id`) →
    `VW_OPLOG_FILE_CREATE`
  - rename/update path (currently ~line 634, payload `file_id`) →
    `VW_OPLOG_FILE_UPDATE`
  - version-write path (currently ~line 801, payload `rec->file_id`) →
    `VW_OPLOG_FILE_VERSION`
- `src/server/vw_file_handlers.c` (`handle_audit_query`): update the
  request/response doc comment for the new entry size; no logic change
  expected since it serialises raw entry bytes already.
- **`src/server/vw_cluster.c`** (SEC.07 review finding, 2026-08-04 — do not
  skip this one): the replica-side `OPLOG_DATA` receive loop (around the
  `for (uint32_t i = 0; i < entry_count; i++)` block that calls
  `vw_oplog_append_raw`) independently hardcodes the pre-v17 header size
  twice — `if (remaining < 17u + 1u) ...` and
  `uint32_t entry_total = 17u + entry_plen;` — to split the concatenated
  batch buffer into individual entries before handing each to
  `vw_oplog_append_raw`. This is a **third, independent copy** of the
  header-size constant (alongside `vw_oplog.c` and `vw_view_audit.cpp`,
  below) and was missed in this task's first draft. Left at `17u`, it
  under-reads every entry by 8 bytes and desyncs the replica from the
  second entry in every batch onward — a real replication-correctness
  break, not just a doc gap. Update both literals to the new size (prefer
  referencing `VW_OPLOG_ENTRY_HDR_BYTES` from `vw_oplog.h` rather than a
  fourth hardcoded number).
- `src/gui/server/views/vw_view_audit.cpp` (`OPLOG_ENTRY_HDR = 17u`,
  `vw_view_audit.cpp:26`): also update to the new size — this is TASK-124's
  responsibility, but flagging here since it's the same constant-divergence
  bug class as the `vw_cluster.c` finding above and TASK-124 depends on
  this task landing first.
- Prefer having `vw_oplog.c`, `vw_cluster.c`, and `vw_view_audit.cpp` all
  reference the single public `VW_OPLOG_ENTRY_HDR_BYTES` constant from
  `vw_oplog.h` instead of each hardcoding their own private copy — three
  independently-maintained copies of the same magic number is exactly how
  the `vw_cluster.c` gap above went unnoticed until this review.
- Document the hard-cutover upgrade step (clear `<data_dir>/oplog/` per
  node — see §7.7) in `docs/RELEASE.md` if that document has an
  upgrade-steps section; otherwise note it in this task for BLD.05/ARCH.00
  awareness.
- Unit tests (mirroring the existing oplog test coverage from
  `TASK-114`/`TASK-115`) for: CRC still validates with the new field
  included, the append timestamp round-trips through append →
  read_range/replay, and each of the three new `FILE_*` codes is emitted
  from the correct call site. (Shipped as `ts_unix_secs`, not `ts_unix_ms`
  as drafted here — see the SRV.01 note below.)
- Do not start until `TASK-121` and `TASK-122` are `done` (spec is
  reviewed/approved by SEC.07 given `security-sensitive`) — the format
  could still change during that review.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

PRT.04 [2026-08-04]: Filed alongside publishing the v17 format spec in
`docs/PROTOCOL.md` §7.7 (`TASK-121`/`TASK-122`). Blocks `TASK-124` (GUI.03)
since the GUI needs the new fields to exist on the wire before it can
consume them.

SRV.01 [2026-08-04]: Implemented.

- **Field renamed `ts_unix_ms` → `ts_unix_secs`** (still 8 bytes, so no
  change to header size math). The codebase has zero precedent for a
  millisecond-precision clock anywhere (every existing timestamp —
  `mtime_unix`, session expiry, invite TTL — uses `time_t`/seconds via
  `time(NULL)`); adding a new cross-platform ms-clock helper for a
  date/time-range filter that doesn't need sub-second resolution would
  have been unjustified complexity. Updated `docs/PROTOCOL.md` §7.7 and
  `vw_oplog.h` to match — this is a naming/precision correction, not a
  layout change (still offset 16, still 8 bytes).
- `vw_oplog.h`: added `VW_OPLOG_ENTRY_HDR_BYTES = 25`, the three new
  `VW_OPLOG_FILE_*` op codes, retired-value comment on `VW_OPLOG_FILE_WRITE`,
  updated format doc comment. Also **widened the `vw_oplog_replay_from`
  callback signature** to add a `ts_unix_secs` parameter (inserted after
  `op_type`) — needed so `vw_oplog_read_range`'s rebuild-from-decoded-fields
  path (used by `AUDIT_RESP` and `OPLOG_DATA`) could preserve the original
  timestamp instead of losing it; the alternative (read_range re-deriving
  its own timestamp) would have silently broken the "same entry_id, same
  timestamp on every node" property the whole design rests on. Updated
  every callback implementation for the new signature: `vw_oplog.c`'s own
  `read_range_cb`, `vw_admin.c`'s `tail_cb` (ignores it — that admin-IPC
  frame format is unrelated to this task and unchanged),
  `tests/unit/test_vw_oplog.c`'s `replay_collect`, `tests/unit/test_vw_gc.c`'s
  `count_replay_cb`, and `tests/fuzz/fuzz_oplog_replay.c`'s `noop_cb` — the
  last two weren't in this task's original file list and would have failed
  to compile (`/W4 /WX` treats the signature mismatch as an error) had they
  been missed.
- `vw_oplog.c`: constants widened as specified (`ENTRY_HDR_SIZE` 17→25 via
  the new public constant, `ENTRY_CONFIRMED_OFF` 16→24, added `ENTRY_TS_OFF`
  =16, `CRC_HEADER_BYTES` 12→20). `vw_oplog_append` stamps `ts_unix_secs` via
  `time(NULL)`. `vw_oplog_append_raw` untouched beyond the constant widening
  — it already copied `entry_bytes` through verbatim, which is exactly the
  "preserve, don't re-stamp" behavior the spec requires. All literal `17`/`18`
  offsets replaced with the named constants.
- `vw_store_files.c`: the three call sites now use `VW_OPLOG_FILE_CREATE`/
  `_UPDATE`/`_VERSION` respectively, as specified.
- `vw_file_handlers.c`: doc comment updated. **Found and fixed a fourth
  hardcoded-header-size site this task's checklist missed**: the
  `entries_bytes`/`p` advance loop in `handle_audit_query` itself (walking
  `vw_oplog_read_range`'s output to size the `AUDIT_RESP` frame) hardcoded
  `17u`. Left alone, this would have undersized `entries_bytes` and
  corrupted `AUDIT_RESP` framing for every query once entries carried the
  new format. Now uses `VW_OPLOG_ENTRY_HDR_BYTES`.
- `vw_cluster.c`: fixed the replica-side batch-splitting loop's two `17u`
  literals as SEC.07 flagged on `TASK-121`/`TASK-122`. **Also found and
  fixed a fifth site**: the primary-side `entries_bytes` computation in the
  `OPLOG_PULL` handler (building the `OPLOG_DATA` payload from
  `vw_oplog_read_range`'s output) has the identical loop with the identical
  hardcoded `17u` — this task's checklist only called out the replica side.
  Both now use `VW_OPLOG_ENTRY_HDR_BYTES`.
- No changes needed to `docs/RELEASE.md` (confirmed it has no
  upgrade-steps section to extend) — the hard-cutover operator procedure
  lives in `docs/PROTOCOL.md` §7.7; noting here for BLD.05/ARCH.00
  awareness per this task's fallback instruction.
- Tests added to `tests/unit/test_vw_oplog.c`: `ts_unix_secs` stamped
  within an observed `[before, after]` window and delivered via
  `replay_from`; survives close/reopen; `read_range` output decodes the
  same value at the correct new offset with `confirmed=1` and the right
  `op_type`; all three new `FILE_*` codes round-trip as distinct values.
  Existing `replay_collect`/CJ-1..5 tests updated for the new callback
  signature and pass unchanged otherwise (some still use the retired
  `VW_OPLOG_FILE_WRITE` value as an arbitrary op_type for generic
  mechanism testing — harmless, that enumerator is kept defined
  specifically for this).
- **Verified**: full local build (`build-msvc-105`, MSVC, `/W4 /WX`) of
  `vw_server_lib`, `vapourwault-server-gui`, `vapourwaultd`,
  `vapourwault-server-cli`, and every unit test target succeeds clean.
  All unit test binaries pass (`test_vw_oplog` 158/158, `test_vw_gc`,
  `test_vw_file_handlers`, `test_vw_store`, `test_vw_share`, `test_vw_vault`,
  `test_vw_auth`, others) — no regressions. Integration test binaries
  (`test_shared_sync*`, `test_vault_e2ee*`) require a live server + args
  and weren't exercised here (unchanged by this task; no wire opcode
  changed, only the entries' internal byte layout).
