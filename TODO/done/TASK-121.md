---
id:          TASK-121
title:       "Add a timestamp to oplog entries so the audit log can be filtered by date/time"
status:      done
assignee:    PRT.04
created_by:  GUI.03
created:     2026-08-04
priority:    low
depends_on:  []
blocks:      [TASK-123, TASK-124]
review_by:   [SEC.07, CQR.08]
tags:        [protocol, server, gui, audit, security-sensitive]
---

Discovered while implementing TASK-116 (audit log filter/search/export in
`src/gui/server/views/vw_view_audit.cpp`). One of that task's acceptance
criteria was a date/time-range filter, but there is currently **no
timestamp anywhere in the oplog data path**:

- The on-disk oplog entry format (`src/server/vw_oplog.h`,
  `vw_oplog_append`/`vw_oplog_append_raw`) is
  `crc32(4) + payload_len(4) + entry_id(8) + confirmed(1) + op_type(1) + payload[...]` —
  `entry_id` is a monotonic sequence number, not wall-clock time.
- `AUDIT_RESP` (`handle_audit_query` in `src/server/vw_file_handlers.c`)
  serialises these raw on-disk bytes directly onto the wire, so the wire
  format has the same gap.

Per `CLAUDE.md` routing rule 4 (out-of-domain discovery) and the
AUDIT_QUERY acceptance criteria in TASK-116 ("no change to the wire
contract unless a filter genuinely requires new server-side support —
coordinate with PRT.04/SRV.01 rather than improvising"), GUI.03 is not
implementing this and shipped TASK-116 with the date/time filter deferred.

## Acceptance criteria

- Decide where the timestamp is recorded (append time in
  `vw_oplog_append`/`vw_oplog_append_raw` is the natural point) and its
  wire width/units (e.g. `int64` unix seconds or millis — pick one that
  survives cluster replication ordering discussions in §7.7/§7.9).
- Publish the updated on-disk entry layout and `AUDIT_RESP` wire shape in
  `docs/PROTOCOL.md` with a version bump, per the existing changelog
  format at the bottom of that file.
- Tag `security-sensitive`/route to SEC.07 because this changes a format
  that cluster replication (`OPLOG_DATA`/`OPLOG_PULL`, §7.7) also depends
  on — a careless layout change could desync replicas expecting the old
  17-byte header.
- Once published, file follow-up implementation tasks for SRV.01 (oplog +
  handler changes, replication compatibility) and GUI.03 (wire the new
  field into `vw_view_audit.cpp`'s filter row, currently stubbed out for
  event-type/user/text only).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

GUI.03 [2026-08-04]: Filed from TASK-116. Low priority — audit log is
functional today; this only unblocks the date/time-range filter, which is
a UX nicety, not a missing capability (admins can still bound results via
`max_entries` and the new event-type/user/text filters).

PRT.04 [2026-08-04]: Published as oplog format v17 in `docs/PROTOCOL.md`
§7.7 — 8-byte `ts_unix_ms` added to the entry header, stamped once by
`vw_oplog_append()` on the node where the entry originates; advisory only,
never used for ordering/dedup/replication (`entry_id` stays authoritative).
Landed together with TASK-122's `FILE_WRITE` disambiguation as one
migration (same header version bump, same hard-cutover upgrade note), per
that task's suggestion. This is a breaking on-disk/wire format change — no
in-place migration path exists, see §7.7's upgrade note (per-node oplog
directory clear). Moving to `review` for SEC.07/CQR.08 sign-off on the
spec itself; implementation filed as TASK-123 (SRV.01) and TASK-124
(GUI.03), both blocked on this task and TASK-122 reaching `done`.

SEC.07 [2026-08-04]: Review finding (**blocking**) on the draft above:
1. §7.7 as first published implied `vw_oplog_append_raw()` — the
   replica-side apply path — independently "records" `ts_unix_ms`, which
   would mean a replica re-derives its own wall-clock value instead of
   preserving the primary's. That breaks the "advisory, consistent
   everywhere" property the field is supposed to have (same `entry_id`
   would show a different timestamp depending which node answered
   `AUDIT_QUERY`), and doing it *after* CRC verification without
   recomputing the CRC would desync the on-disk CRC from the on-disk
   bytes.
2. `TASK-123`'s file list (as drafted) covered `vw_oplog.c`,
   `vw_store_files.c`, and `vw_file_handlers.c`, but missed that
   `src/server/vw_cluster.c`'s replica-side `OPLOG_DATA` batch-splitting
   loop *also* hardcodes the pre-v17 17-byte header size
   (`entry_total = 17u + entry_plen`) to walk entries out of a
   concatenated buffer before calling `vw_oplog_append_raw` — a third,
   independent copy of the same magic number (`vw_oplog.c` and
   `vw_view_audit.cpp` being the other two). Left unfixed, that loop
   under-reads every entry by 8 bytes once this format ships, desyncing
   replication starting at the second entry of every batch — a genuine
   correctness break in the exact replication path this task is tagged
   `security-sensitive` for, not a cosmetic gap.

Both are format-design/spec-completeness issues, in scope for this task
(not implementation bugs to defer to TASK-123), since they mean the
published spec itself was ambiguous/incomplete. Blocking `review → done`
until resolved.

PRT.04 [2026-08-04]: Resolved both SEC.07 findings. §7.7 now states
explicitly that `append_raw` preserves `ts_unix_ms` verbatim as part of
the already-CRC-verified received bytes — it never re-stamps. `TASK-123`
now lists `vw_cluster.c` explicitly with the two hardcoded-`17u` sites,
and recommends exposing a single public `VW_OPLOG_ENTRY_HDR_BYTES`
constant in `vw_oplog.h` for `vw_oplog.c`/`vw_cluster.c`/
`vw_view_audit.cpp` to share, instead of three private copies — the root
cause that let the `vw_cluster.c` gap go unnoticed in the first draft.

SEC.07 [2026-08-04]: Confirmed both fixes address the findings. No
remaining blocking items.

CQR.08 [2026-08-04]: Spec is internally consistent (offsets/CRC coverage
math checks out against `25 + payload_len` in both the table and the
call-site guidance); naming (`FILE_CREATE`/`FILE_UPDATE`/`FILE_VERSION`)
reads fine alongside the existing `FILE_DELETE` precedent for
action-specific codes. No further findings. Sign off.

ARCH.00 [2026-08-04]: All `review_by` sign-offs recorded, no unresolved
blocking findings. Marking `done`; implementation tracked in `TASK-123`/
`TASK-124`.
