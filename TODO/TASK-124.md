---
id:          TASK-124
title:       Wire oplog v17 timestamp + FILE_* discriminators into the audit log view
status:      done
assignee:    GUI.03
created_by:  PRT.04
created:     2026-08-04
priority:    normal
depends_on:  [TASK-123]
blocks:      []
review_by:   [CQR.08]
tags:        [gui, audit]
---

Once `TASK-123` (SRV.01) lands the server-side oplog v17 format from
`docs/PROTOCOL.md` §7.7, update `src/gui/server/views/vw_view_audit.cpp` /
`.h` (from `TASK-116`) to consume the new fields. This restores the
date/time filter deferred in `TASK-121` and the FILE_WRITE user-id
attribution removed as a workaround in `TASK-122`.

## Acceptance criteria

- `OPLOG_ENTRY_HDR` (`vw_view_audit.cpp:26`, currently `17u`) becomes `25u`;
  update the fixed offsets that follow it in `parse_audit_resp` (`confirmed`
  now at `[24]`, `op_type` at `[25]`, payload starts at `p + 25 + 1`) and
  read the new `ts_unix_ms` field at bytes `[16..23]` into a new
  `AuditEntry::ts_unix_ms` (or similar) field.
- Add a date/time-range filter UI control (the acceptance criterion
  deferred from `TASK-116`/filed as `TASK-121`) using the new timestamp,
  alongside the existing type/user/text filters in `render()`
  (`vw_view_audit.cpp:54`).
- Replace the single `VW_OPLOG_FILE_WRITE` branch in `parse_audit_resp`
  (`vw_view_audit.cpp:207-214`, the `ref_id=` workaround from `TASK-122`)
  with three branches for `VW_OPLOG_FILE_CREATE` / `VW_OPLOG_FILE_UPDATE` /
  `VW_OPLOG_FILE_VERSION`:
  - `FILE_CREATE`: restore `owner_id=` labeling and `has_subject = true`
    (matches `VW_OPLOG_USER_WRITE`'s existing pattern at line 188-193) —
    this is the capability TASK-122 flagged as lost.
  - `FILE_UPDATE` / `FILE_VERSION`: label `file_id=`, left unattributed
    (not a user/owner id) — same treatment `VW_OPLOG_FILE_DELETE` already
    gets at line 215-218.
- Update `op_type_name()` (line 28-40) and the `kTypeNames`/`kTypeValues`
  filter-dropdown arrays (line 76-84) to show the three new names instead
  of the single "File Write" entry.
- Update or remove the tooltip at line 100-104 explaining why FILE_WRITE
  was excluded from the user filter — it no longer applies to the create
  case once this lands.
- Existing CSV export (`export_csv`) should include the new timestamp
  column.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

PRT.04 [2026-08-04]: Filed alongside `TASK-123` once the v17 oplog format
was published in `docs/PROTOCOL.md` §7.7, resolving `TASK-121`/`TASK-122`'s
GUI-side follow-up. Depends on `TASK-123` since the new wire bytes must
exist before this can be implemented or tested end-to-end.

GUI.03 [2026-08-04]: Implemented.

- Field shipped as `ts_unix_secs`, not `ts_unix_ms` as this task originally
  said — see `TASK-123`'s SRV.01 note / `docs/PROTOCOL.md` §7.7's
  implementation note for why. `AuditEntry::ts_unix_secs` added.
- `OPLOG_ENTRY_HDR` (the private `17u` constant) removed entirely rather
  than bumped to `25u` — replaced every use with `vw_oplog.h`'s public
  `VW_OPLOG_ENTRY_HDR_BYTES`. This file was itself one of the divergent
  hardcoded copies SEC.07 flagged during the `TASK-121`/`TASK-122` review;
  keeping a private copy here even at the right value would have left the
  same class of bug latent for the next format change.
- `parse_audit_resp` updated: reads `ts_unix_secs` at `[16..23]`, `op_type`
  at `[VW_OPLOG_ENTRY_HDR_BYTES]` (25), payload at
  `p + VW_OPLOG_ENTRY_HDR_BYTES + 1`.
- `FILE_CREATE` branch added exactly as specified (restores `owner_id=`
  attribution + `has_subject = true`). `FILE_UPDATE`/`FILE_VERSION` share
  one branch (`file_id=`, unattributed) since they're identical for display
  purposes. Kept a defensive `VW_OPLOG_FILE_WRITE` branch (labeled "File
  Write (legacy)" in `op_type_name`) rather than deleting it — it's dead
  code under normal operation (no post-v17 write path emits 0x02) but
  costs nothing to keep as a fallback over the generic hex-dump branch.
- Date/time-range filter added as two text inputs ("From"/"To", local
  time, `YYYY-MM-DD [HH:MM[:SS]]`, empty = unbounded on that side),
  parsed with a small `parse_ts_local()` helper (`sscanf` + `mktime`).
  Also added a "Time" column to the results table (not just the filter —
  otherwise there'd be no way to see the timestamp being filtered on) and
  a Time column in CSV export, both via a shared `format_ts_local()`
  helper.
- `op_type_name()` and the `kTypeNames`/`kTypeValues` filter dropdown
  updated for the three new codes (10 entries total now, including "All
  types"). Tooltip on the user-id filter rewritten — File Create is now
  attributable, File Update/Version/Delete and Session Write are not.
- **Verified**: full local build (`build-msvc-105`, MSVC, `/W4 /WX`)
  succeeds for `vapourwault-server-gui.exe` with these changes (no
  warnings). No unit test harness exists for this GUI view (ImGui
  render-loop code isn't unit-testable without a display); correctness
  was verified by compiling and by re-reading `parse_audit_resp` against
  the exact byte offsets `test_vw_oplog.c`'s new `read_range` test asserts
  on in `TASK-123` (same offsets, same constant).

CQR.08 [2026-08-04]: Reviewed `TASK-123`+`TASK-124` together given how
tightly coupled the format and its consumers are. Confirmed: all five
hardcoded-header-size call sites found across the two tasks
(`vw_oplog.c`, `vw_cluster.c` ×2, `vw_file_handlers.c`, `vw_view_audit.cpp`)
now reference the single `VW_OPLOG_ENTRY_HDR_BYTES` constant; the
`vw_oplog_replay_from` callback signature change was propagated to every
implementation (`vw_oplog.c`, `vw_admin.c`, and three test/fuzz files) —
none were left on the old signature, which `/W4 /WX` would have caught
as a hard build failure had any been missed (confirmed by the clean full
build). No blocking findings. Sign off.

SEC.07 [2026-08-04]: Confirmed `vw_oplog_append_raw` still only copies
received bytes through (never re-derives `ts_unix_secs`) and that the
CRC computation correctly covers the new field on both the write and
verify paths — consistent with the `TASK-121` finding this was meant to
close. No blocking findings on the implementation. Sign off.

ARCH.00 [2026-08-04]: Review complete, no unresolved blocking findings on
either task. Marking `TASK-123` and `TASK-124` `done`.
