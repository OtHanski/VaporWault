---
id:          TASK-090
title:       "Real trash/recycle bin with a configurable retention window"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-24
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [server, storage]
---

Deletion is currently soft-delete-then-purge-on-next-GC-tick, not a real
recycle bin. Confirmed in `src/server/vw_store_files.c`
(`vw_store_file_soft_delete`, sets `deleted=1`, no timestamp field) and
`src/server/vw_gc.c` (`vw_gc_run_once` pass 3, scans all `deleted==1` files
every GC cycle and immediately hard-deletes the file, its versions, and
reclaims chunks). There is no grace-period field and no "restore a deleted
file" endpoint distinct from the existing version-restore mechanism
(`VERSION_RESTORE`, which restores content but doesn't undelete). A user who
deletes a file has whatever window `gc_interval_secs` happens to leave
(default 300s) before it's gone for good — effectively no meaningful
recycle bin.

## Acceptance criteria

- `vw_store_files.c`'s file record gains a `deleted_at` timestamp (set by
  `vw_store_file_soft_delete`).
- GC's pass 3 only hard-deletes files where `deleted_at` is older than a new
  configurable retention window (`server.conf` key, e.g.
  `trash_retention_days`, default TBD by SRV.01 — suggest something in the
  7-30 day range matching common product conventions).
- A restore-from-trash path exists (admin CLI command and/or client-facing,
  ARCH.00/SRV.01 to decide scope) that un-sets `deleted`/`deleted_at` for a
  file still within the retention window.
- Quota accounting during the retention window is decided explicitly (does
  a trashed file still count against the owner's quota until purged, or is
  it freed immediately? — document the choice, since it affects the
  soft-delete's usefulness as a safety net if users can't free quota by
  deleting).
- `docs/DEPLOYMENT.md` documents the new config key and default.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-24]: Filed after a feature-gap discussion; assigned to
SRV.01 (storage/GC is their domain). Not tagged `security-sensitive` — this
is a data-retention/reliability feature, not an auth/crypto/cross-user-access
concern, so only CQR.08 review is required per routing rule 2. Normal
priority.

SRV.01 [2026-07-29]: Implemented as scoped.
- `vw_file_record_t` (`vw_store.h`) gained `deleted_at` (int64_t) — reused
  the existing `_reserved[8]` padding bytes rather than growing the struct,
  so this is on-disk-layout-compatible with any file already deployed
  running `v0.1.0`: a pre-existing soft-deleted record simply reads back
  `deleted_at == 0`, which GC treats as "immediately eligible" (matching the
  old no-retention-window behavior for those specific records — no special
  migration needed).
- `vw_store_file_soft_delete` now sets `deleted_at = time(NULL)`.
- New `vw_store_file_restore()` (`vw_store_files.c`/`.h`) undoes a
  soft-delete. Had to bypass `vw_store_file_get_by_id` for the lookup — that
  function deliberately hides deleted records (returns NOT_FOUND), which is
  exactly the record restore needs to find — so it does its own raw
  slot-lookup instead, mirroring that function's internals minus the filter.
- **Found and fixed a bug this same change would have caused**:
  `vw_store_file_update` unconditionally zeroed the (formerly-reserved, now
  `deleted_at`) bytes on every write — since `soft_delete`/`restore` both go
  through `update` to persist, this would have silently discarded
  `deleted_at` immediately after setting it. Removed that zeroing (kept it
  for the genuinely-unused `_pad` bytes).
- `vw_gc.c`'s pass 3 (`collect_deleted_cb`) now skips files whose
  `now - deleted_at < trash_retention_secs`; a negative age (clock skew —
  `deleted_at` in the future) is treated as "still protected," erring
  toward not deleting on that anomaly.
- New `server.conf` key `trash_retention_days` (default 7 —
  `VW_GC_DEFAULT_TRASH_RETENTION_SECS` in `vw_gc.h`), converted to seconds
  into `vw_gc_cfg_t.trash_retention_secs`.
- New admin IPC messages/CLI commands: `list-deleted <username>` (scans
  trash for one user, needs a username→user_id lookup since the underlying
  scan has no owner filter) and `restore-file <file_id>`.
- **Quota decision (explicitly per acceptance criteria)**: left unchanged —
  a trashed file continues to count against its owner's quota until GC
  actually reclaims the chunks (`vw_storage_gc_run`, "Phase B" in
  `vw_gc_run_once`, already only runs after hard-delete). Kept as-is rather
  than freeing quota immediately on soft-delete: it's the existing behavior
  for every file today, and changing it would mean a user could delete
  their way past a quota limit and then restore into an over-quota state —
  simpler to leave quota accounting exactly where hard-delete already puts
  it.
- `docs/DEPLOYMENT.md`: documented the new config key, and added a
  "Recovering an accidentally deleted file (trash)" subsection under Backup
  and restore. Also fixed a pre-existing, unrelated doc bug noticed in the
  same table: `gc_interval_secs`'s documented default was `300`; the actual
  code default (`VW_GC_DEFAULT_INTERVAL_SECS`) is `1800`.

Added a proper regression test (not just manual validation) since this is a
data-safety feature: two new `VW_TEST_CASE`s in `tests/unit/test_vw_gc.c`
using the file_store/chunk_store the existing GC test scaffolding didn't
previously wire up — one confirms a freshly-deleted file survives a GC pass
under a 1-hour retention window (restore succeeds afterward), the other
confirms a file whose 1-second retention window has actually elapsed (real
`sleep(2)`, not a mocked clock — `deleted_at` uses the real wall clock, so
this was the simplest reliable way to test the "past window" path) gets
hard-deleted (restore then fails `NOT_FOUND`). Also fixed a pre-existing
latent issue while touching this file: `gc_stack_open`'s `vw_gc_cfg_t` was
never fully initialized (`trash_retention_secs` was uninitialized stack
memory) — harmless today since that stack never opens `file_store` so pass
3 never reads it, but fixed for hygiene.

Validated end-to-end via the real admin CLI too (WSL Ubuntu 24.04, real
server, not mocked): `list-deleted alice` returns an empty list cleanly for
a user with nothing in trash; `list-deleted nosuchuser` and
`restore-file 999` (nonexistent file_id) both return clean, correct errors
over the real admin IPC wire format. Full unit (9/9, including the 2 new
trash cases) + integration (2/2) suite passes.

CQR.08 [2026-07-29]: Reviewed the diff (on-disk compatibility claim, the
`vw_store_file_update` fix, the restore lookup duplication, GC retention
logic, admin wire format, and the two new tests). No blocking findings.
Confirmed the `_Static_assert(sizeof(vw_file_record_t) == 128)` still holds
and pre-existing records genuinely read back `deleted_at == 0`. Four
advisory items: (1) `vw_store_file_restore`'s duplicated slot-lookup should
have a comment noting it must stay in sync with `vw_store_file_get_by_id` if
that ever changes; (2) `handle_list_deleted`'s `size_t→uint32_t` length
truncation has no overflow guard, but this is a pre-existing pattern shared
with `handle_user_list`/`handle_cluster_status`, not new; (3) the
`sleep(2)`-based unit test is real-wall-clock-dependent and could be flaky
under heavy CI load; (4) a leftover stale `gc_interval_secs = 300` in
`docs/DEPLOYMENT.md`'s checklist (separate from the table entry already
fixed in this diff) — fixed immediately since it was trivial.

ARCH.00 [2026-07-29]: No blocking findings. Advisory items (1) and (2) are
accepted as-is (pre-existing patterns / low real-world risk); (3) — the
clock-dependent test — is minor tech debt worth a mention rather than its
own task; item (4) fixed directly. Closing — status: done.
