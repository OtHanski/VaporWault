---
id:          TASK-158
title:       "GUI file browser - use FILE_LIST_RESP's new per-entry vault_id instead of the capped per-file IPC lookup"
status:      done
assignee:    GUI.03
created_by:  PRT.04
created:     2026-08-12
priority:    low
depends_on:  [TASK-156]
blocks:      []
review_by:   [CQR.08]
tags:        [gui, client, vault]
---

`TASK-156` added a per-entry `vault_id` field to `FILE_LIST_RESP` (`docs/PROTOCOL.md`
revision 19) — `vw_client_file_entry_t.vault_id` is now populated directly
by `vw_client_file_list`/`_file_list_by_id`, with no extra round-trip.

`src/gui/client/views/vw_view_browser.cpp`'s `refresh_vault_badges` currently
works around the field's prior absence with a **capped** (`kMaxVaultLookups
= 200`), one-`VW_IPC_FILE_VAULT_ID`-round-trip-per-file loop over
`s_entries`, explicitly citing the now-outdated `docs/PROTOCOL.md` note as
the reason (see that function's own comment, `vw_view_browser.cpp` ~line
203). This was real, working evidence used to justify `TASK-156`'s own
wire-format reversal — closing the loop by having the GUI actually adopt
the new field is the natural follow-up, not required to consider
`TASK-156` itself done.

## Acceptance criteria

- `refresh_vault_badges` (or its replacement) populates `s_vault_ids`
  directly from each `DisplayRow`'s already-fetched `vault_id` (sourced
  from `vw_client_file_entry_t.vault_id` via the client library / IPC
  layer, whatever plumbing currently carries `FILE_LIST` results into
  `s_entries`) instead of issuing any per-file round trip.
- The `kMaxVaultLookups` cap is removed — every encrypted file in a
  listing shows its lock icon, not just the first 200.
- No behavior change for the encrypted-item indicator itself from the
  user's point of view (same icon, same "Decrypt & Download" menu item)
  — this is a plumbing simplification, not a UX change.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

PRT.04 [2026-08-12]: Filed while implementing `TASK-156` — GUI adoption
of the new field is GUI.03's domain, not this task's own scope, per
`CLAUDE.md`'s out-of-domain routing rule. Low priority: the existing
capped workaround still functions correctly for the common case (fewer
than 200 files in a listing), this is a cleanup/simplification, not a
bug fix.

GUI.03 [2026-08-13]: This task's premise ("the GUI's `s_entries` already
has a fetched `vault_id`, just wire it through") did not hold up once
traced end to end — `vw_view_browser.cpp`'s `s_entries` comes from
`VW_IPC_FILE_LIST_REQ`/`_RESP` against the daemon's **local sync cache**
(`vw_cache_list`, `vw_daemon.c`), not a live server `FILE_LIST` call. The
cache (`vw_cache_entry_t`, `vw_cache.h`) had no `vault_id` field at all —
`TASK-156`'s new wire field only reached as far as `vw_client_core.c`'s
`vw_file_entry_t`, which the sync engine (`vw_sync.c`) does consume
(`vw_client_file_list`/`_by_id`, `vw_client_file_stat`/`_by_id`) but was
dropping on the floor when copying into `srv_entry_t` / `vw_cache_entry_t`.
Closing this properly required plumbing `vault_id` through the whole
chain, not just the last hop:

- `vw_cache_entry_t` (`vw_cache.h`) gains a `vault_id` field. This is an
  on-disk format change (1088 → 1096 bytes/record, `_Static_assert`
  updated) — **not** a no-op struct edit. `vw_cache_open()`
  (`vw_cache.c`) previously computed `nslots = buf_len /
  sizeof(vw_cache_entry_t)` with no format-version guard at all; loading
  a pre-existing `cache.db` (written by a build before this change) under
  the new, larger record size would silently misalign every field past
  the point where the sizes diverge — a real decode-corruption bug, not
  hypothetical. Added a migration guard: if `buf_len` is not a multiple
  of the current record size but *is* a multiple of the pre-158 size
  (`VW_CACHE_ENTRY_SIZE_PRE_TASK158 = 1088`), the file is recognized as
  old-format and reset to a fresh guard-only `cache.db` instead of being
  misread. This is safe (not just convenient) because the cache is a
  fully disposable, rebuildable local index — confirmed by reading
  `vw_sync.c`'s `compute_actions`: every sync cycle re-walks the local
  filesystem and re-lists the server, and treats a missing cache entry
  exactly like a brand-new file (`VW_ERR_NOT_FOUND` → recreated from the
  fresh walk/listing). Losing a cache costs one extra reconciliation
  cycle, not data.
  - Verified per this session's standing discipline: added a regression
    test (`tests/unit/test_vw_sync.c`, "vw_cache_open: pre-TASK-158
    (1088-byte record) cache.db is safely reset, not misread" — writes a
    raw 1088-byte-record file with a fake path planted at the old
    record's path offset, opens it, asserts zero entries surface and the
    file gets rewritten to the current size). Stashed the migration-guard
    fix, rebuilt, reran: failed exactly as predicted (`n == 0` assertion
    failed, old bytes were being reinterpreted). Restored the fix,
    rebuilt, reran: passes.
- `srv_entry_t` (`vw_sync_internal.h`) and `srv_push()` (`vw_sync.c`) gain
  `vault_id`, sourced from `vw_file_entry_t.vault_id` — same struct
  `TASK-156` already populates from the wire.
- `vw_sync.c`'s `compute_actions()` (both the new-remote-file and
  updated-remote-file branches) and `update_cache_after_upload()` now
  copy `vault_id` into the cache entry alongside the `server_*` fields
  they already set from the same `vw_file_entry_t`/`srv_entry_t`.
- `VW_IPC_FILE_LIST_RESP`'s wire format (`vw_ipc.h`, `vw_daemon.c`'s
  encoder) gains a trailing `u64 vault_id` per entry. This is internal
  daemon↔client IPC (both ship from the same build), so no version
  negotiation is needed — but every existing decoder of this message had
  to be updated to consume the new 8 bytes and stay aligned with the next
  entry: `vapourwault-cli`'s `cmd_ls` (`vw_client_cli.c`) and
  `VwGuiIpc::file_list` (`vw_gui_ipc.cpp`/`.h`, which also gained the
  field on `VwGuiFileEntry`).
- `vw_view_browser.cpp`'s `refresh_vault_badges()` now reads
  `e.vault_id` straight off each already-fetched `VwGuiFileEntry` — no
  IPC call, no `kMaxVaultLookups` cap (acceptance criterion: every
  encrypted file in a listing shows its lock icon, not just the first
  200).
- Removed the now-fully-superseded per-file lookup this replaced:
  `VW_IPC_FILE_VAULT_ID_REQ`/`_RESP` (`vw_ipc.h`, `vw_daemon.c` handler),
  `VwGuiIpc::file_vault_id` (`vw_gui_ipc.h`/`.cpp`), and
  `ClientApp::ipc_file_vault_id` (`ClientApp.h`/`.cpp`) — confirmed dead
  (grepped for every reference before deleting; nothing else called it).

No behavior change to the encrypted-item indicator or "Decrypt &
Download" flow itself from the user's point of view, per this task's own
third acceptance criterion — same `s_vault_ids` map, same lookup at
render/download time, just populated without a round trip or a cap.

Built and passed on both configured trees: `build-msvc-105` (MSVC, GUI
target included) and `build-gw-e2e` (WSL/GCC). Full `ctest` suite green
on both (17/17 and 18/18 respectively) after this change, including the
new migration regression test.

CQR.08 [2026-08-13]: Self-review. Checked: (1) the on-disk format bump
is real and matches the `_Static_assert`, verified by building — an
earlier draft of this fix tried to reuse the old struct's alignment pad
without growing `sizeof()`, which is unsound (a `uint64_t` field can't be
placed at a non-8-byte-aligned offset by reordering C struct members; the
compiler would just re-pad around it) and was caught by literally
computing the resulting offsets, not just by inspection — corrected
before it reached a build. (2) Every consumer of
`VW_IPC_FILE_LIST_RESP`'s wire format was located via `grep` and updated
in the same change (`vapourwault-cli`, the GUI, the daemon encoder) —
none left silently reading a now-misaligned trailing field. (3) The
migration guard rewrites the on-disk file itself at open time (not just
the in-memory view), so a second reopen doesn't re-trigger the same
migration against untouched trailing bytes on disk. (4) Confirmed no
test hardcodes the old `1088` size or `sizeof(vw_cache_entry_t)` anywhere
in `tests/`. No blocking findings. `status: done`.
