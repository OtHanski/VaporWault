---
id:          TASK-158
title:       GUI file browser: use FILE_LIST_RESP's new per-entry vault_id instead of the capped per-file IPC lookup
status:      todo
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
