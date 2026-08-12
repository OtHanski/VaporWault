---
id:          TASK-159
title:       Web gateway file listing: use FILE_LIST_RESP's new per-entry vault_id instead of the folder-level workaround
status:      todo
assignee:    WEB.09
created_by:  PRT.04
created:     2026-08-12
priority:    low
depends_on:  [TASK-156]
blocks:      []
review_by:   [CQR.08]
tags:        [gateway, web, vault]
---

`TASK-156` added a per-entry `vault_id` field to `FILE_LIST_RESP` (`docs/PROTOCOL.md`
revision 19) — `vw_client_file_entry_t.vault_id` is now populated directly
by `vw_client_file_list`/`_file_list_by_id`, with no extra round-trip.

`TASK-141`'s note records that `web/`'s file browser keys its lock-icon
display off "is the containing folder a registered vault"
(`main.ts`'s `currentFolderVaultId`) rather than a real per-entry field,
specifically because `FILE_LIST_RESP` didn't carry one at the time —
correct for anything the web client itself uploaded into a vault folder,
but with acknowledged limits for anything else. That gap can now close:
`src/gateway/vw_gateway_api.c`'s file-list handler already forwards
`vw_client_file_entry_t` fields into its JSON response; `entry.vault_id`
is one more field to include, and `web/src/main.ts` can switch from the
folder-level inference to the real per-entry value.

## Acceptance criteria

- The gateway's `/api/files/list` JSON response includes a real per-entry
  `vault_id` (hex or decimal, consistent with this codebase's existing
  convention for other id-shaped fields in this endpoint set).
- `web/src/main.ts`'s lock-icon rendering uses the per-entry field
  directly instead of `currentFolderVaultId` inference.
- `TASK-141`'s documented limitation (a vault-encrypted file whose
  containing folder isn't itself the registered vault entry point,
  however that can arise) no longer applies — verify with a case the
  old inference would have gotten wrong, not just the common case it
  already handled correctly.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

PRT.04 [2026-08-12]: Filed while implementing `TASK-156` — gateway/
frontend adoption of the new field is WEB.09's domain, not this task's
own scope, per `CLAUDE.md`'s out-of-domain routing rule. Low priority:
the existing folder-level inference is correct for every case this
project's own upload path can produce today.
