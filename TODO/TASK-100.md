---
id:          TASK-100
title:       Vault UI (setup wizard, passphrase prompts, encrypted indicators)
status:      todo
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-099]
blocks:      [TASK-101]
review_by:   [CQR.08]
tags:        [gui, crypto]
---

Add GUI surfaces for the E2EE feature designed in `TASK-089` /
`docs/PROTOCOL.md` §7.11, once CLI.02 (`TASK-099`) has published the client
vault API. Per the GUI.03 constraint in `CLAUDE.md`, this consumes the
client library only.

Scope:

- Vault setup wizard for opting a folder/file into encryption: prompt for
  an encryption passphrase, with a clear, prominent warning that this
  passphrase is separate from the account password, is never sent to the
  server, and that losing it means **permanent, unrecoverable** loss of
  that vault's files — do not soften this warning.
- New-device unlock prompt: when an encrypted vault is encountered without
  a locally-cached VK, prompt for the passphrase and call CLI.02's unlock
  flow.
- Encrypted-item indicators in the file browser (lock icon or similar) to
  distinguish encrypted content from plain content.
- Metadata-scope disclosure: somewhere reachable from the encryption UI
  (e.g. a tooltip or info panel), state plainly that filenames, folder
  structure, and file sizes are **not** encrypted and remain visible to the
  server — this is the same disclosure requirement flagged in §7.11.3 and
  must not be omitted or softened into implying full metadata protection.
- **Delta-sync/bandwidth tradeoff disclosure (SEC.07 advisory, ARCH.00
  sign-off, added 2026-07-29)**: the setup wizard must also disclose that
  encrypted files lose delta-sync — every edit to a file in a vault causes
  a full-file re-upload, since each version gets a fresh DEK (§7.11.5's
  "Accepted tradeoff"). Surface this near the passphrase warning, so a user
  encrypting a large, frequently-edited file (e.g. a database or VM image)
  makes an informed choice rather than discovering the bandwidth cost later.

## Acceptance criteria

- All flows above work against a real client + server.
- Passphrase-loss, metadata-scope, and delta-sync/bandwidth warnings are
  present, accurate, and not buried behind extra clicks.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-089`. Blocked on
`TASK-099` per the standing GUI.03 constraint.
