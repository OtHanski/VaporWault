---
id:          TASK-096
title:       Sharing UI (share/unshare, link management, permission indicators)
status:      todo
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-095]
blocks:      []
review_by:   [CQR.08]
tags:        [gui]
---

Add GUI surfaces for the sharing feature designed in `TASK-088` /
`docs/PROTOCOL.md` §7.5, once CLI.02 (`TASK-095`) has published the client
library API. Per the GUI.03 constraint in `CLAUDE.md`, this consumes the
client library only — no protocol or socket code in this task.

Scope:

- Share/unshare dialog on a file or folder: pick a user, choose read or
  edit permission, optional expiry.
- Public link management: create link (with a clear "anyone with this link
  can access this item" disclosure per §7.10's disclosure requirement),
  copy-to-clipboard (shown once, matching the server never re-displaying
  the token), revoke, list active links with their permission/expiry.
- Permission indicators in the file browser: a shared-with-me item should
  be visually distinguishable from an owned item, and show its permission
  level (read vs. edit).
- "Shared with me" view, reflecting CLI.02's defined namespace for
  shared/incoming items.

## Acceptance criteria

- All flows above work against a real client + server (manual test, not
  just compiles).
- The public-link disclosure text is present and accurate (matches the
  actual security properties in §7.10 — do not overstate protection).
- Keyboard navigation and accessibility for the new dialogs, consistent
  with existing GUI.03 views.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-088`. Blocked on
`TASK-095` per the standing GUI.03 constraint — do not start until CLI.02's
client API for sharing is marked done.
