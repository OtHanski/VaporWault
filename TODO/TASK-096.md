---
id:          TASK-096
title:       Sharing UI (share/unshare, link management, permission indicators)
status:      todo
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-095, TASK-107, TASK-108]
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

ARCH.00 [2026-07-31]: `TASK-095` is done, but starting this task surfaced a
bigger gap: the GUI client has no working login (stub pointing at the CLI)
and its file browser has never called `FILE_LIST` at all (hardcoded
placeholder row). This task's own acceptance criteria ("all flows work
against a real client + server") are unreachable without both. Filed
`TASK-107` (login) and `TASK-108` (browser) as blocking prerequisites per
explicit user direction (fix those first, then layer sharing UI on top,
rather than building a sharing-only view disconnected from real
login/browsing). Added both to `depends_on`.

Scope note for whoever picks this up: `TASK-108`'s browser shows the
current user's own synced files only (local sync cache, same as
`vapourwault-cli ls`) — it is not a live remote browse of the whole server
tree, and it can never show items *shared with* the user, since those live
in someone else's path namespace and are only reachable by `file_id` (no
IPC message lists a folder's children by `file_id` — `FILE_LIST`'s wire
payload has no `file_id` field, per `TASK-095`'s own header comment on
`vw_client_file_list_by_id` being deliberately not provided). So: "shared
by me" can be shown as a badge on browser rows (cross-referenced against a
`SHARE_LIST`/`LINK_LIST` snapshot by `file_id`), but "Shared with me" must
be its own flat list view (`SHARE_LIST` mode=1) showing item metadata —
not a browsable tree, and with no way to descend into a shared *folder*'s
contents in this GUI without a further protocol extension (out of scope
here — note it as a disclosed limitation, not a silent gap, if it isn't
already tracked elsewhere).
