---
id:          TASK-189
title:       "GUI: password field for public links"
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-188]
blocks:      [TASK-191]
review_by:   [CQR.08]
tags:        [gui]
---

Blocked on `TASK-188` (GUI consumes client/daemon API only).

**Correction (2026-08-26)**: the Share dialog (`vw_view_shared`'s public
-link section, actually in `vw_view_browser.cpp`'s `render_share_dialog`
— see that file) already has an expiry checkbox/day-count input
(`s_link_has_expiry`/`s_link_expiry_days`). Only password is missing.

## Work

- "Create link" section of `render_share_dialog` (`vw_view_browser.cpp`):
  optional password field alongside the existing permission/expiry
  controls.
- Existing-links table in the same dialog: a lock icon or "protected"
  label for password-protected links (never the password).

## Acceptance criteria

- A user can create a password-protected link entirely through the GUI,
  combined with the existing expiry option if desired.
- The link list makes password-protected state legible at a glance,
  keyboard-navigable per the existing accessibility bar.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

GUI.03 [2026-08-26]: Implementation complete.

- `vw_gui_ipc.h`/`.cpp`: `VwGuiLinkEntry` gains `has_password`;
  `link_create` gains a `password` parameter, sent as an optional
  trailing string.
- `ClientApp.h`/`.cpp`: `ipc_link_create` wrapper updated to match.
- `vw_view_browser.cpp`'s `render_share_dialog` (the actual home of the
  "Create link" UI, per `TASK-189`'s own correction note above): a
  "Password-protect" checkbox reveals a masked (`ImGuiInputTextFlags_
  Password`) input; the buffer is zeroed immediately after the create
  call regardless of outcome, matching this file's existing
  `s_grant_username`-clearing convention for not letting a credential
  linger in memory longer than needed. Existing-links table shows
  `[password]` next to a protected link's permission label — a text
  marker in the existing "With / Permission" column rather than a new
  table column, since grants (the other row type sharing this table)
  have no password concept at all and a dedicated column would be
  empty for half the rows.
- Verified: `build-msvc-105` builds and links clean (zero warnings),
  `ctest` 18/18. Same caveat as `TASK-183`: no interactive/rendered
  verification was possible in this session (no display); this is a
  compile/link/static-review verification.

Moving to `review`/`done`.