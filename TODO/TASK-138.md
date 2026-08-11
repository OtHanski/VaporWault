---
id:          TASK-138
title:       Frontend file browser view (list/stat/mkdir/move/delete)
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-133, TASK-136, TASK-137]
blocks:      [TASK-139, TASK-140, TASK-141]
review_by:   [SEC.07, CQR.08]
tags:        [web, security-sensitive]
---

Build the core file browser view against `TASK-133`'s list/stat/mkdir/
move/delete endpoints — the web equivalent of the ImGui GUI's
`vw_view_browser.cpp` (`src/gui/client/views/`), but this task is an
independent implementation, not a port (different stack, no shared code).

Scope: folder navigation, file list rendering, mkdir/move/delete actions,
basic error states (permission denied, not found).

Security note carried from `TASK-127`/`TASK-130`: this view renders
arbitrary user-controlled filenames and folder names directly into the DOM.
Every rendering path must escape/sanitize this content correctly (e.g. use
`textContent`, not `innerHTML`, for filenames) — a filename containing
`<script>` or similar is fully attacker-controlled input the moment
sharing/uploads from other users are in play (a shared folder can contain
files named by someone else).

## Acceptance criteria

- Folder navigation, listing, mkdir/move/delete all work end-to-end from a
  browser.
- A file or folder named with HTML/script-like characters
  (`<img src=x onerror=alert(1)>`, etc.) renders as inert text, not
  executable markup — verified by an explicit test case, not just visual
  inspection, since this is exactly the kind of bug that looks fine until
  someone deliberately tries it.
- Permission-denied and not-found states are shown clearly, not as a raw
  error dump.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` for the filename-
rendering XSS surface — this is a real risk unique to a browser frontend
that didn't exist for the ImGui GUI (ImGui text rendering isn't an HTML
injection vector).
