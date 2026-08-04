---
id:          TASK-116
title:       Improve the server GUI's audit log view (filter, search, export)
status:      todo
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-04
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [gui, server]
---

Surfaced by a 2026-08-04 project-state review. `src/gui/server/views/
vw_view_audit.cpp` exists and displays the server's audit log, but is
read-only with no filtering, search, or export — it's a plain scrolling
view of whatever `AUDIT_QUERY` returns. For an admin trying to answer a
concrete question ("did user X download file Y last week", "what did this
share-link do before I revoked it") this is currently a manual scroll-and-
read exercise.

## Acceptance criteria

- Filter controls for at least: user, action/event type, and a date/time
  range — check what `AUDIT_QUERY`'s existing request payload
  (`src/core/vw_proto.h` / the admin protocol) already supports server-side
  before assuming new server plumbing is needed; prefer using what exists.
- A text search box for free-text matching against the visible log entries
  (client-side filter over the currently-loaded page is fine if the
  server-side query doesn't support it — don't block this on a protocol
  change unless genuinely necessary).
- An export action (CSV or plain text) for the currently-filtered view, so
  an admin can hand a slice of the log to someone else without screen-
  scraping.
- No change to the underlying `AUDIT_QUERY` wire contract unless a
  filter genuinely requires new server-side support — if it does, coordinate
  with PRT.04/SRV.01 on the protocol change rather than improvising a new
  message type unilaterally.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested.
Low priority — this is a UX improvement on an already-functional feature,
not a gap in core functionality.
