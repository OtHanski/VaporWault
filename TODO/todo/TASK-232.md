---
id:          TASK-232
title:       "Account/profile self-service UI (email, 2FA toggle, notify prefs)"
status:      todo
assignee:    MOB.10
created_by:  ARCH.00
created:     2026-08-31
priority:    normal
depends_on:  [TASK-226, TASK-229]
blocks:      []
review_by:   [CQR.08]
tags:        []
---

Surface the existing account self-service wire messages (already reachable
via `VwClient` per TASK-226: `ACCOUNT_EMAIL_GET`/`_SET`,
`ACCOUNT_2FA_SET`, `NOTIFY_PREFS_GET`/`_SET`) as a profile/settings screen —
no protocol work needed, every message type already exists and is exercised
by the desktop GUI and web frontend today.

## Acceptance criteria

- A user can view/change their account email, toggle 2FA on/off, and set
  per-category notification preferences, entirely through the UI.

## Notes
