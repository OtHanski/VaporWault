---
id:          TASK-231
title:       "Sharing + public-link management UI"
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

Surface the existing sharing/public-link wire messages (already reachable
via `VwClient` per TASK-226: `share_grant`/`_revoke`/`_list`,
`link_create`/`_revoke`/`_list`) in the UI, matching the feature parity the
web frontend already has (grant/revoke user shares, create/revoke/list
public links including password-protected and expiring links).

## Acceptance criteria

- A file/folder can be shared with another user and the grant later revoked,
  entirely through the UI.
- A public link (optionally password-protected, optionally expiring) can be
  created, listed, and revoked through the UI.

## Notes
