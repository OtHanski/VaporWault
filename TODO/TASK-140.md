---
id:          TASK-140
title:       Frontend version history + sharing/public-link management views
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    normal
depends_on:  [TASK-127, TASK-134, TASK-138]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [web, security-sensitive]
---

Build the remaining non-vault views: version history (list/restore against
`TASK-133`'s version endpoints) and sharing/public-link management (grant/
revoke/list shares, create/revoke/list public links, against `TASK-134`'s
endpoints).

Security note: public link tokens are effectively bearer credentials — a
link's full URL grants access to whatever it scopes. This view must not log
them, must not include them in analytics/error-reporting payloads if any
are ever added, and should give the user an explicit copy-link action
rather than displaying the raw token where it might be inadvertently
screenshotted/shared alongside unrelated content.

## Acceptance criteria

- Version list/restore works end-to-end from a browser.
- Share grant/revoke/list and public link create/revoke/list work
  end-to-end from a browser.
- Public link tokens are never written to browser console logs or any
  future telemetry hook.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` for the public-
link-token handling.
