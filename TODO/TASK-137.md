---
id:          TASK-137
title:       Frontend login view (+ 2FA) against gateway auth endpoints
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-132, TASK-136]
blocks:      [TASK-138]
review_by:   [SEC.07, CQR.08]
tags:        [web, security-sensitive]
---

Build the login view against `TASK-132`'s `/api/login`, `/api/login/otp`,
`/api/logout` endpoints, using `TASK-136`'s scaffold.

Scope:

- Username/password form → `/api/login`; on a 2FA challenge response, show
  an OTP entry step → `/api/login/otp`.
- Session persistence across page reloads (the gateway session cookie,
  `TASK-131`, should just work via the browser's normal cookie handling —
  confirm `Secure`/`HttpOnly`/`SameSite` attributes are set gateway-side in
  `TASK-131`/`TASK-132`, not left to the frontend to compensate for).
- Logout action.
- Clear, non-enumerating error states (wrong password vs. wrong OTP should
  not visibly differ in a way that reveals which factor failed, matching
  the server's own auth-failure design intent).

## Acceptance criteria

- Full login (including 2FA) and logout work from an actual browser against
  a running gateway + server.
- No credential or session token is ever written to `localStorage`/
  `sessionStorage`/logged to the console — the cookie set by the gateway is
  the only place session state lives client-side.
- Reloading the page keeps the user logged in until the session actually
  expires or they log out.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` — this view is the
browser-side half of credential handling.
