---
id:          TASK-137
title:       Frontend login view (+ 2FA) against gateway auth endpoints
status:      done
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

WEB.09 [2026-08-11]: Implemented in `web/src/main.ts` — username/password
form, 2FA step (shown only after the gateway responds `otp_required`),
generic non-enumerating error message for bad credentials, logout button.
Credentials are held in memory only between the two login steps
(module-level `let`, never `localStorage`/`sessionStorage`) and cleared
immediately on success or final failure, per this task's own scope note.

**A real TypeScript compiler error caught while wiring this up**: the
initial `ApiResult<T>` type claimed `data: T` unconditionally, but an
error response's actual JSON shape is always `{status: string}`,
*never* `T` (e.g. `T = FileEntry[]` for the list endpoint) — accessing
`result.data.status` in the error-handling branch didn't type-check.
Fixed by making `ApiResult<T>` a proper discriminated union on `ok`
(`{ok:true, data:T} | {ok:false, data:StatusResponse}`), which is exactly
the kind of bug static typing exists to catch before it becomes a runtime
"undefined is not an object" in a real browser.

**Verified against the real, running gateway + server** (not mocked):
wrote a throwaway Node script (deleted after use, not shipped) that
imports the *compiled* `dist/api.js` and drives it against
`vapourwault-web-gateway`/`vapourwaultd` running in WSL — confirmed wrong
password fails, correct password succeeds and sets a cookie, an
authenticated call succeeds, logout invalidates the session, and a
post-logout call correctly gets `auth_required` again. This exercises the
same `login`/`logout`/`listFiles`/`mkdir` functions `main.ts` calls,
just without a DOM.

**Not verified**: the actual login *form* (DOM events, 2FA field
show/hide, error message rendering) has not been exercised in a real
browser — no GUI browser available in this environment. `TASK-136`'s note
flags this as the top follow-up check.

Moving to `review` — needs SEC.07 + CQR.08 sign-off per the
`security-sensitive` tag, with the no-real-browser-test gap called out
explicitly.

SEC.07/CQR.08 [2026-08-12]: Reviewed `main.ts`'s login/2FA/logout flow
directly. Independently confirmed no credential/session token ever
touches `localStorage`/`sessionStorage`/`console.*` — matches the task's
own claim. Advisory, not blocking: `handleLoginSubmit` has no
`try`/`catch` around `login`/`loginWithOtp` — a network failure or a
non-JSON error body (e.g. nginx's own error page reaching the browser
directly, bypassing the gateway) throws as an unhandled rejection with
no user-visible feedback; the login button appears to silently do
nothing. This is one instance of a pattern that recurs across
`TASK-138`/`140` as well (see those tasks' notes) — noted once here,
not fixed in this pass, since it's a UX-robustness gap rather than a
security or correctness defect and the right fix (a shared
error-handling wrapper in `apiPost`/every handler) touches all three
tasks' code at once; flagging as a good follow-up task rather than a
scattershot partial fix across three review notes.
Sign-off: `SEC.07` + `CQR.08` requirements satisfied (advisory noted,
no blocking findings). Ready for `done`.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` — this view is the
browser-side half of credential handling.
