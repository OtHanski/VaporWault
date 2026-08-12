---
id:          TASK-132
title:       Implement gateway auth endpoints (login, 2FA, logout, resume)
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-131]
blocks:      [TASK-133, TASK-134, TASK-135, TASK-137]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, security-sensitive]
---

Wire the gateway's first real HTTP/JSON endpoints onto `vw_client_core`'s
existing connect/auth API (`src/client/vw_client_core.h`), using the
session manager from `TASK-131`.

Endpoints:

- `POST /api/login` — username + password → calls `vw_client_core`'s
  connect/`AUTH_REQUEST` equivalent; on `AUTH_CHALLENGE` (2FA enabled)
  return a challenge state to the browser rather than failing.
- `POST /api/login/otp` — OTP code → completes the 2FA round trip
  (`AUTH_OTP`/`AUTH_OK` per `docs/PROTOCOL.md` §8.3), on success creates a
  gateway session (`TASK-131`) and sets the session cookie.
- `POST /api/logout` — invalidates the gateway session and the underlying
  server session.
- Session-resume-on-reconnect handled transparently inside the session
  manager (`TASK-131`), not a separate browser-facing endpoint.

Password handling: the browser sends the raw password over HTTPS (nginx
terminates TLS) to `/api/login`; the gateway performs whatever client-side
stretching `vw_client_core`'s connect path already does before putting it
on the wire (matching what `vapourwault-cli`/`vapourwault-gui` do today) —
this task does not change the wire auth scheme itself (that's `TASK-009`'s
pre-existing, separately-tracked concern), only wires the existing client
path through HTTP.

## Acceptance criteria

- Full login flow (including 2FA challenge/response) works end-to-end
  against a real VaporWault server from an HTTP client (`curl`/integration
  test), producing a valid gateway session cookie.
- Failed login / wrong OTP returns a clean 401-class response, not a crash,
  and does not leak whether a username exists (matching the server's own
  enumeration-resistant design intent for `AUTH_FAIL`/recovery flows).
- Logout actually invalidates both the gateway session and the server-side
  session token (`AUTH_LOGOUT`) — a stolen gateway cookie after logout must
  not still work.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` per `CLAUDE.md`'s
routing rule for anything touching authentication.
