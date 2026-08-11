---
id:          TASK-131
title:       Implement gateway session manager (per-browser vw_client_sess_t pool)
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-129, TASK-130]
blocks:      [TASK-132]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, security-sensitive]
---

Unlike `vapourwault-daemon` (one server session for one desktop user), the
web gateway is a genuine multi-user, multi-session process: every logged-in
browser tab needs its own live `vw_client_sess_t` (`src/client/vw_client_core.h`)
connected to the VaporWault server. This task builds that session manager
(new `src/gateway/vw_gateway_session.{h,c}`) — nothing like it exists in the
codebase today.

Scope:

1. A gateway-issued session identifier (random, `vw_crypto`'s CSPRNG,
   `src/core/vw_crypto.{h,c}`) handed to the browser as an HTTP cookie,
   distinct from the underlying `vw_client_core` `session_token[32]` — the
   browser must never see the raw server session token directly.
2. A concurrency-safe map from gateway session ID → live `vw_client_sess_t`
   (+ its own `SESSION_RESUME` token for reconnecting to the server if the
   TCP connection drops).
3. Idle timeout and explicit logout, calling `vw_client_core`'s
   `AUTH_LOGOUT` equivalent (`vw_client_core.h`) and freeing the slot.
4. **A mandatory hard cap on the number of live sessions** (`ARCHITECTURE.md`'s
   Gateway session model decision, hardened during `TASK-127`'s SEC.07
   review — this is a requirement, not a tunable nice-to-have) plus an
   eviction policy (e.g. oldest-idle-first) for when the cap is reached, so
   one gateway process can't be trivially exhausted by opening unbounded
   sessions — this is a real DoS vector unique to the gateway (a shared,
   multi-user process), unlike `vapourwault-daemon` which only ever holds
   one session for one desktop user.
5. Explicitly decide gateway-side session-identifier storage (in-memory
   only vs. persisted for gateway-restart survival) — do **not** default to
   copying the client daemon's `session.tok` file scheme
   (`vw_daemon.c:219-256`) without addressing its known gaps: no real ACL
   restriction on Windows despite a comment claiming one (`vw_daemon.c:246`),
   and no OS keychain integration anywhere. If persisting anything gateway-
   side, this task must actually fix the Windows ACL gap, not carry it
   forward into a richer, more attractive multi-user target — flagged as a
   specific `TASK-144` review item.

## Acceptance criteria

- Two simultaneous browser sessions against the same gateway process are
  fully isolated — one session's actions never affect or leak into another
  (verified by `TASK-143`'s multi-session concurrency test).
- Gateway session cookie is a distinct value from the underlying server
  `session_token`; the raw server token never round-trips to the browser.
- Idle sessions expire and release their `vw_client_sess_t`; explicit logout
  works.
- If any credential/session material is persisted to disk, file permissions
  are actually restrictive on both POSIX and Windows (not just POSIX,
  matching the daemon's known gap) — call out explicitly in the PR/review
  how this was verified on Windows, not just assumed from POSIX behavior.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` — session/auth
state management is exactly SEC.07's "authentication and session
management review" remit. This is the task most likely to need real design
back-and-forth with SEC.07 before implementation, similar to how `TASK-099`
(vault client module) was flagged as highest-risk in the vault feature.
