---
id:          TASK-176
title:       Gateway: read-only fallback to a replica
status:      done
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-14
priority:    normal
depends_on:  [TASK-172]
blocks:      [TASK-177, TASK-178]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, gateway]
---

Depends on `TASK-172`'s replica hot-standby. Same "opt-in read-only
fallback" idea as `TASK-173`, at the gateway level instead of per-account
(the gateway is one-process-one-server per `ARCHITECTURE.md`'s "Gateway
stays one-process-one-server" decision — there is no per-browser-account
scoping here, so this is a deployment-level flag, not a per-login one).

## Work

- New `main.c` flags: `--fallback-server-host`, `--fallback-server-port`,
  `--fallback-ca-cert` (all three or none, same validation convention as
  `TASK-174`). Optional — omit for today's unchanged behavior.
- Connection logic: `handle_login`/every `require_session`-gated handler's
  underlying `vw_client_connect`/session use currently target
  `cfg->server_host`/`server_port`/`ca_cert_pem_path` unconditionally.
  When the primary is unreachable and a fallback is configured, route new
  sessions (and resume attempts) to the fallback instead, and mark that
  session read-only in the gateway's own session pool
  (`vw_gateway_session.h`'s slot struct gains a flag) so every write
  endpoint (`files/mkdir`, `files/delete`, `files/move`, `files/commit`,
  `chunks/upload`, `shares/grant`, `shares/revoke`, `links/create`,
  `links/revoke`, `vault/create`) rejects cleanly (e.g. `503
  read_only_fallback`) instead of attempting a write against the
  fallback. There is no server-side "offline queue" concept at the
  gateway (unlike the daemon) — the browser frontend is responsible for
  telling the user to retry later, matching this project's existing
  "gateway has no persistent state of its own beyond `TASK-165`'s
  remember-me store" posture; do not invent one here.
- `/api/accounts`-style status: the frontend needs a way to know "this
  session is on the read-only fallback" so `TASK-166`'s existing
  switcher/status UI (or a follow-up) can show it — extend
  `/api/accounts`'s response shape or add a field to `STATUS`-equivalent
  responses rather than a whole new endpoint if the existing shape can
  carry it cleanly.

## Security note (`security-sensitive`)

Same second-trust-anchor reasoning as `TASK-173`'s security note, at the
gateway level — `--fallback-ca-cert` is mandatory whenever a fallback
host/port is set, never defaulted or optional, matching the existing
`--ca-cert` requirement's own enforcement in `main.c`.

## Acceptance criteria

- With no fallback configured: zero behavior change.
- With a fallback configured and the primary reachable: fallback is never
  used.
- With a fallback configured and the primary made unreachable: a browser
  session transparently continues to list/download from the fallback; a
  write attempt gets a clean, distinguishable error, not a crash or an
  attempted write against the fallback.
- Full `tests/integration/test_gateway.py` green with new coverage
  (`TASK-178`).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**WEB.09, 2026-08-14 — implementation complete.**

- `main.c`: `--fallback-server-host`/`--fallback-server-port`/
  `--fallback-ca-cert`, validated as a strict all-three-or-none unit
  (matching `TASK-174`'s CLI convention) before the gateway even starts.
  Startup log line now reports the fallback target when configured.
- `vw_gateway_server_cfg_t` (`vw_gateway_api.h`) gained the three fallback
  fields.
- Connection logic (`vw_gateway_api.c`): new `is_net_err`/
  `fallback_configured`/`build_client_cfg` helpers. `handle_login` and
  `handle_link_access` (anonymous public-link redemption) both retry
  against the fallback — using the SAME already-in-hand credentials —
  only on a network-shaped failure from the primary, never on
  2FA/bad-credentials (those mean the primary was actually reached).
  Unlike the daemon (`TASK-173`), the gateway needs no persisted
  "login token": every login request already carries the raw password
  for exactly this one retry, so there's nothing to retain between
  requests. `try_resume_and_reinsert` (remember-me) deliberately never
  attempts a fallback connect — a primary-issued resume token is
  meaningless against a different server, same reasoning `TASK-173`
  already established for the daemon; only a fresh login can fail over.
  A remember-me login that DOES fail over is intentionally never
  persisted to the on-disk store (and gets a session-only cookie, not
  the usual 30-day one) for the same reason — a fallback-issued token
  would just silently never resume.
- Session pool (`vw_gateway_session.h`/`.c`): `gateway_session_slot_t`
  gained a `read_only` int, set once at `vw_gateway_session_create()`
  time (a session's server identity never changes for its lifetime here,
  unlike the daemon's per-account state machine — there is no
  "keep probing the primary while on fallback" loop at the gateway, since
  the gateway has no background loop at all, only a request-driven accept
  loop). New `vw_gateway_session_is_read_only()` accessor.
  `vw_gateway_session_reinsert` (remember-me resume) intentionally
  untouched — every free slot is already zeroed by construction, so a
  reinserted session is always read_only=0, matching "resume never fails
  over" above.
- All 10 write endpoints the task lists (`files/mkdir`, `files/delete`,
  `files/move`, `files/commit`, `chunks/upload`, `shares/grant`,
  `shares/revoke`, `links/create`, `links/revoke`, `vault/create`) gained
  one `reject_if_read_only()` call each, immediately after
  `require_session()` succeeds — `503 read_only_fallback`, matching the
  task's own suggested status/code, before the request body is even
  parsed. No offline-queue was invented, per the task's own explicit
  instruction not to — this is a clean rejection, not a deferred write.
- `/api/accounts`'s existing per-slot response gained a `read_only`
  boolean field (extending the existing shape, not a new endpoint — per
  the task's own preference) so the frontend can show "read-only
  fallback" and explain disabled write actions, mirroring the daemon/
  GUI's own `conn_mode` surfacing (`TASK-173`/`175`). No frontend
  (TypeScript) work done here — reading this field is `TASK-166`'s
  follow-up territory (the switcher/status UI), not opened as a new task
  since it's explicitly out of this task's own listed scope.
- Wrote a genuine end-to-end proof
  (`tests/integration/test_gateway_fallback.py`) against a real paired
  primary+replica and a real gateway process: login while primary is
  healthy is never read-only; killing the primary makes the NEXT login
  fail over and read_only=true; reads (`files/list`) keep working; a
  write (`files/mkdir`) gets a clean `503 read_only_fallback` rather than
  reaching the replica. A second test confirms zero behavior change with
  no `--fallback-*` flags passed at all (this task's first acceptance
  criterion). Needed two small, backward-compatible test-infra additions
  to make this possible: `GatewayInstance` (`conftest.py`) gained an
  optional `fallback=` constructor param, and `ClusterNode`
  (`test_cluster.py`) gained a `.cert` attribute so it can be passed
  directly as that `fallback=` argument.
- Verified: `build-gw-e2e`/`build-gw-tests` both rebuilt clean; MSVC build
  of `vapourwault-web-gateway` clean; full `ctest` (19/19 WSL, 18/18
  MSVC); the full existing `test_gateway.py` suite (29/29, confirms the
  `vw_gateway_session_create` signature change didn't break any existing
  caller); the new fallback tests (2/2); the full non-cluster Python
  integration suite (95/95) for broader regressions.

**QA.06, 2026-08-17 — TASK-178 sign-off.**
`test_gateway_fallback.py::test_gateway_login_fails_over_to_read_only_fallback`
now also restarts the primary and confirms a fresh login resumes normal
(non-read-only) behavior — `read_only: false` again and a write (`mkdir`)
actually succeeds — closing the "confirm normal read-write resumes once
the primary is back" half this milestone's acceptance list called for
that wasn't originally exercised. Added
`test_gateway_refuses_to_start_without_fallback_ca_cert`, regression-testing
this task's own security note ("`--fallback-ca-cert` is mandatory ...
never defaulted or optional") — the gateway process must exit non-zero
immediately when a fallback host/port is set without a cert, not start
with verification silently deferred.
