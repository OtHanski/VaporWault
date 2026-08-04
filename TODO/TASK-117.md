---
id:          TASK-117
title:       Server runs single-threaded on Windows (thread pool unimplemented)
status:      todo
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-08-04
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, windows, security-sensitive]
---

Surfaced by a 2026-08-04 project-state review. `src/server/vw_server_main.c`
implements a real worker thread pool for the Linux accept loop, but the
Windows path is explicitly single-threaded:

```
841:#else   /* Windows — single-threaded (thread pool not implemented) */
842:    vw_log(LOG_INFO, "VaporWault server listening on %s:%u (single-threaded)",
```

Windows is one of only two supported server/client platforms (macOS is
explicitly deferred — see project memory, do not fold macOS scope into this
task). A single slow, stalled, or malicious client connection on Windows
blocks every other client for the duration — a real availability gap, not
just a performance one, on a platform this project claims to support in
production. Tagged `security-sensitive` because an unauthenticated or
low-effort client that simply holds a connection open (or triggers a slow
code path) becomes a trivial single-client denial-of-service against every
other user on that server.

## Acceptance criteria

- A real worker thread pool (or equivalent concurrency mechanism —
  IOCP-based async I/O is also a legitimate Windows-idiomatic alternative
  to a literal thread-per-connection pool; SRV.01's call which fits better
  given the existing accept-loop structure) for the Windows build, bringing
  it to functional parity with the Linux path's concurrency model.
- Confirm behavior under concurrent load: N simultaneous slow/blocked
  clients on Windows must not stall an (N+1)th client's unrelated request,
  mirroring whatever guarantee the Linux thread pool already provides.
- No regression to existing Windows CI unit-test coverage; ideally this
  also closes part of the gap noted in TASK-118-adjacent findings that
  Windows CI doesn't run the integration suite — even a manual concurrent-
  connection smoke test run by SRV.01/QA.06 during review is better than
  none, given CI won't catch it there yet.
- Update `docs/DEPLOYMENT.md` / any capacity-planning guidance that
  currently assumes or documents the single-threaded Windows limitation, if
  any exists.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested.
Priority high — this is a real availability/DoS-shaped gap on a currently-
supported platform, not a speculative nice-to-have.
