---
id:          TASK-144
title:       Security review pass — web gateway + browser client
status:      todo
assignee:    SEC.07
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-131, TASK-132, TASK-133, TASK-134, TASK-135, TASK-141]
blocks:      []
review_by:   [CQR.08]
tags:        [security-sensitive, gateway, web]
---

Dedicated review pass for the web gateway + browser client feature
(`TASK-127`), beyond the per-task `review_by` sign-offs each implementation
task already requires. This is the feature-level pass `CLAUDE.md`'s Step 6
calls for, matching the depth `TASK-089`'s design review and `TASK-085`'s
independent re-verification got for the vault feature.

Specific items to check, carried forward from `TASK-127`'s design and the
individual implementation tasks' own flagged risks:

1. **New externally-reachable attack surface**: the gateway's HTTP/JSON
   layer (`TASK-129`/`TASK-130`) is the first-ever HTTP-facing code in this
   project. Confirm the "trusts nginx as sole upstream" scoping assumption
   actually holds under adversarial input, not just well-formed nginx
   traffic (what happens if the gateway's loopback listener is reachable
   directly, bypassing nginx, by mistake or misconfiguration?).
2. **Session/auth handling** (`TASK-131`/`TASK-132`): cookie attributes
   (`Secure`/`HttpOnly`/`SameSite`), session fixation, logout actually
   invalidating both gateway and server sessions, multi-session isolation.
3. **XSS/CSRF**: filename rendering (`TASK-138`), public link token
   handling (`TASK-140`), and whether gateway state-changing endpoints need
   CSRF protection given cookie-based auth.
4. **Path traversal / cross-user access** (`TASK-133`/`TASK-134`): confirm
   the gateway introduces no new traversal vector on top of the server's
   existing owner-namespaced checks.
5. **Vault zero-knowledge boundary** (`TASK-135`/`TASK-141`): the single
   highest-stakes property in this feature — confirm by code inspection
   (not just `TASK-143`'s test) that no gateway code path can ever receive
   a passphrase or unwrapped key, and that the WASM Argon2id/AES-256-GCM
   implementation's nonce derivation matches the native client's scheme
   exactly (a mismatch would be a nonce-reuse vulnerability, not just a
   compatibility bug).
6. **Session-storage precedent** (`TASK-131`): confirm the gateway did not
   copy forward the client daemon's known gap (no real Windows ACL
   restriction on `session.tok`, `vw_daemon.c:246`) if it persists any
   credential/session material to disk.

Findings tagged `blocking` prevent any `TASK-128`–`TASK-141` task (or
`TASK-127` itself) from moving to `done`, per `CLAUDE.md`'s routing rules.

## Acceptance criteria

- Every item above explicitly addressed (confirmed sound, or a blocking/
  advisory finding filed) with reference to the specific code reviewed.
- All `blocking` findings resolved and re-verified before this task closes.
- Every resolved finding has a corresponding regression test filed against
  `TASK-143`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. This is the feature's dedicated security
review pass — expect it to run in parallel with, not strictly after, the
individual implementation tasks' own `review_by: [SEC.07, CQR.08]`
sign-offs, same as how `TASK-089`'s design review and the vault
implementation tasks overlapped in practice.
