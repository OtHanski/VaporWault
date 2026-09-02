---
id:          TASK-237
title:       "Server never handles AUTH_LOGOUT — session token not invalidated on logout"
status:      todo
assignee:    SRV.01
created_by:  MOB.10
created:     2026-09-02
priority:    normal
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive]
---

Discovered while running TASK-225's Android runtime smoke test (out-of-domain
find, filed here per `CLAUDE.md`'s routing rule 4 rather than fixed in that
task): the server logged `WARN unhandled msg type 0x0107` when the Android
client sent `AUTH_LOGOUT` on its way out.

Checked the current source, not just the test binary — this is real and
current, not stale-binary noise. `vw_client_logout()`
(`src/client/vw_client_core.c:297`) has always sent `AUTH_LOGOUT` on every
client (CLI, daemon, gateway, and now Android), but `vw_server_core.c`'s
dispatch (~line 972-975) only ever handles `VW_MSG_AUTH_REQUEST` and
`VW_MSG_SESSION_RESUME` — there is no case for `VW_MSG_AUTH_LOGOUT`
anywhere in `src/server/`.

Practical effect: a client-initiated "log out" never actually invalidates
the session token server-side. The token simply sits in the sessions table
until it naturally expires (`expires_at`) — anyone who captured that token
before logout (a shared/compromised device, a proxy log, etc.) can keep
using it for the remainder of its natural lifetime, "log out" notwithstanding.
This is exactly the kind of thing §7.1's other invariants (single-use
resume tokens, no username-existence leak, timing-normalized auth failures)
were designed to avoid leaving open.

## Acceptance criteria

- Server dispatch handles `VW_MSG_AUTH_LOGOUT`: invalidates the session
  (matching whatever `vw_auth.c` already uses for expiry/revocation — reuse
  that mechanism, don't invent a second one) so the token is rejected by any
  subsequent request, including a still-open connection using it.
- No response payload is expected (matches the client's fire-and-forget
  send); confirm this against `docs/PROTOCOL.md` §7.1 and update the spec if
  it doesn't already document the server-side behavior precisely.
- Regression test: log out, then attempt a request with the old
  session_token (on a fresh connection, since the original connection is
  usually already closing) — must fail with `VW_ERR_AUTH_SESSION_EXPIRED`
  (or an equally explicit rejection), not succeed.

## Notes

- MOB.10, 2026-09-02: Filed while verifying TASK-225's Android
  connect+login smoke test — not investigated further, this is SRV.01's
  domain per the routing rules.
