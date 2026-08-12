---
id:          TASK-134
title:       Implement gateway sharing endpoints (grants, public links)
status:      done
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    normal
depends_on:  [TASK-127, TASK-131, TASK-132]
blocks:      [TASK-140]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, security-sensitive]
---

Map `vw_client_core.h`'s sharing surface (grant/revoke/list user-to-user
shares, create/revoke/list/access public links) onto gateway HTTP/JSON
endpoints, per the existing sharing model in `ARCHITECTURE.md`
("Sharing model", `TASK-088`) and `docs/PROTOCOL.md` §7.5/§7.10.

Public-link access (`LINK_ACCESS`) is a pre-auth, unauthenticated flow
server-side (establishes a scoped session bound to one `share_id`) — the
gateway needs a route that doesn't require an existing gateway session
cookie for redeeming a link, mirroring that. Treat a redeemed link's scoped
session the same way `TASK-131`'s session manager treats a normal login:
same session-pool slot type, same timeout/eviction behavior, just
originated differently.

## Acceptance criteria

- Grant/revoke/list a share, and create/revoke/list a public link, all work
  end-to-end through the gateway.
- A public link can be redeemed by a browser with **no** prior gateway
  session/cookie, establishing a scoped gateway session bound to that
  `share_id` exactly like the wire protocol's own `LINK_ACCESS` scoping.
- A revoked share/link is rejected on the scoped session's *next* request,
  not just at future redemption time — matching the server's own live-check
  behavior (`ARCHITECTURE.md`'s sharing-model note) rather than caching
  permission at gateway-session-creation time.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-11]: Implemented in `src/gateway/vw_gateway_api.c`:
`POST /api/shares/grant`, `/api/shares/revoke`, `/api/shares/list` (thin
wrappers over `vw_client_share_grant/_revoke/_list`), and
`/api/links/create`, `/api/links/revoke`, `/api/links/list`,
`/api/links/access` (over `vw_client_link_create/_revoke/_list/_access`).

`/api/links/access` is the one route besides `/api/login` that runs
without `require_session` — it decodes the browser's `link_token` (64 hex
chars → 32 raw bytes) and calls `vw_client_link_access` directly, then
registers the resulting scoped `vw_client_sess_t` in the same session pool
via `vw_gateway_session_create`, exactly like a normal login. This
satisfies the "same slot type, same timeout/eviction behavior" acceptance
criterion by construction — there is no separate code path for scoped
sessions, just a different way of obtaining the `vw_client_sess_t` handed
to the pool.

The "revoked on next request, not cached at redemption time" criterion is
also satisfied by construction: the gateway never stores or re-checks
permission itself anywhere — every file/share operation on a scoped
session round-trips to the server, which is the sole source of truth on
revocation, same as every other endpoint in this file.

`link_token` round-trips as lowercase hex (`vw_crypto_hex_encode`/
`_hex_decode`), consistent with this codebase's existing hex convention
(cookies, `TASK-131`) rather than introducing a base64 dependency for a
single 32-byte value.

Verified against the real gateway+server (not mocked), both users freshly
created for this test (`alice`/`bob`): alice grants bob VIEW access to a
folder, both `mode=0` (alice's own list) and `mode=1` (bob's "granted to
me" list) show it, alice revokes it, bob's next `mode=1` list shows
`revoked: true`. Separately: alice creates a public link, a completely
fresh `curl` session (no cookie jar reused) redeems it via
`/api/links/access`, the resulting scoped session can list the link's
root (empty, as expected) and correctly gets `403 forbidden` on a write
attempt (VIEW-only link) — the server's own permission check, not
anything the gateway enforces itself. Then, with that scoped session
still live, alice revokes the link and the *already-established* scoped
session's next request gets `401 auth_required` (see fix note below) —
this specifically exercises the "server re-checks live, not cached at
redemption" acceptance criterion, not just the happy-path revoke.

**A real bug surfaced during this verification, not a hypothetical**: the
first two times through this exact revoke-while-live-session sequence,
`/api/links/revoke` (and once, `/api/links/revoke` on a link with an
active reader) returned a generic `500 error` and evicted the *caller's*
(alice's) own gateway session — clearly wrong, since alice was the one
issuing a legitimate revoke on her own link, not the affected scoped
session. Root cause, found by bisecting with a temporary debug print
(removed before committing) then confirmed by reading
`src/server/vw_file_handlers.c`'s `handle_file_list`: when a scoped
session's `FILE_LIST` runs after its share/link has been revoked, the
server correctly sends `VW_ERR_AUTH_REQUIRED` — but this gateway's own
`send_file_op_error` (`TASK-133`'s helper, reused here) had no case for
that error and fell into the catch-all "unrecognized error → evict +
500" branch built for `TASK-155`. That catch-all is doing exactly what it
was designed to do (contain a possibly-broken connection), but
`VW_ERR_AUTH_REQUIRED` from a dead scope is a completely ordinary, expected
outcome, not a broken-connection signal, so it deserved its own case.
Fixed in `send_file_op_error` (`src/gateway/vw_gateway_api.c`): added an
explicit `VW_ERR_AUTH_REQUIRED` → `401 auth_required` case (still evicts
the session — it can never succeed again — but no longer reports a scary
generic error). Re-ran the full sequence after the fix: clean `401` on
the dead scoped session, and alice's own revoke calls no longer get
affected by it. **This is a real gateway-side bug this task introduced**
(the file-op error mapping was `TASK-133`'s, but every one of `TASK-134`'s
new handlers reuses it) — not evidence of a new server/protocol bug, and
not the same failure mode as `TASK-155` (that one is a wire-level buffer-
size desync; this one was just a missing switch case in translation
logic). No `TASK-155`-style connection desync was observed in any of this
task's testing.

Builds clean under both MSVC `/W4 /WX` (`build-gw-test`, Ninja) and GCC
(`build-gw-e2e`, WSL) after the fix.

Not verified: the frontend has no sharing/link UI yet (`TASK-140`) — this
task is backend-only per its own scope.

Moving to `review` — needs SEC.07 + CQR.08 sign-off; SEC.07 should pay
particular attention to `/api/links/access` being deliberately
unauthenticated by design (matches the wire protocol's own `LINK_ACCESS`,
not a gap), to the anti-enumeration behavior (unknown/revoked/expired
tokens all return the same `401 bad_credentials`, mirroring
`vw_client_link_access`'s own documented behavior), and to double-check
`send_file_op_error`'s full switch for any other "ordinary outcome"
`vw_err_t` values still falling into the evict-and-500 catch-all
unnecessarily.

SEC.07/CQR.08 [2026-08-12]: Reviewed alongside `TASK-133` (see that
task's note for the full pass over `vw_gateway_api.c`, including the
`send_file_op_error` switch-completeness check this task specifically
asked for — one more gap found there, `VW_ERR_VERSION_NOT_FOUND`, fixed
under `TASK-133`). This task's own endpoints (`handle_share_*`,
`handle_link_*`): the unauthenticated `/api/links/access` design and
anti-enumeration behavior (`401 bad_credentials` for unknown/revoked/
expired tokens alike) confirmed correct by direct code read of
`handle_link_access`. `expires_at`/`file_id_filter` are numeric fields
(`get_json_uint_field`), so `TASK-133`'s unterminated-buffer finding does
not apply to this task's own field handling. No blocking findings.
Sign-off: `SEC.07` + `CQR.08` requirements satisfied. Ready for `done`.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` since public link
tokens are effectively bearer credentials and this endpoint set has its own
unauthenticated entry point.
