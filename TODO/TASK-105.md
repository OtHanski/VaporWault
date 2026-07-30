---
id:          TASK-105
title:       Server silently hangs (no error, no close) on an unexpected message type after auth instead of responding with an error
status:      todo
assignee:    SRV.01
created_by:  SRV.01
created:     2026-07-30
priority:    low
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, bug, robustness]
---

Discovered while writing `tests/integration/test_sharing.py` for `TASK-094`
(a test bug on my side surfaced this — sending a second `AUTH_REQUEST` on
an already-authenticated connection — but the server's actual behavior in
response is the real, independently-worth-filing finding).

In `vw_server_main.c`'s per-connection loop (the one that runs after
`vw_server_conn_handle` completes the auth phase):

```c
for (;;) {
    vw_err_t err = vw_proto_recv(conn, &type, buf, VW_MAX_MSG_BYTES, &plen);
    if (err == VW_ERR_NET_CLOSED) break;
    if (err != VW_OK) { ...; break; }

    err = vw_server_dispatch_file_op(sctx, conn, type, buf, plen);
    if (err == VW_ERR_AUTH_REQUIRED || err == VW_ERR_PROTO_INVALID) break;
    if (err == VW_ERR_NOT_IMPL)
        vw_log(LOG_WARN, "unhandled msg type 0x%04x", (unsigned)type);
}
```

`vw_server_dispatch_file_op`'s default case for any message type it
doesn't recognize (including every pre-auth-phase type re-sent after
auth — `AUTH_REQUEST`, `SESSION_RESUME`, `INVITE_REDEEM`, `LINK_ACCESS` —
none of which are handled post-auth) returns `VW_ERR_NOT_IMPL` **without
ever calling `send_error`**. The loop above logs a warning and just calls
`vw_proto_recv` again, waiting for the *next* message. The client, having
sent a message it expects a specific response to, gets nothing at all —
not an error, not a close — until its own read timeout fires (120s in the
authenticated phase per this same file). A single confused or buggy client
message ties up a worker thread for up to that full timeout window with
zero feedback to the caller about what went wrong, which is also just a
confusing client-side experience (a hang looks identical to a slow server,
not a protocol violation).

## Acceptance criteria

- An unrecognized/misplaced message type on an authenticated connection
  gets an explicit `VW_MSG_ERROR` response (e.g. `VW_ERR_PROTO_INVALID`)
  rather than silent continuation.
- Confirm this doesn't change behavior for any message type that's
  supposed to return `VW_ERR_NOT_IMPL` today for a legitimate reason (e.g.
  file ops sent before `vw_server_ctx_set_file_stores` — check
  `vw_file_handlers.c`'s existing `if (!fs || !cs)` branch, which already
  calls `send_error` correctly and should be unaffected).
- A regression test sends a genuinely unrecognized message type (or a
  pre-auth-phase type) on an authenticated connection and confirms the
  connection receives an error rather than hanging.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-07-30]: Filed per CLAUDE.md's out-of-domain discovery rule.
Low priority — not exploitable as a meaningful DoS beyond one worker
thread for one connection's timeout window (bounded, not amplifiable), and
no well-behaved client (including the one this session wrote for
TASK-094's own testing, once fixed) would ever trigger it in normal
operation. Still worth fixing for protocol robustness and debuggability.
