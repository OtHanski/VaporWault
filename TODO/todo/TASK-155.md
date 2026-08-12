---
id:          TASK-155
title:       vw_proto_recv leaves unread bytes on the wire on VW_ERR_PROTO_TOO_LARGE, permanently desyncing the connection
status:      todo
assignee:    PRT.04
created_by:  WEB.09
created:     2026-08-11
priority:    critical
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [protocol, client, server, security-sensitive]
---

Discovered while implementing the web gateway's file endpoints (`TASK-133`)
and reproduced with a real client/server pair, not just by code reading —
out-of-domain for `WEB.09`, filed per `CLAUDE.md`'s routing rule rather
than fixed in place.

## The bug

`vw_proto_recv` (`src/core/vw_proto.c:94-122`) checks the incoming
message's declared payload length against the caller's buffer size
**after** it has already consumed the 8-byte frame header from the socket,
but **before** reading the payload:

```c
uint32_t payload_len = total_len - VW_PROTO_HEADER_SIZE;
if (payload_len > buf_size) return VW_ERR_PROTO_TOO_LARGE;   /* <- returns here */
...
if (payload_len > 0) {
    err = vw_net_recv(conn, out_buf, payload_len);            /* <- payload read, skipped above */
```

When `payload_len > buf_size`, the function returns `VW_ERR_PROTO_TOO_LARGE`
**without ever reading the payload bytes off the socket.** Those bytes
remain queued on the TLS/TCP stream. The *next* `vw_proto_recv` call on
that same connection reads them as if they were the start of a new
message header — total desync. Depending on what those stale bytes
happen to decode as, the next call fails fast with a nonsense error, or
blocks forever waiting for a "message" whose declared length will never
actually arrive.

## Why this actually triggers in practice

Several `vw_client_core.c` functions allocate a fixed, undersized stack
buffer for their expected ACK, sized for the *success* response only:

- `vw_client_file_move` (`vw_client_core.c:1263`): `uint8_t rbuf[4]`
- `vw_client_file_delete` (`vw_client_core.c:1192`): `uint8_t rbuf[4]`
- `vw_client_file_mkdir` and likely others follow the same pattern — not
  exhaustively audited here; whoever picks this up should grep for
  `recv_expect(sess->conn, VW_MSG_.*_ACK, .*\[4\]` (or similar small
  fixed-size buffers) across the file to find every instance.

Meanwhile, the server's generic rejection path,
`send_error()` (`src/server/vw_file_handlers.c:57-65`), always sends a
**6-byte** payload even for an empty message
(`vw_proto_encode_error(code, NULL, 0, ...)` still writes `error_code(u32)
+ an empty string's u16 length prefix` = 6 bytes) — 2 bytes more than
these 4-byte ACK buffers.

**Net effect: any time the server rejects one of these operations via its
normal generic error path (permission denied, invalid argument, or any
other business-rule rejection — not a rare or exotic condition), the
client's connection gets permanently desynced.** This is not a
theoretical edge case; it is the *normal* error path for these RPCs.

## Reproduction (real, not hypothetical)

Via the web gateway (`TASK-133`) against a real server:
1. `mkdir` a directory (succeeds).
2. `move` (rename) it (succeeds — its own 4-byte ACK happens to fit that
   specific response, since a *successful* move's ACK really is exactly 4
   bytes).
3. `delete` the renamed path. The server rejected this specific delete via
   its generic error path (exact business-logic reason not fully isolated
   in this filing — worth investigating, but secondary to the mechanism
   bug below). The client's 4-byte delete buffer couldn't hold the
   resulting 6-byte `VW_MSG_ERROR`, `vw_proto_recv` returned
   `VW_ERR_PROTO_TOO_LARGE` without draining it.
4. Every subsequent call on that same connection then either fails
   immediately with a nonsense error, or **hangs indefinitely** — observed
   directly: a `curl` request against an totally unrelated, freshly-issued
   session on the *gateway* (a separate connection entirely) still worked,
   but every further call *on the desynced session* hung until killed.

## Blast radius

This affects every consumer of these `vw_client_core.c` functions, not
just the new gateway: `vapourwault-daemon`'s sync engine calls
`vw_client_file_move`/`_delete` too (e.g. `compute_actions`/`exec_action`
per `ARCHITECTURE.md`'s sync engine notes). A sync cycle that hits a
permission-denied or any other generic-error rejection on a move/delete
could desync the daemon's own server connection the same way — worth
QA.06 checking whether this explains any previously-unexplained "sync
daemon stopped making progress until restarted" reports, if any exist.

## Suggested fix (PRT.04/CLI.02 to decide, not prescribed here)

Two options, not mutually exclusive:

1. **Systemic, defends every current and future caller**: change
   `vw_proto_recv` to drain and discard `payload_len` bytes from the
   socket before returning `VW_ERR_PROTO_TOO_LARGE`, so the connection
   remains usable even when a caller's buffer turns out to be too small.
   This is the safer default and doesn't rely on every caller getting
   their buffer size right.
2. **Per-caller**: audit every `vw_client_core.c` function using a small
   fixed ACK buffer and size it to accommodate the generic error
   response shape too (a `VW_MSG_ERROR` with an empty message is 6 bytes;
   with a real message, potentially much larger — `vw_proto_encode_error`
   allows up to `buf_size`). This doesn't protect against future misuse
   the way option 1 does.

## Acceptance criteria

- Root cause confirmed and fixed (recommend option 1 as the primary fix,
  regardless of whether option 2 is also done).
- A regression test reproducing this exact scenario (mkdir, move, a
  delete that the server rejects via its generic error path, then a
  further call on the same connection) added to `tests/`.
- `TASK-133`'s gateway mitigation (closing a session's connection on an
  unrecognized error, rather than continuing to reuse a possibly-desynced
  one) can be reconsidered/simplified once this is fixed at the source,
  but should not be *removed* — closing on truly-unexpected errors is
  reasonable defense in depth regardless.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-11]: Filed while implementing `TASK-133` (gateway file
endpoints) — reproduced against a real client/server pair via the
gateway's own end-to-end testing, not discovered by code reading alone.
Marked `critical` priority and `security-sensitive`: an unauthenticated or
low-privilege client triggering a predictable "any rejected move/delete
desyncs my own connection" is at minimum a reliability bug and plausibly a
self-inflicted DoS vector worth SEC.07's attention, even though the
immediate impact observed here was on the attacker's/caller's own
connection rather than other users' sessions. Did not attempt to fix
`vw_proto.c`/`vw_client_core.c` directly — out of `WEB.09`'s domain per
`CLAUDE.md`'s routing rule for out-of-domain discoveries; a mitigation was
added gateway-side instead (see `TASK-133`'s implementation note).
