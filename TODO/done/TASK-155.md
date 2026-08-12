---
id:          TASK-155
title:       vw_proto_recv leaves unread bytes on the wire on VW_ERR_PROTO_TOO_LARGE, permanently desyncing the connection
status:      done
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

PRT.04 [2026-08-12]: Fixed via option 1 (systemic fix at the source),
per this task's own recommendation, in `src/core/vw_proto.c`.

**Root cause confirmed exactly as filed**: `vw_proto_recv` (line ~110)
returned `VW_ERR_PROTO_TOO_LARGE` when the caller's buffer couldn't hold
the incoming payload, without ever reading those bytes off the socket —
they stayed queued on the connection and the next `vw_proto_recv` call
decoded them as a bogus message header instead of the real next message.

**Fix**: added `drain_bytes()`, a small helper that reads and discards
exactly N bytes off the wire in bounded 4 KiB chunks. `vw_proto_recv` now
calls it before returning `VW_ERR_PROTO_TOO_LARGE` at line ~110, so the
connection stays correctly positioned at the start of the *next* real
message rather than mid-payload of the rejected one. **Deliberately
scoped to only this one check**, not the earlier `total_len >
VW_MAX_MSG_BYTES` check a few lines above it: that check runs on a raw,
not-yet-validated header field that could claim any value up to
`UINT32_MAX` — draining an attacker-declared unbounded length would be
its own resource-exhaustion vector. The line-110 check this fix targets
only ever sees a `payload_len` that has *already* been validated against
`VW_MAX_MSG_BYTES` (a real, bounded, 8 MiB ceiling) by the check above
it — it's a legitimate, bounded message that happens to be larger than
this *specific caller's* buffer, exactly the scenario this task's own
reproduction describes (a real `VW_MSG_ERROR` that just doesn't fit a
4-byte success-sized `rbuf`), not attacker-controlled in a way that
draining could weaponize. If the drain itself hits a real network error,
that error propagates instead of the original `TOO_LARGE` — the
connection is unusable either way at that point, so the more specific
failure is more useful to the caller.

Per-caller audit (option 2, not done as the primary fix but checked
regardless): did not resize every small fixed-ACK-buffer caller in
`vw_client_core.c` — the systemic fix means they no longer need to be
exactly right, which was the point of choosing option 1.

**Verified, not just read the diff**:
- New regression test, `tests/integration/test_proto_recv_drain.c`
  (`integration_proto_recv_drain` in `ctest`) — two cases, both driving a
  real TLS-connected `vw_conn_t` pair (no server/auth stack needed, just
  raw `vw_proto_send`/`vw_proto_recv`): (1) a 6-byte payload into a
  4-byte buffer (the exact real-world shape — `VW_MSG_ERROR`'s minimum
  encoding into `vw_client_file_move`'s real `rbuf[4]`), then a second,
  distinguishable message on the *same* connection, asserting the second
  `vw_proto_recv` call correctly receives the second message rather than
  a bogus header; (2) an off-by-one case (buffer exactly one byte short).
- **Confirmed the test actually catches the regression, not just
  exercises the happy path**: reverted just `vw_proto.c` (via `git
  stash`), rebuilt, reran — both cases failed exactly as predicted (the
  second `vw_proto_recv` call got `VW_OK` with garbage `type`/`plen`
  instead of the real second message); restored the fix, rebuilt, reran
  — 19/19 assertions pass.
- Rebuilt clean under both MSVC (`build-msvc-105`, `/W4`) and GCC (WSL
  `build-gw-e2e`, `-Wall -Wextra -Wpedantic -Werror`) — the GCC build
  needed one portability fix in the new test file itself (missing
  `<sys/stat.h>` for `mkdir` on POSIX, caught immediately by
  `-Werror=implicit-function-declaration`).
- Full existing suite reruns clean: 16/16 `ctest` (MSVC, including the
  new test), and the full 22-test gateway integration suite
  (`tests/integration/test_gateway.py`) against a rebuilt
  `vapourwaultd` + `vapourwault-web-gateway` pair in WSL — this exercises
  the exact `TASK-133`-reported real-world path (a rejected file
  operation through the gateway) with the fix in place, not just the new
  isolated unit test.

**On `TASK-133`'s gateway-side mitigation**: per this task's own
acceptance criteria, left in place, not removed — a session that
receives a truly unrecognized error is still evicted defensively. With
this fix, that mitigation should simply trigger far less often in
practice (the connection itself no longer desyncs on the *ordinary*
generic-error-rejection path this task was filed from), not that it's
now redundant in every case.

Moving to `review` — needs SEC.07 + CQR.08 sign-off per this task's own
`review_by`, given the `security-sensitive`/`critical` tags.

SEC.07/CQR.08 [2026-08-12]: Reviewed `vw_proto.c`'s change directly.
The scoping decision (drain only the already-bounded line-110 case, not
the raw-header `total_len > VW_MAX_MSG_BYTES` case) is correct and
exactly the right line to draw — confirmed by tracing that `payload_len`
at the drain call site is provably `<= VW_MAX_MSG_BYTES -
VW_PROTO_HEADER_SIZE` (checked immediately above, before any drain-
related code runs), so `drain_bytes` never reads an attacker-unbounded
amount. `drain_bytes` itself has no overflow/underflow risk (`n -=
chunk` where `chunk <= n` by construction of the `min()`). Error
propagation from a failed drain is sound (surfaces the real network
error rather than masking it as `TOO_LARGE`). The regression test
meaningfully exercises the two-call desync shape (not just single-call
encode/decode, which `test_vw_proto.c`'s own header comment already
flags as insufficient for this class of bug) and was confirmed via
revert-and-rerun to actually catch the bug, not just pass trivially. No
blocking findings.
Sign-off: `SEC.07` + `CQR.08` requirements satisfied. Ready for `done`.
