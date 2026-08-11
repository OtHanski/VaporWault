---
id:          TASK-129
title:       Implement minimal HTTP/1.1 layer for the web gateway (vw_http)
status:      review
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-128]
blocks:      [TASK-131]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, security-sensitive]
---

Per `TASK-127`'s design decision, the gateway hand-rolls its own minimal
HTTP/1.1 request/response layer rather than vendoring a general-purpose HTTP
server. This is safe to scope down because nginx is the gateway's sole
upstream in this deployment model (it reverse-proxies `/api/*` from the
browser) — the gateway only ever needs to parse well-formed HTTP/1.1
requests that nginx itself produced, not arbitrary/malformed browser input.

Scope (new `src/gateway/vw_http.{h,c}`):

- Parse request line (method, path, `HTTP/1.1`), headers (need
  `Content-Length`, `Content-Type`, `Cookie`), and body.
- Support `GET`, `POST`, `PUT`, `DELETE` — the methods the endpoint set in
  `TASK-132`–`TASK-135` actually needs.
- Support chunked-file-upload bodies large enough for a single 4 MiB chunk
  (`VW_CHUNK_SIZE_DEFAULT`, `src/core/vw_proto.h`) plus JSON metadata —
  check the actual max request size needed against `VW_MAX_MSG_BYTES`
  (`vw_proto.h`) for consistency with the wire protocol's own ceiling.
- Write minimal HTTP responses (status line, headers, body) — status codes
  actually used by the endpoint tasks (200, 400, 401, 403, 404, 409, 500 at
  minimum).
- **Correction from the original filing**: `vw_net.h` cannot be reused for
  this listener — it is TLS-only by design ("All connections are
  encrypted; plaintext is not supported", `vw_net.h:7`), and `vw_net_listen`
  requires a cert/key PEM pair. The gateway's nginx-facing side is
  deliberately plain HTTP (nginx terminates browser TLS; gateway↔nginx is
  plain loopback HTTP). Instead, reuse mbedTLS's own transport helper layer
  (`mbedtls/net_sockets.h`: `mbedtls_net_bind`/`_accept`/`_recv`/`_send`/
  `_free`) — already a linked dependency via `vw_core`
  (`third_party/CMakeLists.txt`'s mbedTLS `FetchContent`), cross-platform
  (handles Winsock init internally), and exactly the plain-TCP layer
  `vw_net.c` itself builds its TLS wrapper on top of. This avoids both a
  new dependency and hand-rolled platform socket `#ifdef`s.
- **Default bind address is `127.0.0.1` only** (`ARCHITECTURE.md`'s Gateway
  listener bind address decision, added during `TASK-127`'s SEC.07 review).
  Binding more broadly requires an explicit, documented config opt-in — not
  the default — since this module's reduced parser hardening assumes
  nginx as the sole reachable upstream.

Explicitly out of scope (would be needed for a general-purpose HTTP server,
not for this trust model): HTTP/1.0, pipelining, arbitrary transfer
encodings, malformed-request tolerance beyond "reject cleanly." Document
this scoping assumption prominently in `vw_http.h` so a future reader
doesn't assume it's meant to be internet-facing directly.

## Acceptance criteria

- Parses every request shape the endpoint tasks (`TASK-132`–`TASK-135`)
  actually send/receive, verified by unit tests.
- Malformed input (truncated headers, oversized `Content-Length`, missing
  required headers) is rejected with a clean error response, not a crash or
  hang — SEC.07 should specifically probe this given the module's role as
  the gateway's outermost input boundary.
- `vw_http.h` documents the "trusts nginx as sole upstream" assumption
  explicitly, including what it does *not* need to handle and why.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` — this is the
gateway's outermost parser, and SEC.07's remit explicitly covers "input
validation at all server and client entry points" and buffer/integer
overflow checks in C parsers.

WEB.09 [2026-08-10]: Implemented (`src/gateway/vw_http.{h,c}`). Listener
uses `mbedtls_net_bind`/`_accept`/`_recv`/`_send`/`_free` (see the
correction above — `vw_net.h` cannot be reused, it's TLS-only). Header/body
parsing is bounded and allocation-explicit throughout:

- Header block read into a fixed `VW_HTTP_MAX_HEADER_BLOCK` (16 KiB) buffer
  via an incremental scan for `\r\n\r\n` that never re-scans more than the
  last 3 bytes of already-scanned data per `recv()` call (so a terminator
  split across TCP segments is never missed, without rescanning the whole
  buffer each time); returns `VW_ERR_PROTO_TOO_LARGE` if it doesn't fit.
- Request line and headers are parsed by splitting on `\r\n` with explicit
  bounds checks at every index advance — no unbounded loops, no reliance on
  NUL-termination of attacker-controlled data.
- `Content-Length` is parsed with `strtoul` and explicitly rejected
  (`VW_ERR_PROTO_INVALID`) if any trailing non-digit characters remain, and
  capped at `VW_HTTP_MAX_BODY_BYTES` (6 MiB — one 4 MiB chunk plus
  base64/JSON framing headroom) before any body allocation happens.
- Method/path/header-name/header-value/header-count all have explicit
  fixed ceilings (`VW_HTTP_MAX_PATH_BYTES`, `VW_HTTP_MAX_HEADER_NAME`,
  `VW_HTTP_MAX_HEADER_VALUE`, `VW_HTTP_MAX_HEADERS`) checked before copying,
  never after.
- Every response sends `Connection: close` (no keep-alive/pipelining, per
  the module's stated scope).
- Default bind address is left as a caller-supplied parameter (not
  hardcoded in this module) — `TASK-131`'s gateway startup code is
  responsible for actually passing `"127.0.0.1"` per `ARCHITECTURE.md`'s
  decision; documented prominently in `vw_http.h`'s module comment so this
  isn't missed when that task lands.

Verified: compiles clean under MSVC `/W4 /WX` as part of `TASK-128`'s
build (no warnings in `vw_http.c` specifically). Did not write a dedicated
unit test in this pass (no `tests/unit` harness entry added) — flagging
this as outstanding for whoever does the CQR.08/SEC.07 review pass: the
malformed-input acceptance criterion above (truncated headers, oversized
`Content-Length`, missing headers) has been reasoned through but not yet
exercised by an automated adversarial-input test. Recommend that be a
condition of this task's `review` → `done` transition, not deferred
entirely to `TASK-143`.

Moving to `review` — implementation complete; needs SEC.07 + CQR.08
sign-off per the `security-sensitive` tag, with the unit-test gap above
called out explicitly for the reviewer's attention.
