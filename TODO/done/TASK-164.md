---
id:          TASK-164
title:       "Gateway multi-slot sessions (per-slot cookies, X-Vw-Slot header, /api/accounts)"
status:      done
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-13
priority:    high
depends_on:  [TASK-160]
blocks:      [TASK-165, TASK-166]
review_by:   [CQR.08]
tags:        [gateway, web]
---

Today the gateway (`src/gateway/vw_gateway_api.c`, `vw_gateway_session.c`)
supports many concurrent live sessions in its pool (cap
`VW_GATEWAY_MAX_SESSIONS = 256`), but exposes exactly one fixed cookie name
(`VW_GATEWAY_COOKIE_NAME`, `"vw_session"`) to the browser — one browser can
only ever present/use one logged-in account at a time.

**Settled scope note (2026-08-13):** unlike the local daemon (`TASK-161`),
which was reworked to let one client hold accounts on entirely different
servers, this task deliberately does **not** make the gateway multi-server.
Every slot here is still an account on the *one* server this gateway
process is configured for (`ARCHITECTURE.md`'s "Gateway stays
one-process-one-server" decision) — a second, unrelated server gets its
own separate gateway deployment/URL. Don't add a per-slot host/CA-cert
field to `/api/login`; that would be scope creep against an explicit
decision, not an oversight.

## Work

- Replace the single fixed cookie name with per-slot names
  (`vw_session_0`..`vw_session_<N-1>`; pick a small hard cap, e.g. `6`, same
  "mandatory hard cap" philosophy as `VW_GATEWAY_MAX_SESSIONS` —
  `vw_gateway_session.h`'s own doc comment explains why an unbounded
  anything here is a DoS risk). All slot cookies are `HttpOnly; Secure;
  SameSite=Strict` exactly as today.
- New `X-Vw-Slot` request header (small integer) tells the gateway which
  of the several cookies the browser is presenting backs *this* request.
  Generalize `get_cookie_value()`/`require_session()`
  (`vw_gateway_api.c:34-91`) from a fixed cookie name to a slot-derived one
  (`vw_session_<slot-from-header>`), defaulting to slot 0 if the header is
  absent (preserves today's single-account behavior with zero frontend
  changes needed for that case).
- `/api/login` gains an optional target `slot` field (defaults to "next
  free slot" — i.e. "add account" semantics — or a specific slot to
  replace/re-authenticate).
- `/api/logout` gains a `slot` field; clears only that one cookie/pool
  entry, others unaffected.
- New `/api/accounts` endpoint (POST, matching this codebase's
  POST-only convention): returns which slots are occupied and each one's
  display username (safe, non-secret — never the cookie/session token
  itself). This is read directly off the request's own `Cookie:` header
  (whichever slot cookies this specific browser presents), so it can never
  leak another browser's sessions.

## Acceptance criteria

- One `requests.Session` (simulating one browser) can log in as two
  different accounts into two different slots and make authenticated
  calls against both concurrently, without either affecting the other's
  session.
- `/api/accounts` correctly reports occupied slots + usernames for exactly
  the calling browser's own cookies.
- A request with no `X-Vw-Slot` header behaves exactly as today (slot 0),
  so this is a non-breaking addition for anything not yet updated to use
  it.
- Full gateway integration test suite (`tests/integration/test_gateway.py`)
  stays green; new test added for two-slot concurrent sessions.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**WEB.09 [2026-08-13]:** Implemented per the task's own design (matches
`ARCHITECTURE.md`'s pre-existing "Gateway multi-account browser sessions"
decision row exactly — cookie names `vw_session_0`..`vw_session_5`
(`VW_GATEWAY_MAX_SLOTS = 6`), `X-Vw-Slot` request header, `/api/accounts`).

- `vw_gateway_api.c`: new `resolve_slot()` (reads `X-Vw-Slot`, fails open
  to slot 0 on absent/malformed/out-of-range — a routing hint, not a
  security boundary, since the cookie *value* is what actually
  authenticates) and `slot_cookie_name()`. `require_session()` now derives
  the cookie name from the resolved slot instead of the old fixed
  `VW_GATEWAY_COOKIE_NAME` — every other handler (file/share/vault/etc.)
  needed zero changes since they all go through `require_session()`.
- `handle_login()` gained an optional body `slot` field: explicit and
  in-range picks that exact slot (re-authenticate semantics — the old
  session there, if live, is evicted only *after* the new login succeeds,
  never before, so a failed re-auth attempt can't kill a still-good
  session); absent means "next free slot," resolved by scanning this
  browser's own Cookie header for the lowest slot that's either absent or
  doesn't map to a live pool session (`resolve_login_slot()`, shared with
  `handle_link_access()` — a redeemed link is a login-like action from
  the browser's own perspective). All slots full and no explicit slot ->
  `507 no_free_slot`; an explicit out-of-range slot -> `400 bad_request`
  (deliberately NOT the same fail-open-to-0 behavior as the `X-Vw-Slot`
  header — here the caller is asserting a specific target, so a bad one
  is a caller error, not something to silently reinterpret). Slot
  resolution happens *before* the network round-trip to the server, so a
  full slot set fails fast.
- `handle_logout()` gained an optional body `slot` field (default 0 —
  zero frontend changes needed for the single-account case).
- New `/api/accounts` (no `require_session()` — an empty result is a
  normal response, not a 401; this is meant to be the frontend's
  page-load "does the browser already have anything to resume" check,
  closing the pre-existing gap this task's own design note flagged where
  the frontend always showed the login form even with a still-valid
  cookie already present — TASK-166's job to actually wire that up).
  Reads only the calling request's own cookies, so it can never observe
  another browser's sessions.
- `vw_gateway_session.[ch]`: `vw_gateway_session_create()` gained a
  `username` parameter (display-only, never used for authorization —
  the server remains sole authority on that) so `/api/accounts` has
  something to show; empty/NULL for a redeemed-link session (no real
  logged-in user). New `vw_gateway_session_get_username()` — deliberately
  does NOT touch `last_active` (a status check must not itself reset a
  session's idle-eviction countdown, unlike `vw_gateway_session_get()`).
- Test fix: `test_invalid_cookie_is_rejected` (TASK-144 regression test)
  was setting the bare `"vw_session"` cookie, which no longer names
  anything post-this-task — silently turned into a "missing cookie" test
  instead of the "wrong but well-formed cookie" case it's meant to cover.
  Fixed to use `"vw_session_0"`.
- New tests: `test_multi_slot_same_browser` (this task's own headline
  acceptance criterion — one `requests.Session`, two accounts in two
  slots, concurrent authenticated calls, isolation, `/api/accounts`
  correctness, no-header-means-slot-0) and
  `test_login_no_free_slot_is_rejected` (fills all 6 slots, confirms a
  7th fails with `507`/`no_free_slot`). The latter needed its own
  dedicated `ServerInstance`/`GatewayInstance` (not this file's shared
  module-scoped `server`/`gateway` fixtures, which pin `max_workers = 2`)
  — holding 6 simultaneously-live sessions open against a 2-worker test
  server hangs on the 3rd login waiting for a server worker that never
  frees up, which is a test-server capacity artifact, not the gateway's
  own 6-slot cap this test is actually meant to exercise. Added an
  optional `max_workers` parameter to `conftest.py`'s
  `ServerInstance`/`_write_server_conf` (default 2, unchanged for every
  other test) to make this possible.
- Build: `build-msvc-105` and `build-gw-e2e` both clean (`-Werror` on the
  GCC tree caught one real issue immediately — see CQR.08 note).
- Tests: full `ctest` green on both trees (17/17, 18/18). Full Python
  integration suite green: 91 passed, 3 cluster-marked deselected,
  including the two new tests and the full `test_gateway.py` file
  (25/25).

**CQR.08 self-review [2026-08-13]:** One `blocking`-class finding, caught
by the WSL/GCC tree's `-Werror -Wformat-truncation` before it ever reached
a test: `handle_logout()`'s new per-slot cookie-clear header buffer
(`char clear_header[64]`) was undersized for
`"vw_session_5=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"`
(71 bytes + NUL). Fixed by growing to 96 bytes. No other buffer changed
in this task uses a size close to its own worst case — re-derived each
one (`cookie_header[VW_GATEWAY_COOKIE_HEX_LEN + 96]` unchanged from
before this task, `slot_name[16]`/`name[16]` all comfortably oversized
for `"vw_session_" + 1 digit + NUL"`) — no other finding.
Also caught and fixed (before any build attempt, while writing the code):
`get_json_string_field`/`get_json_uint_field` were used by
`handle_login`/`handle_logout`/`handle_link_access` (textually earlier in
the file) but still *defined* further down, after their first use —
would not have compiled. Moved both definitions up, ahead of the auth
endpoints section, rather than adding a forward declaration (one
definition point is simpler to keep in sync going forward).

**QA.06 [2026-08-13] — TASK-168 sign-off:** `TASK-168`'s "gateway
multi-slot switching" requirement is covered by
`tests/integration/test_gateway.py::test_multi_slot_same_browser` (already
written above, during this task) — one `requests.Session`, two accounts
logged into two slots, interleaved authenticated calls via `X-Vw-Slot`,
asserting each slot's own file listing shows only that slot's own data
(no cross-slot leakage), plus `/api/accounts` correctness and the
no-header-means-slot-0 backward-compatibility case. No SEC.07 finding
from this task's own review (none was raised — this task wasn't tagged
`security-sensitive`; `TASK-165` is the security-sensitive one in this
pair). Full `ctest` (18/18 MSVC, 19/19 WSL) and the full
`tests/integration/` suite (95 passed, 3 deselected) green as of this
sign-off.
