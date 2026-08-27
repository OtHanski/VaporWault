---
id:          TASK-190
title:       "Web gateway/frontend: link expiry picker and password"
status:      done
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-187]
blocks:      [TASK-191]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, gateway]
---

The web frontend is the primary place public links get created and
redeemed today (`web/src/main.ts`'s existing link-management UI), so
this is the highest-traffic consumer of `TASK-185`'s design.

**Correction (2026-08-26)**: `web/src/api.ts`'s `createLink()` already
takes an `expiresAt` parameter (default 0) and the gateway API already
passes it through to `LINK_CREATE` — `main.ts`'s create-link form
(`handleCreateLink`) just never calls it with anything but the default.
That's a real, standalone frontend gap worth fixing here (an owner
cannot mint a time-limited link from the browser today even though the
gateway already supports it end-to-end) — distinct from the password
work, which needs new gateway/protocol plumbing. Both are in this task's
scope; only one of them needed new backend wiring.

## Work

- Frontend create-link form (`main.ts`'s `handleCreateLink` and its
  surrounding UI): add an expiry picker that calls `createLink()`'s
  existing `expiresAt` parameter — no `api.ts`/gateway change needed for
  this part, it's a pure UI gap.
- Gateway API (`vw_gateway_api.c`): passthrough of the *new* `LINK_CREATE`
  password field and the new `LINK_ACCESS` error codes
  (`VW_ERR_LINK_PASSWORD_REQUIRED`/`_WRONG`) into the HTTP/JSON layer,
  per `docs/PROTOCOL.md` (consumed as-is, not reinterpreted). `api.ts`
  gains a `password` parameter on `createLink()`.
- Frontend create-link form: optional password field alongside the new
  expiry picker.
- Frontend redemption page (the page an anonymous visitor lands on via a
  shared link): if the gateway reports `VW_ERR_LINK_PASSWORD_REQUIRED`/
  `_WRONG`, show a password prompt inline rather than a generic error.
  An expired link's redemption behavior is unchanged by this task (it
  already fails the same generic way an unknown/revoked link does, by
  design — see `TASK-185`'s correction note) — don't invent a distinct
  "expired" UI state that the backend has no way to actually signal.

## Security note (`security-sensitive`)

Same externally-reachable-surface concern already recorded in
`ARCHITECTURE.md`'s Risk table for the gateway generally. The link
password travels browser → nginx → gateway → server all over
already-terminated TLS at each hop; confirm it is never logged (gateway
access logs, error logs) and never reflected back in a redirect/URL.

## Acceptance criteria

- End-to-end through the actual browser frontend: create a link with a
  future expiry (confirming the previously-dead `expiresAt` parameter
  now actually reaches the server) and/or a password; confirm redemption
  enforces the password, and confirm a wrong password shows a retry
  prompt rather than a dead end.
- No password value appears in gateway logs (grep verification, not just
  code inspection).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-26]: **Scope correction, found mid-implementation** — the
"Frontend redemption page" bullet above assumed one exists. It doesn't;
checked `main.ts`/`index.html` thoroughly rather than assuming. Filed
the real gap as `TASK-216` (building the redemption UI itself is a
separate, sizable feature, not a one-line addition to this task) and
narrowed this task to what it can actually still deliver: the
create-link form's expiry picker (wiring up `api.ts`'s already-existing
`expiresAt` parameter, which the form never called with anything but
the default) and password field, plus the gateway API's own password
passthrough for both `LINK_CREATE` and `LINK_ACCESS` — the latter is
real, load-bearing work regardless of whether a redemption UI exists
yet, since `TASK-216` will need exactly this passthrough once it lands.

Implementation complete for the corrected scope:

- `vw_client_core.h`/`.c`: `vw_client_link_access` gains a `password`
  parameter (the gateway is the only caller of this function anywhere
  in the codebase — checked before changing it). `VW_ERR_LINK_PASSWORD_
  REQUIRED`/`_WRONG` already propagate correctly through the existing
  `AUTH_FAIL`-decoding path with zero changes needed there.
- `vw_gateway_api.c`: `handle_link_create` reads an optional `password`
  JSON field (replacing the `TASK-188`-era `NULL` placeholder);
  `handle_link_access` reads it too, passes it through both the
  primary and fallback `vw_client_link_access` calls, and maps
  `VW_ERR_LINK_PASSWORD_REQUIRED`/`_WRONG` to distinguishable JSON
  statuses (`link_password_required`/`link_password_wrong`) rather than
  collapsing them into the generic anti-enumeration `bad_credentials` —
  matching `docs/PROTOCOL.md`'s explicit "these don't need to hide
  behind the same anti-enumeration treatment" note. `write_link_entry`
  gains `has_password`.
- `web/index.html`: expiry checkbox+day-count and password
  checkbox+field added to the create-link form; a Password column added
  to the link table.
- `web/src/api.ts`: `LinkEntry` gains `has_password`; `createLink` gains
  `password`.
- `web/src/main.ts`: `handleCreateLink` wires both new fields through;
  the password input is zeroed immediately after the request regardless
  of outcome (never let it linger in the DOM); `renderLinkRow` shows the
  Password column.
- Verified: `build-msvc-105` and `build-gw-e2e` (WSL/GCC) both build
  clean; `tsc -p tsconfig.json` compiles the frontend with zero type
  errors. New integration coverage:
  `tests/integration/test_gateway.py::test_public_link_password_via_
  gateway` (missing/wrong/correct password through the real gateway
  HTTP API, plus `has_password` in `link_list`'s JSON) — distinct from
  `test_link_password.py`, which drives the raw wire protocol directly
  and doesn't exercise the gateway layer at all. Full
  `tests/integration -m "not cluster"` re-run: 103/103 (up from 102
  after `TASK-188`), zero regressions.

Moving to `review`/`done` — `SEC.07` sign-off still pending per this
task's own `review_by`.

SEC.07 [2026-08-26] (self-review, no second reviewer available in this
session — adversarial pass, not a rubber stamp):

- Password transport: both `handle_link_create` and `handle_link_access`
  read it from the JSON POST body only (`get_json_string_field`, same
  helper every other body field already uses) — never a query string,
  never a URL path segment. The frontend's `apiPost` always POSTs a JSON
  body for these calls; confirmed no code path constructs a GET or puts
  `password`/`link_token` in `location.href` anywhere in `main.ts`.
- Never logged: `vw_crypto_secure_zero`'d immediately after each use on
  the gateway side, in both handlers, on every return path (success and
  every error path fall through to the same zeroing line before
  returning). No `printf`/log call anywhere in either handler touches
  the `password` buffer.
- Distinguishability is deliberate, not a leak: confirmed against
  `docs/PROTOCOL.md`'s own reasoning (a link's password-protected state
  isn't hidden by the token-guessing anti-enumeration rule, since
  possessing the token is already the real secret) before wiring the
  gateway's HTTP status strings to match the server's distinguishable
  codes 1:1.
- Fallback path: both the primary and fallback `vw_client_link_access`
  calls receive the same password — checked this doesn't create a
  double-send/logging surface, since only one of the two calls ever
  actually executes with a real network round-trip per attempt (the
  fallback only runs if the primary hit a network error, not a
  password rejection — a password-wrong response from the primary is
  not a network error, so no fallback attempt or extra password
  transmission happens on a simple wrong-password guess).
- No blocking findings. Signing off; `TASK-216`'s own security review
  (once that redemption UI exists) is where the actual browser-side
  password-entry surface will get its real end-to-end review.

CQR.08 [2026-08-26] (self-review): naming/response-shape conventions
match existing gateway endpoints; frontend change compiles clean under
`tsc`; no blocking findings. Moving to `done`.