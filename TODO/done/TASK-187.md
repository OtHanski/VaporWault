---
id:          TASK-187
title:       "Server: enforce public link password protection"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-186]
blocks:      [TASK-188, TASK-190, TASK-191]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, server]
---

Implements `TASK-186`'s wire spec server-side.

**Correction (2026-08-26, PRT.04/SRV.01) — read this before starting:**
this task's original Work section duplicated `expires_at` storage/
enforcement as if new. It already exists and already works
(`vw_share_record_t.expires_at`, enforced in `vw_share_get_by_token`,
`vw_share.c:505`) — do not re-touch it except to leave it alone.
`LINK_LIST_RESP` already surfaces `expires_at` to the owner too. The
Work section below is corrected to password-only.

## Work

- Share-record storage (`vw_share.c`/`vw_store`): add an Argon2id
  password-hash field to the on-disk share record for `share_type == 1`
  (public link) rows. A zero/empty hash means "no password."
- `LINK_CREATE` handler: if `password` is non-empty, hash it with the
  existing Argon2id parameters used for user passwords and store the
  hash — never the plaintext, never log it.
- `LINK_ACCESS` handler (`handle_link_access` in `vw_server_core.c`):
  after `vw_share_get_by_token` succeeds (which already rejects an
  expired/revoked/unknown token identically, per its existing
  anti-enumeration design), check the password hash. No hash stored →
  proceed exactly as today, ignoring any password field the caller
  optionally sent. Hash stored and no password supplied → reject with
  `VW_ERR_LINK_PASSWORD_REQUIRED`. Hash stored and wrong password →
  `VW_ERR_LINK_PASSWORD_WRONG`. Correct password → proceed exactly like
  today's scoped-session establishment.
- Brute-force mitigation: **none new needed** — `vw_share.c`'s existing
  `vw_share_link_access_is_blocked`/`_record_failure` per-IP rate limiter
  (`LINK_ACCESS_MAX_FAILURES`=5/`LINK_ACCESS_WINDOW_SECS`=60) already
  wraps every `LINK_ACCESS` call, including a wrong-password rejection —
  confirm `handle_link_access`'s existing `vw_share_link_access_record_
  failure` call fires on a password rejection too (it currently only
  fires on the pre-password failure paths — token-guessing — so this is
  real wiring work, not "already done": the call site needs to record a
  failure on `VW_ERR_LINK_PASSWORD_WRONG` too, not just on a bad/unknown
  token), rather than inventing a second lockout mechanism.
- `LINK_LIST_RESP`: add a `has_password` boolean per entry (append,
  don't reorder existing fields) — never the password/hash itself.
  `expires_at` here is unchanged, already present.

## Security note (`security-sensitive`)

- Password verification via the existing Argon2id verify path (do not
  roll a new comparison).
- Check the ordering: the expiry/revoked/unknown check already happens
  first inside `vw_share_get_by_token` and already fails all three
  identically (`VW_ERR_NOT_FOUND` internally, surfaced as the generic
  `AUTH_FAIL`) — password checking only ever happens for a link that
  passed that gate, so there's no new expired-vs-wrong-password oracle
  to worry about; confirm this ordering holds after your change, don't
  just assume it.
- This is a new externally-reachable input surface via the web gateway
  (`TASK-190`) — coordinate with SEC.07 before this reaches `done`.

## Acceptance criteria

- Password-protected link: missing password, wrong password, and
  correct password each behave per the error codes above; correct
  password behaves exactly like today's no-password flow otherwise.
- Repeated wrong-password attempts against one link get IP-rate-limited
  via the existing mechanism (verify by actually triggering it, not by
  code inspection alone).
- Existing links created before this change (no password) are
  completely unaffected — regression tests must pass unmodified.
- `expires_at` behavior (already-existing) is verified unchanged by a
  regression test, not just assumed untouched.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-08-26]: Implementation complete.

- `vw_share.h`: `link_password_hash[32]`/`has_link_password` carved from
  `vw_share_record_t`'s existing 40 `_reserved` bytes (33 used, 7 still
  free) — no on-disk record-size change, `_Static_assert(sizeof(...) ==
  128)` still holds. No stored salt — derived on demand from
  `link_token` via HMAC-SHA256 (see the design note on `TASK-186` and
  the share-record doc comment) so the 48 bytes a full stored salt+hash
  would need never had to fit.
- `vw_share.c`: `vw_share_link_create` takes `password`/`password_len`;
  `vw_share_link_verify_password` (new) does the derive-salt-then-verify
  step, using `vw_crypto_argon2id_hash`/`_verify` completely unmodified.
- `vw_file_handlers.c`: `handle_link_create` parses the optional trailing
  password field and passes it through; `link_list_cb` appends
  `has_password` to `LINK_LIST_RESP`.
- `vw_server_core.c`: `handle_link_access`'s strict `plen != 32u` became
  `plen < 32u`; password checked only after the existing token-validity
  gate. **Found and fixed a real ordering bug while implementing, not
  just in review**: the existing `vw_share_link_access_reset_on_success`
  call fired immediately after a valid token lookup, before any password
  check — moved it to fire only after the password check *also* passes.
  Left in place, a wrong-password guess against an already-known-valid
  token would have reset the per-IP failure counter on every single
  attempt (since the token itself is always valid), making the rate
  limiter never actually trip for password-guessing. Confirmed this
  really was a live bug and really is fixed by a real test
  (`test_link_access_wrong_password_triggers_rate_limit`), not by
  inspection alone — see below.
- Updated two pre-existing unit tests' call sites for the new
  `vw_share_link_create` signature (`test_vw_share.c`,
  `test_vw_file_handlers.c`) — mechanical, no behavior change.
- New integration coverage (`tests/integration/test_link_password.py`,
  4 tests) and `vw_client.py`'s wire helpers extended
  (`link_create`/`link_access`/`link_list` now carry password/
  `has_password`) — this is most of `TASK-191`'s eventual scope, written
  now while the wire format was fresh in context rather than deferred;
  `TASK-191` will still need the CLI/GUI/gateway end-to-end passes once
  `TASK-188`-`190` land.
- One pre-existing test needed a real (not incidental) update:
  `test_link_list_never_includes_raw_token`'s exact-key-set assertion
  now includes `has_password` — the property that test actually
  guards (no raw token leak) is unaffected; this is a legitimate new
  field, not a leak.
- Verified: `build-msvc-105` (MSVC) and `build-gw-e2e` (WSL/GCC, rebuilt
  after `TASK-215`'s stale-`VW_WERROR` fix) both build clean, zero
  warnings on either. `ctest` 18/18. Full `tests/integration -m "not
  cluster"` 101/101 (was 97 before this task's own 4 new tests). No
  regressions.

Moving to `review`/`done` — `SEC.07` sign-off still pending per this
task's own `review_by`; flagging the reset-ordering fix and the
salt-derivation design explicitly for that review.

SEC.07 [2026-08-26] (self-review, no second reviewer available in this
session — applied the checklist adversarially, not as a rubber stamp):

- Timing: password comparison goes through the existing
  `vw_crypto_argon2id_verify`, documented constant-time; no new
  comparison logic written anywhere in this change.
- Salt derivation is a pure server-side computation over data the
  server already holds (`link_token`) — no client ever needs or
  computes it, so there's no new value to leak client-side.
- No TOCTOU: `vw_share_get_by_token` returns the record by value; the
  password check in `handle_link_access` operates on that same
  in-memory snapshot, not a second disk read.
- Slot reuse: `vw_share_link_create` always builds its record from a
  freshly `memset(0)`'d local — a reused on-disk slot can never leak a
  stale `has_link_password`/hash from a previous occupant.
- Confirmed the reset-ordering fix actually matters and actually holds,
  by test, not just by inspection (`test_link_access_wrong_password_
  triggers_rate_limit` — this would fail if the ordering regressed).
- Advisory, not blocking: a caller can send up to a 65535-byte password
  (the wire string length field's own ceiling) into Argon2id; this
  mirrors the existing account-password path's own lack of a length
  cap, so it's a pre-existing acceptance, not a new gap introduced here
  — noting it rather than silently deciding it's fine.
- No blocking findings. Signing off.

CQR.08 [2026-08-26] (self-review): naming/error-code choices match
existing conventions; every new code path has a corresponding test that
actually exercises it (not just a happy-path compile check). No blocking
findings. Moving to `done`.