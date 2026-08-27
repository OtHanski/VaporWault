---
id:          TASK-185
title:       "ARCH.00 design - public link password protection (expiration already existed - see Notes)"
status:      done
assignee:    ARCH.00
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  []
blocks:      [TASK-186, TASK-187, TASK-188, TASK-189, TASK-190, TASK-191]
review_by:   [CQR.08]
tags:        [design]
---

Feature-gap review found `LINK_CREATE` (`docs/PROTOCOL.md` §7.5/§7.10)
carries only `file_id`/`permission`/`link_token` — no expiration, no
password. A link, once minted, is valid forever until manually revoked.
This is out of step with the sharing/vault feature set's general care
around access scoping and is a common expectation for this class of
product.

## Decisions

1. ~~**Expiration**: `expires_at` (uint64, unix seconds; 0 = never
   expires)...~~ **STRUCK, 2026-08-26 — this already existed in full.**
   See the dated correction note below. Not part of this task's actual
   scope.
2. **Password**: optional plaintext password at `LINK_CREATE` time, sent
   to the server over the existing TLS 1.3 connection (not client-side
   hashed — a link password isn't a user credential and doesn't need the
   zero-knowledge treatment `docs/PROTOCOL.md` §8.1 gives real account
   passwords). Server stores only an Argon2id hash (reusing the existing
   vendored Argon2 implementation and encoding used for user passwords —
   never plaintext, never returned by `LINK_LIST`). `LINK_ACCESS` gains an
   optional password field; wrong/missing password on a password-protected
   link rejects with `VW_ERR_LINK_PASSWORD_REQUIRED` (no password given)
   or `VW_ERR_LINK_PASSWORD_WRONG` (given but incorrect) — distinct codes
   so the frontend can tell "prompt for a password" apart from "that
   password is wrong."
3. **Brute-force mitigation**: reuse the existing per-identifier lockout
   mechanism that already backs OTP attempts (`vw_auth.c`), keyed by
   `link_token` instead of by account, so guessing a link's password is
   rate-limited the same way guessing a 2FA code is.
4. **Scope**: both fields optional and independent — a link can have
   neither, either, or both. Existing links (no password, no expiry)
   behave byte-for-byte as today; this is purely additive, same pattern
   as `TASK-106`'s `FILE_LIST` `dir_file_id` extension — no protocol
   version bump.
5. **Externally-reachable surface**: the web gateway is the primary
   consumer of public links (per the frontend's existing link-management
   UI) and is already flagged in `ARCHITECTURE.md`'s Risk table as a
   high-severity new attack surface. Both the server implementation and
   the gateway's own handling of link passwords are tagged
   `security-sensitive` below.

## Decisions recorded (`ARCHITECTURE.md`, Decision Log table)

- New row: `Public link password protection` — see `ARCHITECTURE.md` for
  the recorded entry (corrected in place 2026-08-26; originally titled
  and worded as if expiration were new too — it wasn't).

## Task breakdown

(Corrected 2026-08-26 — expiration dropped from every row below; each
task file has its own dated correction note.)

| Task | Assignee | Depends on | review_by | tags |
|------|----------|------------|-----------|------|
| `TASK-186` — Protocol: `LINK_CREATE`/`LINK_ACCESS` password field additions, new error codes, in `docs/PROTOCOL.md` | PRT.04 | 185 | CQR.08 | protocol |
| `TASK-187` — Server: password storage + enforcement (Argon2id hash; brute-force mitigation via the existing `LINK_ACCESS` IP rate limiter, no new lockout mechanism) | SRV.01 | 186 | SEC.07, CQR.08 | security-sensitive, server |
| `TASK-188` — Client: daemon IPC + client-core wrapper + `vapourwault-cli link create --password` | CLI.02 | 187 | CQR.08 | client |
| `TASK-189` — GUI: password field in the "Create link" dialog, badge in the link list | GUI.03 | 188 | CQR.08 | gui |
| `TASK-190` — Web gateway + frontend: create-link form gains both an expiry picker (wiring up the gateway API's already-existing `expiresAt` parameter, `web/src/api.ts:396`, which the form never surfaced) and a password field; password-prompt on redemption | WEB.09 | 187 | SEC.07, CQR.08 | security-sensitive, gateway |
| `TASK-191` — Integration tests: password (missing/wrong/correct), brute-force rate limiting, regression on existing (password-less) links | QA.06 | 186-190 | CQR.08 | test |

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-25]: Design complete, `ARCHITECTURE.md` updated, task
breakdown above created directly in `TODO/todo/`. Proceeding per
CLAUDE.md's routing rule 3 — `TASK-186` (protocol) must land before
`TASK-187`/`188` pick up implementation.

PRT.04 [2026-08-26] — **correction, found while starting `TASK-186`**:
decision 1 above (expiration) describes a feature that already existed
in full before this design task was ever written. Read the actual code
before designing against it this time: `LINK_CREATE`'s payload already
has `expires_at` (`docs/PROTOCOL.md` §7.5, unchanged), `vw_share.c`'s
`vw_share_get_by_token` already rejects an expired link with
`VW_ERR_NOT_FOUND` at line 505 (same anti-enumeration treatment as
revoked/unknown — this was never half-built, it was fully done), and
`vapourwault-cli create-link`/the GUI's Share dialog already expose an
expiry input end-to-end. Only the web frontend's create-link form never
wired a picker to it (real, kept as part of `TASK-190`). The original
feature-gap review that spawned this task simply got this wrong, and
this design task repeated the error without re-verifying against
source. Decision 1 is struck; this task's actual scope from here on is
password protection only (decisions 2-5), and `TASK-186`-`191` below
have been edited in place to match, each with its own dated correction
note. `ARCHITECTURE.md`'s Decision Log row is corrected the same way,
in place, with its own dated note — not left describing unbuilt work.
Filed as a fix, not a new task, since nothing here needs (re)building —
it's a documentation correction that happened to be caught mid-flight.
