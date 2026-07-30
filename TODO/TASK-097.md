---
id:          TASK-097
title:       Integration tests for sharing (grants, links, permission enforcement, quota)
status:      todo
assignee:    QA.06
created_by:  ARCH.00
created:     2026-07-29
priority:    high
depends_on:  [TASK-094, TASK-095]
blocks:      []
review_by:   [CQR.08]
tags:        [testing, security-sensitive]
---

Write regression tests for the sharing feature (`TASK-088`,
`docs/PROTOCOL.md` §7.5/§7.10). This is a security-sensitive feature per
routing rule 1, and every SEC.07 finding resolved against `TASK-094`/
`TASK-095` needs a corresponding regression test per the standing QA.06
responsibility in `CLAUDE.md`.

Scope (minimum, expand based on SEC.07 findings from TASK-094/095):

- User-to-user grant: create, use (read + edit), revoke, confirm access is
  denied post-revoke.
- Public link: create, redeem anonymously (no account), use within
  permission bounds, confirm denied outside bounds (e.g. a read-only link
  attempting a write), revoke, confirm an *already-issued* scoped session
  loses access on its next request after revocation (not just new
  redemptions) — this is the specific "live revocation" property flagged in
  `TASK-088`'s design notes as easy to get wrong.
- Quota: confirm uploads through an EDIT grant or a public edit link debit
  the file owner's quota, not the acting user's.
- Cross-user isolation: confirm a user cannot access another user's file
  through any path (direct, forged share_id, wrong link_token) without an
  active grant/link.
- Rate limiting: confirm repeated invalid `LINK_ACCESS` attempts from one
  source trigger the same silent-drop behavior as `NODE_HELLO`.
- **Scoped-session privilege escalation (SEC.07 finding, added
  2026-07-29)**: confirm an anonymous scoped session (from `LINK_ACCESS`)
  is rejected with `VW_ERR_PERMISSION` when attempting `SHARE_GRANT`,
  `SHARE_REVOKE`, `LINK_CREATE`, or `LINK_REVOKE` — this is the regression
  test for the "leaked link mints an independent, revocation-surviving
  grant" gap.
- **Write-count rate limiting (SEC.07 finding, added 2026-07-29)**: confirm
  a scoped session is blocked after exceeding the configured write-count
  threshold, independent of remaining byte quota (e.g. many near-zero-byte
  `FILE_COMMIT`s in rapid succession).
- **FILE_MOVE ownership/cycle rules (SEC.07 finding, added 2026-07-29)**:
  confirm moving a shared file into a folder owned by someone other than
  the file's actual owner fails, and confirm moving a directory into its
  own descendant fails.

## Acceptance criteria

- All scenarios above pass.
- Sign-off note added to `TASK-094`/`TASK-095` before ARCH.00 closes the
  sharing milestone.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-088`.
