---
id:          TASK-095
title:       Implement client library support for sharing (grants + links)
status:      todo
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-29
priority:    high
depends_on:  [TASK-088, TASK-094]
blocks:      [TASK-096, TASK-097]
review_by:   [SEC.07, CQR.08]
tags:        [client, protocol, security-sensitive]
---

Implement the client-side API for the sharing design published in
`docs/PROTOCOL.md` §7.5 (`TASK-088`). GUI.03 blocks on this per the existing
CLAUDE.md constraint that the GUI consumes the client library API only.

Scope:

- `vw_client_core.c` gains share/link API functions: create/revoke/list
  grants, create/revoke/list public links, and redeem a public link
  (unauthenticated connect path — needs its own connect-then-`LINK_ACCESS`
  flow distinct from the normal `AUTH_REQUEST` login path, since no
  username/password is involved).
- Sync engine awareness: items shared-with-me should be visible to the
  local sync engine as effectively read-only or read-write per the grant's
  permission, without conflating them with the user's own owned-file
  namespace. Define exactly how a shared folder appears in the local
  virtual path tree (this is the "GUI integration point definition" this
  task should write, per CLI.02's TODO-interaction responsibilities in
  `CLAUDE.md`).
- Client-side path validation for share/link targets should mirror the
  server-side rules in §7.8.2 for UX (fail fast locally) but the server
  check remains authoritative — do not skip server-side validation on the
  assumption the client already checked.
- `vw_client_cli.c`: add commands for share/link management (share, unshare,
  list-shares, create-link, revoke-link, list-links), following the
  existing CLI conventions (stdin-based input for anything sensitive,
  matching the `login`/admin CLI precedent).

## Acceptance criteria

- Client library functions for every message in §7.5 exist and are
  exercised by at least a manual WSL round-trip against the real server
  (once TASK-094 lands).
- CLI commands work end-to-end.
- Integration point definition for GUI.03 is written down (in this task's
  notes or a doc) before GUI.03 starts `TASK-096`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-088`. Depends on
`TASK-094` for the real wire handlers to test against, but the client-side
message encode/decode work can start in parallel once the protocol spec is
published (it already is, in `docs/PROTOCOL.md` §7.5).
