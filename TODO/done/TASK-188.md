---
id:          TASK-188
title:       "Client: expose link password protection in daemon IPC and CLI"
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-187]
blocks:      [TASK-189]
review_by:   [CQR.08]
tags:        [client]
---

**Correction (2026-08-26)**: `vapourwault-cli create-link <path>
<view|edit> [expires_unix]` already has an expiry argument, wired all
the way through `vw_client_core.c`'s link-create wrapper. Only password
is missing. Work section corrected to match.

## Work

- `vw_client_core.c`/`.h`: extend the existing link-create wrapper to
  accept an optional `password`; surface the new error codes
  (`VW_ERR_LINK_PASSWORD_REQUIRED`/`_WRONG`).
- Daemon IPC (`vw_ipc.h`, matching `cmd_create_link`'s existing IPC
  message in `vw_client_cli.c`): add an optional trailing password field
  to the create-link request; add a `has_password` boolean to the
  list-links response (mirrors `TASK-187`'s `LINK_LIST_RESP` addition).
- `vapourwault-cli`: `create-link <path> <view|edit> [expires_unix]
  [--password <pw>]`; `list-links` shows whether a link is
  password-protected (never the password itself). `expires_unix`'s
  existing behavior is unchanged.

## Acceptance criteria

- `create-link /foo.txt view 0 --password secret` mints a link that
  `LINK_ACCESS` (tested via `TASK-191`) actually enforces.
- `list-links` output clearly shows which links are password-protected
  without printing the password.
- Omitting `--password` behaves exactly like today's `create-link`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-08-26]: Implementation complete.

- `vw_client_core.h`/`.c`: `vw_client_link_create` gains a `password`
  parameter (sent as an optional trailing string, matches `TASK-186`'s
  wire spec); `vw_link_entry_t` gains `has_password`, decoded in
  `vw_client_link_list`.
- `vw_daemon.c`: `VW_IPC_LINK_CREATE_REQ` parses an optional trailing
  password field and passes it through; `VW_IPC_LINK_LIST_RESP` gains
  `has_password`.
- `vw_ipc.h`: both payload doc comments updated.
- `vapourwault-cli`: `create-link <path> <view|edit> [expires_unix]
  [--password <pw>]`; `list-links` gained a PASSWORD column.
- Fixed two other call sites the signature change broke: the web
  gateway's `vw_gateway_api.c` (passes `NULL` for now — real wiring is
  `TASK-190`'s job, noted inline) and two unit tests' now-stale
  `vw_share_link_create` call sites were already fixed on `TASK-187`.
- Verified: `build-msvc-105` and `build-gw-e2e` (WSL/GCC) both build
  clean, zero warnings — including the gateway target, which also
  calls the changed function. New CLI-level integration test
  (`tests/integration/test_cli_link_password.py`) exercises
  `create-link --password` and `list-links`'s new column through the
  real compiled `vapourwault-cli` against a real daemon+server. Full
  `tests/integration -m "not cluster"` re-run: 102/102 passed (up from
  101 after `TASK-187`), zero regressions.

Moving to `review`/`done`.