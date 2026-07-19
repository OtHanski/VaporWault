---
id:          TASK-074
title:       Admin socket handles only one request per connection; AdminClient (and possibly future admin tooling) expects a persistent multi-RPC connection
status:      todo
assignee:    QA.06
created_by:  SRV.01
created:     2026-07-19
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [bug, ci, admin-ipc]
---

Discovered while verifying TASK-073 end-to-end against the full pytest
integration suite (not part of TASK-073's own scope — filed separately per
CLAUDE.md's out-of-domain/out-of-task-scope discovery rule).

## Symptom

Any integration test that issues **more than one** admin-socket RPC over the
same `AdminClient` connection fails on the second RPC with a Python
`BrokenPipeError: [Errno 32] Broken pipe`. Observed failures (run against a
Linux/gcc build, `-DVW_WERROR=ON`, WSL Ubuntu, 2026-07-19):

- `test_dedup.py::test_dedup_across_users` — second `create_user()` call
  breaks.
- `test_gc.py::test_oplog_tail_returns_entries` — `oplog_tail()` after an
  earlier `create_user()` on the same client breaks.
- `test_gc.py::test_multiple_versions_and_gc` — same pattern.
- `test_quota.py::test_upload_fails_when_quota_exceeded` — `set_quota()`
  after `create_user()` breaks.
- `test_quota.py::test_quota_adjust_allows_upload` — same pattern.

## Root cause

`vw_admin.c`'s `admin_listener` accepts a connection, calls
`handle_admin_connection(srv, fd)` exactly **once** (reads one 8-byte frame
header + one payload, dispatches to exactly one handler), then returns —
the connection is a one-shot request/response channel by design (see
`src/server/vw_admin.c:433-467`, `handle_admin_connection`).

`tests/integration/vw_client.py`'s `AdminClient` (`vw_client.py:497-538`)
opens a single `AF_UNIX` socket in `__init__` and reuses it across however
many RPCs the calling test makes (`create_user`, `set_quota`, `oplog_tail`,
etc. all call `self._send`/`self._recv` on the same `self._sock`). The
`admin_client` pytest fixture (`conftest.py:244-254`) is function-scoped but
persists for the whole test function — so any test calling two or more
admin RPCs hits this.

Note `vapourwault-server-cli.exe` (the real operator CLI) is unaffected: it
opens one connection, sends one request, reads one response, and exits per
invocation (see `cmd_user_create` etc. in `vw_server_cli.c`) — it never
reuses a connection for multiple RPCs, so this was not visible from that
side.

## Options (not evaluated in depth — pick during implementation)

- **Server-side**: loop in `handle_admin_connection` to read and dispatch
  multiple frames until the client closes the connection or an idle/EOF
  condition is hit — bringing the admin socket in line with what the test
  harness (and potentially future admin tooling) already assumes.
- **Test-side**: change `AdminClient` to open a fresh connection per RPC
  (matching the server's actual one-shot design) instead of reusing
  `self._sock`.

Whichever is chosen should also consider whether real deployment/ops
tooling (if any beyond `vapourwault-server-cli`) would benefit from a
persistent multi-RPC admin connection.

## Acceptance criteria

- All admin-socket-driven integration tests pass without `BrokenPipeError`.
- Full pytest integration suite passes locally (or in CI) against the real
  server binary — the remaining blocker after TASK-073's credential fix.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-07-19]: Filed while verifying TASK-073's fix end-to-end via the
full (non-cluster) pytest integration suite on a Linux/WSL build. 13/20
tests passed (including all of TASK-073's directly-affected
credential/login tests); 7 failed. 5 of those 7 are this issue. The
remaining 2 (`test_auth.py::test_brute_force_lockout`,
`test_quota.py::test_used_bytes_does_not_increase_after_delete`) are
separate, also pre-existing and unrelated — see TASK-073's notes for
details; not filing separate tasks for those yet pending ARCH.00 triage.

ARCH.00 [2026-07-19]: Reassigning from SRV.01 to QA.06. Re-read the root
cause: the server's one-shot-per-connection admin socket design is not
itself shown to be a defect — the task's own notes confirm the one real
production caller, `vapourwault-server-cli`, already works correctly
against exactly this design (opens one connection, sends one request,
reads one response, exits per invocation; never reuses a connection for
multiple RPCs). Nothing in this task demonstrates the server's behavior is
wrong or needs to change; what's actually broken is
`tests/integration/vw_client.py`'s `AdminClient`, which assumes a
persistent multi-RPC connection that no real caller relies on. Per
CLAUDE.md's domain table, that file is integration **test-scripting**
code ("QA.06 ... Integration tests: full client-server round-trips across
the wire protocol", "Python for integration scripting if needed"), not
server implementation — fixing it does not touch `src/server/` at all.
Making the single-assignee call: **QA.06**, fix Option B from the task
body (open a fresh `AF_UNIX` connection per RPC in `AdminClient`, matching
the server's actual, apparently-intentional one-shot design and the real
CLI's own usage pattern) rather than Option A (changing production server
code in `vw_admin.c` to grow a new multi-request-per-connection mode
purely to satisfy a test harness that doesn't reflect any real caller's
behavior). If QA.06's investigation instead concludes the server-side
persistent-connection mode is genuinely warranted (e.g. for future admin
tooling, not just this test), that is a new, separate feature task against
SRV.01 per the out-of-domain discovery rule — not a reason to reassign
this one back. `review_by: [CQR.08]` is unchanged (not security-sensitive:
this is a test-harness connection-lifecycle bug, no auth/crypto/traversal
surface). Priority `high` unchanged — SRV.01's original framing stands.
