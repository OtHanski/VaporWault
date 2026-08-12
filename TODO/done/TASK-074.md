---
id:          TASK-074
title:       Admin socket handles only one request per connection; AdminClient (and possibly future admin tooling) expects a persistent multi-RPC connection
status:      done
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

QA.06 [2026-07-19]: Implemented Option B in
`tests/integration/vw_client.py`. Changes:

- `AdminClient.__init__` (was `vw_client.py:506-509`) no longer opens an
  `AF_UNIX` socket eagerly; it now just stores `self._socket_path =
  socket_path`. Opening a connection now happens lazily, once per RPC.
- Added a new private helper `AdminClient._request(msg_type, payload=b"")`
  that opens one fresh `AF_UNIX` socket, connects, sends the single
  request frame, reads the single response frame, and closes the socket
  in a `finally` block — this is the one-shot open/send/recv/close unit
  shared by every RPC method, so the logic isn't duplicated three times.
- `create_user()`, `set_quota()`, and `oplog_tail()` (previously
  `self._send(...)` + `self._recv()` on the persistent `self._sock`, at
  the old `vw_client.py:531-573`) now each call `self._request(...)`
  once and use the returned `(mt, resp)` tuple — no other logic in these
  methods changed.
- `close()` is now a no-op (`pass`), documented as kept only for backward
  compatibility with existing callers that call `.close()` or use
  `AdminClient` as a context manager (e.g. the `admin_client` pytest
  fixture in `conftest.py:244-254`, `server_fixture.py`'s
  `new_admin_client()`), since there is no longer a persistent socket to
  close.
- Updated the class docstring to describe the new one-shot-per-RPC
  connection behavior and reference the server's `handle_admin_connection`
  design plus the real CLI's matching usage pattern, replacing the old
  text that implied a persistent connection.
- Verified no other file in the repo touches `AdminClient._sock` directly
  or otherwise depends on eager-connect-in-`__init__` semantics (checked
  `tests/integration/*.py`, `tests/perf/bench.py`; `server_fixture.py`'s
  `_wait_ready()` already polls for the admin socket file's existence
  independently of `AdminClient` construction, so lazy connection does not
  change readiness semantics).

Verification (this is a real end-to-end run, not just static checks):

- `python -m py_compile tests/integration/vw_client.py` — clean.
- No Linux build was available in the sandbox by default (WSL Ubuntu had
  gcc/g++ 13.3.0 but no cmake/ninja, and no passwordless sudo to install
  them), so I built a throwaway Python venv (`python3 -m venv`) and `pip
  install`ed `cmake`, `ninja`, and `pytest` into it (user-level, no sudo
  needed), then configured and built `vapourwaultd` and
  `vapourwault-server-cli` with `-G Ninja -DCMAKE_BUILD_TYPE=Release` into
  a scratch `build-wsl/` directory (all deps vendored under
  `third_party/`, build succeeded clean). Generated `test.crt`/`test.key`
  via the existing `tests/integration/gen_test_cert.sh`.
- Ran the full real pytest integration suite (`-m "not cluster"`) against
  the freshly built binaries:
  - All 5 originally-failing tests now pass with no `BrokenPipeError`:
    `test_dedup.py::test_dedup_across_users`,
    `test_gc.py::test_oplog_tail_returns_entries`,
    `test_gc.py::test_multiple_versions_and_gc`,
    `test_quota.py::test_upload_fails_when_quota_exceeded`,
    `test_quota.py::test_quota_adjust_allows_upload`.
  - Full `test_dedup.py`, `test_gc.py`, `test_quota.py`, `test_auth.py`,
    `test_file_ops.py` run: 26 passed, 1 failed. The 1 failure is
    `test_auth.py::test_brute_force_lockout` (6th wrong-password attempt
    returns code=300 instead of the expected code=304/locked) — this is
    the separate, pre-existing, unrelated issue already called out in
    SRV.01's original note above (also flagged in TASK-073's notes); it is
    not touched by this fix and not part of this task's acceptance
    criteria. `test_quota.py::test_used_bytes_does_not_increase_after_delete`,
    previously also flagged as failing/flaky by SRV.01, passed cleanly in
    this run.
  - Single-admin-RPC-per-test cases (e.g. most of `test_auth.py`,
    `test_file_ops.py`) still pass, confirming no regression for tests
    that only ever made one admin RPC.
- Cleaned up all scratch verification artifacts afterward
  (`build-wsl/`, generated `test.crt`/`test.key`, `__pycache__/`,
  `.pytest_cache/`) — they are not part of this change. Note:
  `src/server/vw_auth.c`, `vw_auth.h`, `vw_server_core.c`,
  `vw_server_main.c`, and `tests/unit/test_vw_auth.c` show as modified in
  `git status` in this working tree; those are pre-existing, in-flight
  changes from other work (not part of this task, not touched by me) —
  the only file this task modifies is `tests/integration/vw_client.py`.

Setting `status: review` per `review_by: [CQR.08]`. Not marking `done`
myself per protocol (ARCH.00 confirms after CQR.08 sign-off).

CQR.08 [2026-07-19]: Reviewed the diff to `tests/integration/vw_client.py`
against all six focus points. Clean sign-off, no blocking findings.

- **Correctness**: `_request()`'s `try/finally: sock.close()` is safe in
  every failure mode. `socket.socket(...)` (object construction, outside
  the `try`) essentially never fails; once inside the `try`, whether
  `connect()`, `sendall()`, or `_read_frame()` raises, the socket object
  is always a valid, constructed `socket` — Python's `socket.close()` is
  safe to call on an unconnected or partially-used socket and does not
  require a prior successful `connect()`.
- **Resource cleanup**: every exit path (normal return, exception from
  `connect`/`sendall`/`_read_frame`, timeout) runs through the same
  `finally: sock.close()`. No leak path found. Minor theoretical nit
  (non-blocking): `sock.close()` itself isn't wrapped in
  `try/except Exception: pass` the way `VwClient.close()` wraps
  `self._sock.close()` (`vw_client.py:483-486`) — if `close()` itself ever
  raised, it would mask an in-flight exception from the `try` body. In
  practice `close()` on a validly-constructed socket essentially never
  raises, so this is not worth blocking on, just noting for awareness.
- **Backward compatibility**: grepped `tests/perf/bench.py`,
  `tests/e2e/test_sync.py`, `tests/integration/conftest.py`,
  `server_fixture.py`, and all `tests/integration/test_*.py` for
  `AdminClient`/`admin_client`/`.close()` usage. Every `admin.close()` call
  (bench.py teardown, `conftest.py:254` fixture teardown) is the last use
  of that `AdminClient` instance — nothing calls an RPC method after
  `close()` or asserts a closed-connection error (`BrokenPipeError` etc.)
  as a way of testing lifecycle behavior. No caller depends on `close()`
  actually severing a connection. `__enter__`/`__exit__` are unaffected.
- **Consistency**: `_request()` mirrors `VwClient._send`/`_recv`'s use of
  `_make_frame`/`_read_frame` and the same 15 s `settimeout`, just scoped
  per-call instead of per-object. Reasonable and idiomatic given the
  one-shot design.
- **Completeness**: grepped the whole file for `self._sock`, `self._send`,
  `self._recv` — all remaining hits are in `VwClient` (lines ≤155, 480-486);
  none remain in `AdminClient` (lines 497-601). All three RPC methods
  migrated.
- **Docs**: updated class docstring and new `_request()`/`close()`
  docstrings are clear, accurate, and appropriately terse.

No `blocking` findings. Recommend ARCH.00 proceed to close after
confirming QA.06's verification notes.

ARCH.00 [2026-07-19]: CQR.08 signed off clean. QA.06 verified end-to-end
(26/27 tests pass locally, remaining failure is TASK-075, unrelated).
Confirming resolution and closing — status: done.
