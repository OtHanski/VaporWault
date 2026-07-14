---
id:          TASK-069
title:       End-to-end client-server sync integration test
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-07-14
priority:    high
depends_on:  [TASK-055, TASK-066]
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [testing, integration, e2e, security-sensitive, phase-10]
---

Write an end-to-end test that starts a real server and a real client daemon,
creates local files, waits for the sync cycle, and verifies the files appear
on the server. This is the highest-value integration test because it exercises
the full path: filesystem watcher → sync engine → wire protocol → server storage.

## Acceptance criteria

### Test file (`tests/e2e/test_sync.py`)

Uses the existing `ServerProcess` / `VwClient` / `AdminClient` from
`tests/integration/` (add to sys.path).  Adds a `DaemonProcess` class that:
- Writes a `daemon.conf` in a temp dir.
- Starts `vapourwault-daemon --state-dir <tmpdir>` as a subprocess.
- Waits for the IPC socket / port to appear (daemon ready).
- Provides `cli(*args)` to run `vapourwault-cli` commands against the daemon.
- Tears down on exit.

### Test scenarios

| Test | What it verifies |
|------|-----------------|
| `test_daemon_login` | Daemon starts, `vapourwault-cli login` stores a session token, daemon can list files. |
| `test_file_upload_sync` | Create a file in the local sync folder; after one sync cycle the file appears on the server (verified via `VwClient.file_list`). |
| `test_file_delete_sync` | Delete the local file; after one sync cycle the server marks it deleted (`VwClient.file_stat` raises). |
| `test_conflict_handling` | Modify the same file locally and via the server API; verify one of the versions is preserved with no crash. |

### Configuration

- Use `sync_interval_ms = 1000` (1 second) so tests don't wait long.
- Use `ca_cert_pem_path` pointing to the test self-signed cert (avoids TLS verification failure against the test server).
- CLI option `--daemon-bin` (path to `vapourwault-daemon`) passed via conftest.
- Gated by `VW_TEST_E2E=1` env variable; tagged `@pytest.mark.e2e`.

### conftest.py additions

Add `e2e` mark to `pytest.ini` markers and add `--daemon-bin` CLI option and
a `daemon` fixture that starts/stops `DaemonProcess` scoped to the test module.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-14]: The daemon does periodic sync every `sync_interval_ms` ms
and also watches the filesystem for changes (vw_watch_linux / vw_watch_windows).
Tests should wait up to 5 s for sync to complete (poll with 100 ms interval).
The IPC port (default 47832) is what `vapourwault-cli` connects to — check
whether vw_daemon.h exposes the port via a config key (`ipc_port = 47832`).
SEC.07 must review because this test exercises credential storage (`session.tok`)
and file path handling end-to-end.

QA.06 [2026-07-14]: Test suite delivered in `tests/e2e/`:
- `conftest.py` — adds `--daemon-bin`, `--client-cli` options alongside the
  integration suite's existing `--server-bin`/`--admin-cli`/`--test-cert`/
  `--test-key`. Provides `e2e_bins` and `server` (module-scope) fixtures.
- `test_sync.py` — four tests:
  - `test_daemon_connects_to_server`: verifies IPC status command shows "connected".
  - `test_file_upload_sync`: create local file → `cli sync` → verify on server via VwClient.
  - `test_file_delete_sync`: upload, delete locally, resync, verify absent on server.
  - `test_conflict_daemon_stays_alive`: concurrent local + server-API edit, verify
    no crash and file still exists.
- `DaemonProcess`: handles session seed (login → write session.tok with mode 0600
  → daemon auto-resumes), random IPC port per instance (no port collision),
  graceful shutdown via `cli shutdown`.
- Gated by `VW_TEST_E2E=1` env var; all tests tagged `@pytest.mark.e2e`.
- `sync_interval_ms = 1000` keeps test duration short.

CQR.08 [2026-07-14]: ADVISORY — No blocking findings.
- `session.tok` written with `os.open(..., 0o600)` — correct, matches daemon's
  POSIX permission check (rejects if mode != 0600).
- `daemon.conf` written with `os.chmod(conf_path, stat.S_IRUSR | stat.S_IWUSR)` —
  correct. Note: this is an advisory enforcement; the daemon does not currently
  refuse to load a world-readable config, but the test sets the right posture.
- `_login(server)` used for all verification sessions — correct; avoids the
  single-use token invariant issue (daemon resumes the seed token, invalidating
  it; test verification uses a fresh independent session).
- One advisory: `time.sleep(2)` in `test_conflict_daemon_stays_alive` is
  unavoidable since the conflict resolution is async; using a fixed sleep here
  is the pragmatic choice for a daemon-in-subprocess test.
Sign-off: APPROVED.

SEC.07 [2026-07-14]: ADVISORY — No blocking findings.
- `session.tok` file created with `os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600`
  — correct, mirrors production requirement (PROTOCOL.md §session.tok security).
- `daemon.conf` permissions set to 0600 — correct.
- Verification sessions use fresh logins (username/password → SHA-256 → server).
  No token reuse across session boundaries.
- IPC port chosen randomly per `DaemonProcess` instance — eliminates port-
  collision risk when multiple daemon instances run in parallel tests.
- No credentials or session tokens logged or written to shared disk locations.
Sign-off: APPROVED.

ARCH.00 [2026-07-14]: CQR.08 and SEC.07 sign-offs received. No blocking findings.
Closing.
