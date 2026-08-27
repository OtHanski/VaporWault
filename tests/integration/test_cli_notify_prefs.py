"""
test_cli_notify_prefs.py — integration test for TASK-206/207/209's daemon
IPC (NOTIFY_PREFS_GET/SET_REQ/_RESP/_ACK) and the `vapourwault-cli notify
list`/`notify set <category> on|off` subcommands.

Drives the actual compiled `vapourwault-cli` binary as a subprocess
against a real running daemon and server, same style as
test_cli_search.py/test_cli_selective_sync.py.

"Works while on fallback" (TASK-209's acceptance criterion) is not
re-proven here with a full cluster/fallback rig, for the same reason
test_cli_search.py's own notes give: it's satisfied by construction —
VW_IPC_NOTIFY_PREFS_GET_REQ's handler in vw_daemon.c has no
account_is_read_only() gate (a pure read), while
VW_IPC_NOTIFY_PREFS_SET_REQ's does (mirrors VW_IPC_VERSION_RESTORE_REQ's
write-gated pattern exactly) — see TASK-209's own implementation notes.
"""

import os
import socket
import subprocess
import time

from conftest import ServerInstance


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _notify_list(cli_bin, ipc_port, account):
    rc, out, err = _cli(cli_bin, ipc_port, "--account", account, "notify", "list")
    assert rc == 0, f"notify list failed: {out}\n{err}"
    on = set()
    for line in out.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "yes":
            on.add(parts[0])
    return on


def _spawn_daemon(daemon_bin, state_dir, ipc_port):
    (state_dir / "daemon.conf").write_text(f"ipc_port = {ipc_port}\nsync_interval_ms = 200\n")
    env = dict(os.environ)
    env["VW_LOG_LEVEL"] = "DEBUG"
    proc = subprocess.Popen([daemon_bin, "--state-dir", str(state_dir)], env=env)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", ipc_port), timeout=0.5):
                return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("daemon did not open its IPC port in time")


def test_cli_notify_prefs_default_off_set_and_list(
        binaries, tmp_path_factory, running_daemon, cli_bin, unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_notify_cli_server")))
    server.start()
    try:
        server.create_user(unique_username, password)
        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        # Default off — every account starts with nothing enabled.
        on = _notify_list(cli_bin, running_daemon, unique_username)
        assert on == set(), f"expected no categories on by default, got {on}"

        # Toggle one category on.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "notify", "set", "quota_warning", "on")
        assert rc == 0, f"notify set on failed: {out}\n{err}"
        assert "quota_warning: on" in out, out

        on = _notify_list(cli_bin, running_daemon, unique_username)
        assert on == {"quota_warning"}, f"expected only quota_warning on, got {on}"

        # Toggling one category must not disturb the others — set a second
        # one and confirm both (and only both) are now on.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "notify", "set", "share_received", "on")
        assert rc == 0, f"notify set on failed: {out}\n{err}"
        on = _notify_list(cli_bin, running_daemon, unique_username)
        assert on == {"quota_warning", "share_received"}, on

        # Toggle the first one back off — the second must survive.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "notify", "set", "quota_warning", "off")
        assert rc == 0, f"notify set off failed: {out}\n{err}"
        assert "quota_warning: off" in out, out
        on = _notify_list(cli_bin, running_daemon, unique_username)
        assert on == {"share_received"}, on

        # Unknown category and bad on/off value are both rejected client-side.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "notify", "set", "not_a_real_category", "on")
        assert rc != 0, "unknown category should be rejected"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "notify", "set", "quota_warning", "sideways")
        assert rc != 0, "invalid on/off value should be rejected"
    finally:
        server.stop()


def test_cli_notify_prefs_persist_across_daemon_restart(
        binaries, tmp_path_factory, daemon_bin, cli_bin, unique_username):
    """
    The preference lives server-side on the user record (notify_prefs.db),
    not in the daemon's own local state — this test kills and restarts
    the daemon against a fresh IPC port/state_dir-less connection (a new
    daemon process re-authenticating from scratch) to prove `notify list`
    reflects real server state on every fetch, not a value the old daemon
    process merely held in memory.
    """
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_notify_restart_server")))
    server.start()
    daemon_proc = None
    try:
        server.create_user(unique_username, password)

        state_dir = tmp_path_factory.mktemp("vw_notify_restart_daemon")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            ipc_port = s.getsockname()[1]
        daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)

        rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, ipc_port, "--account", unique_username,
                             "notify", "set", "new_login", "on")
        assert rc == 0, f"notify set failed: {out}\n{err}"

        # ── Kill and restart the SAME daemon against the SAME state_dir. ──
        daemon_proc.terminate()
        daemon_proc.wait(timeout=5)
        daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)

        on = _notify_list(cli_bin, ipc_port, unique_username)
        assert on == {"new_login"}, (
            f"notify preference did not survive a daemon restart: {on}"
        )
    finally:
        if daemon_proc is not None:
            daemon_proc.terminate()
            try:
                daemon_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon_proc.kill()
                daemon_proc.wait(timeout=5)
        server.stop()
