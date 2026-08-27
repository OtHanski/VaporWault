"""
test_cli_selective_sync.py — integration test for TASK-192/193's
selective-sync exclude rules, driven through the real compiled
`vapourwault-cli` (`set-folder-rules`) against a real running daemon and
server.

The key correctness property (TASK-192 decision 5) is negative — "this
file must NEVER be uploaded again" — which can't be observed by polling
`status` alone (a file that's correctly excluded and a sync engine that's
silently broken both look like "nothing happened"). This test proves it
instead by checking the server's own version count via `version list`
(TASK-182): if an excluded file's local content changes and no new
version appears after a real sync cycle, the change was never sent.
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


def _wait_for_sync(cli_bin, ipc_port, timeout=15):
    time.sleep(1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, out, _ = _cli(cli_bin, ipc_port, "status")
        if rc == 0 and "0 uploads, 0 downloads" in out:
            return True
        time.sleep(0.3)
    return False


def _version_count(cli_bin, ipc_port, account, virtual_path):
    rc, out, err = _cli(cli_bin, ipc_port, "--account", account, "version", "list", virtual_path)
    assert rc == 0, f"version list {virtual_path} failed: {out}\n{err}"
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return len(lines) - 1  # minus header row


def test_cli_selective_sync_exclude_stops_further_uploads(
        binaries, tmp_path_factory, cli_bin, running_daemon, unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_selsync_server")))
    server.start()
    try:
        server.create_user(unique_username, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_selsync_root"))
        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)
        keep_path = os.path.join(local_root, "keep.txt")
        cache_path = os.path.join(local_root, "cache.tmp")

        with open(keep_path, "w") as f:
            f.write("keep v1\n")
        with open(cache_path, "w") as f:
            f.write("cache v1\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        assert _wait_for_sync(cli_bin, running_daemon), "initial upload never completed"

        assert _version_count(cli_bin, running_daemon, unique_username, "/cache.tmp") == 1
        assert _version_count(cli_bin, running_daemon, unique_username, "/keep.txt") == 1

        # ── Exclude *.tmp for this folder. ──
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "set-folder-rules", local_root, "--exclude", "*.tmp")
        assert rc == 0, f"set-folder-rules failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username, "list-folders")
        assert rc == 0
        assert "exclude: *.tmp" in out, f"list-folders should show the new rule: {out!r}"

        # Modify the now-excluded file locally; a real sync cycle must
        # never push this change (decision 5: excluded paths stop
        # generating actions in either direction, they don't just get a
        # one-time pass).
        with open(cache_path, "w") as f:
            f.write("cache v2 — must never reach the server\n")
        # Control: also modify the NOT-excluded file, to prove the sync
        # engine itself is still running normally during this same window
        # (otherwise a broken sync engine would look identical to correct
        # exclusion — "nothing uploaded" either way).
        with open(keep_path, "w") as f:
            f.write("keep v2\n")
        assert _wait_for_sync(cli_bin, running_daemon)

        assert _version_count(cli_bin, running_daemon, unique_username, "/cache.tmp") == 1, (
            "excluded file's local edit must not have been uploaded"
        )
        # Not asserting an exact count here: a single local write can
        # legitimately produce more than one version record on this
        # server (a pre-existing, unrelated sync-engine quirk — see
        # TASK-215 — not anything selective sync touches). The property
        # this line actually needs to prove is "the non-excluded control
        # file kept syncing normally in the same cycle", i.e. more than
        # its original one version — not an exact count.
        assert _version_count(cli_bin, running_daemon, unique_username, "/keep.txt") > 1, (
            "non-excluded file's edit should have synced normally in the same cycle"
        )
        # The excluded file's local content must be exactly what this test
        # wrote — untouched by the sync engine in either direction (no
        # download overwriting it, since nothing was ever uploaded for it
        # to conflict against).
        with open(cache_path) as f:
            assert f.read() == "cache v2 — must never reach the server\n"

        # ── Clear the rule; the file resumes normal sync. ──
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "set-folder-rules", local_root)
        assert rc == 0, f"clearing rules failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username, "list-folders")
        assert rc == 0
        assert "exclude:" not in out, f"rules should be cleared: {out!r}"

        with open(cache_path, "w") as f:
            f.write("cache v3 — rule cleared, should upload now\n")
        assert _wait_for_sync(cli_bin, running_daemon)

        # Again not asserting an exact count — see the TASK-215 note above.
        assert _version_count(cli_bin, running_daemon, unique_username, "/cache.tmp") > 1, (
            "clearing the exclude rule should let the next real edit sync normally"
        )
    finally:
        server.stop()


def test_cli_selective_sync_excluded_remote_change_never_redownloaded(
        binaries, tmp_path_factory, cli_bin, running_daemon, unique_username):
    """
    The mirror-image property of the upload test above: once a path is
    excluded, a change on the SERVER side must not be pulled down either
    (TASK-192 decision 4/5 — exclusion is symmetric). Proven by deleting
    the local copy of an already-synced, now-excluded file and confirming
    a real sync cycle does not resurrect it — if exclusion only worked in
    the upload direction, this cycle's REMOTE_DEL-vs-download logic could
    easily re-download content the user just removed locally, or worse,
    interpret the local absence as a delete instruction and remove the
    server's copy (the exact class of bug this feature's own
    implementation notes describe finding and fixing).
    """
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_selsync_remote_server")))
    server.start()
    try:
        server.create_user(unique_username, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_selsync_remote_root"))
        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)
        secret_path = os.path.join(local_root, "secret.tmp")

        with open(secret_path, "w") as f:
            f.write("uploaded once, then this device stops wanting it\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        assert _wait_for_sync(cli_bin, running_daemon), "initial upload never completed"
        assert _version_count(cli_bin, running_daemon, unique_username, "/secret.tmp") == 1

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "set-folder-rules", local_root, "--exclude", "*.tmp")
        assert rc == 0, f"set-folder-rules failed: {out}\n{err}"

        # Remove the local copy — the file still exists server-side.
        os.remove(secret_path)
        assert _wait_for_sync(cli_bin, running_daemon)

        assert not os.path.exists(secret_path), (
            "test setup invariant broken: local file should still be absent"
        )
        # The critical assertion: the server's copy must be untouched —
        # excluding this path must not have propagated the local removal
        # as a delete, and the local removal must not have triggered a
        # fresh re-download either.
        assert _version_count(cli_bin, running_daemon, unique_username, "/secret.tmp") == 1, (
            "excluded path's server-side content must survive a local deletion untouched"
        )
    finally:
        server.stop()


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


def test_cli_selective_sync_rules_persist_across_daemon_restart(
        binaries, tmp_path_factory, daemon_bin, cli_bin, unique_username):
    """
    TASK-193's persistence design stores rules in account.conf, re-read
    at daemon startup and mirrored into the live sync engine
    (account_ctx_open_existing). A test that only ever talks to one
    already-running daemon process can't tell that apart from "the
    daemon just kept the rule in memory and never really wrote/read the
    file" — this test kills and restarts the same daemon against the
    same state_dir to actually exercise the on-disk round trip, not
    assume it.
    """
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_selsync_restart_server")))
    server.start()
    daemon_proc = None
    try:
        server.create_user(unique_username, password)

        state_dir = tmp_path_factory.mktemp("vw_selsync_restart_daemon")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            ipc_port = s.getsockname()[1]
        daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)

        rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_selsync_restart_root"))
        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)

        rc, out, err = _cli(cli_bin, ipc_port, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, ipc_port, "--account", unique_username,
                             "set-folder-rules", local_root,
                             "--exclude", "*.tmp", "--exclude", "*.bak")
        assert rc == 0, f"set-folder-rules failed: {out}\n{err}"

        # ── Kill and restart the SAME daemon against the SAME state_dir. ──
        daemon_proc.terminate()
        daemon_proc.wait(timeout=5)
        daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)

        rc, out, err = _cli(cli_bin, ipc_port, "--account", unique_username,
                             "list-folders")
        assert rc == 0, f"list-folders after restart failed: {out}\n{err}"
        assert "exclude: *.tmp" in out and "exclude: *.bak" in out, (
            f"exclude rules did not survive a daemon restart: {out!r}"
        )
    finally:
        if daemon_proc is not None:
            daemon_proc.terminate()
            try:
                daemon_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon_proc.kill()
        server.stop()
