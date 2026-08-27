"""
test_cli_version_fallback.py — TASK-184's fallback-rejection acceptance
criterion for TASK-182's `version restore`: a real primary+replica pair,
a real failover, and a real `vapourwault-cli version restore` attempt
while parked on the read-only fallback (must be rejected, never sent to
the replica) — same style and fixtures as test_cli_fallback.py, which
covers the equivalent case for `share`.

Marked `cluster`/`slow` for the same reason test_cli_fallback.py is:
requires two real server processes and a real cluster pairing.
"""

import os
import subprocess
import time

import pytest

from test_cluster import ClusterNode, _pair_nodes

pytestmark = [pytest.mark.cluster, pytest.mark.slow]


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _account_conn_state(cli_bin, ipc_port, label):
    rc, out, err = _cli(cli_bin, ipc_port, "account", "list")
    assert rc == 0, f"account list failed: {out}\n{err}"
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == label:
            return " ".join(parts[4:])
    return None


def test_cli_version_restore_rejected_on_fallback(
    binaries, tmp_path_factory, cli_bin, running_daemon, unique_username,
):
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_cli_version_fallback"))
    primary = ClusterNode(binaries, tmpdir, "primary")
    replica = None
    try:
        primary.start()
        replica = ClusterNode(
            binaries, tmpdir, "replica",
            is_replica=True, primary_host="127.0.0.1", primary_port=primary.cluster_port,
        )
        replica.start()
        _pair_nodes(primary, replica)

        password = "TestP@ssw0rd!"
        primary.create_user(unique_username, password)
        time.sleep(2)  # replica poll thread + one sync pass (users.dat)

        rc, out, err = _cli(
            cli_bin, running_daemon, "account", "add",
            primary.host, str(primary.port), unique_username, password,
            "--ca-cert", binaries.test_cert,
            "--fallback-host", replica.host,
            "--fallback-port", str(replica.port),
            "--fallback-ca-cert", binaries.test_cert,
        )
        assert rc == 0, f"account add with --fallback-* failed: {out}\n{err}"

        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)
        with open(os.path.join(local_root, "notes.txt"), "w") as f:
            f.write("version one\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        time.sleep(2)  # let the initial upload complete while the primary is healthy

        # ── Simulate a primary outage and wait for failover ──
        primary.stop()
        deadline = time.monotonic() + 15
        state = None
        while time.monotonic() < deadline:
            state = _account_conn_state(cli_bin, running_daemon, unique_username)
            if state == "fallback (read-only)":
                break
            time.sleep(0.3)
        assert state == "fallback (read-only)", (
            f"daemon never failed over to the read-only fallback (last state={state!r})"
        )

        # ── version restore is write-shaped (TASK-182) — must be rejected
        # up front, never sent to the replica. ──
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "version", "restore", "/notes.txt", "1")
        assert rc != 0, f"version restore must fail while on the read-only fallback: {out}\n{err}"

        # ── version list is a read — must keep working against the fallback. ──
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "version", "list", "/notes.txt")
        assert rc == 0, f"version list should still work against the fallback: {out}\n{err}"
    finally:
        primary.stop()
        if replica is not None:
            replica.stop()
