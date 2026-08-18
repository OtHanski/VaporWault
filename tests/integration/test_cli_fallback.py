"""
test_cli_fallback.py — end-to-end integration test for TASK-172/173/174's
automatic read-only fallback feature, driven entirely through the real
`vapourwault-cli` binary against a real running daemon and a real
primary+replica server pair.

Reuses test_cluster.py's `ClusterNode`/pairing helpers for the primary and
replica (a fallback target must be an already-paired cluster replica, per
this feature's own design), and conftest.py's `running_daemon`/`cli_bin`
fixtures for the client side. Requires all three real processes and a real
cluster pairing, so — like test_cluster.py — this is marked `cluster` and
`slow` and excluded from the fast default run (`-m "not cluster"`).
"""

import os
import subprocess
import time

import pytest

from test_cluster import ClusterNode, _pair_nodes
from vw_client import VwClient

pytestmark = [pytest.mark.cluster, pytest.mark.slow]


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _account_conn_state(cli_bin, ipc_port, label):
    """Parse `account list`'s STATUS column for one account label."""
    rc, out, err = _cli(cli_bin, ipc_port, "account", "list")
    assert rc == 0, f"account list failed: {out}\n{err}"
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == label:
            return " ".join(parts[4:])
    return None


def _ls_sync_state(cli_bin, ipc_port, account, virtual_name):
    """Parse `ls`'s SYNC STATE column for one entry, matched by its NAME
    (last whitespace-separated field — every virtual path used by this
    module's tests is space-free)."""
    rc, out, err = _cli(cli_bin, ipc_port, "--account", account, "ls", "/")
    assert rc == 0, f"ls failed: {out}\n{err}"
    for line in out.splitlines()[1:]:
        parts = line.split()
        if parts and parts[-1] == virtual_name:
            return parts[0]
    return None


def test_cli_account_add_fallback_and_real_failover(
    binaries, tmp_path_factory, cli_bin, running_daemon, unique_username,
):
    """
    `account add --fallback-host/--fallback-port` round-trips correctly
    (TASK-174's first acceptance criterion), and `account list` accurately
    tracks the daemon's live connection state through a real primary
    outage and recovery (TASK-173's mechanism, TASK-174's second
    criterion): primary -> fallback (read-only) -> primary again, with a
    write attempt while on the fallback rejected rather than silently
    executed against it.
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_cli_fallback"))
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

        # Give the replica's poll thread + one sync pass (users.dat) time
        # to complete before the daemon tries to fail over to it.
        time.sleep(2)

        rc, out, err = _cli(
            cli_bin, running_daemon, "account", "add",
            primary.host, str(primary.port), unique_username, password,
            "--ca-cert", binaries.test_cert,
            "--fallback-host", replica.host,
            "--fallback-port", str(replica.port),
            "--fallback-ca-cert", binaries.test_cert,
        )
        assert rc == 0, f"account add with --fallback-* failed: {out}\n{err}"
        assert "fallback=" in out, f"account add did not confirm fallback config: {out}"

        state = _account_conn_state(cli_bin, running_daemon, unique_username)
        assert state == "primary", f"expected 'primary' right after add, got {state!r}"

        # A sync folder is what actually drives the daemon's round-robin
        # loop to attempt real network I/O every cycle — an account with
        # zero folders has nothing to notice the primary died until some
        # other IPC request happens to need the network, so this test
        # gives it one, matching how this feature is meant to be used in
        # practice (this is the same reason TASK-173's own acceptance
        # criteria phrases the check as "file list/download continue
        # working," not "the daemon polls the primary independently").
        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)
        with open(os.path.join(local_root, "hello.txt"), "w") as f:
            f.write("hello from the primary\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"

        # Let one sync cycle upload hello.txt while the primary is healthy.
        time.sleep(2)

        # ── Simulate a primary outage ──
        primary.stop()

        deadline = time.monotonic() + 15
        state = None
        while time.monotonic() < deadline:
            state = _account_conn_state(cli_bin, running_daemon, unique_username)
            if state == "fallback (read-only)":
                break
            time.sleep(0.3)
        assert state == "fallback (read-only)", (
            f"daemon never failed over to the read-only fallback (last state={state!r}) — "
            f"replica log:\n{replica.log_contents()}"
        )

        # ── A write attempt while on the fallback must be rejected, never
        # silently executed against the replica (the entire point of this
        # feature being read-only). share is a synchronous write-shaped IPC
        # request with no offline-queue equivalent (TASK-173) — the CLI has
        # no path to a file_id here without a synced folder, so this just
        # confirms the daemon rejects it up front rather than hanging or
        # succeeding; the exact wording is whatever this CLI already prints
        # for a nonzero daemon error code. ──
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "share", "/nonexistent", unique_username, "view")
        assert rc != 0, f"share must fail while on the read-only fallback: {out}\n{err}"

        # ── TASK-178: the milestone's own explicit acceptance criterion
        # this test didn't originally cover — a sync-engine upload attempt
        # (not just a synchronous no-queue-equivalent IPC call like `share`
        # above) must be QUEUED, not sent to the replica at all. ──
        with open(os.path.join(local_root, "queued.txt"), "w") as f:
            f.write("written while on the fallback\n")

        deadline = time.monotonic() + 10
        state = None
        while time.monotonic() < deadline:
            state = _ls_sync_state(cli_bin, running_daemon, unique_username, "/queued.txt")
            if state is not None:
                break
            time.sleep(0.3)
        assert state is not None and state != "synced", (
            f"queued.txt should show as a queued local change while on the "
            f"fallback, not disappear or show 'synced' (got {state!r})"
        )

        # Confirm it was never actually sent to the replica — connect
        # directly to the replica's own listener (independent of the
        # daemon/fallback session entirely) and list the root.
        rc_client = VwClient(replica.host, replica.port, binaries.test_cert)
        try:
            tok = rc_client.login(unique_username, password)["session_token"]
            names = {e["name"] for e in rc_client.file_list(tok, "/")}
            assert "queued.txt" not in names, (
                "queued.txt reached the replica while the daemon was "
                "supposedly treating it as read-only"
            )
        finally:
            rc_client.close()

        # ── Bring the primary back; the daemon must reconnect to it (not
        # stay parked on the fallback indefinitely) within a few cycles. ──
        primary.start()

        deadline = time.monotonic() + 15
        state = None
        while time.monotonic() < deadline:
            state = _account_conn_state(cli_bin, running_daemon, unique_username)
            if state == "primary":
                break
            time.sleep(0.3)
        assert state == "primary", (
            f"daemon never reconnected to the primary after it came back (last state={state!r})"
        )

        # The queued write must now actually land — on the PRIMARY, not the
        # replica (that would mean the daemon somehow flushed the queue to
        # the wrong server).
        deadline = time.monotonic() + 15
        state = None
        while time.monotonic() < deadline:
            state = _ls_sync_state(cli_bin, running_daemon, unique_username, "/queued.txt")
            if state == "synced":
                break
            time.sleep(0.3)
        assert state == "synced", (
            f"queued write was never flushed to the primary after reconnect (last state={state!r})"
        )

        pc_client = VwClient(primary.host, primary.port, binaries.test_cert)
        try:
            tok = pc_client.login(unique_username, password)["session_token"]
            names = {e["name"] for e in pc_client.file_list(tok, "/")}
            assert "queued.txt" in names, "queued write never actually reached the primary"
        finally:
            pc_client.close()
    finally:
        if replica is not None:
            replica.stop()
        primary.stop()


def _generate_mismatched_cert(tmp_path):
    """A throwaway self-signed cert/key pair that does NOT match the
    replica's real certificate — for proving TLS verification against the
    fallback is genuinely enforced, not silently skipped."""
    cert = str(tmp_path / "wrong.crt")
    key = str(tmp_path / "wrong.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", key, "-out", cert, "-days", "1", "-nodes",
         "-subj", "/CN=not-the-real-replica",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True, timeout=30,
    )
    return cert


def test_cli_fallback_rejects_mismatched_ca_cert(
    binaries, tmp_path_factory, cli_bin, running_daemon, unique_username,
):
    """
    Regression test for TASK-173's own security note ("same
    VW_CERT_VERIFY_REQUIRED requirement as the primary ... never
    optional/defaulted") per CLAUDE.md's standing rule that every resolved
    SEC.07 finding gets a regression test. A `--fallback-ca-cert` that
    does not actually match the replica's real certificate must make every
    fallback connection attempt fail — proving certificate verification
    for the fallback path is genuinely enforced against a real mismatch,
    not merely an argument-presence check (`TASK-177` found and documented
    the distinct, narrower case of *omitting* the flag entirely — this
    test is the complementary "a cert is present but wrong" case).
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_cli_fallback_wrong_cert"))
    wrong_cert = _generate_mismatched_cert(tmp_path_factory.mktemp("wrong_cert"))
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
        time.sleep(2)

        rc, out, err = _cli(
            cli_bin, running_daemon, "account", "add",
            primary.host, str(primary.port), unique_username, password,
            "--ca-cert", binaries.test_cert,
            "--fallback-host", replica.host,
            "--fallback-port", str(replica.port),
            "--fallback-ca-cert", wrong_cert,
        )
        assert rc == 0, f"account add failed: {out}\n{err}"

        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)
        with open(os.path.join(local_root, "hello.txt"), "w") as f:
            f.write("hello\n")
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        time.sleep(2)

        primary.stop()

        # Give it every chance a real failover would need — if it never
        # shows up, that's the point: the mismatched cert must never be
        # silently accepted.
        deadline = time.monotonic() + 15
        state = None
        while time.monotonic() < deadline:
            state = _account_conn_state(cli_bin, running_daemon, unique_username)
            if state == "fallback (read-only)":
                break
            time.sleep(0.3)
        assert state != "fallback (read-only)", (
            "daemon connected to the fallback despite a --fallback-ca-cert "
            "that does not match the replica's real certificate — TLS "
            "verification for the fallback path is not actually enforced"
        )
        assert state == "offline", (
            f"expected 'offline' (mismatched cert must fail closed), got {state!r}"
        )
    finally:
        if replica is not None:
            replica.stop()
        primary.stop()
