"""
test_gateway_fallback.py — end-to-end integration test for TASK-176's
gateway-level automatic read-only fallback, driven through the real
`vapourwault-web-gateway` HTTP/JSON API against a real primary+replica
server pair (reusing test_cluster.py's `ClusterNode`/pairing helpers, same
as test_cli_fallback.py does for the daemon side).

Requires all three real processes (primary, replica, gateway) and a real
cluster pairing — marked `cluster`/`slow` and excluded from the fast
default run (`-m "not cluster"`), same convention as test_cluster.py.
"""

import subprocess
import time

import pytest

from conftest import GatewayInstance
from test_cluster import ClusterNode, _pair_nodes
from test_gateway import GatewayClient

pytestmark = [pytest.mark.cluster, pytest.mark.slow]

PASSWORD = "GatewayFallbackP@ss1"


def test_gateway_login_fails_over_to_read_only_fallback(
    binaries, tmp_path_factory, unique_username,
):
    """
    With the primary reachable, login and every subsequent request go to
    it, and /api/accounts reports read_only=false (TASK-176's first
    acceptance criterion). With the primary killed, a fresh login
    transparently fails over to the already-paired replica, /api/accounts
    reports read_only=true, reads (files/list) keep working, and a write
    (files/mkdir) is cleanly rejected with 503 read_only_fallback rather
    than attempted against the replica (TASK-176's third criterion).
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_gw_fallback"))
    primary = ClusterNode(binaries, tmpdir, "primary")
    replica = None
    gateway = None
    try:
        primary.start()
        replica = ClusterNode(
            binaries, tmpdir, "replica",
            is_replica=True, primary_host="127.0.0.1", primary_port=primary.cluster_port,
        )
        replica.start()
        _pair_nodes(primary, replica)

        primary.create_user(unique_username, PASSWORD)
        # Let the replica's poll thread pull + apply one sync pass
        # (store/users.dat) before the gateway ever needs it.
        time.sleep(2)

        gateway = GatewayInstance(binaries, primary, fallback=replica)
        gateway.start()

        client = GatewayClient(gateway)
        r = client.login(unique_username, PASSWORD)
        assert r.status_code == 200 and r.json().get("status") == "ok", r.text

        r = client.accounts()
        assert r.status_code == 200, r.text
        slots = r.json()["slots"]
        assert any(s["username"] == unique_username and s["read_only"] is False
                   for s in slots), f"expected a non-read-only slot: {slots}"
        client.logout()

        # ── Simulate a primary outage ──
        primary.stop()

        client2 = GatewayClient(gateway)
        r = client2.login(unique_username, PASSWORD)
        assert r.status_code == 200 and r.json().get("status") == "ok", (
            f"login did not fail over to the fallback: {r.status_code} {r.text}"
        )

        r = client2.accounts()
        assert r.status_code == 200, r.text
        slots = r.json()["slots"]
        assert any(s["username"] == unique_username and s["read_only"] is True
                   for s in slots), f"expected a read-only slot after failover: {slots}"

        # Reads still work against the fallback.
        r = client2.list_files("/")
        assert r.status_code == 200, f"file list against the fallback failed: {r.text}"

        # A write must be cleanly rejected, never silently attempted
        # against the read-only fallback.
        r = client2.mkdir("should_not_be_created")
        assert r.status_code == 503, f"mkdir should be rejected while read-only: {r.text}"
        assert r.json().get("status") == "read_only_fallback", r.text

        # ── TASK-178: the milestone's own acceptance criterion this test
        # didn't originally cover — "confirm normal read-write resumes
        # once the primary is back." A read-only session that was already
        # established stays read-only for its own lifetime (no persistent
        # per-session state at the gateway to silently upgrade — see
        # TASK-176's own note on why remember-me deliberately never
        # upgrades either); what must resume is a *fresh* login. ──
        primary.start()

        deadline = time.monotonic() + 20
        resumed = False
        r = None
        while time.monotonic() < deadline:
            client3 = GatewayClient(gateway)
            r = client3.login(unique_username, PASSWORD)
            if r.status_code == 200 and r.json().get("status") == "ok":
                accts = client3.accounts().json()["slots"]
                if any(s["username"] == unique_username and s["read_only"] is False
                       for s in accts):
                    resumed = True
                    break
            time.sleep(0.5)
        assert resumed, (
            f"gateway never resumed normal (non-read-only) login after the "
            f"primary came back — last response: {r.status_code if r else None} "
            f"{r.text if r else None}"
        )

        # A write must actually succeed again too, not just report read_only=false.
        r = client3.mkdir("created_after_primary_restart")
        assert r.status_code == 200, f"mkdir should succeed once resumed: {r.text}"
    finally:
        if gateway is not None:
            gateway.stop()
        if replica is not None:
            replica.stop()
        primary.stop()


def test_gateway_without_fallback_configured_is_unaffected(
    binaries, tmp_path_factory, server, unique_username,
):
    """TASK-176's first acceptance criterion: with no --fallback-* flags
    passed at all, behavior is completely unchanged from before this task
    — a normal login/logout round trip against the module-scoped `server`
    fixture (reused across the whole test_gateway.py suite), with no
    fallback configured."""
    binaries.require_server()
    binaries.require_tls()

    gateway = GatewayInstance(binaries, server)  # fallback=None (default)
    gateway.start()
    try:
        server.create_user(unique_username, PASSWORD)
        client = GatewayClient(gateway)
        r = client.login(unique_username, PASSWORD)
        assert r.status_code == 200 and r.json().get("status") == "ok", r.text

        r = client.accounts()
        assert r.status_code == 200, r.text
        slots = r.json()["slots"]
        assert any(s["username"] == unique_username and s["read_only"] is False
                   for s in slots), slots
        client.logout()
    finally:
        gateway.stop()


def test_gateway_refuses_to_start_without_fallback_ca_cert(binaries, server):
    """
    Regression test for TASK-176's own security note ("`--fallback-ca-cert`
    is mandatory whenever a fallback host/port is set, never defaulted or
    optional") per CLAUDE.md's standing rule that every resolved SEC.07
    finding gets a regression test. `--fallback-server-host`/`-port`
    without `--fallback-ca-cert` must make the gateway refuse to start
    entirely (a loud, immediate failure) rather than starting with TLS
    verification silently disabled or deferred for the fallback connection.
    """
    binaries.require_server()
    binaries.require_gateway()
    binaries.require_tls()

    args = [
        binaries.gateway_bin,
        "--server-host", server.host, "--server-port", str(server.port),
        "--ca-cert", server.cert,
        "--listen-host", "127.0.0.1", "--listen-port", "0",
        "--fallback-server-host", "127.0.0.1",
        "--fallback-server-port", "1",
        # --fallback-ca-cert deliberately omitted
    ]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise AssertionError(
            "gateway started (and kept running) with a fallback host/port "
            "configured but no --fallback-ca-cert — it must refuse to start"
        )
    assert rc != 0, "gateway must exit non-zero when --fallback-ca-cert is missing"
