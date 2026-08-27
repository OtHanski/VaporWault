"""
test_daemon_multi_account.py — pytest wrapper for TASK-161's C-level
integration test.

Same rationale as test_shared_sync.py: the actual test logic lives in the
compiled C binary test_daemon_multi_account (from
test_daemon_multi_account.c), which links vw_client_core.c + vw_cache.c +
vw_sync.c directly and replicates vw_daemon_run()'s new round-robin
multi-account loop, rather than a Python reimplementation of the wire
protocol.

This file's only job is to spawn TWO fully independent vapourwaultd
processes (not one server with two users — see the 2026-08-13 design
revision recorded in ARCHITECTURE.md's "Accounts are per-server, not just
per-user": a user may add accounts on two unrelated self-hosted servers on
the same client), create one user on each, and hand both connection specs
to the subprocess.
"""

import subprocess

import pytest

from conftest import ServerInstance, _find_client_bin


@pytest.fixture(scope="module")
def multi_account_bin():
    # TASK-217: folded into the one shared search-order helper
    # (conftest.py's daemon_bin/cli_bin fixtures already use it) instead
    # of this file's own copy of the list — a stale binary elsewhere
    # winning silently over this session's own known-current build is
    # exactly the failure mode a single shared helper avoids by
    # construction, rather than by every copy remembering to order
    # build-gw-e2e/bin first on its own.
    path = _find_client_bin("test_daemon_multi_account")
    if not path:
        pytest.skip("test_daemon_multi_account binary not found (build it first)")
    return path


def test_daemon_multi_account_round_robin(binaries, tmp_path_factory, multi_account_bin, unique_username):
    """
    Runs the compiled test_daemon_multi_account C binary against TWO
    genuinely independent, freshly-spawned vapourwaultd processes (own data
    dir, own port, own admin socket each) — not one server with two users —
    proving every configured account keeps making sync progress on its own
    (TASK-161's round-robin loop) even when each account is talking to a
    completely different server, with real cross-server isolation (account
    A cannot see account B's file, and vice versa — unsurprising given
    they're different servers entirely, but this is the concrete proof the
    2026-08-13 design revision's claim rests on) and no cross-account side
    effects when only one account's cycle runs. See
    test_daemon_multi_account.c's header comment for the full list of
    TAP-style assertions this exercises — this test's only assertion is
    the process's exit code, with stdout surfaced on failure the same way
    test_shared_folder_sync_full_lifecycle does.
    """
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    user_a = f"{unique_username}_a"
    user_b = f"{unique_username}_b"

    server_a = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_server_a")))
    server_b = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_server_b")))
    server_a.start()
    server_b.start()
    try:
        server_a.create_user(user_a, password)
        server_b.create_user(user_b, password)

        result = subprocess.run(
            [multi_account_bin,
             server_a.host, str(server_a.port), server_a.cert, user_a, password,
             server_b.host, str(server_b.port), server_b.cert, user_b, password],
            capture_output=True, text=True, timeout=120,
        )
    finally:
        server_a.stop()
        server_b.stop()

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)

    assert result.returncode == 0, (
        f"test_daemon_multi_account exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
