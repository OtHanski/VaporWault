"""
test_shared_sync.py — pytest wrapper for TASK-106's C-level integration test.

Same rationale as test_vault_e2ee.py: the actual test logic lives in the
compiled C binary test_shared_sync (from test_shared_sync.c), which links
vw_client_core.c + vw_cache.c + vw_sync.c directly and drives the real
production sync engine's shared-folder branch against a real server, rather
than a Python reimplementation of the wire protocol.

This file's only job is to spawn the server, create the two users the C
binary needs (an owner and a grantee — this is the one integration test in
this directory that needs two, since shared-folder sync is inherently a
two-party scenario), and hand connection details to the subprocess.
"""

import subprocess

import pytest

from conftest import _find_client_bin


@pytest.fixture(scope="module")
def shared_sync_bin():
    # TASK-217: was a hand-rolled search list missing build-gw-e2e/bin;
    # now the one shared helper conftest.py's daemon_bin/cli_bin fixtures
    # already use, so this and every other wrapper drift the same way if
    # the search order ever needs to change again.
    path = _find_client_bin("test_shared_sync")
    if not path:
        pytest.skip("test_shared_sync binary not found (build it first)")
    return path


def test_shared_folder_sync_full_lifecycle(server, admin_client, shared_sync_bin, unique_username):
    """
    Runs the compiled test_shared_sync C binary against this module's real
    server, with two users: an owner (who creates the shared folder and
    grants EDIT access) and a grantee (whose sync engine syncs it). See
    test_shared_sync.c's header comment for the full list of TAP-style
    assertions this exercises — this test's only assertion is the process's
    exit code, with stdout surfaced on failure the same way
    test_vault_e2ee_full_roundtrip does.
    """
    password = "TestP@ssw0rd!"
    owner_username = f"{unique_username}_owner"
    grantee_username = f"{unique_username}_grantee"
    server.create_user(owner_username, password)
    server.create_user(grantee_username, password)

    result = subprocess.run(
        [shared_sync_bin, server.host, str(server.port), server.cert,
         owner_username, password, grantee_username, password],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)

    assert result.returncode == 0, (
        f"test_shared_sync exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
