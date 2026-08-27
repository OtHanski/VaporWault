"""
test_shared_sync_hardening.py — pytest wrapper for TASK-111's C-level
regression test.

Same rationale as test_shared_sync.py: the actual test logic lives in the
compiled C binary test_shared_sync_hardening (from
test_shared_sync_hardening.c), which links vw_client_core.c + vw_cache.c +
vw_sync.c directly (built with VW_SYNC_TEST_HOOKS so it can deterministically
inject the subdirectory-delete race — see that file's header comment) and
drives the real production sync engine against a real server.

This file's only job is to spawn the server, create the owner/grantee users,
and hand connection details to the subprocess.
"""

import subprocess

import pytest

from conftest import _find_client_bin


@pytest.fixture(scope="module")
def hardening_bin():
    # TASK-217: shared search-order helper, see test_shared_sync.py's
    # own note on why (was a hand-rolled list missing build-gw-e2e/bin).
    path = _find_client_bin("test_shared_sync_hardening")
    if not path:
        pytest.skip("test_shared_sync_hardening binary not found (build it first)")
    return path


def test_shared_sync_hardening(server, admin_client, hardening_bin, unique_username):
    """
    Runs the compiled test_shared_sync_hardening C binary against this
    module's real server, with an owner and a grantee. See
    test_shared_sync_hardening.c's header comment for the full list of
    TAP-style assertions this exercises (TASK-111's two hardening findings) —
    this test's only assertion is the process's exit code, with stdout
    surfaced on failure the same way test_shared_folder_sync_full_lifecycle
    does.
    """
    password = "TestP@ssw0rd!"
    owner_username = f"{unique_username}_owner"
    grantee_username = f"{unique_username}_grantee"
    server.create_user(owner_username, password)
    server.create_user(grantee_username, password)

    result = subprocess.run(
        [hardening_bin, server.host, str(server.port), server.cert,
         owner_username, password, grantee_username, password],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)

    assert result.returncode == 0, (
        f"test_shared_sync_hardening exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
