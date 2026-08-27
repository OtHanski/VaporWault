"""
test_search.py — pytest wrapper for TASK-198's C-level integration test.

Same rationale as test_shared_sync.py: the actual test logic lives in the
compiled C binary test_search (from test_search.c), which links
vw_client_core.c directly and hand-drives the real SEARCH/SEARCH_RESP wire
message (docs/PROTOCOL.md §7.12) against a real server, rather than a
Python reimplementation of the wire protocol.

This file's only job is to spawn the server, create the three users the C
binary needs (an owner, a grantee with a VIEW grant on one of the owner's
folders, and a stranger with no access at all — SEARCH's permission-safety
property is inherently a three-party scenario: owner, someone who should
see a match, and someone who must not), and hand connection details to the
subprocess.
"""

import subprocess

import pytest

from conftest import _find_client_bin


@pytest.fixture(scope="module")
def search_bin():
    # TASK-217: folded into the one shared search-order helper instead of
    # this file's own copy of the list (this copy already had
    # build-gw-e2e/bin first, from when this file was written — but a
    # second copy of a search order is exactly what let every earlier
    # copy drift and miss it, so it's folded in here too rather than left
    # as one more list to keep in sync by hand).
    path = _find_client_bin("test_search")
    if not path:
        pytest.skip("test_search binary not found (build it first)")
    return path


def test_search_permission_safety(server, admin_client, search_bin, unique_username):
    """
    Runs the compiled test_search C binary against this module's real
    server, with three users: an owner (creates a shared folder + files and
    grants VIEW to the grantee), a grantee (should see only the shared
    file via search), and a stranger (should see nothing at all). See
    test_search.c's header comment for the full list of TAP-style
    assertions this exercises — this test's only assertion is the
    process's exit code, with stdout surfaced on failure the same way
    test_shared_folder_sync_full_lifecycle does.
    """
    password = "TestP@ssw0rd!"
    owner_username = f"{unique_username}_owner"
    grantee_username = f"{unique_username}_grantee"
    stranger_username = f"{unique_username}_stranger"
    server.create_user(owner_username, password)
    server.create_user(grantee_username, password)
    server.create_user(stranger_username, password)

    result = subprocess.run(
        [search_bin, server.host, str(server.port), server.cert,
         owner_username, password, grantee_username, password,
         stranger_username, password],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)

    assert result.returncode == 0, (
        f"test_search exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
