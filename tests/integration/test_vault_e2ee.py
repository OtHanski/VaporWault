"""
test_vault_e2ee.py — pytest wrapper for TASK-099's C-level integration test.

Unlike every other file in this directory, the actual test logic here is
NOT Python — it's in the compiled C binary test_vault_e2ee (built from
test_vault_e2ee.c), which links vw_client_core.c + vw_vault.c directly and
exercises the real production client code (not a Python reimplementation
of the wire protocol, which is all vw_client.py is). This was a deliberate
choice (see TASK-099's notes) over the two alternatives: hand-wiring
a full server context in C (like test_auth_handshake.c does, but that
pattern only wires up the auth handshake, not the file-op dispatch loop),
or reimplementing the crypto in Python (which would never call vw_vault.c
at all).

This file's only job is what every other pytest file in this directory
already does for the real server: spawn it (via the `server` fixture),
create a user (via the `admin_client` fixture), then hand connection
details to something that speaks the wire protocol — except here that
"something" is a subprocess, not an in-process VwClient.
"""

import subprocess

import pytest

from conftest import _find_client_bin


@pytest.fixture(scope="module")
def vault_e2ee_bin():
    # TASK-217: this used to hand-roll its own search list with the
    # stated rationale "not folded into conftest.py's shared helper since
    # it resolves a test-only binary, not a product binary" — that
    # distinction doesn't actually matter for a directory *search order*
    # (the helper is already generic over the binary name), and the
    # separate copy is exactly what let this list drift and miss
    # build-gw-e2e/bin while conftest.py's own copy got it. Folded in.
    path = _find_client_bin("test_vault_e2ee")
    if not path:
        pytest.skip("test_vault_e2ee binary not found (build it first)")
    return path


def test_vault_e2ee_full_roundtrip(server, admin_client, vault_e2ee_bin, unique_username):
    """
    Runs the compiled test_vault_e2ee C binary against this module's real
    server. The C binary itself contains the individual TAP-style
    assertions (see test_vault_e2ee.c's header comment for the full list);
    this test's only assertion is the process's exit code, with stdout
    surfaced on failure so a broken assertion is diagnosable from CI logs
    without needing to reproduce locally.
    """
    password = "TestP@ssw0rd!"
    server.create_user(unique_username, password)

    result = subprocess.run(
        [vault_e2ee_bin, server.host, str(server.port), server.cert,
         unique_username, password],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)

    assert result.returncode == 0, (
        f"test_vault_e2ee exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
