"""
test_vault_regression.py — pytest wrapper for TASK-101's E2EE regression
suite.

Like test_vault_e2ee.py, the actual test logic is a compiled C binary
(test_vault_regression, from test_vault_regression.c) that links
vw_client_core.c + vw_vault.c directly and exercises the real production
client code — see that file's header for exactly which scenarios it
covers (dedup-defeat, key-loss scoping, multi-chunk round-trip,
realistic-scale retry safety).

This file adds the one scenario the C binary cannot do itself: server
opacity. After the C binary uploads its distinctive MARKER string as
encrypted content, this test does a black-box scan of the server's raw
on-disk storage (every file under server.data_dir) and asserts the marker
never appears anywhere in it — format-agnostic (it doesn't need to know
chunks.blob's/versions.blob's internal layout), which is exactly the
point: no plaintext should be recoverable no matter how you look at the
raw bytes.
"""

import os
import subprocess

import pytest

# Must match test_vault_regression.c's MARKER macro exactly.
MARKER = b"VW_E2EE_REGRESSION_MARKER_98237456_do_not_change_without_updating_the_py_wrapper"


def _find_regression_bin():
    name = "test_vault_regression.exe" if os.name == "nt" else "test_vault_regression"
    for d in ("build/bin", "build-release/bin", "../build/bin",
              "build-wsl-werror/bin", "build-wsl/bin"):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


@pytest.fixture(scope="module")
def regression_bin():
    path = _find_regression_bin()
    if not path:
        pytest.skip("test_vault_regression binary not found (build it first)")
    return path


def _scan_dir_for_marker(root):
    """Return the path of the first file under root whose raw bytes
    contain MARKER, or None if no file does."""
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            if MARKER in data:
                return path
    return None


def test_vault_e2ee_regression_suite(server, admin_client, regression_bin, unique_username):
    """
    Runs the compiled test_vault_regression C binary (dedup-defeat,
    key-loss scoping, multi-chunk round-trip, realistic-scale retry
    safety — see test_vault_regression.c's header for the full list),
    then scans the server's raw on-disk storage for the plaintext marker
    the binary uploaded, asserting it is never observable server-side
    (server opacity — the last item in TASK-101's scope that the C binary
    itself has no access point for).
    """
    password = "TestP@ssw0rd!"
    server.create_user(unique_username, password)

    result = subprocess.run(
        [regression_bin, server.host, str(server.port), server.cert,
         unique_username, password],
        capture_output=True, text=True, timeout=180,
    )

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)

    assert result.returncode == 0, (
        f"test_vault_regression exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    # Sanity: the marker really was uploaded as *plaintext* somewhere
    # locally reachable, so a hit in server storage would be meaningful
    # and not just "the marker never existed anywhere." The C binary
    # writes it to a local temp file which it deletes at the end, so we
    # don't re-check that here — the binary's own "upload plaintext copy"
    # checks already confirm the upload succeeded, which is our proof the
    # marker was sent to the server (as ciphertext, for the encrypted
    # copies, and as literal plaintext for the one unencrypted copy).

    hit = _scan_dir_for_marker(server.data_dir)
    assert hit is None, (
        f"server opacity violated: plaintext marker found in server-side storage at {hit!r} "
        f"— an encrypted file's content must never be recoverable from raw server storage"
    )
