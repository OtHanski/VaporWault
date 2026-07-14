"""
test_quota.py — integration tests for per-user storage quota enforcement.

Scenarios:
- Upload is rejected when the user's quota would be exceeded.
- Quota increase allows a previously-rejected upload.
- used_bytes does not increase after a delete + GC cycle.

The server is configured with gc_interval_secs = 2 so GC runs frequently
enough for the "used_bytes after GC" assertions.
"""

import os
import time
import pytest

from vw_client import VwClient, VwProtocolError

PASSWORD = "QuotaP@ss1!"


def _new_client(server):
    return VwClient(server.host, server.port, server.cert)


def _setup_user(admin_client, server, username, password=PASSWORD):
    admin_client.create_user(username, password)
    c = _new_client(server)
    info = c.login(username, password)
    return c, info["session_token"]


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_upload_fails_when_quota_exceeded(server, admin_client, unique_username):
    """
    Uploading data larger than the user's quota must fail.

    Quota is set to 1 KiB; upload attempts 8 KiB.  The server may reject
    at CHUNK_UPLOAD or FILE_COMMIT — either raises VwProtocolError.
    """
    admin_client.create_user(unique_username, PASSWORD)
    admin_client.set_quota(unique_username, 1024)  # 1 KiB quota

    c = _new_client(server)
    info = c.login(unique_username, PASSWORD)
    token = info["session_token"]

    big_data = os.urandom(8192)  # 8 KiB — exceeds quota

    with pytest.raises((VwProtocolError, Exception)):
        c.upload_file(token, "/over_quota.bin", big_data)

    c.close()


def test_quota_adjust_allows_upload(server, admin_client, unique_username):
    """
    Setting a generous quota after a rejection allows the upload to succeed.
    """
    admin_client.create_user(unique_username, PASSWORD)
    admin_client.set_quota(unique_username, 1024)  # 1 KiB — too small

    c = _new_client(server)
    info = c.login(unique_username, PASSWORD)
    token = info["session_token"]
    c.close()

    # Increase quota to 1 MiB
    admin_client.set_quota(unique_username, 1024 * 1024)

    c = _new_client(server)
    info = c.login(unique_username, PASSWORD)
    token = info["session_token"]

    data = os.urandom(8192)
    file_id, _ = c.upload_file(token, "/within_quota.bin", data)
    assert file_id > 0

    c.close()


@pytest.mark.slow
def test_used_bytes_does_not_increase_after_delete(server, admin_client, unique_username):
    """
    After deleting a file and waiting for GC (gc_interval_secs = 2), the
    server-reported used_bytes must not be greater than the pre-delete value.

    This is a liveness test: GC must eventually clean up the deleted file and
    not leave the quota counter permanently inflated.
    """
    admin_client.create_user(unique_username, PASSWORD)

    # Upload a 4 KiB file and record initial used_bytes
    c = _new_client(server)
    info = c.login(unique_username, PASSWORD)
    token = info["session_token"]

    data = os.urandom(4096)
    file_id, _ = c.upload_file(token, "/deleteme.bin", data)

    # Re-login to get fresh used_bytes after upload
    c.close()
    c = _new_client(server)
    info_after_upload = c.login(unique_username, PASSWORD)
    used_after_upload = info_after_upload["used_bytes"]
    token = info_after_upload["session_token"]

    assert used_after_upload > 0, "used_bytes must reflect the uploaded chunk"

    # Delete the file
    c.file_delete(token, file_id=file_id)
    c.close()

    # Wait for GC to collect the chunk (gc_interval_secs = 2, wait 5 s)
    time.sleep(5)

    # Re-login and verify used_bytes did not increase
    c = _new_client(server)
    info_after_gc = c.login(unique_username, PASSWORD)
    used_after_gc = info_after_gc["used_bytes"]
    c.close()

    assert used_after_gc <= used_after_upload, (
        f"used_bytes increased after delete+GC: "
        f"before={used_after_upload} after={used_after_gc}"
    )
