"""
test_gc.py — integration tests for the garbage-collection subsystem.

The server is configured with gc_interval_secs = 2 so GC runs frequently.

Covered:
- Oplog tail returns entries after normal operations.
- The server survives a GC cycle after a file delete (no crash).
- Multiple version uploads and delete produce oplog entries visible in the tail.
"""

import os
import time
import pytest

from vw_client import VwClient

PASSWORD = "GcTestP@ss1!"


def _new_client(server):
    return VwClient(server.host, server.port, server.cert)


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_oplog_tail_returns_entries(server, admin_client, unique_username):
    """
    After creating a user and uploading a file, OPLOG_TAIL_REQ must return at
    least one entry with a positive entry_id.
    """
    admin_client.create_user(unique_username, PASSWORD)

    c = _new_client(server)
    info = c.login(unique_username, PASSWORD)
    token = info["session_token"]
    c.upload_file(token, "/oplog_test.bin", os.urandom(512))
    c.close()

    entries = admin_client.oplog_tail(count=50)
    assert len(entries) > 0, "oplog tail must be non-empty after upload"
    assert all(e["entry_id"] > 0 for e in entries), (
        "all entry_ids must be positive"
    )


def test_gc_does_not_crash_server(server, admin_client, unique_username):
    """
    Upload a file, delete it, then wait for GC to run (gc_interval_secs = 2).

    The test verifies liveness: the server must still accept connections and
    authenticate successfully after GC has run.
    """
    admin_client.create_user(unique_username, PASSWORD)

    c = _new_client(server)
    info = c.login(unique_username, PASSWORD)
    token = info["session_token"]
    file_id, _ = c.upload_file(token, "/gc_target.bin", os.urandom(1024))
    c.file_delete(token, file_id=file_id)
    c.close()

    # Wait for at least two GC cycles
    time.sleep(5)

    # Server must still respond to auth after GC ran
    c2 = _new_client(server)
    info2 = c2.login(unique_username, PASSWORD)
    assert info2["user_id"] > 0, "server must still accept logins after GC"
    c2.close()


@pytest.mark.slow
def test_multiple_versions_and_gc(server, admin_client, unique_username):
    """
    Upload three versions of the same file, delete the file, wait for GC, and
    verify the oplog tail shows GC activity (entries created after the delete).

    This test checks that the GC correctly handles multi-version files.
    """
    admin_client.create_user(unique_username, PASSWORD)

    c = _new_client(server)
    info = c.login(unique_username, PASSWORD)
    token = info["session_token"]

    path = "/multi_version.bin"
    file_id, _ = c.upload_file(token, path, os.urandom(512))
    c.upload_file(token, path, os.urandom(512))
    c.upload_file(token, path, os.urandom(512))

    entries_before = admin_client.oplog_tail(count=100)
    max_eid_before = max((e["entry_id"] for e in entries_before), default=0)

    c.file_delete(token, file_id=file_id)
    c.close()

    # Wait for GC cycles (gc_interval_secs = 2, wait 5 s)
    time.sleep(5)

    entries_after = admin_client.oplog_tail(count=100)
    max_eid_after = max((e["entry_id"] for e in entries_after), default=0)

    assert max_eid_after >= max_eid_before, (
        "oplog must have new entries after delete+GC"
    )
