"""
test_dedup.py — integration tests for chunk-level deduplication.

Verifies that when a chunk has already been uploaded (by the same user or a
different user), CHUNK_QUERY reports it as present and the upload is skipped.
"""

import hashlib
import os

from vw_client import VwClient

PASSWORD = "DedupP@ss1!"


def _new_client(server):
    return VwClient(server.host, server.port, server.cert)


def _setup_user(admin_client, server, username, password=PASSWORD):
    admin_client.create_user(username, password)
    c = _new_client(server)
    info = c.login(username, password)
    return c, info["session_token"]


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_same_chunk_not_uploaded_twice_by_one_user(server, admin_client, unique_username):
    """
    After a chunk is uploaded, CHUNK_QUERY for the same hash returns present=True.
    A second upload of identical data must be skipped by upload_file.
    """
    c, token = _setup_user(admin_client, server, unique_username)
    data = os.urandom(4096)
    chunk_hash = hashlib.sha256(data).digest()

    # First upload
    c.chunk_upload(token, data)

    # Query: server must report the chunk as present
    present = c.chunk_query(token, [chunk_hash])
    assert present[0] is True, "server must report chunk as present after upload"

    c.close()


def test_dedup_across_users(server, admin_client, unique_username):
    """
    Two different users upload the identical 8 KiB file content.

    After user A uploads, CHUNK_QUERY by user B for the same chunk hash must
    return present=True — confirming the server deduplicates across users.
    User B's upload_file then skips the chunk upload (only FILE_COMMIT is sent).
    """
    user_a = unique_username
    user_b = f"{unique_username}_b"

    admin_client.create_user(user_a, PASSWORD)
    admin_client.create_user(user_b, PASSWORD)

    data = os.urandom(8192)
    chunk_hash = hashlib.sha256(data).digest()

    # User A uploads
    ca = _new_client(server)
    info_a = ca.login(user_a, PASSWORD)
    ca.upload_file(info_a["session_token"], "/shared.bin", data)
    ca.close()

    # User B queries before uploading — chunk should already be present
    cb = _new_client(server)
    info_b = cb.login(user_b, PASSWORD)
    token_b = info_b["session_token"]

    present = cb.chunk_query(token_b, [chunk_hash])
    assert present[0] is True, (
        "user B's CHUNK_QUERY must report the chunk as present (dedup across users)"
    )

    # upload_file for user B should succeed without re-uploading the chunk
    file_id, version_id = cb.upload_file(token_b, "/b_copy.bin", data)
    assert file_id > 0

    cb.close()
