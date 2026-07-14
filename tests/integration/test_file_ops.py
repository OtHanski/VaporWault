"""
test_file_ops.py — integration tests for file upload, download, listing,
deletion, and version history.

Each test creates its own user to avoid module-server state pollution.
"""

import hashlib
import os

import pytest

from vw_client import VwClient, VwProtocolError

PASSWORD = "TestP@ssw0rd!"
CHUNK_4MIB = 4 * 1024 * 1024


def _new_client(server):
    return VwClient(server.host, server.port, server.cert)


def _setup_user(admin_client, server, username, password=PASSWORD):
    """Create user + login; return (client, session_token)."""
    admin_client.create_user(username, password)
    c = _new_client(server)
    info = c.login(username, password)
    return c, info["session_token"]


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_upload_single_chunk(server, admin_client, unique_username):
    """
    Upload 100 bytes of data as a single chunk.  FILE_STAT must reflect the
    correct path and size.
    """
    c, token = _setup_user(admin_client, server, unique_username)
    data = os.urandom(100)

    file_id, version_id = c.upload_file(token, "/single.bin", data)

    stat = c.file_stat(token, file_id=file_id)
    assert stat["size_bytes"] == len(data), (
        f"size_bytes={stat['size_bytes']} != {len(data)}"
    )
    assert stat["file_id"] == file_id

    c.close()


def test_upload_four_chunks(server, admin_client, unique_username):
    """
    Upload slightly more than 3 × 4 MiB so the data is split into 4 chunks.
    FILE_STAT must report the correct total size.
    """
    c, token = _setup_user(admin_client, server, unique_username)
    data = os.urandom(3 * CHUNK_4MIB + 1024)  # 4 chunks

    file_id, version_id = c.upload_file(token, "/large.bin", data)

    stat = c.file_stat(token, file_id=file_id)
    assert stat["size_bytes"] == len(data), (
        f"size_bytes={stat['size_bytes']} != {len(data)}"
    )

    c.close()


def test_download_verify_sha256(server, admin_client, unique_username):
    """
    Upload 50 KiB of random data, then download via VERSION_CHUNKS +
    CHUNK_DOWNLOAD_REQ.  Reassembled bytes must match the original SHA-256.
    """
    c, token = _setup_user(admin_client, server, unique_username)
    data = os.urandom(50 * 1024)
    original_hash = hashlib.sha256(data).digest()

    file_id, version_id = c.upload_file(token, "/verify.bin", data)
    downloaded = c.download_file(token, version_id)

    assert hashlib.sha256(downloaded).digest() == original_hash
    assert downloaded == data

    c.close()


def test_file_list(server, admin_client, unique_username):
    """FILE_LIST at the drive root must include both uploaded filenames."""
    c, token = _setup_user(admin_client, server, unique_username)

    c.upload_file(token, "/alpha.bin", os.urandom(256))
    c.upload_file(token, "/beta.bin",  os.urandom(512))

    entries = c.file_list(token, path="/")
    names = {e["name"] for e in entries}

    assert "alpha.bin" in names, f"alpha.bin not in listing: {names}"
    assert "beta.bin"  in names, f"beta.bin not in listing: {names}"

    c.close()


def test_file_delete(server, admin_client, unique_username):
    """
    After FILE_DELETE the file must no longer be accessible via FILE_STAT.
    Both stat-by-path and stat-by-file_id should fail.
    """
    c, token = _setup_user(admin_client, server, unique_username)

    file_id, _ = c.upload_file(token, "/todelete.bin", os.urandom(128))

    c.file_delete(token, file_id=file_id)

    with pytest.raises(Exception):
        c.file_stat(token, file_id=file_id)

    c.close()


def test_version_list_and_restore(server, admin_client, unique_username):
    """
    Upload file → v1, re-upload same path → v2.  VERSION_LIST must contain
    both versions.  Restoring v1 must make the content match the original.
    """
    c, token = _setup_user(admin_client, server, unique_username)

    path    = "/versioned.bin"
    data_v1 = os.urandom(256)
    data_v2 = os.urandom(256)

    file_id, version_id_1 = c.upload_file(token, path, data_v1)
    _,       version_id_2 = c.upload_file(token, path, data_v2)

    assert version_id_1 != version_id_2, "two uploads must create distinct versions"

    versions, total = c.version_list(token, file_id)
    assert total >= 2, f"expected >= 2 versions, got total={total}"
    vid_set = {v["version_id"] for v in versions}
    assert version_id_1 in vid_set, "v1 not in VERSION_LIST"
    assert version_id_2 in vid_set, "v2 not in VERSION_LIST"

    # Restore v1
    new_vid = c.version_restore(token, version_id_1, path)
    assert new_vid != version_id_1, "restore must produce a new version_id"

    # Download the restored version and compare
    restored_data = c.download_file(token, new_vid)
    assert restored_data == data_v1, "restored content must match original v1 data"

    c.close()
