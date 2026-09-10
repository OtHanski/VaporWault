"""
test_file_ops.py — integration tests for file upload, download, listing,
deletion, and version history.

Each test creates its own user to avoid module-server state pollution.
"""

import hashlib
import os

import pytest

from vw_client import VwClient, VwProtocolError, VW_ENTRY_DIR, VW_ERR_CHUNK_CORRUPT

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


def test_chunk_download_detects_corruption(server, admin_client, unique_username):
    """
    TASK-254: a chunk whose on-disk bytes have been tampered with (bit rot /
    corruption at rest, simulated here by flipping bytes directly in the
    server's data_dir) must never be served — CHUNK_DOWNLOAD_REQ must fail
    with VW_ERR_CHUNK_CORRUPT instead of returning the corrupted bytes.
    """
    c, token = _setup_user(admin_client, server, unique_username)
    data = os.urandom(4096)
    chunk_hash = hashlib.sha256(data).digest()

    c.upload_file(token, "/corrupt-me.bin", data)

    hexhash = chunk_hash.hex()
    chunk_path = os.path.join(server.data_dir, "chunks", hexhash[:2], f"{hexhash}.chunk")
    assert os.path.isfile(chunk_path), f"expected chunk file at {chunk_path}"

    with open(chunk_path, "r+b") as f:
        f.seek(0)
        first_byte = f.read(1)
        f.seek(0)
        f.write(bytes([first_byte[0] ^ 0xFF]))

    with pytest.raises(VwProtocolError) as exc_info:
        c.chunk_download(token, chunk_hash)
    assert exc_info.value.code == VW_ERR_CHUNK_CORRUPT, (
        f"expected VW_ERR_CHUNK_CORRUPT ({VW_ERR_CHUNK_CORRUPT}), "
        f"got code={exc_info.value.code}"
    )

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


def test_mkdir_creates_nested_directory_structure(server, admin_client, unique_username):
    """
    TASK-104: before FILE_MKDIR existed, there was no wire message capable
    of creating a VW_ENTRY_DIR record at all — folders were only reachable
    via direct vw_store_file_create calls, bypassing the wire entirely.
    Creates a two-level nested structure purely over the wire and confirms
    FILE_LIST/FILE_STAT see all of it, including a file uploaded inside the
    deepest directory (via the file_id-addressed FILE_COMMIT branch) and
    resolved back out through purely path-based FILE_LIST — which only
    works now that every ancestor in the path is a real record.
    """
    c, token = _setup_user(admin_client, server, unique_username)

    docs_id = c.file_mkdir(token, "docs")
    sub_id = c.file_mkdir(token, "sub", new_parent_dir_id=docs_id)

    root_entries = c.file_list(token, path="/")
    docs_entry = next((e for e in root_entries if e["name"] == "docs"), None)
    assert docs_entry is not None, f"docs/ missing from root listing: {root_entries}"
    assert docs_entry["entry_type"] == VW_ENTRY_DIR
    assert docs_entry["file_id"] == docs_id

    docs_listing = c.file_list(token, path="/docs")
    sub_entry = next((e for e in docs_listing if e["name"] == "sub"), None)
    assert sub_entry is not None, f"sub/ missing from /docs listing: {docs_listing}"
    assert sub_entry["entry_type"] == VW_ENTRY_DIR
    assert sub_entry["file_id"] == sub_id

    data = b"nested content"
    chash = hashlib.sha256(data).digest()
    c.chunk_upload(token, data)
    file_id, _ = c.file_commit(token, "leaf.txt", [chash], file_id=sub_id, logical_size=len(data))

    stat = c.file_stat(token, file_id=file_id)
    assert stat["file_id"] == file_id

    nested_listing = c.file_list(token, path="/docs/sub")
    leaf_entry = next((e for e in nested_listing if e["name"] == "leaf.txt"), None)
    assert leaf_entry is not None, f"leaf.txt missing from /docs/sub listing: {nested_listing}"
    assert leaf_entry["file_id"] == file_id

    c.close()


def test_mkdir_duplicate_name_rejected(server, admin_client, unique_username):
    """A second FILE_MKDIR with the same name under the same parent must fail."""
    c, token = _setup_user(admin_client, server, unique_username)

    c.file_mkdir(token, "dup")
    with pytest.raises(VwProtocolError):
        c.file_mkdir(token, "dup")

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
