"""
test_vault.py — integration tests for TASK-098 (server-side vault storage).

Exercises VAULT_CREATE/VAULT_KEY_FETCH/VAULT_LIST and the FILE_COMMIT
extension over the real wire, against a real running server — the
acceptance criterion "VAULT_* messages round-trip correctly against a real
client" from TASK-098's own filing.

The server's role is deliberately narrow (docs/PROTOCOL.md §7.11): store
opaque key-wrapping blobs and treat encrypted chunk content exactly like
any other chunk. wrapped_vk/kdf_params/wrapped_dek here are therefore
meaningless-looking test bytes, not real cryptographic material — there is
no real client-side vault module yet (TASK-099), so nothing on the client
side of these tests actually encrypts or decrypts anything. What's under
test is the server's storage/permission behavior around these opaque blobs,
not cryptographic correctness (that's TASK-101's job, once TASK-099 exists).

A version's vault_id/wrapped_dek IS retrievable after a FILE_COMMIT that
set them, via VERSION_CHUNKS_RESP's TASK-099 extension (see
test_version_chunks_surfaces_vault_id_and_wrapped_dek below) — this closed
the gap originally flagged in TASK-098's own notes. The on-disk round-trip
(does the server actually persist and return the right bytes) is also
covered at the unit level in test_vw_vault.c, which has direct access to
the internal record.

Each test creates its own users to avoid module-server state pollution, and
closes every client it opens (via try/finally) — see test_sharing.py's
module docstring for why this server's small worker pool makes that matter.
"""

import hashlib
import os

import pytest

from vw_client import (
    VwClient, VwProtocolError,
    VW_ERR_NOT_FOUND, VW_ERR_PERMISSION, VW_ERR_INVALID_ARG, VW_ERR_VAULT_NOT_EMPTY,
)

PASSWORD = "TestP@ssw0rd!"


def _new_client(server):
    return VwClient(server.host, server.port, server.cert)


def _setup_user(admin_client, server, username, password=PASSWORD):
    admin_client.create_user(username, password)
    c = _new_client(server)
    info = c.login(username, password)
    return c, info["session_token"]


def test_vault_create_and_key_fetch_roundtrip(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/secret.bin", b"placeholder content")

        wrapped_vk = os.urandom(48)
        kdf_salt = os.urandom(16)
        kdf_params = os.urandom(6)

        vault_id = owner.vault_create(otoken, fid, wrapped_vk, kdf_salt, kdf_params)
        assert vault_id != 0

        got_vk, got_salt, got_params = owner.vault_key_fetch(otoken, vault_id)
        assert got_vk == wrapped_vk
        assert got_salt == kdf_salt
        assert got_params == kdf_params
    finally:
        owner.close()


def test_vault_create_with_empty_kdf_params(server, admin_client, unique_username):
    """kdf_params is optional (0 length is valid) — unlike wrapped_vk."""
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/secret.bin", b"x")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")
        _, _, got_params = owner.vault_key_fetch(otoken, vault_id)
        assert got_params == b""
    finally:
        owner.close()


def test_vault_create_requires_ownership_of_the_target(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    stranger, stoken = _setup_user(admin_client, server, f"{unique_username}_stranger")
    try:
        fid, _ = owner.upload_file(otoken, "/secret.bin", b"placeholder")

        with pytest.raises(VwProtocolError) as exc_info:
            stranger.vault_create(stoken, fid, os.urandom(32), os.urandom(16), b"")
        assert exc_info.value.code == VW_ERR_PERMISSION
    finally:
        owner.close(); stranger.close()


def test_vault_key_fetch_requires_ownership(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    stranger, stoken = _setup_user(admin_client, server, f"{unique_username}_stranger")
    try:
        fid, _ = owner.upload_file(otoken, "/secret.bin", b"placeholder")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")

        with pytest.raises(VwProtocolError) as exc_info:
            stranger.vault_key_fetch(stoken, vault_id)
        assert exc_info.value.code == VW_ERR_PERMISSION
    finally:
        owner.close(); stranger.close()


def test_vault_key_fetch_unknown_vault_id_not_found(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        with pytest.raises(VwProtocolError) as exc_info:
            owner.vault_key_fetch(otoken, 999999999)
        assert exc_info.value.code == VW_ERR_NOT_FOUND
    finally:
        owner.close()


def test_vault_list_only_shows_my_vaults(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    other, otoken2 = _setup_user(admin_client, server, f"{unique_username}_other")
    try:
        fid_a, _ = owner.upload_file(otoken, "/a.bin", b"a")
        fid_b, _ = other.upload_file(otoken2, "/b.bin", b"b")

        vault_a = owner.vault_create(otoken, fid_a, os.urandom(32), os.urandom(16), b"")
        vault_b = other.vault_create(otoken2, fid_b, os.urandom(32), os.urandom(16), b"")

        owner_vaults = owner.vault_list(otoken)
        owner_ids = {v["vault_id"] for v in owner_vaults}
        assert vault_a in owner_ids
        assert vault_b not in owner_ids

        other_vaults = other.vault_list(otoken2)
        other_ids = {v["vault_id"] for v in other_vaults}
        assert vault_b in other_ids
        assert vault_a not in other_ids
    finally:
        owner.close(); other.close()


def test_vault_create_rejects_empty_wrapped_vk(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/secret.bin", b"placeholder")
        with pytest.raises(VwProtocolError) as exc_info:
            owner.vault_create(otoken, fid, b"", os.urandom(16), b"")
        assert exc_info.value.code == VW_ERR_INVALID_ARG
    finally:
        owner.close()


# ── FILE_COMMIT extension ────────────────────────────────────────────────────

def test_file_commit_with_vault_id_succeeds(server, admin_client, unique_username):
    """
    Smoke test for the FILE_COMMIT wire extension: committing a new version
    with a valid vault_id + wrapped_dek must succeed and behave exactly like
    a normal commit from every externally observable angle. See
    test_version_chunks_surfaces_vault_id_and_wrapped_dek for the
    round-trip check via VERSION_CHUNKS_RESP.
    """
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/plain.bin", b"first version, unencrypted")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")

        data = b"second version, pretend-encrypted"
        chash = hashlib.sha256(data).digest()
        owner.chunk_upload(otoken, data)
        new_fid, new_vid = owner.file_commit(
            otoken, "", [chash], file_id=fid, logical_size=len(data),
            vault_id=vault_id, wrapped_dek=os.urandom(48),
        )
        assert new_fid == fid
        assert new_vid != 0

        stat = owner.file_stat(otoken, file_id=fid)
        assert stat["file_id"] == fid
        assert stat["size_bytes"] == len(data)
        assert stat["vault_id"] == vault_id
    finally:
        owner.close()


def test_file_stat_vault_id_reflects_current_version(server, admin_client, unique_username):
    """
    TASK-100: FILE_STAT_RESP's vault_id must track the file's CURRENT
    version, not just "was this file ever encrypted" — an unencrypted file
    reports vault_id 0, and a directory (which has no version at all)
    always reports vault_id 0 too.
    """
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/plain.bin", b"unencrypted content")
        stat = owner.file_stat(otoken, file_id=fid)
        assert stat["vault_id"] == 0

        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")
        data = b"now encrypted"
        chash = hashlib.sha256(data).digest()
        owner.chunk_upload(otoken, data)
        owner.file_commit(otoken, "", [chash], file_id=fid, logical_size=len(data),
                           vault_id=vault_id, wrapped_dek=os.urandom(48))

        stat2 = owner.file_stat(otoken, file_id=fid)
        assert stat2["vault_id"] == vault_id

        dir_id = owner.file_mkdir(otoken, "somedir")
        dir_stat = owner.file_stat(otoken, file_id=dir_id)
        assert dir_stat["vault_id"] == 0
    finally:
        owner.close()


def test_file_commit_rejects_unknown_vault_id(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/plain.bin", b"content")
        data = b"v2"
        chash = hashlib.sha256(data).digest()
        owner.chunk_upload(otoken, data)
        with pytest.raises(VwProtocolError) as exc_info:
            owner.file_commit(otoken, "", [chash], file_id=fid, logical_size=len(data),
                               vault_id=999999999, wrapped_dek=os.urandom(32))
        assert exc_info.value.code == VW_ERR_NOT_FOUND
    finally:
        owner.close()


def test_file_commit_rejects_vault_owned_by_someone_else(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    other, otoken2 = _setup_user(admin_client, server, f"{unique_username}_other")
    try:
        fid, _ = owner.upload_file(otoken, "/plain.bin", b"content")
        other_fid, _ = other.upload_file(otoken2, "/other.bin", b"other content")
        other_vault_id = other.vault_create(otoken2, other_fid, os.urandom(32), os.urandom(16), b"")

        data = b"v2"
        chash = hashlib.sha256(data).digest()
        owner.chunk_upload(otoken, data)
        with pytest.raises(VwProtocolError) as exc_info:
            owner.file_commit(otoken, "", [chash], file_id=fid, logical_size=len(data),
                               vault_id=other_vault_id, wrapped_dek=os.urandom(32))
        assert exc_info.value.code == VW_ERR_PERMISSION
    finally:
        owner.close(); other.close()


def test_version_restore_after_encrypted_commit_succeeds(server, admin_client, unique_username):
    """
    Restoring an earlier version of a file that has since had an
    "encrypted" (vault_id-carrying) commit must not error — exercises
    handle_version_restore's carry-forward-vault_id-and-wrapped_dek path
    (§7.11.2: a restore re-points HEAD at existing ciphertext rather than
    performing a new encryption, so it must not require a new DEK).
    """
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, v1 = owner.upload_file(otoken, "/plain.bin", b"version one")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")

        data2 = b"version two, pretend-encrypted"
        chash2 = hashlib.sha256(data2).digest()
        owner.chunk_upload(otoken, data2)
        _, v2 = owner.file_commit(otoken, "", [chash2], file_id=fid, logical_size=len(data2),
                                   vault_id=vault_id, wrapped_dek=os.urandom(48))

        # Restore v2 (the encrypted one) back onto itself as a new HEAD —
        # confirms the carry-forward path runs without erroring.
        new_vid = owner.version_restore(otoken, v2, "/plain.bin")
        assert new_vid != 0
        assert new_vid != v2
    finally:
        owner.close()


def test_version_chunks_surfaces_vault_id_and_wrapped_dek(server, admin_client, unique_username):
    """
    TASK-099: VERSION_CHUNKS_RESP must carry back the exact vault_id and
    wrapped_dek a FILE_COMMIT set, so a downloading client can decrypt.
    An unencrypted version must report vault_id == 0 and wrapped_dek is None
    (no trailing fields at all, distinguishing it from a real-but-empty
    wrapped_dek — VAULT_CREATE separately rejects an empty wrapped_dek, so
    "present but empty" should never occur on the wire either).
    """
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, v1 = owner.upload_file(otoken, "/plain.bin", b"unencrypted version")
        hashes, vault_id, wrapped_dek = owner.version_chunks_ex(otoken, v1)
        assert vault_id == 0
        assert wrapped_dek is None
        assert len(hashes) == 1

        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")
        data2 = b"encrypted version content"
        chash2 = hashlib.sha256(data2).digest()
        owner.chunk_upload(otoken, data2)
        wrapped_dek_sent = os.urandom(48)
        _, v2 = owner.file_commit(otoken, "", [chash2], file_id=fid, logical_size=len(data2),
                                   vault_id=vault_id, wrapped_dek=wrapped_dek_sent)

        hashes2, vault_id2, wrapped_dek2 = owner.version_chunks_ex(otoken, v2)
        assert vault_id2 == vault_id
        assert wrapped_dek2 == wrapped_dek_sent
        assert hashes2 == [chash2]
    finally:
        owner.close()


# ── VAULT_DELETE (TASK-00274/00275) ──────────────────────────────────────────

def test_vault_delete_removes_it_from_list_and_key_fetch(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/secret.bin", b"placeholder")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")

        owner.vault_delete(otoken, vault_id)

        with pytest.raises(VwProtocolError) as exc_info:
            owner.vault_key_fetch(otoken, vault_id)
        assert exc_info.value.code == VW_ERR_NOT_FOUND

        remaining = {v["vault_id"] for v in owner.vault_list(otoken)}
        assert vault_id not in remaining
    finally:
        owner.close()


def test_vault_delete_requires_ownership(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    stranger, stoken = _setup_user(admin_client, server, f"{unique_username}_stranger")
    try:
        fid, _ = owner.upload_file(otoken, "/secret.bin", b"placeholder")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")

        with pytest.raises(VwProtocolError) as exc_info:
            stranger.vault_delete(stoken, vault_id)
        assert exc_info.value.code == VW_ERR_PERMISSION

        # Untouched — still fetchable by the real owner.
        owner.vault_key_fetch(otoken, vault_id)
    finally:
        owner.close(); stranger.close()


def test_vault_delete_unknown_or_already_deleted_not_found(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        with pytest.raises(VwProtocolError) as exc_info:
            owner.vault_delete(otoken, 999999999)
        assert exc_info.value.code == VW_ERR_NOT_FOUND

        fid, _ = owner.upload_file(otoken, "/secret.bin", b"placeholder")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")
        owner.vault_delete(otoken, vault_id)

        with pytest.raises(VwProtocolError) as exc_info:
            owner.vault_delete(otoken, vault_id)
        assert exc_info.value.code == VW_ERR_NOT_FOUND
    finally:
        owner.close()


def test_vault_delete_rejects_while_a_version_still_references_it(server, admin_client, unique_username):
    """A vault with at least one live encrypted version must not be
    deletable — that version's wrapped_dek would become permanently
    unrecoverable (docs/PROTOCOL.md §7.11.4)."""
    owner, otoken = _setup_user(admin_client, server, unique_username)
    try:
        fid, _ = owner.upload_file(otoken, "/plain.bin", b"first version, unencrypted")
        vault_id = owner.vault_create(otoken, fid, os.urandom(32), os.urandom(16), b"")

        data = b"second version, pretend-encrypted"
        chash = hashlib.sha256(data).digest()
        owner.chunk_upload(otoken, data)
        owner.file_commit(otoken, "", [chash], file_id=fid, logical_size=len(data),
                           vault_id=vault_id, wrapped_dek=os.urandom(48))

        with pytest.raises(VwProtocolError) as exc_info:
            owner.vault_delete(otoken, vault_id)
        assert exc_info.value.code == VW_ERR_VAULT_NOT_EMPTY

        # Untouched — still fully usable after the rejected delete.
        owner.vault_key_fetch(otoken, vault_id)
    finally:
        owner.close()


# Note: FILE_DELETE only soft-deletes (vw_store_file_soft_delete) — the
# version record (and its vault_id) survives until vw_gc.c hard-deletes it
# past trash_retention_days, so "delete becomes possible once the file is
# deleted" isn't reproducible without a GC-tuned server fixture (see
# test_cluster.py's gc_interval_secs/trash_retention_days server params).
# That GC hard-delete path already has its own coverage; not duplicated
# here.
