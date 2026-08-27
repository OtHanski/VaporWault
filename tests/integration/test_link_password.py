"""
test_link_password.py — integration tests for TASK-186/187's public link
password protection, over the real wire (not just vw_share.c unit tests).
Same style/fixtures as test_sharing.py, which this is a sibling of.

Does NOT re-test link expiration — that already existed and already has
its own coverage before this milestone (see TASK-185's correction note);
this file is password-only, plus one regression check that password-less
links (the overwhelming majority of existing/expected usage) are
completely unaffected.
"""

import os

import pytest

import hashlib

from vw_client import (
    VwAuthError, VwProtocolError,
    VW_PERM_VIEW, VW_PERM_EDIT,
    VW_ERR_LINK_PASSWORD_REQUIRED, VW_ERR_LINK_PASSWORD_WRONG,
)
from test_sharing import _new_client, PASSWORD


def test_link_no_password_unaffected(server, admin_client, unique_username):
    """Regression: a link created with no password behaves exactly as
    before this feature — access with no password succeeds, and
    has_password reports False."""
    owner_name = f"{unique_username}_owner"
    admin_client.create_user(owner_name, PASSWORD)

    owner = _new_client(server)
    try:
        otoken = owner.login(owner_name, PASSWORD)["session_token"]
        fid, _ = owner.upload_file(otoken, "/plain.bin", os.urandom(256))
        share_id, token = owner.link_create(otoken, fid, VW_PERM_VIEW)

        entries = owner.link_list(otoken)
        entry = next(e for e in entries if e["share_id"] == share_id)
        assert entry["has_password"] is False
    finally:
        owner.close()

    anon = _new_client(server)
    try:
        info = anon.link_access(token)  # no password supplied
        assert info["session_token"]
    finally:
        anon.close()


def test_link_password_required_and_wrong_and_correct(server, admin_client, unique_username):
    owner_name = f"{unique_username}_owner"
    admin_client.create_user(owner_name, PASSWORD)

    owner = _new_client(server)
    try:
        otoken = owner.login(owner_name, PASSWORD)["session_token"]
        fid, _ = owner.upload_file(otoken, "/secret.bin", os.urandom(256))
        share_id, token = owner.link_create(otoken, fid, VW_PERM_VIEW, password="hunter2")

        entries = owner.link_list(otoken)
        entry = next(e for e in entries if e["share_id"] == share_id)
        assert entry["has_password"] is True
    finally:
        owner.close()

    # No password supplied at all.
    anon = _new_client(server)
    try:
        with pytest.raises(VwAuthError) as exc_info:
            anon.link_access(token)
        assert exc_info.value.code == VW_ERR_LINK_PASSWORD_REQUIRED
    finally:
        anon.close()

    # Wrong password.
    anon = _new_client(server)
    try:
        with pytest.raises(VwAuthError) as exc_info:
            anon.link_access(token, password="wrong")
        assert exc_info.value.code == VW_ERR_LINK_PASSWORD_WRONG
    finally:
        anon.close()

    # Correct password — succeeds exactly like a no-password link.
    anon = _new_client(server)
    try:
        info = anon.link_access(token, password="hunter2")
        assert info["session_token"]
    finally:
        anon.close()


def test_link_password_edit_permission_still_enforced(server, admin_client, unique_username):
    """Password protection is a second, independent gate — it doesn't
    change or bypass the existing VIEW/EDIT permission model."""
    owner_name = f"{unique_username}_owner"
    admin_client.create_user(owner_name, PASSWORD)

    owner = _new_client(server)
    try:
        otoken = owner.login(owner_name, PASSWORD)["session_token"]
        fid, _ = owner.upload_file(otoken, "/view_only.bin", os.urandom(256))
        _, token = owner.link_create(otoken, fid, VW_PERM_VIEW, password="hunter2")
    finally:
        owner.close()

    anon = _new_client(server)
    try:
        info = anon.link_access(token, password="hunter2")
        # A VIEW-only link must still reject a write, same as an
        # unprotected VIEW link already does (test_sharing.py's
        # test_grant_view_allows_read_but_not_write covers the
        # equivalent baseline for a user grant) — this just confirms the
        # password gate didn't accidentally widen the permission it sits
        # in front of. chunk_upload itself isn't permission-checked
        # (matching that same baseline test) — file_commit is where the
        # write is actually rejected.
        data = b"overwritten"
        chash = hashlib.sha256(data).digest()
        anon.chunk_upload(info["session_token"], data)
        with pytest.raises(VwProtocolError):
            anon.file_commit(info["session_token"], "", [chash], file_id=fid, logical_size=len(data))
    finally:
        anon.close()


def test_link_access_wrong_password_triggers_rate_limit(server, admin_client, unique_username):
    """
    A wrong password against an already-known-valid token must still be
    throttled by the existing LINK_ACCESS per-IP rate limiter — the whole
    point of TASK-187's ordering fix (reset_on_success moved to AFTER the
    password check, not right after the token lookup) is that guessing
    passwords against a valid token doesn't get a free reset on every
    attempt. Mirrors test_link_access_repeated_failures_trigger_silent_drop
    in test_sharing.py, which covers the equivalent token-guessing case.
    """
    owner_name = f"{unique_username}_owner"
    admin_client.create_user(owner_name, PASSWORD)

    owner = _new_client(server)
    try:
        otoken = owner.login(owner_name, PASSWORD)["session_token"]
        fid, _ = owner.upload_file(otoken, "/rl.bin", os.urandom(256))
        _, token = owner.link_create(otoken, fid, VW_PERM_VIEW, password="hunter2")
    finally:
        owner.close()

    # Same loop shape as test_sharing.py's
    # test_link_access_repeated_failures_trigger_silent_drop: keep
    # guessing wrong until the connection gets silently dropped instead
    # of returning a normal AUTH_FAIL, which is this rate limiter's
    # documented behavior (§7.9-style posture, not a distinguishable
    # error). Using the CORRECT password on the final over-the-threshold
    # attempt (rather than another wrong one) is the actual point of
    # this test: if reset_on_success fired on every wrong-password
    # attempt just because the token itself was valid, the limiter would
    # never trip and this would incorrectly succeed instead of being
    # dropped.
    for attempt in range(8):
        anon = _new_client(server)
        try:
            anon.link_access(token, password="hunter2" if attempt == 7 else "wrong")
            pytest.fail(f"attempt {attempt}: expected this to fail or be dropped")
        except VwAuthError:
            continue  # under the threshold so far — an ordinary rejection
        except Exception:
            return  # blocked — see test_sharing.py's identical pattern
        finally:
            anon.close()

    pytest.fail("expected LINK_ACCESS to be silently dropped within 8 failed attempts")
