"""
test_sharing.py — integration tests for TASK-094/TASK-097 (server-side
sharing and its full regression scenario matrix).

Exercises the real running server over the wire (not just vw_share.c unit
tests): user-to-user grants, public links, live revocation, quota
attribution, rate limiting, and the anonymous-scoped-session restrictions.
Originally written as TASK-094's own validation (a subset); TASK-097
extended it to the full scenario matrix against TASK-094/TASK-095's SEC.07
findings once a real client existed to drive it.

Deliberately root-level-file-only: there is no wire message that creates a
directory (VW_ENTRY_DIR) anywhere in this protocol today — FILE_COMMIT's
path-based branch requires every ancestor directory to already exist, and
never creates one itself (see TASK-103's sibling finding, filed as
TASK-104). Folder-sharing's ancestor-walk-up permission resolution is
covered at the unit level instead (test_vw_share.c builds folder records
directly via vw_store_file_create, bypassing the wire).

Each test creates its own users to avoid module-server state pollution, and
closes every client it opens (via try/finally) even on assertion failure —
this server's worker pool is small in the test config, so a leaked,
never-GOODBYE'd connection from one failing test can starve every
subsequent test in this module of a worker thread, turning one real
failure into a wall of unrelated-looking timeouts.
"""

import hashlib
import os

import pytest

from vw_client import (
    VwClient, VwProtocolError, VwAuthError,
    VW_PERM_VIEW, VW_PERM_EDIT, VW_ERR_NOT_FOUND, VW_ERR_RATE_LIMITED,
)

PASSWORD = "TestP@ssw0rd!"


def _new_client(server):
    return VwClient(server.host, server.port, server.cert)


def _setup_user(admin_client, server, username, password=PASSWORD):
    admin_client.create_user(username, password)
    c = _new_client(server)
    info = c.login(username, password)
    return c, info["session_token"]


# ── User-to-user grants ─────────────────────────────────────────────────────

def test_grant_view_allows_read_but_not_write(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    grantee, gtoken = _setup_user(admin_client, server, f"{unique_username}_grantee")
    try:
        fid, _ = owner.upload_file(otoken, "/shared.txt", b"hello world")
        owner.share_grant(otoken, fid, f"{unique_username}_grantee", VW_PERM_VIEW)

        stat = grantee.file_stat(gtoken, file_id=fid)
        assert stat["file_id"] == fid
        assert stat["perm"] == VW_PERM_VIEW

        # Grantee cannot write (only VIEW granted) — commit a new version.
        data = b"overwritten"
        chash = hashlib.sha256(data).digest()
        grantee.chunk_upload(gtoken, data)
        with pytest.raises(VwProtocolError):
            grantee.file_commit(gtoken, "", [chash], file_id=fid, logical_size=len(data))
    finally:
        owner.close(); grantee.close()


def _used_bytes(server, username, password=PASSWORD):
    """
    Fresh connection just to read used_bytes off AUTH_OK. Never reuse an
    already-authenticated VwClient for a second login() — the server's
    accept loop leaves the auth phase after the first AUTH_REQUEST/AUTH_OK
    on a connection, so a second AUTH_REQUEST on the same connection is a
    message type the file-op dispatcher doesn't recognize; it appears to
    hang (no response ever sent) rather than error, and starves this
    module's small worker pool for every later test.
    """
    c = _new_client(server)
    try:
        return c.login(username, password)["used_bytes"]
    finally:
        c.close()


def test_grant_edit_allows_write_and_quota_charges_owner(server, admin_client, unique_username):
    """
    Deliberately sequential — at most ONE client connection open at a
    time — rather than the usual owner+grantee-simultaneously shape used
    elsewhere in this file. This test's own quota checks need extra
    connections beyond just owner+grantee, and this server's test config
    caps worker threads at 2 (see module note): a third simultaneous
    connection while two are still open doesn't error, it just hangs
    forever waiting for a worker that will never free up, which then
    leaks those two connections (no GOODBYE ever sent) and starves every
    later test in this module too. Closing each connection before opening
    the next one sidesteps the limit entirely instead of relying on
    happening to never exceed it.
    """
    owner_name = f"{unique_username}_owner"
    grantee_name = f"{unique_username}_grantee"
    admin_client.create_user(owner_name, PASSWORD)
    admin_client.create_user(grantee_name, PASSWORD)

    owner = _new_client(server)
    try:
        otoken = owner.login(owner_name, PASSWORD)["session_token"]
        fid, _ = owner.upload_file(otoken, "/doc.bin", os.urandom(1024))
        owner.share_grant(otoken, fid, grantee_name, VW_PERM_EDIT)
    finally:
        owner.close()

    used_before_owner = _used_bytes(server, owner_name)
    used_before_grantee = _used_bytes(server, grantee_name)

    # Grantee commits a NEW VERSION of the owner's file via their EDIT
    # grant (file_id-addressed — this is the "update an existing shared
    # file" path, distinct from "create a new file under a shared
    # folder", which needs a folder to already exist and so isn't
    # reachable in this wire-only test file — see module note).
    data = os.urandom(65536)
    chash = hashlib.sha256(data).digest()
    grantee = _new_client(server)
    try:
        gtoken = grantee.login(grantee_name, PASSWORD)["session_token"]
        grantee.chunk_upload(gtoken, data)
        grantee.file_commit(gtoken, "", [chash], file_id=fid, logical_size=len(data))
    finally:
        grantee.close()

    used_after_owner = _used_bytes(server, owner_name)
    used_after_grantee = _used_bytes(server, grantee_name)

    assert used_after_owner - used_before_owner == len(data), (
        f"owner's quota should be debited by {len(data)}, "
        f"delta was {used_after_owner - used_before_owner}"
    )
    assert used_after_grantee == used_before_grantee, (
        "the editing grantee's own quota must be unaffected by a write "
        f"through someone else's EDIT grant (before={used_before_grantee} "
        f"after={used_after_grantee})"
    )


def test_public_link_edit_quota_charges_owner(server, admin_client, unique_username):
    """
    Same quota-attribution property as test_grant_edit_allows_write_and_
    quota_charges_owner, but through an anonymous public EDIT link instead
    of a named user-to-user grant — the two mechanisms share the same
    quota-resolution code path (§7.5: "quota is always resolved against the
    file's real owner"), but that path is reached differently (scope_share_id
    on an anonymous session vs. a grant lookup for a real user_id), so this
    is a distinct regression scenario, not a duplicate.
    """
    owner_name = f"{unique_username}_owner"
    admin_client.create_user(owner_name, PASSWORD)

    owner = _new_client(server)
    try:
        otoken = owner.login(owner_name, PASSWORD)["session_token"]
        fid, _ = owner.upload_file(otoken, "/doc.bin", os.urandom(1024))
        _, token = owner.link_create(otoken, fid, VW_PERM_EDIT)
    finally:
        owner.close()

    used_before = _used_bytes(server, owner_name)

    data = os.urandom(65536)
    chash = hashlib.sha256(data).digest()
    anon = _new_client(server)
    try:
        info = anon.link_access(token)
        anon.chunk_upload(info["session_token"], data)
        anon.file_commit(info["session_token"], "", [chash], file_id=fid, logical_size=len(data))
    finally:
        anon.close()

    used_after = _used_bytes(server, owner_name)
    assert used_after - used_before == len(data), (
        f"owner's quota should be debited by {len(data)} for a write through "
        f"a public EDIT link, delta was {used_after - used_before}"
    )


def test_no_grant_or_link_means_no_access(server, admin_client, unique_username):
    """
    Baseline cross-user isolation (TASK-097): a user with no grant, no link,
    and no ownership relationship to a file must get VW_ERR_NOT_FOUND (not
    VW_ERR_PERMISSION — existence itself must not be revealed) when trying
    to reach it directly by file_id.
    """
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    stranger, stoken = _setup_user(admin_client, server, f"{unique_username}_stranger")
    try:
        fid, _ = owner.upload_file(otoken, "/private.txt", b"not for you")

        with pytest.raises(VwProtocolError) as exc_info:
            stranger.file_stat(stoken, file_id=fid)
        assert exc_info.value.code == VW_ERR_NOT_FOUND
    finally:
        owner.close(); stranger.close()


def test_only_share_owner_can_revoke(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    grantee, gtoken = _setup_user(admin_client, server, f"{unique_username}_grantee")
    try:
        fid, _ = owner.upload_file(otoken, "/doc.txt", b"secret")
        share_id = owner.share_grant(otoken, fid, f"{unique_username}_grantee", VW_PERM_VIEW)

        with pytest.raises(VwProtocolError):
            grantee.share_revoke(gtoken, share_id)

        owner.share_revoke(otoken, share_id)
        with pytest.raises(VwProtocolError):
            grantee.file_stat(gtoken, file_id=fid)
    finally:
        owner.close(); grantee.close()


def test_share_list_reflects_grants_created_and_received(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    grantee, gtoken = _setup_user(admin_client, server, f"{unique_username}_grantee")
    try:
        fid, _ = owner.upload_file(otoken, "/x.txt", b"x")
        owner.share_grant(otoken, fid, f"{unique_username}_grantee", VW_PERM_VIEW)

        created = owner.share_list(otoken, mode=0)
        assert any(e["file_id"] == fid for e in created)

        received = grantee.share_list(gtoken, mode=1)
        assert any(e["file_id"] == fid for e in received)
    finally:
        owner.close(); grantee.close()


# ── Public links ─────────────────────────────────────────────────────────────

def test_public_link_view_access_anonymous(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    anon = _new_client(server)
    try:
        fid, _ = owner.upload_file(otoken, "/public.txt", b"anyone can read this")
        share_id, token = owner.link_create(otoken, fid, VW_PERM_VIEW)

        info = anon.link_access(token)
        assert info["user_id"] == 0
        assert info["is_admin"] is False

        stat = anon.file_stat(info["session_token"], file_id=fid)
        assert stat["file_id"] == fid

        # Anonymous scoped session cannot write (VIEW only).
        data = b"nope"
        chash = hashlib.sha256(data).digest()
        anon.chunk_upload(info["session_token"], data)
        with pytest.raises(VwProtocolError):
            anon.file_commit(info["session_token"], "", [chash], file_id=fid, logical_size=len(data))
    finally:
        owner.close(); anon.close()


def test_public_link_root_navigation_returns_scope_not_server_root(server, admin_client, unique_username):
    """
    A scoped session's FILE_LIST at the root must return the scope's own
    target, never the server's actual root — verified here against a
    FILE-scoped link (the single-item case); the folder-scoped case (an
    immediate-children listing) is exercised at the unit level in
    test_vw_share.c, since building a folder needs vw_store_file_create
    directly (see module note on the missing wire mkdir).
    """
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    try:
        # A second, unrelated file (also the owner's — no need for a third
        # user/connection just to prove it's excluded) must never appear
        # in the scoped listing.
        owner.upload_file(otoken, "/other.txt", b"not shared")
        fid, _ = owner.upload_file(otoken, "/scoped.txt", b"the shared one")
        _, token = owner.link_create(otoken, fid, VW_PERM_VIEW)
    finally:
        owner.close()

    anon = _new_client(server)
    try:
        info = anon.link_access(token)
        entries = anon.file_list(info["session_token"], path="/")
        names = {e["name"] for e in entries}
        assert names == {"scoped.txt"}, f"unexpected root listing for scoped session: {names}"
    finally:
        anon.close()


def test_public_link_live_revocation_blocks_already_issued_session(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    anon = _new_client(server)
    try:
        fid, _ = owner.upload_file(otoken, "/doc.txt", b"content")
        share_id, token = owner.link_create(otoken, fid, VW_PERM_VIEW)

        info = anon.link_access(token)
        # Works once.
        anon.file_stat(info["session_token"], file_id=fid)

        owner.link_revoke(otoken, share_id)

        # The SAME already-issued scoped session must be blocked on its
        # very next request — not just future LINK_ACCESS redemptions.
        with pytest.raises(VwProtocolError):
            anon.file_stat(info["session_token"], file_id=fid)
    finally:
        owner.close(); anon.close()


def test_link_access_unknown_token_rejected(server, admin_client, unique_username):
    anon = _new_client(server)
    try:
        with pytest.raises(VwAuthError):
            anon.link_access(os.urandom(32))
    finally:
        anon.close()


def test_scoped_session_cannot_grant_or_create_link(server, admin_client, unique_username):
    """
    SEC.07 finding: a leaked link must never let its holder mint an
    independent grant/link that would survive revocation of the one they
    used to get in — and must equally never let it REVOKE an existing
    grant/link (a scoped session has no account and so no share/link it
    could legitimately own the right to revoke).
    """
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    other_username = f"{unique_username}_other"
    admin_client.create_user(other_username, PASSWORD)
    anon = _new_client(server)
    try:
        fid, _ = owner.upload_file(otoken, "/doc.txt", b"content")
        _, token = owner.link_create(otoken, fid, VW_PERM_EDIT)

        info = anon.link_access(token)

        with pytest.raises(VwProtocolError):
            anon.share_grant(info["session_token"], fid, other_username, VW_PERM_VIEW)
        with pytest.raises(VwProtocolError):
            anon.link_create(info["session_token"], fid, VW_PERM_VIEW)

        # A real share_id/link the owner legitimately created, purely so the
        # scoped session has something concrete to attempt (and fail) to
        # revoke — the anon-attempted grant/link above never succeeded, so
        # they never produced a real id to test against.
        real_share_id = owner.share_grant(otoken, fid, other_username, VW_PERM_VIEW)
        real_link_share_id, _ = owner.link_create(otoken, fid, VW_PERM_VIEW)

        with pytest.raises(VwProtocolError):
            anon.share_revoke(info["session_token"], real_share_id)
        with pytest.raises(VwProtocolError):
            anon.link_revoke(info["session_token"], real_link_share_id)
    finally:
        owner.close(); anon.close()


def test_scoped_session_write_count_rate_limited(server, admin_client, unique_username):
    """
    SEC.07 finding: a public EDIT link must not let an anonymous holder
    write an unbounded number of files/versions regardless of remaining
    byte quota — SHARE_WRITE_MAX_PER_WINDOW (30, see vw_share.c) writes
    succeed, the next one must fail with VW_ERR_RATE_LIMITED. Uses
    zero-chunk commits (logical_size=0) so this is fast and independent of
    quota entirely — it's the write COUNT being bounded, not bytes.
    """
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    anon = _new_client(server)
    try:
        fid, _ = owner.upload_file(otoken, "/doc.txt", b"content")
        _, token = owner.link_create(otoken, fid, VW_PERM_EDIT)
        info = anon.link_access(token)

        for i in range(30):
            anon.file_commit(info["session_token"], "", [], file_id=fid, logical_size=0)

        with pytest.raises(VwProtocolError) as exc_info:
            anon.file_commit(info["session_token"], "", [], file_id=fid, logical_size=0)
        assert exc_info.value.code == VW_ERR_RATE_LIMITED
    finally:
        owner.close(); anon.close()


def test_link_list_never_includes_raw_token(server, admin_client, unique_username):
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    try:
        fid, _ = owner.upload_file(otoken, "/doc.txt", b"content")
        share_id, token = owner.link_create(otoken, fid, VW_PERM_VIEW)

        links = owner.link_list(otoken)
        assert any(e["share_id"] == share_id for e in links)
        # The wire format for LINK_LIST_RESP has no token field at all — if
        # it did, this would be the place a leak would show up as raw
        # bytes matching `token` somewhere unaccounted for in the entry.
        for e in links:
            assert set(e.keys()) == {
                "share_id", "file_id", "name", "permission",
                "created_at", "expires_at", "revoked",
            }
    finally:
        owner.close()


# ── FILE_MOVE ────────────────────────────────────────────────────────────────

def test_file_move_rename_at_root(server, admin_client, unique_username):
    """
    Rename-only (parent unchanged, new_parent_dir_id=0 -> 0): relocating
    into a genuinely different folder isn't reachable in this wire-only
    test file — see module note. That codepath (destination_parent.owner_id
    == file.owner_id, EDIT on both parents) is exercised by code review and
    the cycle-check logic shares its shape with handle_file_list's own
    ancestor walk, which test_vw_share.c does exercise directly.
    """
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    try:
        fid, _ = owner.upload_file(otoken, "/src.txt", b"move me")

        owner.file_move(otoken, fid, new_parent_dir_id=0, new_name="renamed.txt")

        listing = owner.file_list(otoken, path="/")
        names = {e["name"] for e in listing}
        assert "renamed.txt" in names
        assert "src.txt" not in names
    finally:
        owner.close()


def test_file_move_requires_edit_not_just_view(server, admin_client, unique_username):
    """
    A VIEW-only grant on the file itself must not allow moving it. (Since
    the file sits at the owner's root, this also incidentally exercises
    the "no grant can target root itself" rule — a file-only EDIT grant
    would fail the same way, since FILE_MOVE gates on parent-folder EDIT,
    not file-level EDIT; that stricter distinction isn't separately
    isolated here.)
    """
    owner, otoken = _setup_user(admin_client, server, f"{unique_username}_owner")
    grantee, gtoken = _setup_user(admin_client, server, f"{unique_username}_grantee")
    try:
        fid, _ = owner.upload_file(otoken, "/doc.txt", b"content")
        owner.share_grant(otoken, fid, f"{unique_username}_grantee", VW_PERM_VIEW)

        with pytest.raises(VwProtocolError):
            grantee.file_move(gtoken, fid, new_parent_dir_id=0, new_name="renamed.txt")
    finally:
        owner.close(); grantee.close()


# ── LINK_ACCESS IP rate limiting ─────────────────────────────────────────────
#
# MUST remain the LAST test in this file. vw_share.c's LINK_ACCESS failure
# counter is keyed by source IP (not by token or share_id), and every
# connection in this whole test module comes from the same IP (127.0.0.1
# against this module's one dedicated server instance — see the `server`
# fixture's module scope in conftest.py, so this doesn't bleed into other
# test files' servers). Once this test trips the block
# (LINK_ACCESS_MAX_FAILURES=5 within LINK_ACCESS_WINDOW_SECS=60), every
# LINK_ACCESS from this IP — even with a perfectly valid token — silently
# drops (no response, connection closes) for up to 60 more seconds. Any test
# added after this one that calls link_access() would flakily fail.

def test_link_access_repeated_failures_trigger_silent_drop(server, admin_client, unique_username):
    """
    SEC.07: repeated invalid LINK_ACCESS attempts from one source must
    trigger the same silent-drop behavior as NODE_HELLO (§7.9) — no
    AUTH_FAIL, no error, just a closed connection, so a scanning attacker
    can't distinguish "still guessing" from "now blocked" by response
    shape alone. A fresh VwClient is created for each attempt since the
    server closes the connection on the blocked path (matching how a real
    attacker would reconnect and retry, and how NODE_HELLO's existing
    equivalent behavior is exercised).

    Note: test_link_access_unknown_token_rejected (earlier in this file)
    already contributed one prior failure from this same IP before a
    successful redemption reset it (see vw_share_link_access_reset_on_success
    in handle_link_access) — every test between here and there redeems a
    valid link at least once, so this test starts from a clean counter
    regardless of file execution order among the tests above it.
    """
    for attempt in range(8):
        anon = _new_client(server)
        try:
            anon.link_access(os.urandom(32))
            pytest.fail(f"attempt {attempt}: a random token must never succeed")
        except VwAuthError:
            continue  # under the threshold so far — an ordinary rejection
        except Exception:
            # Blocked: the server sent no response at all and closed the
            # connection, which surfaces as some transport-level failure
            # (ConnectionError, ssl.SSLError, ...) depending on platform/
            # OpenSSL version — any of them is evidence of the silent drop,
            # since VwAuthError is the only well-defined "not yet blocked"
            # outcome and nothing else should occur on a healthy connection.
            return
        finally:
            anon.close()

    pytest.fail("expected LINK_ACCESS to be silently dropped within 8 failed attempts")
