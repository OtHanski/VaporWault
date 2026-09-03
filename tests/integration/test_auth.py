"""
test_auth.py — integration tests for the VaporWault authentication flow.

Covers: login success/failure, session resume (single-use), and brute-force
lockout after 5 consecutive wrong-password attempts.

Each test creates its own unique user so module-shared server state does not
bleed between test cases.
"""

import uuid
import pytest

from vw_client import (
    VwClient, VwAuthError, VW_ERR_AUTH_BAD_CREDS, VW_ERR_AUTH_LOCKED,
    MSG_AUTH_REQUEST, MSG_ERROR,
)

PASSWORD = "TestP@ssw0rd!"


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_user(admin_client, server, username, password=PASSWORD, is_admin=False):
    """Create a user via admin socket; return username."""
    admin_client.create_user(username, password, is_admin=is_admin)
    return username


def new_client(server):
    """Return a fresh VwClient connected to the test server."""
    from vw_client import VwClient
    return VwClient(server.host, server.port, server.cert)


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_login_success(server, admin_client, unique_username):
    """Successful login returns a 32-byte session token and a positive user_id."""
    make_user(admin_client, server, unique_username)

    with new_client(server) as c:
        info = c.login(unique_username, PASSWORD)

    assert len(info["session_token"]) == 32, "session token must be 32 bytes"
    assert info["user_id"] > 0, "user_id must be positive"


def test_login_wrong_password(server, admin_client, unique_username):
    """Wrong password returns AUTH_FAIL with code VW_ERR_AUTH_BAD_CREDS (300)."""
    make_user(admin_client, server, unique_username)

    with new_client(server) as c:
        with pytest.raises(VwAuthError) as exc_info:
            c.login(unique_username, "definitely-wrong-password")

    assert exc_info.value.code == VW_ERR_AUTH_BAD_CREDS


def test_login_unknown_user(server):
    """
    Login with a non-existent username returns the same AUTH_FAIL code as a
    wrong password — the server must not reveal whether the account exists
    (timing equalization, username enumeration prevention).
    """
    username = f"nosuchuser_{uuid.uuid4().hex[:8]}"
    with new_client(server) as c:
        with pytest.raises(VwAuthError) as exc_info:
            c.login(username, "irrelevant")

    assert exc_info.value.code == VW_ERR_AUTH_BAD_CREDS


def test_session_resume(server, admin_client, unique_username):
    """
    After a successful login the session token can be sent in SESSION_RESUME
    to get a new session token.  The new token must differ from the old one
    (token is rotated on every resume).
    """
    make_user(admin_client, server, unique_username)

    with new_client(server) as c:
        info1 = c.login(unique_username, PASSWORD)
    token1 = info1["session_token"]

    with new_client(server) as c:
        info2 = c.session_resume(token1)
    token2 = info2["session_token"]

    assert token1 != token2, "session token must be rotated on resume"
    assert len(token2) == 32


def test_session_resume_single_use(server, admin_client, unique_username):
    """
    A session token is single-use: after SESSION_RESUME the old token is
    invalidated.  Attempting to resume again with the old token must fail
    with AUTH_FAIL.
    """
    make_user(admin_client, server, unique_username)

    with new_client(server) as c:
        info = c.login(unique_username, PASSWORD)
    old_token = info["session_token"]

    # First resume: should succeed and rotate the token
    with new_client(server) as c:
        c.session_resume(old_token)

    # Second resume with the same old token: must fail
    with new_client(server) as c:
        with pytest.raises(VwAuthError):
            c.session_resume(old_token)


def test_brute_force_lockout(server, admin_client, unique_username):
    """
    After 5 consecutive wrong-password attempts the server must lock the account
    and return AUTH_FAIL with code VW_ERR_AUTH_LOCKED (304) on the 6th attempt.
    """
    make_user(admin_client, server, unique_username)

    fail_codes = []
    for _ in range(5):
        with new_client(server) as c:
            try:
                c.login(unique_username, "wrong_password_attempt")
            except VwAuthError as e:
                fail_codes.append(e.code)

    assert len(fail_codes) == 5, (
        f"expected 5 AUTH_FAIL responses, got {len(fail_codes)}"
    )
    assert all(code == VW_ERR_AUTH_BAD_CREDS for code in fail_codes), (
        f"pre-lockout responses should be VW_ERR_AUTH_BAD_CREDS, got {fail_codes}"
    )

    # 6th attempt must return VW_ERR_AUTH_LOCKED with lockout_secs > 0
    with new_client(server) as c:
        with pytest.raises(VwAuthError) as exc_info:
            c.login(unique_username, "wrong_password_attempt")

    err = exc_info.value
    assert err.code == VW_ERR_AUTH_LOCKED, (
        f"6th attempt: expected code={VW_ERR_AUTH_LOCKED} (locked), got {err.code}"
    )
    assert err.lockout_secs > 0, (
        f"lockout_remaining_secs must be > 0, got {err.lockout_secs}"
    )


def test_logout_invalidates_session(server, admin_client, unique_username):
    """
    TASK-237 regression: AUTH_LOGOUT must actually invalidate the session
    token server-side. Before the fix, the server's post-auth dispatch had
    no case for AUTH_LOGOUT at all (logged "unhandled msg type 0x0107" and
    silently did nothing) — the token stayed valid until its natural
    expires_at, so a captured pre-logout token could keep being used for
    the rest of its lifetime regardless of the user's own "log out" action.

    Log out on the original connection, then attempt SESSION_RESUME with
    the same token on a fresh connection (matching how a real client would
    reuse a stored token) — this must now fail, not succeed. Expects
    VW_ERR_AUTH_BAD_CREDS, matching every other SESSION_RESUME failure
    (docs/PROTOCOL.md §7.1's anti-oracle invariant: the wire code never
    reveals *why* a token was rejected — expired, revoked, or never valid
    all look identical to the caller).
    """
    make_user(admin_client, server, unique_username)

    with new_client(server) as c:
        info = c.login(unique_username, PASSWORD)
        token = info["session_token"]
        c.logout()

    with new_client(server) as c:
        with pytest.raises(VwAuthError) as exc_info:
            c.session_resume(token)

    assert exc_info.value.code == VW_ERR_AUTH_BAD_CREDS, (
        f"expected VW_ERR_AUTH_BAD_CREDS ({VW_ERR_AUTH_BAD_CREDS}) after logout, "
        f"got {exc_info.value.code}"
    )


def test_logout_does_not_affect_other_sessions(server, admin_client, unique_username):
    """
    Logging out one session must not invalidate a different, still-active
    session for the same user (e.g. the same account logged in on two
    devices) — AUTH_LOGOUT must revoke exactly the token this connection
    authenticated with, not every session belonging to that user_id.
    """
    make_user(admin_client, server, unique_username)

    with new_client(server) as c:
        info_a = c.login(unique_username, PASSWORD)
    token_a = info_a["session_token"]

    with new_client(server) as c:
        c.login(unique_username, PASSWORD)
        c.logout()

    # token_a (a separate, still-active session) must remain valid.
    with new_client(server) as c:
        c.session_resume(token_a)


def test_unrecognized_message_after_auth_gets_error_not_hang(server, admin_client, unique_username):
    """
    TASK-105 regression: re-sending a pre-auth-phase message type (here,
    AUTH_REQUEST again) on an already-authenticated connection must get an
    explicit ERROR response, not silence. Before the fix,
    vw_server_dispatch_file_op's default case returned VW_ERR_NOT_IMPL
    without ever calling send_error, and the server's per-connection loop
    only logs a warning and waits for the *next* message on that code —
    so the client hung until its own receive timeout, tying up a worker
    thread the whole time with no feedback at all.
    """
    make_user(admin_client, server, unique_username)

    with new_client(server) as c:
        c.login(unique_username, PASSWORD)

        # Send a second AUTH_REQUEST directly on the now-authenticated
        # connection (bypassing login()'s normal pre-auth-phase-only use).
        c._send(MSG_AUTH_REQUEST, b"\x00\x00" + b"\x00" * 32)
        mt, resp = c._recv()  # must not raise a socket timeout

    assert mt == MSG_ERROR, f"expected MSG_ERROR (0x{MSG_ERROR:04X}), got 0x{mt:04X}"
