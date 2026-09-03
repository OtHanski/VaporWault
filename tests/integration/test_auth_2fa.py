"""
test_auth_2fa.py — integration tests for TASK-238: a real end-to-end
email-OTP 2FA login against a real vapourwaultd and a real (if minimal,
see mock_smtp.py) SMTP relay.

Before this task's fix, `vw_auth_begin_login` (src/server/vw_auth.c)
unconditionally minted and emailed a brand-new OTP on *every* AUTH_REQUEST
for a 2FA account. Every 2FA-capable client (desktop daemon, Android)
authenticates in two steps that are two *separate* connections — an
empty-OTP "probe" to trigger the email, then a second connection supplying
the code the user read from that email — rather than blocking the first
connection open while the user reads their inbox. The second connection's
own AUTH_REQUEST re-ran begin_login from scratch, discarding the challenge
the probe's email was actually valid against and minting a different one,
so the code the user just read could never match what the server was
checking. A real login was structurally unreachable. See TASK-00238.md for
the full original report, including the concrete two-different-codes
repro this file's first test below reproduces the exact shape of.

vw_client.py's login() models this precisely: otp_code=None mirrors a real
client's otp_cb==NULL probe (raises VwTwoFaRequired without submitting
anything); otp_code=<code> mirrors an otp_cb that returns an already-known
code (submits AUTH_OTP on that same connection).
"""

import re
import time

import pytest

from conftest import ServerInstance
from mock_smtp import MockSmtpServer
from vw_client import VwClient, VwAuthError, VwTwoFaRequired

PASSWORD = "TestP@ssw0rd!"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _smtp_conf(smtp: MockSmtpServer) -> str:
    """Server.conf `extra` block pointing smtp_* at the mock relay — same
    shape as test_notify_alerts.py's _notify_conf, without the notify.*
    keys this file has no use for."""
    return "\n".join([
        f"smtp_host = {smtp.host}",
        f"smtp_port = {smtp.port}",
        "smtp_tls_mode = none",
        "smtp_verify_cert = 0",
        "smtp_username =",
        "smtp_password =",
        "smtp_from_addr = vaporwault@example.invalid",
        "smtp_from_name = VaporWault Test",
    ]) + "\n"


def _wait_until(predicate, timeout=15, interval=0.2):
    deadline = time.time() + timeout
    ok = False
    while time.time() < deadline:
        ok = predicate()
        if ok:
            return True
        time.sleep(interval)
    return ok


def _extract_otp(body: str) -> str:
    """Parse the 6-digit code out of send_otp_email's own fixed template
    (src/server/vw_auth.c): "...verification code is: NNNNNN\\r\\n\\r\\n
    This code expires in 10 minutes...". A plain digit-scan would also
    pick up the "10 minutes" digits, so match the specific "is: " prefix."""
    m = re.search(r"code is:\s*(\d{6})", body)
    assert m, f"could not find a 6-digit code in email body: {body!r}"
    return m.group(1)


def _enable_2fa(server, username, password, email):
    """Log in (no 2FA yet), set an email, then enable 2FA — the real wire
    path (ACCOUNT_EMAIL_SET, ACCOUNT_2FA_SET) a self-service settings
    screen uses, not a test-only shortcut."""
    with VwClient(server.host, server.port, server.cert) as c:
        info = c.login(username, password)
        token = info["session_token"]
        c.account_email_set(token, email)
        c.account_2fa_set(token, password, True)


def _start_2fa_server(binaries, tmp_path_factory, label, smtp):
    binaries.require_server()
    binaries.require_tls()
    tmpdir = str(tmp_path_factory.mktemp(label))
    server = ServerInstance(binaries, tmpdir, extra_conf=_smtp_conf(smtp))
    server.start()
    return server


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_2fa_login_probe_then_retry_succeeds(binaries, tmp_path_factory, unique_username):
    """
    The core TASK-238 regression: probe on one connection (must not itself
    log in), then submit the code the probe's own email contained on a
    SEPARATE connection — this must now succeed, and must not have sent a
    second, different code as a side effect of the second connection's own
    AUTH_REQUEST.
    """
    with MockSmtpServer() as smtp:
        server = _start_2fa_server(binaries, tmp_path_factory, "vw_2fa_probe_retry", smtp)
        try:
            server.create_user(unique_username, PASSWORD)
            _enable_2fa(server, unique_username, PASSWORD, "probe-retry@example.invalid")

            with VwClient(server.host, server.port, server.cert) as c:
                with pytest.raises(VwTwoFaRequired):
                    c.login(unique_username, PASSWORD)

            assert _wait_until(lambda: len(smtp.messages) >= 1), (
                "no OTP email arrived after the probe"
            )
            assert len(smtp.messages) == 1, (
                f"expected exactly one OTP email after the probe, got {len(smtp.messages)}"
            )
            otp_code = _extract_otp(smtp.messages[0].body)

            with VwClient(server.host, server.port, server.cert) as c:
                info = c.login(unique_username, PASSWORD, otp_code=otp_code)

            assert len(info["session_token"]) == 32
            assert info["user_id"] > 0

            assert len(smtp.messages) == 1, (
                f"reusing the pending challenge for the retry must not send "
                f"another email, got {len(smtp.messages)} total"
            )
        finally:
            server.stop()


def test_2fa_repeated_probes_reuse_the_same_code(binaries, tmp_path_factory, unique_username):
    """
    A second probe (e.g. the user re-opening the login screen before typing
    the code) must reuse the same pending challenge, not mint and email a
    second one — otherwise whichever code the user acts on last is a race
    against however many probes happened to fire.
    """
    with MockSmtpServer() as smtp:
        server = _start_2fa_server(binaries, tmp_path_factory, "vw_2fa_double_probe", smtp)
        try:
            server.create_user(unique_username, PASSWORD)
            _enable_2fa(server, unique_username, PASSWORD, "double-probe@example.invalid")

            for _ in range(2):
                with VwClient(server.host, server.port, server.cert) as c:
                    with pytest.raises(VwTwoFaRequired):
                        c.login(unique_username, PASSWORD)

            assert _wait_until(lambda: len(smtp.messages) >= 1)
            assert len(smtp.messages) == 1, (
                f"two probes within the OTP window must send exactly one "
                f"email, got {len(smtp.messages)}"
            )
            otp_code = _extract_otp(smtp.messages[0].body)

            with VwClient(server.host, server.port, server.cert) as c:
                info = c.login(unique_username, PASSWORD, otp_code=otp_code)
            assert info["user_id"] > 0
        finally:
            server.stop()


def test_2fa_wrong_code_on_fresh_connection_then_correct_code_succeeds(
    binaries, tmp_path_factory, unique_username
):
    """
    A wrong guess on one connection must not burn the pending challenge —
    the correct code, submitted on a later, separate connection within the
    same window/attempt budget, must still work.
    """
    with MockSmtpServer() as smtp:
        server = _start_2fa_server(binaries, tmp_path_factory, "vw_2fa_wrong_then_right", smtp)
        try:
            server.create_user(unique_username, PASSWORD)
            _enable_2fa(server, unique_username, PASSWORD, "wrong-then-right@example.invalid")

            with VwClient(server.host, server.port, server.cert) as c:
                with pytest.raises(VwTwoFaRequired):
                    c.login(unique_username, PASSWORD)
            assert _wait_until(lambda: len(smtp.messages) >= 1)
            otp_code = _extract_otp(smtp.messages[0].body)

            wrong_code = "".join("1" if d != "1" else "2" for d in otp_code)
            with VwClient(server.host, server.port, server.cert) as c:
                with pytest.raises(VwAuthError):
                    c.login(unique_username, PASSWORD, otp_code=wrong_code)

            with VwClient(server.host, server.port, server.cert) as c:
                info = c.login(unique_username, PASSWORD, otp_code=otp_code)
            assert info["user_id"] > 0

            assert len(smtp.messages) == 1, (
                "the wrong-code attempt must not have triggered another email"
            )
        finally:
            server.stop()


def test_2fa_non_2fa_account_unaffected(binaries, tmp_path_factory, unique_username):
    """
    Sanity check that the pending-challenge table introduced by this fix is
    scoped to 2FA accounts only — a plain (non-2FA) account must still log
    in directly with no AUTH_CHALLENGE at all.
    """
    with MockSmtpServer() as smtp:
        server = _start_2fa_server(binaries, tmp_path_factory, "vw_2fa_unaffected", smtp)
        try:
            server.create_user(unique_username, PASSWORD)
            with VwClient(server.host, server.port, server.cert) as c:
                info = c.login(unique_username, PASSWORD)
            assert info["user_id"] > 0
            assert smtp.messages == []
        finally:
            server.stop()
