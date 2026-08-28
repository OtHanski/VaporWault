"""
test_cli_account_2fa.py — integration test for TASK-219's daemon IPC
(ACCOUNT_2FA_SET_REQ/_ACK) and the `vapourwault-cli account 2fa on|off`
subcommand.

Drives the actual compiled `vapourwault-cli` binary as a subprocess
against a real running daemon and server, same style as
test_cli_account_email.py. This is the acceptance-criterion test TASK-219
itself asked for: a user enabling/disabling their own 2FA enrollment
without admin intervention, through a real, documented wire mechanism.

The email-delivery side of 2FA (does a real AUTH_CHALLENGE/AUTH_OTP round
trip actually happen once enabled) is not re-proven here — that's
pre-existing, already-shipped behavior (vw_auth.c's OTP flow, gated on
otp_enabled, predates this task). This file's job is proving the new
*toggle* mechanism itself: who can flip it, what it requires, and what it
refuses. `account_security_change` actually firing on both directions of
the toggle is covered separately in test_notify_alerts.py, since that
needs the mock-SMTP harness this file doesn't otherwise use.
"""

import subprocess

from conftest import ServerInstance


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def test_cli_account_2fa_enable_requires_email_and_correct_password(
        binaries, tmp_path_factory, running_daemon, cli_bin, unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_2fa_cli_server")))
    server.start()
    try:
        server.create_user(unique_username, password)
        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        # No email on file yet — enabling must be refused (2FA codes are
        # emailed; enabling without an email would lock the account out).
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "2fa", "on", password)
        assert rc != 0, f"2fa on with no email on file should be refused: {out}\n{err}"

        # Set an email (TASK-222's real mechanism), then wrong password
        # must still be refused.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email", "set", f"{unique_username}@example.com")
        assert rc == 0, f"account email set failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "2fa", "on", "wrong-password")
        assert rc != 0, f"2fa on with the wrong password should be refused: {out}\n{err}"

        # Correct password, email on file: enabling succeeds for real.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "2fa", "on", password)
        assert rc == 0, f"2fa on failed: {out}\n{err}"
        assert "on" in out.lower()

        # Disabling requires the correct password too.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "2fa", "off", "wrong-password")
        assert rc != 0, f"2fa off with the wrong password should be refused: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "2fa", "off", password)
        assert rc == 0, f"2fa off failed: {out}\n{err}"
        assert "off" in out.lower()
    finally:
        server.stop()


def test_cli_account_2fa_toggle_is_scoped_to_the_calling_account_only(
        binaries, tmp_path_factory, running_daemon, cli_bin, unique_username):
    """Same session/account-scoping posture as account email and notify
    prefs: an account can only ever toggle its own 2FA state, never
    another account's, and there is no user_id field anywhere on the
    wire that could be pointed at someone else."""
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    a = unique_username
    b = f"{unique_username}_other"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_2fa_cli_scope_server")))
    server.start()
    try:
        server.create_user(a, password)
        server.create_user(b, password)
        for user in (a, b):
            rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                                 server.host, str(server.port), user, password,
                                 "--ca-cert", server.cert, "--label", user)
            assert rc == 0, f"account add ({user}) failed: {out}\n{err}"
            rc, out, err = _cli(cli_bin, running_daemon, "--account", user,
                                 "account", "email", "set", f"{user}@example.com")
            assert rc == 0, f"account email set ({user}) failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", a,
                             "account", "2fa", "on", password)
        assert rc == 0, f"2fa on (a) failed: {out}\n{err}"

        # b's own toggle is independent — enabling a's did not affect b.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", b,
                             "account", "2fa", "off", password)
        assert rc == 0, f"2fa off (b) failed: {out}\n{err}"
    finally:
        server.stop()
