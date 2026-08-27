"""
test_cli_account_email.py — integration test for TASK-222's daemon IPC
(ACCOUNT_EMAIL_GET/SET_REQ/_RESP/_ACK) and the `vapourwault-cli account
email`/`account email set <address>` subcommands.

This is the acceptance-criterion test TASK-222 itself asked for: a real
admin or end user getting a non-empty, real email address onto an account
through a documented, implemented wire mechanism, verified WITHOUT
patching users.dat directly (unlike test_notify_alerts.py's test-only
`_set_user_email_raw`, which existed only because no real path existed
until this task shipped it).

Drives the actual compiled `vapourwault-cli` binary as a subprocess
against a real running daemon and server, same style as
test_cli_notify_prefs.py.
"""

import subprocess

from conftest import ServerInstance


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def test_cli_account_email_default_empty_then_set_and_get(
        binaries, tmp_path_factory, running_daemon, cli_bin, unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_email_cli_server")))
    server.start()
    try:
        server.create_user(unique_username, password)
        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        # Default: no email on file for a freshly created account.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email")
        assert rc == 0, f"account email (get) failed: {out}\n{err}"
        assert "no email on file" in out, out

        # Set a real address through the real wire mechanism.
        address = f"{unique_username}@example.com"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email", "set", address)
        assert rc == 0, f"account email set failed: {out}\n{err}"
        assert address in out, out

        # It round-trips back on a fresh get.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email")
        assert rc == 0, f"account email (get) after set failed: {out}\n{err}"
        assert address in out, out

        # Changing it again works (old address must not linger/shadow).
        address2 = f"{unique_username}-2@example.com"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email", "set", address2)
        assert rc == 0, f"account email set (change) failed: {out}\n{err}"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email")
        assert rc == 0
        assert address2 in out and address not in out, out

        # Clearing back to empty works too.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email", "set", "")
        assert rc == 0, f"account email clear failed: {out}\n{err}"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "account", "email")
        assert rc == 0
        assert "no email on file" in out, out
    finally:
        server.stop()


def test_cli_account_email_rejects_malformed_and_duplicate(
        binaries, tmp_path_factory, running_daemon, cli_bin, unique_username):
    """
    Server-side format validation (vw_email_validate) is the real security
    boundary here — an unvalidated address would be SMTP command injection
    into vw_smtp.c's "RCPT TO:<%s>" once the email-alert system (TASK-207)
    tries to mail it. This also proves the email_ht uniqueness index
    (fixed alongside this feature — TASK-222) actually rejects a second
    account claiming an address already on file.
    """
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    owner = unique_username
    other = f"{unique_username}_other"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_email_cli_bad_server")))
    server.start()
    try:
        server.create_user(owner, password)
        server.create_user(other, password)
        for user in (owner, other):
            rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                                 server.host, str(server.port), user, password,
                                 "--ca-cert", server.cert, "--label", user)
            assert rc == 0, f"account add ({user}) failed: {out}\n{err}"

        # Malformed addresses: no '@', control characters (CRLF injection
        # attempt), no dot in the domain part.
        for bad in ("not-an-email", "a@b", "evil@example.com\r\nDATA"):
            rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                                 "account", "email", "set", bad)
            assert rc != 0, f"malformed address should be rejected: {bad!r} -> {out}\n{err}"

        # owner claims an address.
        address = f"{owner}@example.com"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "account", "email", "set", address)
        assert rc == 0, f"account email set failed: {out}\n{err}"

        # other cannot claim the same address.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", other,
                             "account", "email", "set", address)
        assert rc != 0, f"duplicate address should be rejected: {out}\n{err}"

        # other's own email is untouched (still empty) after the rejection.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", other,
                             "account", "email")
        assert rc == 0
        assert "no email on file" in out, out
    finally:
        server.stop()
