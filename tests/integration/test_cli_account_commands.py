"""
test_cli_account_commands.py — integration test for TASK-162's
`vapourwault-cli account add|list|remove` subcommands and `--account` flag.

Unlike test_daemon_ipc_accounts.py (which speaks the daemon's IPC wire
format directly in Python) and test_daemon_multi_account.py (which drives
the sync engine directly), this drives the actual compiled
`vapourwault-cli` binary as a subprocess against a real running daemon —
the thing TASK-162 actually added, and the part neither of those other
tests exercises: argument parsing, `--account <label-or-id>` resolution,
and the `account` subcommand's own output formatting.

Uses TWO fully independent vapourwaultd processes (not one server with two
users) for the same reason test_daemon_multi_account.py does: accounts are
per-server, not just per-user (ARCHITECTURE.md's 2026-08-13 design
revision), and `account add` takes host/port/CA-cert per account
specifically so a user can add accounts on two unrelated self-hosted
networks from the same client.
"""

import subprocess

from conftest import ServerInstance


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def test_account_add_list_remove_via_cli(binaries, tmp_path_factory, cli_bin, running_daemon,
                                          unique_username):
    """
    `account add` against two genuinely different server processes,
    `account list` showing both correctly, an account-scoped command
    (`ls`) correctly requiring/accepting `--account` once a second account
    exists, and `account remove` cleanly dropping one.
    """
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    label_a = f"{unique_username}_a"
    label_b = f"{unique_username}_b"

    server_a = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_server_a")))
    server_b = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_server_b")))
    server_a.start()
    server_b.start()
    try:
        server_a.create_user(label_a, password)
        server_b.create_user(label_b, password)

        # ── account add: two accounts, two different servers, each with its
        # own CA cert (vw_net_connect requires VW_CERT_VERIFY_REQUIRED with
        # a real ca_cert_pem_path — an empty one is VW_ERR_INVALID_ARG, per
        # ARCHITECTURE.md's "CA store (vw_net)" decision) ──
        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server_a.host, str(server_a.port), label_a, password,
                             "--ca-cert", server_a.cert)
        assert rc == 0, f"account add (server A) failed: {out}\n{err}"
        assert "account added" in out

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server_b.host, str(server_b.port), label_b, password,
                             "--ca-cert", server_b.cert)
        assert rc == 0, f"account add (server B) failed: {out}\n{err}"
        assert "account added" in out

        # ── account list: both present, correct server column each ──
        rc, out, err = _cli(cli_bin, running_daemon, "account", "list")
        assert rc == 0, f"account list failed: {out}\n{err}"
        assert label_a in out
        assert label_b in out
        assert f"{server_a.host}:{server_a.port}".split(":")[0] in out  # host shown

        # ── An account-scoped command with two accounts configured and no
        # --account must fail with a helpful error, not silently guess. ──
        rc, out, err = _cli(cli_bin, running_daemon, "ls")
        assert rc != 0, "ls without --account should fail once multiple accounts exist"
        assert "--account" in (out + err)

        # ── ...but works once --account disambiguates, for both accounts. ──
        rc, out, err = _cli(cli_bin, running_daemon, "--account", label_a, "ls")
        assert rc == 0, f"ls --account {label_a} failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", label_b, "ls")
        assert rc == 0, f"ls --account {label_b} failed: {out}\n{err}"

        # ── account remove: drop B, confirm only A remains, and A's
        # commands no longer need --account (back to the zero-config
        # single-account case). ──
        rc, out, err = _cli(cli_bin, running_daemon, "account", "remove", label_b)
        assert rc == 0, f"account remove failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "account", "list")
        assert rc == 0
        assert label_a in out
        assert label_b not in out

        rc, out, err = _cli(cli_bin, running_daemon, "ls")
        assert rc == 0, f"ls with the sole remaining account should need no --account: {out}\n{err}"
    finally:
        server_a.stop()
        server_b.stop()


def test_account_add_bad_credentials_fails_cleanly(binaries, tmp_path_factory, cli_bin,
                                                     running_daemon, unique_username):
    """A wrong password must fail account add with a clear error, and must
    not leave a half-added account behind."""
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    label = unique_username

    server_a = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_server_bad")))
    server_a.start()
    try:
        server_a.create_user(label, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server_a.host, str(server_a.port), label, "wrong-password")
        assert rc != 0
        assert "failed" in (out + err).lower()

        rc, out, err = _cli(cli_bin, running_daemon, "account", "list")
        assert rc == 0
        assert "no accounts configured" in out
    finally:
        server_a.stop()
