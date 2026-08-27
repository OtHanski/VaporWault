"""
test_cli_link_password.py — integration test for TASK-188's
`vapourwault-cli create-link --password` and `list-links`' PASSWORD
column, driven through the real compiled binaries (the daemon IPC +
CLI argument-parsing surface this task actually added — the server-side
enforcement itself is already covered by test_link_password.py, which
drives the wire protocol directly).
"""

import os
import subprocess

from conftest import ServerInstance


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def test_cli_create_link_with_password(binaries, tmp_path_factory, cli_bin, running_daemon,
                                         unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_link_pw_server")))
    server.start()
    try:
        server.create_user(unique_username, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_cli_link_pw_root"))
        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)
        with open(os.path.join(local_root, "doc.txt"), "w") as f:
            f.write("hello\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"

        import time
        time.sleep(2)  # let the initial upload complete

        # A password-protected link.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "create-link", "/doc.txt", "view", "0", "--password", "hunter2")
        assert rc == 0, f"create-link --password failed: {out}\n{err}"
        assert "link created" in out

        # A plain link, no password.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "create-link", "/doc.txt", "view")
        assert rc == 0, f"create-link (no password) failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username, "list-links")
        assert rc == 0, f"list-links failed: {out}\n{err}"
        lines = [l for l in out.strip().splitlines() if l.strip()]
        assert len(lines) == 3, f"expected header + 2 link rows, got: {out!r}"
        # PASSWORD column: one row "yes", one row "no" — not asserting
        # which row is which, just that both states are represented and
        # visible in the CLI's own output.
        password_values = [line.split()[5] for line in lines[1:]]
        assert sorted(password_values) == ["no", "yes"], f"list-links PASSWORD column: {lines[1:]}"
    finally:
        server.stop()
