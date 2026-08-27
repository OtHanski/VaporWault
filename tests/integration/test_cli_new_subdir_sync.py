"""
test_cli_new_subdir_sync.py — regression test for TASK-218.

Reproduces the exact bug report: create a new local subdirectory inside an
already-added sync folder, put a file in it, both done directly on the
filesystem (not through the CLI/GUI's own `mkdir` command) — background
sync used to never create the matching remote folder at all, so the file
never uploaded and the daemon repeated "sync cycle for '<user>' had 1
action error(s)" forever (see TASK-218's own notes for the root cause:
resolve_or_create_dir(), previously shared-folders-only, now also handles
an owned folder's tree).

Drives the real compiled `vapourwault-cli`/`vapourwault-daemon` against a
real server, same style as test_cli_version_history.py.
"""

import os
import subprocess
import time

from conftest import ServerInstance


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _wait_for_clean_sync(cli_bin, ipc_port, account, timeout=15):
    """Like test_cli_version_history.py's _wait_for_sync, but also requires
    0 errors — TASK-218's bug specifically left uploads permanently stuck
    behind a repeating action error, which "0 uploads, 0 downloads" alone
    (ignoring the error count) would not have caught."""
    time.sleep(1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, out, _ = _cli(cli_bin, ipc_port, "--account", account, "status")
        if rc == 0 and "0 uploads, 0 downloads, 0 errors" in out:
            return True
        time.sleep(0.3)
    return False


def test_new_local_subdirectory_syncs_up_without_manual_mkdir(
        binaries, tmp_path_factory, cli_bin, running_daemon, unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_new_subdir_server")))
    server.start()
    try:
        server.create_user(unique_username, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_new_subdir_root"))
        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        assert _wait_for_clean_sync(cli_bin, running_daemon, unique_username), \
            "initial (empty) sync never settled"

        # The exact repro: mkdir + write, both directly on the filesystem,
        # never touching the CLI/GUI's own mkdir command.
        new_subdir = os.path.join(local_root, "newsub")
        os.makedirs(new_subdir, exist_ok=True)
        with open(os.path.join(new_subdir, "file.txt"), "w") as f:
            f.write("created inside a brand-new local subdirectory\n")

        assert _wait_for_clean_sync(cli_bin, running_daemon, unique_username), (
            "sync never settled after creating a new local subdirectory + file — "
            "this is exactly TASK-218's bug if it reappears (background sync "
            "unable to create the matching remote folder, looping on an action "
            "error forever instead of uploading)"
        )

        # The file must actually be findable server-side now, not just
        # "no error reported" — belt-and-suspenders against a fix that
        # silently drops the action instead of completing it.
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "search", "file.txt")
        assert rc == 0, f"search failed: {out}\n{err}"
        assert "file.txt" in out, f"uploaded file not found via search: {out}"

        # A second local file in the SAME new subdirectory, added in a
        # later cycle — proves the remote folder, once created, is
        # reused (not re-created, not erroring on "already exists")
        # for a sibling that arrives afterward.
        with open(os.path.join(new_subdir, "second.txt"), "w") as f:
            f.write("a second file in the same new subdirectory\n")
        assert _wait_for_clean_sync(cli_bin, running_daemon, unique_username), (
            "sync never settled for a second file added to the "
            "already-created new subdirectory"
        )
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "search", "second.txt")
        assert rc == 0, f"search failed: {out}\n{err}"
        assert "second.txt" in out, f"second uploaded file not found via search: {out}"
    finally:
        server.stop()
