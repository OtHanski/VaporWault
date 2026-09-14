"""
test_cli_list_folder.py — integration test for TASK-00281's daemon IPC
(VW_IPC_SHARED_FOLDER_LIST_REQ/RESP) and the `vapourwault-cli list-folder`
subcommand.

Same style as test_cli_version_history.py's file_id-based tests: a grantee
has no owner-namespaced path into content they don't own, so browsing has
to go through file_id instead — `list-shares --to-me` for the top-level
shared folder, then `list-folder <file_id>` to descend, one level (or the
whole subtree with --recursive) at a time. This is the actual gap TASK-00281
closed: the wire protocol and permission model (unbounded-depth inheritance
down a shared folder's subtree) already worked; no daemon IPC message ever
exposed a live, non-cache listing by file_id to a caller.
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


def _wait_for_sync(cli_bin, ipc_port, timeout=15):
    time.sleep(1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, out, _ = _cli(cli_bin, ipc_port, "status")
        if rc == 0 and "0 uploads, 0 downloads" in out:
            return True
        time.sleep(0.3)
    return False


def _list_shares_to_me(cli_bin, ipc_port, account, name):
    rc, out, err = _cli(cli_bin, ipc_port, "--account", account,
                         "list-shares", "--to-me")
    assert rc == 0, f"list-shares --to-me failed: {out}\n{err}"
    for line in out.strip().splitlines()[1:]:  # skip header
        cols = line.split()
        if cols and cols[-1] == name:
            return int(cols[1])  # SHARE_ID, FILE, TYPE, PERM, TARGET, EXPIRES..., NAME
    raise AssertionError(f"no share named {name!r} found in list-shares --to-me output:\n{out}")


def _parse_list_folder(out):
    """Returns {name: (file_id, is_dir)} from `list-folder`'s output."""
    rows = {}
    for line in out.strip().splitlines()[1:]:  # skip header
        cols = line.split()
        if not cols:
            continue
        file_id = int(cols[0])
        is_dir = cols[1] == "dir"
        name = cols[-1]
        rows[name] = (file_id, is_dir)
    return rows


def test_cli_list_folder_descends_into_a_shared_folders_nested_subfolder(
        binaries, tmp_path_factory, cli_bin, running_daemon, unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    owner = unique_username
    grantee = f"{unique_username}_grantee"

    # max_workers=4: owner + grantee concurrently connected, same
    # worker-pool-exhaustion class test_cli_version_history.py already
    # hits and fixes the same way.
    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_list_folder_server")),
                             max_workers=4)
    server.start()
    try:
        server.create_user(owner, password)
        server.create_user(grantee, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), owner, password,
                             "--ca-cert", server.cert, "--label", owner)
        assert rc == 0, f"account add (owner) failed: {out}\n{err}"

        # Local tree: shared_dir/{top.txt, nested/{deep.txt}}
        tmpdir = str(tmp_path_factory.mktemp("vw_cli_list_folder_root"))
        owner_root = os.path.join(tmpdir, "owner_root")
        shared_dir = os.path.join(owner_root, "shared_dir")
        nested_dir = os.path.join(shared_dir, "nested")
        os.makedirs(nested_dir, exist_ok=True)
        with open(os.path.join(shared_dir, "top.txt"), "w") as f:
            f.write("top-level content\n")
        with open(os.path.join(nested_dir, "deep.txt"), "w") as f:
            f.write("nested content, a bit longer than top\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "add-folder", owner_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        assert _wait_for_sync(cli_bin, running_daemon), "initial upload never completed"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "share", "/shared_dir", grantee, "view")
        assert rc == 0, f"share (folder) failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), grantee, password,
                             "--ca-cert", server.cert, "--label", grantee)
        assert rc == 0, f"account add (grantee) failed: {out}\n{err}"

        # ── The grantee has no owner-namespaced path to shared_dir at all —
        # this is exactly the case list-folder exists for. ──
        top_id = _list_shares_to_me(cli_bin, running_daemon, grantee, "shared_dir")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", grantee,
                             "list-folder", str(top_id))
        assert rc == 0, f"list-folder (top) failed: {out}\n{err}"
        top_entries = _parse_list_folder(out)
        assert "top.txt" in top_entries, f"expected top.txt in {top_entries}"
        assert "nested" in top_entries, f"expected nested/ in {top_entries}"
        assert top_entries["top.txt"][1] is False, "top.txt must be listed as a file"
        assert top_entries["nested"][1] is True, "nested must be listed as a dir"

        # ── Descend one level, by the nested folder's own file_id — the
        # actual thing TASK-00281 makes possible: permission inherits down
        # an unbounded-depth subtree with no separate grant needed. ──
        nested_id = top_entries["nested"][0]
        rc, out, err = _cli(cli_bin, running_daemon, "--account", grantee,
                             "list-folder", str(nested_id))
        assert rc == 0, f"list-folder (nested) failed: {out}\n{err}"
        nested_entries = _parse_list_folder(out)
        assert "deep.txt" in nested_entries, f"expected deep.txt in {nested_entries}"
        assert nested_entries["deep.txt"][1] is False

        # ── --recursive from the top returns the whole subtree in one call. ──
        rc, out, err = _cli(cli_bin, running_daemon, "--account", grantee,
                             "list-folder", str(top_id), "--recursive")
        assert rc == 0, f"list-folder --recursive failed: {out}\n{err}"
        recursive_entries = _parse_list_folder(out)
        assert "top.txt" in recursive_entries
        assert "deep.txt" in recursive_entries, (
            f"--recursive must include the nested subtree: {recursive_entries}"
        )

        # ── An unrelated third party (no grant at all) must not be able to
        # browse the same folder by guessing its file_id. ──
        stranger = f"{unique_username}_stranger"
        server.create_user(stranger, password)
        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), stranger, password,
                             "--ca-cert", server.cert, "--label", stranger)
        assert rc == 0, f"account add (stranger) failed: {out}\n{err}"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", stranger,
                             "list-folder", str(top_id))
        assert rc != 0, (
            f"an unrelated user must not be able to list a folder they have "
            f"no grant on: {out}\n{err}"
        )
    finally:
        server.stop()
