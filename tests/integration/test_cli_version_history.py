"""
test_cli_version_history.py — integration test for TASK-182's daemon IPC
(VERSION_LIST_REQ/RESP, VERSION_RESTORE_REQ/RESP) and the `vapourwault-cli
version list|restore` subcommands.

Drives the actual compiled `vapourwault-cli` binary as a subprocess against
a real running daemon and server, same style as test_cli_account_commands.py
and test_cli_fallback.py — this is the first exposure of version history
outside the web frontend (server-side VERSION_LIST/VERSION_RESTORE and the
vw_client_core.c wrappers already existed and were already exercised by
other tests; the daemon IPC and CLI subcommands are new here).
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
    """Poll `status` until it reports 0 pending uploads and downloads.

    A short grace sleep runs first — a status check immediately after
    writing a local file can race the watcher/next scan cycle and see
    "0 pending" because the change hasn't been noticed yet, not because
    it finished (the same race `test_cli_fallback.py` avoids with a flat
    `time.sleep(2)` after every filesystem change, not a poll)."""
    time.sleep(1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, out, _ = _cli(cli_bin, ipc_port, "status")
        if rc == 0 and "0 uploads, 0 downloads" in out:
            return True
        time.sleep(0.3)
    return False


def test_cli_version_list_and_restore(binaries, tmp_path_factory, cli_bin, running_daemon,
                                        unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_version_server")))
    server.start()
    try:
        server.create_user(unique_username, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), unique_username, password,
                             "--ca-cert", server.cert)
        assert rc == 0, f"account add failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_cli_version_root"))
        local_root = os.path.join(tmpdir, "sync_root")
        os.makedirs(local_root, exist_ok=True)
        local_file = os.path.join(local_root, "notes.txt")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "add-folder", local_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"

        # v1
        with open(local_file, "w") as f:
            f.write("version one\n")
        assert _wait_for_sync(cli_bin, running_daemon), "v1 upload never completed"

        # v2 — overwrite, forcing a new version record on the server
        with open(local_file, "w") as f:
            f.write("version two, a bit longer than v1\n")
        assert _wait_for_sync(cli_bin, running_daemon), "v2 upload never completed"

        # ── version list: v1's and v2's content sizes are both present. ──
        # Note: a single local write can legitimately produce more than one
        # version record here (the watcher/sync-engine change-detection path
        # firing more than once for one write is pre-existing, unrelated
        # behavior — not something this task's IPC/CLI addition causes or
        # is meant to fix; flagged separately as TASK-215). This test only
        # asserts what TASK-182 is actually responsible for: that
        # `version list`/`version restore` correctly reflect whatever
        # version records the server actually has.
        v1_size = len("version one\n")
        v2_size = len("version two, a bit longer than v1\n")

        def _list_versions():
            rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                                 "version", "list", "/notes.txt")
            assert rc == 0, f"version list failed: {out}\n{err}"
            lines = [l for l in out.strip().splitlines() if l.strip()]
            rows = [l.split() for l in lines[1:]]  # skip header
            return [(int(r[0]), int(r[-1])) for r in rows]  # (version_id, size)

        versions = _list_versions()
        v1_ids = [vid for vid, sz in versions if sz == v1_size]
        v2_ids = [vid for vid, sz in versions if sz == v2_size]
        assert len(v1_ids) == 1, f"expected exactly one v1-sized version, got: {versions}"
        assert len(v2_ids) == 1, f"expected exactly one v2-sized version, got: {versions}"
        assert set(v1_ids).isdisjoint(v2_ids)
        count_before_restore = len(versions)

        # ── restore the most recent v1-sized version as the new HEAD ──
        v1_id = max(v1_ids)
        rc, out, err = _cli(cli_bin, running_daemon, "--account", unique_username,
                             "version", "restore", "/notes.txt", str(v1_id))
        assert rc == 0, f"version restore failed: {out}\n{err}"
        assert str(v1_id) in out

        # A restore creates exactly one brand-new version record (per
        # vw_client_core.h's doc comment on vw_client_version_restore).
        # TASK-215 (fixed): this used to need a loosened ">" here instead
        # of "==" — the daemon's own download of the restored content
        # triggered its own filesystem-watcher event, which
        # vw_sync_mark_local_modified used to treat as a genuine new
        # local edit (it never compared the reported mtime/size against
        # what was already cached), causing an immediate spurious
        # re-upload of the exact content that had just been downloaded.
        versions_after = _list_versions()
        assert len(versions_after) == count_before_restore + 1, (
            f"expected exactly one new version after restore, "
            f"before={versions}, after={versions_after}"
        )
        new_ids = [vid for vid, _ in versions_after if vid not in dict(versions)]
        new_sizes = {sz for vid, sz in versions_after if vid in new_ids}
        assert new_sizes == {v1_size}, (
            f"the new version after restoring a v1-sized version should "
            f"itself be v1-sized, got sizes {new_sizes}"
        )

        # ── The restored content should sync back down to the local file. ──
        deadline = time.monotonic() + 15
        restored = False
        while time.monotonic() < deadline:
            _wait_for_sync(cli_bin, running_daemon, timeout=5)
            with open(local_file) as f:
                if f.read() == "version one\n":
                    restored = True
                    break
            time.sleep(0.5)
        assert restored, "local file content never reverted to v1's content after restore"
    finally:
        server.stop()


def test_cli_version_restore_not_available_for_a_shared_file(
        binaries, tmp_path_factory, cli_bin, running_daemon, unique_username):
    """
    Known, documented limitation (recorded on TASK-182, corrected and
    tracked as TASK-214, client-side follow-up filed as TASK-224):
    vw_client_version_list/vw_client_version_restore are 100% path-based
    (both resolve file_id via vw_client_file_stat first), and path
    resolution is owner-namespaced (ARCHITECTURE.md's TASK-106 note) —
    unlike FILE_LIST/STAT/UPLOAD/DOWNLOAD/DELETE, version history never got
    a file_id-based client entry point. The server side is NOT the
    blocker: handle_version_list/handle_version_restore already resolve
    and authorize purely via file_id/version_id + effective_permission()
    (TASK-214 found and corrected TASK-182's original claim that
    VERSION_RESTORE resolved by path server-side — it never did). So a
    grantee still gets VW_ERR_NOT_FOUND here today, but only because the
    client never gives them a way to reach the server without an
    owner-namespaced path first — this test locks in that it fails
    *cleanly* (a legible error, not a hang or a crash), not that
    permission is being enforced by level (it isn't reached yet)."""
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    owner = unique_username
    viewer = f"{unique_username}_viewer"

    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_version_perm_server")))
    server.start()
    try:
        server.create_user(owner, password)
        server.create_user(viewer, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), owner, password,
                             "--ca-cert", server.cert, "--label", owner)
        assert rc == 0, f"account add (owner) failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_cli_version_perm_root"))
        owner_root = os.path.join(tmpdir, "owner_root")
        os.makedirs(owner_root, exist_ok=True)
        with open(os.path.join(owner_root, "shared.txt"), "w") as f:
            f.write("owner's original content\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "add-folder", owner_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        assert _wait_for_sync(cli_bin, running_daemon), "initial upload never completed"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "share", "/shared.txt", viewer, "view")
        assert rc == 0, f"share (view) failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), viewer, password,
                             "--ca-cert", server.cert, "--label", viewer)
        assert rc == 0, f"account add (viewer) failed: {out}\n{err}"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", viewer,
                             "version", "restore", "/shared.txt", "1")
        assert rc != 0, (
            f"restore against another owner's path must fail cleanly (path "
            f"resolution is owner-namespaced — see TASK-214), not hang or "
            f"crash: {out}\n{err}"
        )
    finally:
        server.stop()
