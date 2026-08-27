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


def _list_shares_to_me(cli_bin, ipc_port, account, name):
    """Parse `list-shares --to-me` and return the file_id for the share
    whose NAME column matches (the last whitespace-split column)."""
    rc, out, err = _cli(cli_bin, ipc_port, "--account", account,
                         "list-shares", "--to-me")
    assert rc == 0, f"list-shares --to-me failed: {out}\n{err}"
    for line in out.strip().splitlines()[1:]:  # skip header
        cols = line.split()
        if cols and cols[-1] == name:
            return int(cols[1])  # SHARE_ID, FILE, TYPE, PERM, TARGET, EXPIRES..., NAME
    raise AssertionError(f"no share named {name!r} found in list-shares --to-me output:\n{out}")


def test_cli_version_history_by_file_id_for_a_shared_file(
        binaries, tmp_path_factory, cli_bin, running_daemon, unique_username):
    """
    TASK-223: the real fix for the gap `test_cli_version_restore_not_
    available_for_a_shared_file` used to lock in (that test name/docstring
    is gone — this replaces it, per TASK-223's own acceptance criteria).

    Background: TASK-214 found the server side was never actually the
    blocker — handle_version_list/handle_version_restore already resolved
    and authorized purely via file_id/version_id + effective_permission().
    The real gap was client-side: vw_client_version_list/_restore only
    ever obtained file_id via an owner-namespaced FILE_STAT. TASK-223
    added vw_client_version_list_by_id/_restore_by_id (and this test)
    to actually close that gap: a grantee identifies the file via
    `list-shares --to-me` (which already returns file_id) instead of a
    path they don't have, then uses `version list --file-id <id>` /
    `version restore --file-id <id> <version_id>`.

    Proves the permission boundary is real and level-dependent, not just
    "fails cleanly regardless of level" (the old test's only claim):
    a VIEW grantee can list versions (VW_PERM_VIEW) but not restore one
    (VW_PERM_EDIT required — handle_version_restore rejects with
    VW_ERR_VERSION_NOT_FOUND rather than a distinct permission error, a
    deliberate existing "don't leak existence below EDIT" posture, not
    something this task introduced); an EDIT grantee can do both.
    """
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    owner = unique_username
    viewer = f"{unique_username}_viewer"
    editor = f"{unique_username}_editor"

    # max_workers=4: three concurrently-connected daemon accounts (owner,
    # viewer, editor) exceed ServerInstance's default of 2 — same
    # worker-pool-exhaustion class of timeout test_cli_search.py and
    # test_notify_alerts.py both already hit and fixed the same way.
    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_version_perm_server")),
                             max_workers=4)
    server.start()
    try:
        server.create_user(owner, password)
        server.create_user(viewer, password)
        server.create_user(editor, password)

        rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                             server.host, str(server.port), owner, password,
                             "--ca-cert", server.cert, "--label", owner)
        assert rc == 0, f"account add (owner) failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_cli_version_perm_root"))
        owner_root = os.path.join(tmpdir, "owner_root")
        os.makedirs(owner_root, exist_ok=True)
        local_file = os.path.join(owner_root, "shared.txt")
        with open(local_file, "w") as f:
            f.write("v1 content\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "add-folder", owner_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        assert _wait_for_sync(cli_bin, running_daemon), "v1 upload never completed"

        with open(local_file, "w") as f:
            f.write("v2 content, a bit longer\n")
        assert _wait_for_sync(cli_bin, running_daemon), "v2 upload never completed"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "share", "/shared.txt", viewer, "view")
        assert rc == 0, f"share (view) failed: {out}\n{err}"
        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "share", "/shared.txt", editor, "edit")
        assert rc == 0, f"share (edit) failed: {out}\n{err}"

        for grantee in (viewer, editor):
            rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                                 server.host, str(server.port), grantee, password,
                                 "--ca-cert", server.cert, "--label", grantee)
            assert rc == 0, f"account add ({grantee}) failed: {out}\n{err}"

        # ── VIEW grantee: list succeeds (VW_PERM_VIEW), restore does not
        #    (VW_PERM_EDIT required) — the permission boundary itself, not
        #    a path-resolution failure. ──
        viewer_file_id = _list_shares_to_me(cli_bin, running_daemon, viewer, "shared.txt")
        rc, out, err = _cli(cli_bin, running_daemon, "--account", viewer,
                             "version", "list", "--file-id", str(viewer_file_id))
        assert rc == 0, f"VIEW grantee's version list --file-id failed: {out}\n{err}"
        lines = [l for l in out.strip().splitlines() if l.strip()]
        rows = [l.split() for l in lines[1:]]
        assert len(rows) >= 2, f"expected at least 2 versions visible to VIEW grantee: {out}"
        viewer_v1_id = min(int(r[0]) for r in rows)

        rc, out, err = _cli(cli_bin, running_daemon, "--account", viewer,
                             "version", "restore", "--file-id", str(viewer_file_id),
                             str(viewer_v1_id))
        assert rc != 0, (
            f"a VIEW-only grantee must not be able to restore a version: {out}\n{err}"
        )

        # ── EDIT grantee: both list and restore succeed for real. ──
        editor_file_id = _list_shares_to_me(cli_bin, running_daemon, editor, "shared.txt")
        assert editor_file_id == viewer_file_id, "same underlying file, same file_id"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", editor,
                             "version", "list", "--file-id", str(editor_file_id))
        assert rc == 0, f"EDIT grantee's version list --file-id failed: {out}\n{err}"
        rows = [l.split() for l in out.strip().splitlines()[1:] if l.strip()]
        v1_id = min(int(r[0]) for r in rows)
        count_before = len(rows)

        rc, out, err = _cli(cli_bin, running_daemon, "--account", editor,
                             "version", "restore", "--file-id", str(editor_file_id), str(v1_id))
        assert rc == 0, f"EDIT grantee's version restore --file-id failed: {out}\n{err}"
        assert str(v1_id) in out

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "version", "list", "/shared.txt")
        assert rc == 0
        rows_after = [l.split() for l in out.strip().splitlines()[1:] if l.strip()]
        assert len(rows_after) == count_before + 1, (
            f"restore by an EDIT grantee should create exactly one new "
            f"version, same as an owner's own restore: before={count_before}, "
            f"after={len(rows_after)}"
        )
    finally:
        server.stop()
