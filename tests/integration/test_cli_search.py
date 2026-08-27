"""
test_cli_search.py — integration test for TASK-199's daemon IPC
(SEARCH_REQ/RESP) and the `vapourwault-cli search <query>` subcommand.

Drives the actual compiled `vapourwault-cli` binary as a subprocess against
a real running daemon and server, same style as test_cli_version_history.py.
The server-side SEARCH handler's own permission-safety properties (a
stranger's search never observes a match they can't see, the 200-entry
cap/truncated boundary) are already proven at the wire level by
tests/integration/test_search.c/.py (TASK-198) — this file's job is the
layer above that: does the real daemon IPC round-trip and the real CLI
subcommand carry those same properties through correctly, end to end.

"Works while on fallback" (this task's third acceptance criterion) is not
re-proven here with a full cluster/fallback rig (that mechanism itself
already has dedicated regression coverage in test_cli_fallback.py, TASK-179)
— it's satisfied by construction: the daemon's VW_IPC_SEARCH_REQ handler in
vw_daemon.c mirrors VW_IPC_VERSION_LIST_REQ's read pattern (no
account_is_read_only() gate), not VW_IPC_VERSION_RESTORE_REQ's write-gated
one. See TASK-199's own notes for this reasoning.
"""

import os
import time

from conftest import ServerInstance


def _cli(cli_bin, ipc_port, *args, timeout=15):
    import subprocess
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _wait_for_sync(cli_bin, ipc_port, account, timeout=15):
    """Same race-avoidance rationale as test_cli_version_history.py's helper."""
    time.sleep(1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, out, _ = _cli(cli_bin, ipc_port, "--account", account, "status")
        if rc == 0 and "0 uploads, 0 downloads" in out:
            return True
        time.sleep(0.3)
    return False


def _search_names(cli_bin, ipc_port, account, query):
    rc, out, err = _cli(cli_bin, ipc_port, "--account", account, "search", query)
    assert rc == 0, f"search failed: {out}\n{err}"
    lines = [l for l in out.strip().splitlines() if l.strip()]
    rows = [l.split() for l in lines[1:]]  # skip header
    # NAME is the last column in cmd_search's fixed-width layout.
    return [r[-1] for r in rows if r]


def test_cli_search_whole_tree_and_permission_scoping(
        binaries, tmp_path_factory, cli_bin, running_daemon, unique_username):
    binaries.require_server()
    binaries.require_tls()
    password = "TestP@ssw0rd!"
    owner = f"{unique_username}_owner"
    grantee = f"{unique_username}_grantee"
    stranger = f"{unique_username}_stranger"

    # max_workers=4: the daemon keeps one persistent connection open per
    # configured account for its background sync cycle, and this test
    # configures three accounts (owner/grantee/stranger) concurrently —
    # the default max_workers=2 test-server config isn't enough headroom
    # (same worker-pool-exhaustion class of issue as TASK-198's own
    # test_search.c fix, but here it's the daemon's persistent per-account
    # connections rather than short-lived test-harness sessions, so closing
    # sessions between steps isn't an option).
    server = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_cli_search_server")),
                             max_workers=4)
    server.start()
    try:
        server.create_user(owner, password)
        server.create_user(grantee, password)
        server.create_user(stranger, password)

        for user in (owner, grantee, stranger):
            rc, out, err = _cli(cli_bin, running_daemon, "account", "add",
                                 server.host, str(server.port), user, password,
                                 "--ca-cert", server.cert, "--label", user)
            assert rc == 0, f"account add ({user}) failed: {out}\n{err}"

        tmpdir = str(tmp_path_factory.mktemp("vw_cli_search_root"))
        owner_root = os.path.join(tmpdir, "owner_root")
        os.makedirs(owner_root, exist_ok=True)

        # Both files at top level — a locally-created new subdirectory is
        # a separate, real gap (background sync never creates the matching
        # remote folder for one; see TASK-218, filed while first writing
        # this test) and not what this test is about. "Whole tree, not
        # just the current directory" is still meaningfully exercised
        # here: this CLI has no directory-scoped listing at all (unlike
        # FILE_LIST's per-directory shallow enumeration), so a flat
        # multi-file account already proves SEARCH isn't limited the way
        # a hypothetical directory-scoped search would be.
        with open(os.path.join(owner_root, "findme_owned.txt"), "w") as f:
            f.write("owner only\n")
        with open(os.path.join(owner_root, "findme_shared.txt"), "w") as f:
            f.write("shared with grantee\n")

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "add-folder", owner_root, "/")
        assert rc == 0, f"add-folder failed: {out}\n{err}"
        assert _wait_for_sync(cli_bin, running_daemon, owner), "initial upload never completed"

        rc, out, err = _cli(cli_bin, running_daemon, "--account", owner,
                             "share", "/findme_shared.txt", grantee, "view")
        assert rc == 0, f"share failed: {out}\n{err}"

        # ── owner: sees both matches, whole tree ──────────────────────────
        owner_names = _search_names(cli_bin, running_daemon, owner, "findme")
        assert "findme_owned.txt" in owner_names, owner_names
        assert "findme_shared.txt" in owner_names, owner_names

        # ── grantee: sees only the file actually shared with them ─────────
        grantee_names = _search_names(cli_bin, running_daemon, grantee, "findme")
        assert "findme_shared.txt" in grantee_names, grantee_names
        assert "findme_owned.txt" not in grantee_names, grantee_names

        # ── stranger: no access at all — command still succeeds, no match ─
        stranger_names = _search_names(cli_bin, running_daemon, stranger, "findme")
        assert stranger_names == [], stranger_names

        # Case-insensitivity, passed all the way through the daemon/CLI layer.
        owner_names_upper = _search_names(cli_bin, running_daemon, owner, "FINDME_OWNED")
        assert "findme_owned.txt" in owner_names_upper, owner_names_upper
    finally:
        server.stop()
