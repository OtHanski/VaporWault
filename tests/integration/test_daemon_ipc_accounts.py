"""
test_daemon_ipc_accounts.py — integration test for TASK-161's new daemon
IPC surface (VW_IPC_ACCOUNT_LIST_REQ/_ADD_REQ/_REMOVE_REQ, and the leading
account_id field every other account-scoped request now carries).

Unlike test_daemon_multi_account.py (which drives vw_client_core.c/
vw_cache.c/vw_sync.c directly, bypassing the daemon process entirely, same
as test_shared_sync.py's established pattern), this spawns the real
compiled vapourwault-daemon binary and speaks its actual IPC wire format
directly over a plain TCP socket — the thing that's actually new and
hand-rolled in this task, and the part no other test here exercises.

Reuses vw_client.py's low-level frame helpers (_make_frame/_read_frame/
_encode_str/_read_str) — same 8-byte header format the daemon IPC channel
shares with the server wire protocol (see vw_ipc.h's own header comment),
just over plain TCP instead of TLS, with message types in the
0x8000-0x8FFF range instead of 0x0000-0x09FF.
"""

import socket
import struct

from vw_client import _make_frame, _read_frame, _encode_str, _read_str

# ── IPC message types (vw_ipc.h) ────────────────────────────────────────────
IPC_STATUS_REQ          = 0x8001
IPC_STATUS_RESP         = 0x8002
IPC_FILE_LIST_REQ       = 0x800F
IPC_FILE_LIST_RESP      = 0x8010
IPC_SHUTDOWN_REQ        = 0x8011
IPC_SHUTDOWN_RESP       = 0x8012
IPC_ACCOUNT_LIST_REQ    = 0x8031
IPC_ACCOUNT_LIST_RESP   = 0x8032
IPC_ACCOUNT_ADD_REQ     = 0x8033
IPC_ACCOUNT_ADD_RESP    = 0x8034
IPC_ACCOUNT_REMOVE_REQ  = 0x8035
IPC_ACCOUNT_REMOVE_RESP = 0x8036

VW_IPC_FILTER_ALL = 0xFF


class DaemonIpcClient:
    """Bare-minimum client for the daemon's IPC channel — plain TCP, same
    8-byte frame header as the server wire protocol (vw_ipc.h). One-shot
    connection per call, matching every real client's own convention
    (vw_gui_ipc.h's one_shot(), vapourwault-cli's cli_connect() per
    invocation): the daemon's main loop closes each accepted connection
    right after handling exactly one request (see vw_daemon.c's
    handle_ipc_client caller), so reusing a socket across calls fails."""

    def __init__(self, port):
        self.port = port

    def call(self, req_type, payload=b""):
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(_make_frame(req_type, payload))
            return _read_frame(sock)

    def close(self):
        pass


def _account_add_payload(account_id, label, host, port, ca_cert_path, username, password, otp=""):
    return (
        struct.pack("<I", account_id)
        + _encode_str(label)
        + _encode_str(host)
        + struct.pack("<H", port)
        + _encode_str(ca_cert_path)
        + _encode_str(username)
        + _encode_str(password)
        + _encode_str(otp)
    )


def test_account_add_list_remove_over_real_ipc(server, running_daemon, unique_username):
    """
    Drives VW_IPC_ACCOUNT_ADD_REQ/_LIST_REQ/_REMOVE_REQ against a real
    compiled daemon process, with two real server-side users — the actual
    hand-rolled wire format this task introduced, not the sync-engine
    logic underneath it (that's test_daemon_multi_account.py's job).
    """
    password = "TestP@ssw0rd!"
    user_a = f"{unique_username}_a"
    user_b = f"{unique_username}_b"
    server.create_user(user_a, password)
    server.create_user(user_b, password)

    c = DaemonIpcClient(running_daemon)

    # ── Add two accounts ──
    mt, payload = c.call(IPC_ACCOUNT_ADD_REQ, _account_add_payload(
        0, user_a, server.host, server.port, server.cert, user_a, password))
    assert mt == IPC_ACCOUNT_ADD_RESP
    err_code, account_id_a = struct.unpack_from("<II", payload, 0)
    assert err_code == 0, f"ACCOUNT_ADD_REQ for user_a failed with code {err_code}"
    assert account_id_a != 0

    mt, payload = c.call(IPC_ACCOUNT_ADD_REQ, _account_add_payload(
        0, user_b, server.host, server.port, server.cert, user_b, password))
    assert mt == IPC_ACCOUNT_ADD_RESP
    err_code, account_id_b = struct.unpack_from("<II", payload, 0)
    assert err_code == 0, f"ACCOUNT_ADD_REQ for user_b failed with code {err_code}"
    assert account_id_b != 0
    assert account_id_b != account_id_a

    # ── List: both present, connected, correct usernames ──
    mt, payload = c.call(IPC_ACCOUNT_LIST_REQ)
    assert mt == IPC_ACCOUNT_LIST_RESP
    count = struct.unpack_from("<I", payload, 0)[0]
    assert count == 2
    off = 4
    seen = {}
    for _ in range(count):
        acc_id = struct.unpack_from("<I", payload, off)[0]; off += 4
        label, off = _read_str(payload, off)
        username, off = _read_str(payload, off)
        host, off = _read_str(payload, off)
        connected = payload[off]; off += 1
        off += 8  # pending_uploads (u32) + pending_downloads (u32)
        seen[acc_id] = (username.decode(), connected)
    assert seen[account_id_a][0] == user_a
    assert seen[account_id_b][0] == user_b
    assert seen[account_id_a][1] == 1, "account A should be connected right after ACCOUNT_ADD_REQ"
    assert seen[account_id_b][1] == 1, "account B should be connected right after ACCOUNT_ADD_REQ"

    # ── FILE_LIST_REQ is account-scoped now: empty prefix, ALL filter ──
    file_list_payload = struct.pack("<I", account_id_a) + _encode_str("") + bytes([VW_IPC_FILTER_ALL])
    mt, payload = c.call(IPC_FILE_LIST_REQ, file_list_payload)
    assert mt == IPC_FILE_LIST_RESP
    assert struct.unpack_from("<I", payload, 0)[0] == 0, "account A's fresh cache starts with no entries"

    # An unknown account_id must be rejected, not silently answered.
    bogus_payload = struct.pack("<I", 0xDEADBEEF) + _encode_str("") + bytes([VW_IPC_FILTER_ALL])
    mt, payload = c.call(IPC_FILE_LIST_REQ, bogus_payload)
    assert mt == IPC_FILE_LIST_RESP
    assert len(payload) == 0, "an unknown account_id must get an empty/error response, not another account's data"

    # ── Remove account B, confirm only A remains ──
    mt, payload = c.call(IPC_ACCOUNT_REMOVE_REQ, struct.pack("<I", account_id_b))
    assert mt == IPC_ACCOUNT_REMOVE_RESP
    assert struct.unpack_from("<I", payload, 0)[0] == 0

    mt, payload = c.call(IPC_ACCOUNT_LIST_REQ)
    count = struct.unpack_from("<I", payload, 0)[0]
    assert count == 1
    remaining_id = struct.unpack_from("<I", payload, 4)[0]
    assert remaining_id == account_id_a

    c.close()
