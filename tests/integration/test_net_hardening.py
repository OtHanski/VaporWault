"""
test_net_hardening.py — regression coverage for TASK-245: a single failed/
incomplete TLS handshake against the client-facing listener must never take
the whole server down.

Root cause was in the accept loops (src/server/vw_server_main.c,
src/server/vw_cluster.c), not vw_net_accept() itself — vw_net_accept()
already returned a distinct error code for "the listening socket itself is
broken" (VW_ERR_NET_CONNECT) versus "this one connection's TLS handshake
didn't complete" (VW_ERR_NET_TLS); the accept loops just treated any
non-VW_OK return as fatal instead of only the former.
"""

import socket

from vw_client import VwClient

PASSWORD = "TestP@ssw0rd!"


def _connect_and_close_immediately(server):
    """Raw TCP connect to the server's TLS port, closed without sending a
    single byte — never even a TLS ClientHello. This is the exact
    reproduction that killed the server outright before TASK-245's fix
    (both an incidental Test-NetConnection-style probe and a deliberate
    /dev/tcp connect+close hit this)."""
    sock = socket.create_connection((server.host, server.port), timeout=5)
    sock.close()


def _connect_and_send_garbage(server):
    """Raw TCP connect, send a few bytes that are not a valid TLS record at
    all (not just an incomplete one), then close without completing a
    handshake — the other real-world shape of this failure (a
    misconfigured plaintext client, not just a bare port probe)."""
    sock = socket.create_connection((server.host, server.port), timeout=5)
    try:
        sock.sendall(b"not a tls client hello\r\n")
    finally:
        sock.close()


def _assert_server_still_healthy(server, admin_client, unique_username):
    """The real assertion: the server process is still alive and the
    listener still accepts and correctly serves a genuine client — not
    just "some socket call didn't raise," which a dead server can also
    satisfy briefly during TCP teardown."""
    assert server._proc.poll() is None, "server process exited"

    admin_client.create_user(unique_username, PASSWORD)
    with VwClient(server.host, server.port, server.cert) as c:
        info = c.login(unique_username, PASSWORD)
    assert info["user_id"] > 0


def test_survives_bare_tcp_connect_no_handshake(server, admin_client, unique_username):
    _connect_and_close_immediately(server)
    _assert_server_still_healthy(server, admin_client, unique_username)


def test_survives_malformed_client_hello(server, admin_client, unique_username):
    _connect_and_send_garbage(server)
    _assert_server_still_healthy(server, admin_client, unique_username)


def test_survives_repeated_bad_connections(server, admin_client, unique_username):
    """A single bad connection not killing the server is the core bug; this
    guards against a subtler variant where the server survives once but
    something (a leaked fd, a corrupted counter) degrades after repeated
    hits."""
    for _ in range(10):
        _connect_and_close_immediately(server)
    _assert_server_still_healthy(server, admin_client, unique_username)
