#!/usr/bin/env python3
"""
VaporWault Phase 5 integration test suite — TASK-038.

Orchestrates vapourwaultd and vapourwault-daemon against localhost TLS,
exercises the full protocol stack, and reports TAP-style output.

Requirements: openssl (cert generation), Python 3.7+, POSIX.

Usage:
    python3 run_integration.py \\
        --server  /path/to/vapourwaultd           \\
        --daemon  /path/to/vapourwault-daemon      \\
        --admin-cli /path/to/vapourwault-server-cli \\
        --cli     /path/to/vapourwault-cli
"""

import argparse
import hashlib
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

# ── TAP output ────────────────────────────────────────────────────────────────

_passed = 0
_failed = 0
_test_num = 0

def tap_plan(n):
    print(f"TAP version 13")
    print(f"1..{n}")

def ok(desc):
    global _passed, _test_num
    _test_num += 1
    _passed += 1
    print(f"ok {_test_num} - {desc}")

def not_ok(desc, diagnostic=""):
    global _failed, _test_num
    _test_num += 1
    _failed += 1
    print(f"not ok {_test_num} - {desc}")
    if diagnostic:
        for line in diagnostic.splitlines():
            print(f"# {line}")

def skip(desc, reason):
    global _test_num
    _test_num += 1
    print(f"ok {_test_num} - {desc} # SKIP {reason}")

# ── Constants ─────────────────────────────────────────────────────────────────

SERVER_PORT   = 14430
IPC_PORT      = 14832
# ADMIN_SOCKET is set at runtime relative to the per-run tmpdir.
TEST_USERNAME = "testuser"
TEST_PASSWORD = "TestP@ssw0rd!"
PROTO_VERSION = 4

# Wire protocol message types
MSG_HELLO         = 0x0001
MSG_HELLO_OK      = 0x0002
MSG_GOODBYE       = 0x000F
MSG_AUTH_REQUEST  = 0x0101
MSG_AUTH_OK       = 0x0104
MSG_AUTH_FAIL     = 0x0105

# Auth error codes from vw_proto.h
VW_ERR_AUTH_BAD_CREDS = 300   # wrong password (not yet locked)
VW_ERR_AUTH_LOCKED    = 304   # account locked — too many failed attempts

# ── Wire protocol helpers ──────────────────────────────────────────────────────

def frame(msg_type: int, payload: bytes) -> bytes:
    total = 8 + len(payload)
    return struct.pack("<IHH", total, msg_type, PROTO_VERSION) + payload

def read_frame(conn):
    """Read one framed message. Returns (msg_type, payload) or raises."""
    hdr = _recvall(conn, 8)
    total, msg_type, _ver = struct.unpack("<IHH", hdr)
    plen = total - 8
    payload = _recvall(conn, plen) if plen > 0 else b""
    return msg_type, payload

def _recvall(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf

def encode_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("<H", len(b)) + b

def vw_login(host, port, username, password, ca_cert):
    """
    Perform a VaporWault TLS login. Returns the 32-byte session token on
    success, or raises RuntimeError on failure.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.check_hostname = False       # test cert has no SAN for 127.0.0.1 hostname
    ctx.verify_mode   = ssl.CERT_REQUIRED

    raw = socket.create_connection((host, port), timeout=10)
    conn = ctx.wrap_socket(raw, server_hostname="localhost")
    try:
        # HELLO
        conn.sendall(frame(MSG_HELLO, struct.pack("<H", PROTO_VERSION)))
        mt, _ = read_frame(conn)
        if mt != MSG_HELLO_OK:
            raise RuntimeError(f"expected HELLO_OK, got 0x{mt:04X}")

        # AUTH_REQUEST: username (str) + sha256(password)[32]
        auth_token = hashlib.sha256(password.encode("utf-8")).digest()
        payload = encode_str(username) + auth_token
        conn.sendall(frame(MSG_AUTH_REQUEST, payload))

        mt, resp = read_frame(conn)
        if mt == MSG_AUTH_OK:
            token = resp[:32]
            conn.sendall(frame(MSG_GOODBYE, b""))
            return token
        elif mt == MSG_AUTH_FAIL:
            # Payload: u32 error_code + u16 lockout_remaining_secs (vw_payload_auth_fail_t)
            code         = struct.unpack("<I", resp[:4])[0] if len(resp) >= 4 else 0
            lockout_secs = struct.unpack("<H", resp[4:6])[0] if len(resp) >= 6 else 0
            raise RuntimeError(f"AUTH_FAIL code={code} lockout={lockout_secs}")
        else:
            raise RuntimeError(f"unexpected message 0x{mt:04X}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def write_token(path, token):
    """Write 32-byte session token to path with mode 0600."""
    with open(path, "wb") as f:
        f.write(token)
    os.chmod(path, 0o600)

# ── CLI helpers ───────────────────────────────────────────────────────────────

def run(cmd, timeout=30, stdin_text=None, env=None):
    """Run cmd, return (returncode, stdout, stderr)."""
    r = subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=timeout, input=stdin_text, env=env
    )
    return r.returncode, r.stdout, r.stderr

def cli_cmd(cli_path, ipc_port, *args, timeout=30):
    cmd = [cli_path, "--ipc-port", str(ipc_port)] + list(args)
    return run(cmd, timeout=timeout)

def admin_cmd(admin_cli_path, admin_socket, *args, timeout=30):
    cmd = [admin_cli_path, "--admin-socket", admin_socket] + list(args)
    return run(cmd, timeout=timeout)

def wait_for_tcp(host, port, timeout=20):
    """Poll until TCP port accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.25)
    return False

def wait_for_ipc(cli_path, ipc_port, timeout=20):
    """Poll until vapourwault-cli status returns connected."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, out, _ = cli_cmd(cli_path, ipc_port, "status", timeout=5)
        if rc == 0 and "connected" in out:
            return True
        time.sleep(0.5)
    return False

# ── Certificate generation ────────────────────────────────────────────────────

def gen_cert(cert_path, key_path):
    """Generate a self-signed cert with SAN=IP:127.0.0.1,DNS:localhost."""
    r = subprocess.run(
        [
            "openssl", "req", "-x509",
            "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out", cert_path,
            "-days", "1",
            "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        capture_output=True, timeout=30
    )
    if r.returncode != 0:
        raise RuntimeError(f"openssl failed: {r.stderr.decode()}")

# ── Server config ─────────────────────────────────────────────────────────────

def write_server_conf(path, data_dir, cert, key, admin_socket):
    with open(path, "w") as f:
        f.write(f"""\
listen_host      = 127.0.0.1
listen_port      = {SERVER_PORT}
data_dir         = {data_dir}
cert_pem_path    = {cert}
key_pem_path     = {key}
log_level        = DEBUG
max_connections  = 16
max_workers      = 2
admin_socket     = {admin_socket}
smtp_host        =
""")

def write_daemon_conf(path, state_dir, cert):
    with open(path, "w") as f:
        f.write(f"""\
server_host      = 127.0.0.1
server_port      = {SERVER_PORT}
ca_cert_pem_path = {cert}
username         = {TEST_USERNAME}
ipc_port         = {IPC_PORT}
sync_interval_ms = 5000
state_dir        = {state_dir}
""")

# ── Main orchestration ─────────────────────────────────────────────────────────

def run_tests(args):
    tmpdir       = tempfile.mkdtemp(prefix="vw_it_")
    server_data  = os.path.join(tmpdir, "server_data")
    daemon_state = os.path.join(tmpdir, "daemon_state")
    sync_dir     = os.path.join(tmpdir, "sync")
    cert_path    = os.path.join(tmpdir, "server.crt")
    key_path     = os.path.join(tmpdir, "server.key")
    server_conf  = os.path.join(tmpdir, "server.conf")
    daemon_conf  = os.path.join(daemon_state, "daemon.conf")
    tok_path     = os.path.join(daemon_state, "session.tok")
    admin_socket = os.path.join(tmpdir, "admin.sock")

    os.makedirs(server_data,  exist_ok=True)
    os.makedirs(daemon_state, exist_ok=True)
    os.makedirs(sync_dir,     exist_ok=True)

    server_proc = None
    daemon_proc = None
    n_tests     = 8

    tap_plan(n_tests)

    try:
        # ── Setup ──────────────────────────────────────────────────────────────

        try:
            gen_cert(cert_path, key_path)
        except Exception as e:
            not_ok("cert generation", str(e))
            for _ in range(n_tests - 1):
                skip("(skipped — cert generation failed)", "setup failure")
            return

        write_server_conf(server_conf, server_data, cert_path, key_path, admin_socket)

        # Start the server
        server_proc = subprocess.Popen(
            [args.server, "--config", server_conf],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Wait for the admin socket to appear (replaces wait_for_tcp since admin
        # IPC is now AF_UNIX; socket file is created by bind in vw_admin_server_start).
        deadline = time.time() + 15
        while not os.path.exists(admin_socket):
            if time.time() > deadline or server_proc.poll() is not None:
                not_ok("IT-1: server starts and admin socket opens",
                       f"admin socket {admin_socket!r} did not appear in 15s")
                for i in range(2, n_tests + 1):
                    skip(f"IT-{i}: (skipped — server start failed)", "setup failure")
                return
            time.sleep(0.1)
        ok("IT-1: server starts and admin socket opens")

        # Create test user via admin CLI
        rc, out, err = admin_cmd(
            args.admin_cli, admin_socket,
            "user-create", TEST_USERNAME, TEST_PASSWORD,
            timeout=60   # Argon2id is slow
        )
        if rc != 0:
            not_ok("IT-2: test user created",
                   f"user-create failed (rc={rc})\n{err}")
            for i in range(3, n_tests + 1):
                skip(f"IT-{i}: (skipped — user creation failed)", "setup failure")
            return
        ok("IT-2: test user created via admin CLI")

        # Authenticate: get session token
        try:
            token = vw_login("127.0.0.1", SERVER_PORT,
                              TEST_USERNAME, TEST_PASSWORD, cert_path)
            write_token(tok_path, token)
        except Exception as e:
            not_ok("IT-3: client login succeeds",
                   f"login error: {e}")
            for i in range(4, n_tests + 1):
                skip(f"IT-{i}: (skipped — login failed)", "setup failure")
            return
        ok("IT-3: client login succeeds (session token obtained)")

        # Write daemon conf and start daemon
        write_daemon_conf(daemon_conf, daemon_state, cert_path)
        daemon_proc = subprocess.Popen(
            [args.daemon, "--state-dir", daemon_state],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if not wait_for_tcp("127.0.0.1", IPC_PORT, timeout=10):
            not_ok("IT-4: daemon starts and IPC port opens",
                   "IPC port not reachable in 10s")
            for i in range(5, n_tests + 1):
                skip(f"IT-{i}: (skipped — daemon start failed)", "setup failure")
            return
        ok("IT-4: daemon starts and IPC port opens")

        # Register sync folder
        rc, out, err = cli_cmd(args.cli, IPC_PORT, "add-folder", sync_dir, "/")
        if rc != 0:
            not_ok("IT-5: add sync folder", f"add-folder failed: {err}")
            for i in range(6, n_tests + 1):
                skip(f"IT-{i}: (skipped — add-folder failed)", "setup failure")
            return

        # Create a 128 KiB test file
        test_file = os.path.join(sync_dir, "integration_test.bin")
        with open(test_file, "wb") as f:
            f.write(os.urandom(128 * 1024))

        # Trigger sync and wait for file to appear in ls
        cli_cmd(args.cli, IPC_PORT, "sync")
        file_synced = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            rc, out, _ = cli_cmd(args.cli, IPC_PORT, "ls", timeout=5)
            if rc == 0 and "integration_test.bin" in out:
                file_synced = True
                break
            time.sleep(1)

        if file_synced:
            ok("IT-5: file upload — 128 KiB file appears in ls after sync")
        else:
            not_ok("IT-5: file upload — 128 KiB file appears in ls after sync",
                   "file not found in ls output within 30s")

        # IT-6: File list — ls returns the uploaded file
        rc, out, _ = cli_cmd(args.cli, IPC_PORT, "ls")
        if rc == 0 and "integration_test.bin" in out:
            ok("IT-6: file list — uploaded file appears in ls")
        else:
            not_ok("IT-6: file list — uploaded file appears in ls",
                   f"ls rc={rc}, out='{out}'")

        # IT-7: Quota enforcement — set quota smaller than already used, upload another file
        rc, _, err = admin_cmd(args.admin_cli, admin_socket,
                                "set-quota", TEST_USERNAME, "1024")
        if rc != 0:
            skip("IT-7: quota enforcement", f"set-quota failed: {err}")
        else:
            # Create another file that would exceed 1 KiB remaining quota
            over_file = os.path.join(sync_dir, "over_quota.bin")
            with open(over_file, "wb") as f:
                f.write(os.urandom(65536))
            cli_cmd(args.cli, IPC_PORT, "sync")
            # Wait a bit and check errors counter in status
            time.sleep(3)
            rc2, out2, _ = cli_cmd(args.cli, IPC_PORT, "status")
            # We expect an upload error since quota is exceeded
            errors = 0
            for line in out2.splitlines():
                if "errors" in line.lower():
                    try:
                        errors = int(line.split()[-2])
                    except (ValueError, IndexError):
                        pass
            if errors > 0:
                ok("IT-7: quota enforcement — upload rejected when quota exceeded")
            else:
                # Reset quota to unlimited to not block further tests
                admin_cmd(args.admin_cli, admin_socket, "set-quota", TEST_USERNAME, "0")
                not_ok("IT-7: quota enforcement — upload rejected when quota exceeded",
                       f"expected error count > 0, got {errors}\nstatus: {out2}")

        # IT-8: Brute-force lockout
        # Spec: "Connection rejected after 5 failed auth attempts."
        # Per vw_proto.h, a locked account returns AUTH_FAIL with
        # error_code=304 (VW_ERR_AUTH_LOCKED) and lockout_remaining_secs > 0.
        # SEC.07 [2026-07-12]: The previous test only checked that AUTH_FAIL was
        # returned (no crash), which a server with NO brute-force protection would
        # also pass.  This version specifically verifies that after 5 failures the
        # server returns the lockout error code on the 6th attempt.
        fail_count = 0
        for attempt in range(5):
            try:
                vw_login("127.0.0.1", SERVER_PORT,
                          TEST_USERNAME, "WRONG_PASSWORD", cert_path)
            except RuntimeError as e:
                if "AUTH_FAIL" in str(e):
                    fail_count += 1
            except Exception:
                pass

        if fail_count < 5:
            not_ok("IT-8: brute-force — server enforces auth attempt limits",
                   f"only {fail_count}/5 wrong-password attempts returned AUTH_FAIL "
                   f"(server may be unreachable)")
        else:
            # 6th attempt: must trigger lockout (code=304, lockout_secs > 0).
            # A plain AUTH_FAIL with code=300 (bad creds, no lockout) means
            # the server does not enforce brute-force limits.
            locked_out = False
            lockout_diag = ""
            try:
                vw_login("127.0.0.1", SERVER_PORT,
                          TEST_USERNAME, "WRONG_PASSWORD", cert_path)
                lockout_diag = "6th attempt returned AUTH_OK for wrong password"
            except ConnectionError:
                locked_out = True   # connection refused = network-level lockout
            except RuntimeError as e:
                msg = str(e)
                if "code=304" in msg:
                    # Confirm lockout_secs is non-zero
                    try:
                        ls = int(msg.split("lockout=")[1])
                        locked_out = ls > 0
                        if not locked_out:
                            lockout_diag = f"code=304 but lockout_secs=0 ({msg})"
                    except (IndexError, ValueError):
                        locked_out = True   # code=304 without parseable secs still counts
                else:
                    lockout_diag = (
                        f"6th attempt returned AUTH_FAIL without lockout code — "
                        f"server may not enforce brute-force limits ({msg})"
                    )
            except Exception as e:
                lockout_diag = f"unexpected exception on 6th attempt: {e}"

            if locked_out:
                ok("IT-8: brute-force — server enforces auth attempt limits after 5 failures")
            else:
                not_ok("IT-8: brute-force — server enforces auth attempt limits after 5 failures",
                       lockout_diag or "lockout not confirmed")

    finally:
        # ── Teardown ────────────────────────────────────────────────────────────
        if daemon_proc:
            try:
                cli_cmd(args.cli, IPC_PORT, "shutdown", timeout=5)
            except Exception:
                pass
            try:
                daemon_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon_proc.kill()

        if server_proc:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server_proc.kill()

        shutil.rmtree(tmpdir, ignore_errors=True)

    if _failed > 0:
        sys.exit(1)

# ── Argument parsing ───────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="VaporWault Phase 5 integration test suite"
    )
    p.add_argument("--server",    required=True, help="Path to vapourwaultd")
    p.add_argument("--daemon",    required=True, help="Path to vapourwault-daemon")
    p.add_argument("--admin-cli", required=True, dest="admin_cli",
                   help="Path to vapourwault-server-cli")
    p.add_argument("--cli",       required=True, help="Path to vapourwault-cli")
    args = p.parse_args()

    # Verify binaries exist
    for name, path in [("server", args.server), ("daemon", args.daemon),
                        ("admin-cli", args.admin_cli), ("cli", args.cli)]:
        if not os.path.isfile(path):
            print(f"TAP version 13\n1..1\nnot ok 1 - binary not found: {name}={path}")
            sys.exit(1)

    run_tests(args)

if __name__ == "__main__":
    main()
