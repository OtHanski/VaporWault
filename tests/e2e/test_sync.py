"""
test_sync.py — end-to-end sync tests for the VaporWault client daemon.

Requires:
  VW_TEST_E2E=1    environment variable
  compiled server and client daemon binaries (pass via --daemon-bin / --server-bin)

These tests start a real vapourwaultd server and a real vapourwault-daemon,
write files to a local sync folder, wait for the sync cycle, and verify the
files appear (or disappear) on the server.
"""
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time

import pytest

# Integration helpers are on sys.path via conftest.py
from vw_client import VwClient, VwAuthError    # noqa: E402

# ── Skip gate ─────────────────────────────────────────────────────────────────

if not os.environ.get("VW_TEST_E2E"):
    pytest.skip("VW_TEST_E2E not set — skipping e2e tests",
                allow_module_level=True)


# ── Re-use ServerInstance from the integration conftest ───────────────────────

_INT_DIR = os.path.join(os.path.dirname(__file__), "..", "integration")
if _INT_DIR not in sys.path:
    sys.path.insert(0, _INT_DIR)

import conftest as _int_conftest          # noqa: E402

_write_server_conf = _int_conftest._write_server_conf
ServerInstance = _int_conftest.ServerInstance

# ── Constants ──────────────────────────────────────────────────────────────────

_SYNC_INTERVAL_MS    = 1000   # 1 s — fast sync cycle for tests
_DAEMON_READY_TIMEOUT = 30    # seconds to wait for IPC port to open
_SYNC_WAIT_TIMEOUT   = 8      # seconds to wait for a file to appear on server

_E2E_USERNAME = "syncuser"
_E2E_PASSWORD = "Sync@P4ssword!"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ipc_port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _login(server):
    """Open a new VwClient connection, log in, return (client, session_token)."""
    c = VwClient(server.host, server.port, server.cert)
    auth = c.login(_E2E_USERNAME, _E2E_PASSWORD)
    return c, auth["session_token"]


# ── DaemonProcess ─────────────────────────────────────────────────────────────

class DaemonProcess:
    """
    Manages a vapourwault-daemon subprocess for testing.

    Setup sequence:
      1. Login via VwClient to get a fresh session token T1.
      2. Write T1 to session.tok (mode 0600).
      3. Write daemon.conf.
      4. Start vapourwault-daemon --state-dir <state_dir>.
         The daemon resumes T1 → server issues T2 to daemon; T1 is invalidated.
      5. Wait for the IPC port to open (daemon is ready).

    Test code that needs to verify server state should call _login(server)
    to get a fresh independent session — NOT reuse the daemon's token.
    """

    def __init__(self, daemon_bin, client_cli_bin, server, username, password):
        self.daemon_bin  = daemon_bin
        self.client_cli  = client_cli_bin
        self.server      = server
        self.username    = username
        self._proc       = None
        self._tmpdir_obj = tempfile.TemporaryDirectory(prefix="vw_e2e_")
        self._state_dir  = self._tmpdir_obj.name
        self.ipc_port    = _free_port()

        # ── Authenticate to get a seed session token ───────────────────────
        c = VwClient(server.host, server.port, server.cert)
        try:
            auth = c.login(username, password)
        finally:
            c.close()   # GOODBYE — token remains valid for daemon to resume

        session_token = auth["session_token"]   # bytes[32]

        # ── Write session.tok with mode 0600 ──────────────────────────────
        tok_path = os.path.join(self._state_dir, "session.tok")
        fd = os.open(tok_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.write(fd, session_token)
        finally:
            os.close(fd)

        # ── Write daemon.conf ─────────────────────────────────────────────
        conf_path = os.path.join(self._state_dir, "daemon.conf")
        with open(conf_path, "w") as f:
            f.write(f"server_host      = {server.host}\n")
            f.write(f"server_port      = {server.port}\n")
            f.write(f"ca_cert_pem_path = {server.cert}\n")
            f.write(f"username         = {username}\n")
            f.write(f"ipc_port         = {self.ipc_port}\n")
            f.write(f"sync_interval_ms = {_SYNC_INTERVAL_MS}\n")
        os.chmod(conf_path, stat.S_IRUSR | stat.S_IWUSR)

        # ── Start the daemon ───────────────────────────────────────────────
        env = dict(os.environ)
        env["VW_LOG_LEVEL"] = "DEBUG"
        self._proc = subprocess.Popen(
            [daemon_bin, "--state-dir", self._state_dir],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait until the IPC port opens (daemon is ready for commands).
        deadline = time.monotonic() + _DAEMON_READY_TIMEOUT
        while not _ipc_port_open(self.ipc_port):
            if time.monotonic() > deadline:
                self.stop()
                raise RuntimeError(
                    f"daemon did not open IPC port {self.ipc_port} "
                    f"within {_DAEMON_READY_TIMEOUT}s"
                )
            if self._proc.poll() is not None:
                stdout = self._proc.stdout.read().decode(errors="replace")
                stderr = self._proc.stderr.read().decode(errors="replace")
                raise RuntimeError(
                    f"daemon exited early (rc={self._proc.returncode}):\n"
                    f"stdout: {stdout}\nstderr: {stderr}"
                )
            time.sleep(0.1)

    def cli(self, *args, timeout=30):
        """Run vapourwault-cli with the daemon's IPC port."""
        cmd = [self.client_cli, "--ipc-port", str(self.ipc_port)] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    @property
    def state_dir(self):
        return self._state_dir

    def stop(self):
        if self._proc:
            # Politely request shutdown first.
            try:
                self.cli("shutdown")
                self._proc.wait(timeout=5)
            except Exception:
                pass
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()
            self._proc = None
        if self._tmpdir_obj:
            self._tmpdir_obj.cleanup()
            self._tmpdir_obj = None


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def server(e2e_bins, tmp_path_factory):
    """Start a single vapourwaultd instance for the entire e2e module."""
    e2e_bins.require_all()

    # Build a duck-typed Binaries object expected by ServerInstance.
    bins = type("E2EBins", (), {
        "server_bin": e2e_bins.server_bin,
        "admin_cli":  e2e_bins.admin_cli,
        "test_cert":  e2e_bins.test_cert,
        "test_key":   e2e_bins.test_key,
    })()

    tmpdir = str(tmp_path_factory.mktemp("vw_e2e_server"))
    srv = ServerInstance(bins, tmpdir)
    srv.start()
    srv.create_user(_E2E_USERNAME, _E2E_PASSWORD, timeout=120)
    yield srv
    srv.stop()


@pytest.fixture
def daemon(e2e_bins, server):
    """Fresh daemon process per test function."""
    d = DaemonProcess(
        daemon_bin     = e2e_bins.daemon_bin,
        client_cli_bin = e2e_bins.client_cli,
        server         = server,
        username       = _E2E_USERNAME,
        password       = _E2E_PASSWORD,
    )
    yield d
    d.stop()


@pytest.fixture
def sync_folder(daemon, tmp_path):
    """
    Create a local folder and register it with the daemon for sync.
    Yields (local_path, virtual_root).
    """
    local_path   = str(tmp_path / "local")
    virtual_root = "/e2e-test"
    os.makedirs(local_path, exist_ok=True)
    rc, _, err = daemon.cli("add-folder", local_path, virtual_root)
    assert rc == 0, f"add-folder failed: {err}"
    yield local_path, virtual_root


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.e2e
def test_daemon_connects_to_server(daemon):
    """Daemon starts and reports 'connected' in its status output."""
    rc, out, err = daemon.cli("status")
    assert rc == 0, f"vapourwault-cli status failed:\n{err}"
    assert "connected" in out.lower(), \
        f"expected 'connected' in status output:\n{out}"


@pytest.mark.e2e
def test_file_upload_sync(daemon, sync_folder):
    """
    Create a local file → trigger sync → file appears on the server.
    """
    local_path, virtual_root = sync_folder
    test_file = os.path.join(local_path, "hello.txt")
    with open(test_file, "w") as f:
        f.write("hello from e2e test\n")

    # Trigger immediate sync.
    rc, _, err = daemon.cli("sync")
    assert rc == 0, f"vapourwault-cli sync failed: {err}"

    # Open a fresh verification session (independent of the daemon's session).
    c, tok = _login(daemon.server)
    try:
        deadline = time.monotonic() + _SYNC_WAIT_TIMEOUT
        found = False
        while time.monotonic() < deadline:
            try:
                entries = c.file_list(tok, virtual_root, recursive=True)
                if any(e["name"] == "hello.txt" for e in entries):
                    found = True
                    break
            except Exception:
                pass
            time.sleep(0.3)
        assert found, f"hello.txt not synced to {virtual_root} within {_SYNC_WAIT_TIMEOUT}s"
    finally:
        c.close()


@pytest.mark.e2e
def test_file_delete_sync(daemon, sync_folder):
    """
    Create a file, sync it, delete it locally, sync again →
    file no longer listed on the server.
    """
    local_path, virtual_root = sync_folder
    test_file = os.path.join(local_path, "todelete.txt")
    with open(test_file, "w") as f:
        f.write("this file will be deleted\n")

    # Upload.
    daemon.cli("sync")
    c, tok = _login(daemon.server)
    try:
        # Wait for upload.
        deadline = time.monotonic() + _SYNC_WAIT_TIMEOUT
        uploaded = False
        while time.monotonic() < deadline:
            try:
                entries = c.file_list(tok, virtual_root, recursive=True)
                if any(e["name"] == "todelete.txt" for e in entries):
                    uploaded = True
                    break
            except Exception:
                pass
            time.sleep(0.3)
        assert uploaded, "todelete.txt not uploaded before the delete test"

        # Delete locally.
        os.remove(test_file)
        daemon.cli("sync")

        # Wait for server to reflect deletion.
        deadline = time.monotonic() + _SYNC_WAIT_TIMEOUT
        deleted = False
        while time.monotonic() < deadline:
            try:
                entries = c.file_list(tok, virtual_root, recursive=True)
                if not any(e["name"] == "todelete.txt" for e in entries):
                    deleted = True
                    break
            except Exception:
                pass
            time.sleep(0.3)
        assert deleted, "todelete.txt still listed on server after local delete + sync"
    finally:
        c.close()


@pytest.mark.e2e
def test_conflict_daemon_stays_alive(daemon, sync_folder):
    """
    Modify a file locally and also upload a different version via the server
    API directly, then sync — daemon must survive without crashing and one
    version must be present on the server.
    """
    local_path, virtual_root = sync_folder
    test_file = os.path.join(local_path, "conflict.txt")
    with open(test_file, "w") as f:
        f.write("original content\n")

    # Initial upload.
    daemon.cli("sync")

    c, tok = _login(daemon.server)
    try:
        # Wait for initial upload.
        deadline = time.monotonic() + _SYNC_WAIT_TIMEOUT
        while time.monotonic() < deadline:
            try:
                entries = c.file_list(tok, virtual_root, recursive=True)
                if any(e["name"] == "conflict.txt" for e in entries):
                    break
            except Exception:
                pass
            time.sleep(0.3)

        # Mutate locally.
        with open(test_file, "w") as f:
            f.write("local edit\n")

        # Mutate on server via Python client (simulates a concurrent write
        # from another device or web UI).
        c.upload_file(tok, f"{virtual_root}/conflict.txt",
                      b"server-side edit\n")

        # Sync — daemon must not crash.
        daemon.cli("sync")
        time.sleep(2)

        # Daemon still alive?
        rc_status, out_status, _ = daemon.cli("status")
        assert rc_status == 0, \
            "daemon crashed or IPC broken after conflict-resolution sync"

        # At least one version of the file must exist.
        entries = c.file_list(tok, virtual_root, recursive=True)
        assert any(e["name"] == "conflict.txt" for e in entries), \
            "conflict.txt disappeared entirely from server after conflict sync"
    finally:
        c.close()
