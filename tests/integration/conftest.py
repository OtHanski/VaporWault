"""
conftest.py — pytest fixtures and CLI-option registration for the VaporWault
integration test suite.

Usage:
    pytest tests/integration/ -v -m "not cluster" \
        --server-bin  build/bin/vapourwaultd \
        --admin-cli   build/bin/vapourwault-server-cli \
        --test-cert   tests/integration/test.crt \
        --test-key    tests/integration/test.key
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time

import pytest

# ── CLI option registration ───────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption("--server-bin",  default=None,
                     help="Path to vapourwaultd binary")
    parser.addoption("--admin-cli",   default=None,
                     help="Path to vapourwault-server-cli binary")
    parser.addoption("--test-cert",   default=None,
                     help="Path to TLS certificate (PEM)")
    parser.addoption("--test-key",    default=None,
                     help="Path to TLS private key (PEM)")


# ── Pytest marks ──────────────────────────────────────────────────────────────

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "cluster: requires two server instances (skip with -m 'not cluster')"
    )
    config.addinivalue_line(
        "markers",
        "slow: test takes more than 10 seconds"
    )


# ── Shared binaries fixture ───────────────────────────────────────────────────

class Binaries:
    """Resolved paths to server binaries and TLS credentials."""

    def __init__(self, config):
        self.server_bin = config.getoption("--server-bin")
        self.admin_cli  = config.getoption("--admin-cli")
        self.test_cert  = config.getoption("--test-cert")
        self.test_key   = config.getoption("--test-key")

        # Auto-discover if not explicitly provided (useful for local dev).
        if not self.server_bin:
            self.server_bin = self._find("vapourwaultd")
        if not self.admin_cli:
            self.admin_cli = self._find("vapourwault-server-cli")

    @staticmethod
    def _find(name):
        for d in ("build/bin", "build-release/bin", "../build/bin"):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return os.path.abspath(p)
        return None

    def require_server(self):
        if not self.server_bin or not os.path.isfile(self.server_bin):
            pytest.skip(f"vapourwaultd binary not found (--server-bin={self.server_bin!r})")
        if not self.admin_cli or not os.path.isfile(self.admin_cli):
            pytest.skip(f"admin-cli binary not found (--admin-cli={self.admin_cli!r})")

    def require_tls(self):
        if not self.test_cert or not os.path.isfile(self.test_cert):
            pytest.skip(f"TLS cert not found (--test-cert={self.test_cert!r})")
        if not self.test_key or not os.path.isfile(self.test_key):
            pytest.skip(f"TLS key not found (--test-key={self.test_key!r})")


@pytest.fixture(scope="session")
def binaries(request):
    return Binaries(request.config)


# ── Server instance fixture ───────────────────────────────────────────────────

_FREE_PORT_START = 19400


def _free_port():
    """Return an ephemeral free TCP port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_server_conf(path, data_dir, cert, key, admin_socket, port):
    with open(path, "w") as f:
        f.write(f"""\
listen_host      = 127.0.0.1
listen_port      = {port}
data_dir         = {data_dir}
cert_pem_path    = {cert}
key_pem_path     = {key}
log_level        = DEBUG
max_connections  = 16
max_workers      = 2
admin_socket     = {admin_socket}
smtp_host        =
""")


class ServerInstance:
    """A running vapourwaultd process with its admin socket and TLS port."""

    def __init__(self, binaries: Binaries, tmpdir: str):
        self.binaries = binaries
        self.tmpdir = tmpdir
        self.data_dir     = os.path.join(tmpdir, "data")
        self.admin_socket = os.path.join(tmpdir, "admin.sock")
        self.conf_path    = os.path.join(tmpdir, "server.conf")
        self.port = _free_port()
        self.cert = binaries.test_cert
        self.host = "127.0.0.1"
        self._proc = None

        os.makedirs(self.data_dir, exist_ok=True)
        _write_server_conf(
            self.conf_path, self.data_dir,
            self.cert, binaries.test_key,
            self.admin_socket, self.port
        )

    def start(self, timeout=20):
        self._proc = subprocess.Popen(
            [self.binaries.server_bin, "--config", self.conf_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Wait until the admin socket appears (indicates server is ready).
        deadline = time.monotonic() + timeout
        while not os.path.exists(self.admin_socket):
            if time.monotonic() > deadline:
                self.stop()
                raise RuntimeError(
                    f"server did not create admin socket within {timeout}s"
                )
            if self._proc.poll() is not None:
                raise RuntimeError(
                    f"server process exited with code {self._proc.returncode}"
                )
            time.sleep(0.1)

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def admin(self, *args, timeout=60):
        """Run vapourwault-server-cli with these args against this instance."""
        cmd = [
            self.binaries.admin_cli,
            "--admin-socket", self.admin_socket,
        ] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    def create_user(self, username: str, password: str, is_admin: bool = False,
                    timeout: int = 120):
        """Register a user via the admin CLI. Argon2id is slow — use generous timeout."""
        args = ["user-create", username, password]
        if is_admin:
            args.append("--admin")
        rc, out, err = self.admin(*args, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"user-create failed (rc={rc}): {err.strip()}")


@pytest.fixture(scope="module")
def server(binaries, tmp_path_factory):
    """
    Start a single vapourwaultd instance for the current test module.
    Scope is module-level to avoid the Argon2id key-stretching overhead on
    every test function.
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_server"))
    srv = ServerInstance(binaries, tmpdir)
    srv.start()
    yield srv
    srv.stop()
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="module")
def default_user(server):
    """
    Create (once per module) a default test user and return (username, password).
    """
    username = "testuser"
    password = "TestP@ssw0rd!"
    server.create_user(username, password)
    return username, password


# ── TASK-055 fixtures ─────────────────────────────────────────────────────────
#
# These fixtures provide VwClient / AdminClient instances backed by the
# module-scoped server.  They depend on vw_client.py which implements the
# VaporWault wire protocol directly (no subprocess shell-out).

import uuid as _uuid


@pytest.fixture
def unique_username():
    """Random username suffix, unique per test invocation."""
    return f"user_{_uuid.uuid4().hex[:8]}"


@pytest.fixture
def vw_client(server):
    """
    VwClient connected to the module's server.

    The client is closed (GOODBYE sent) after each test function.
    """
    from vw_client import VwClient
    c = VwClient(server.host, server.port, server.cert)
    yield c
    c.close()


@pytest.fixture
def admin_client(server):
    """
    AdminClient connected to the module's admin socket.

    Closed after each test function.
    """
    from vw_client import AdminClient
    ac = AdminClient(server.admin_socket)
    yield ac
    ac.close()
