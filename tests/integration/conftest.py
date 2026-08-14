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
    parser.addoption("--gateway-bin", default=None,
                     help="Path to vapourwault-web-gateway binary (TASK-143)")


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

        self.gateway_bin = config.getoption("--gateway-bin")

        # Auto-discover if not explicitly provided (useful for local dev).
        if not self.server_bin:
            self.server_bin = self._find("vapourwaultd")
        if not self.admin_cli:
            self.admin_cli = self._find("vapourwault-server-cli")
        if not self.gateway_bin:
            self.gateway_bin = self._find("vapourwault-web-gateway")

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

    def require_gateway(self):
        if not self.gateway_bin or not os.path.isfile(self.gateway_bin):
            pytest.skip(f"vapourwault-web-gateway binary not found (--gateway-bin={self.gateway_bin!r})")


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


def _write_server_conf(path, data_dir, cert, key, admin_socket, port, max_workers=2):
    with open(path, "w") as f:
        f.write(f"""\
listen_host      = 127.0.0.1
listen_port      = {port}
data_dir         = {data_dir}
cert_pem_path    = {cert}
key_pem_path     = {key}
log_level        = DEBUG
max_connections  = 16
max_workers      = {max_workers}
admin_socket     = {admin_socket}
smtp_host        =
""")


class ServerInstance:
    """A running vapourwaultd process with its admin socket and TLS port."""

    def __init__(self, binaries: Binaries, tmpdir: str, max_workers: int = 2):
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
            self.admin_socket, self.port, max_workers=max_workers
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


# ── TASK-143 fixtures: vapourwault-web-gateway ─────────────────────────────────

class GatewayInstance:
    """A running vapourwault-web-gateway process pointed at a ServerInstance."""

    def __init__(self, binaries: Binaries, server: ServerInstance, state_dir: str = None):
        self.binaries = binaries
        self.server = server
        self.host = "127.0.0.1"
        self.port = _free_port()
        # TASK-165: passing state_dir enables "remember me" - omit (the
        # default, used by every test that doesn't care about it) to
        # match this feature's own opt-in-at-the-operator-level framing.
        self.state_dir = state_dir
        self._proc = None

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

    def start(self, timeout=10):
        args = [
            self.binaries.gateway_bin,
            "--server-host", self.server.host,
            "--server-port", str(self.server.port),
            "--ca-cert", self.server.cert,
            "--listen-host", self.host,
            "--listen-port", str(self.port),
        ]
        if self.state_dir is not None:
            args += ["--state-dir", self.state_dir]
        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # No admin socket/readiness signal of its own (unlike vapourwaultd) -
        # poll the listener with a real HTTP request until it responds.
        deadline = time.monotonic() + timeout
        while True:
            if self._proc.poll() is not None:
                raise RuntimeError(
                    f"gateway process exited with code {self._proc.returncode}"
                )
            try:
                with socket.create_connection((self.host, self.port), timeout=0.5):
                    return
            except OSError:
                if time.monotonic() > deadline:
                    self.stop()
                    raise RuntimeError(f"gateway did not start listening within {timeout}s")
                time.sleep(0.1)

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def restart(self, timeout=10):
        """Kill and relaunch the gateway process - always wipes the
        in-memory session pool (TASK-131: no persistence there), but a
        remembered login (this instance's own state_dir set, TASK-165)
        should transparently resume on the next request rather than
        needing to re-authenticate - that's exactly what this helper
        exists to let a test exercise."""
        self.stop()
        self.start(timeout=timeout)


@pytest.fixture(scope="module")
def gateway(binaries, server):
    """
    Start a vapourwault-web-gateway instance for the current test module,
    pointed at the module's server.
    """
    binaries.require_gateway()

    gw = GatewayInstance(binaries, server)
    gw.start()
    yield gw
    gw.stop()


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


# ── TASK-161/162 fixtures: vapourwault-daemon + vapourwault-cli ─────────────
#
# Shared by test_daemon_ipc_accounts.py and test_cli_account_commands.py —
# both need a real running multi-account daemon, not the module-scoped
# `server` fixture above (which is the VaporWault *server*, a different
# binary entirely).

def _find_client_bin(name):
    # build-gw-e2e/bin first and deliberately: build-wsl-werror/bin and
    # build-wsl/bin can (and, discovered while first writing these fixtures,
    # did) contain a stale pre-TASK-161 vapourwault-daemon left over from
    # before the ACCOUNT_* IPC changes — silently falling back to it
    # produces no error, just a request the old binary's switch statement
    # doesn't know about (falls into `default: break`, connection just
    # closes with zero response bytes). Search this session's own known-
    # current tree first so a stale binary elsewhere never wins silently.
    exe = f"{name}.exe" if os.name == "nt" else name
    for d in ("build-gw-e2e/bin", "build/bin", "build-release/bin", "../build/bin",
              "build-wsl-werror/bin", "build-wsl/bin"):
        p = os.path.join(d, exe)
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


@pytest.fixture
def daemon_bin():
    path = _find_client_bin("vapourwault-daemon")
    if not path:
        pytest.skip("vapourwault-daemon binary not found (build it first)")
    return path


@pytest.fixture
def cli_bin():
    path = _find_client_bin("vapourwault-cli")
    if not path:
        pytest.skip("vapourwault-cli binary not found (build it first)")
    return path


@pytest.fixture
def running_daemon(daemon_bin, tmp_path):
    """Spawns a real vapourwault-daemon against a fresh state_dir, waits for
    its IPC port, and guarantees process cleanup even on test failure — same
    "never leak a running process" discipline this file's server/gateway
    fixtures already apply. Yields the daemon's IPC port.

    Cleanup uses terminate() (SIGTERM/CTRL_CLOSE), not an IPC SHUTDOWN_REQ —
    the daemon already installs a signal handler that sets the same
    shutdown flag (vw_daemon.c's install_signal_handlers/sig_handler), so
    this is equally clean and doesn't require this fixture to speak the
    daemon's IPC wire format itself.
    """
    state_dir = tmp_path / "daemon_state"
    state_dir.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        ipc_port = s.getsockname()[1]

    # sync_interval_ms gates how often vw_daemon_run's main loop even checks
    # for pending IPC connections (vw_watcher_wait blocks for up to this long
    # first, every iteration — see vw_daemon.c) - kept short so tests using
    # this fixture don't have to wait out a long poll interval per call.
    # Mirrors run_integration.py's own 5000ms choice, made even shorter
    # since these tests issue several calls back-to-back.
    (state_dir / "daemon.conf").write_text(
        f"ipc_port = {ipc_port}\nsync_interval_ms = 200\n"
    )

    env = dict(os.environ)
    env["VW_LOG_LEVEL"] = "DEBUG"
    proc = subprocess.Popen(
        [daemon_bin, "--state-dir", str(state_dir)], env=env,
    )

    deadline = time.time() + 10
    connected = False
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", ipc_port), timeout=0.5):
                connected = True
                break
        except OSError:
            time.sleep(0.1)

    if not connected:
        proc.kill()
        pytest.fail("daemon did not open its IPC port in time")

    try:
        yield ipc_port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
