"""
server_fixture.py — start/stop vapourwaultd for integration tests.

Manages a temp data directory, server config, TLS cert, and the server
process lifecycle.  Used by conftest.py to provide the `server` fixture.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time


class ServerFixture:
    """
    Manages a single vapourwaultd instance for testing.

    Usage:
        fixture = ServerFixture(server_bin, cert_path=cert, key_path=key)
        client  = fixture.new_client()
        admin   = fixture.new_admin_client()
        ...
        fixture.teardown()
    """

    PORT = 14430

    def __init__(self, server_bin, cert_path=None, key_path=None):
        self.server_bin = server_bin
        self._tmpdir    = tempfile.mkdtemp(prefix="vw_it_")
        self._data_dir  = os.path.join(self._tmpdir, "data")
        self._conf_path = os.path.join(self._tmpdir, "server.conf")
        self.admin_socket = os.path.join(self._tmpdir, "admin.sock")
        os.makedirs(self._data_dir, exist_ok=True)

        if cert_path and key_path:
            self.cert_path = cert_path
            self.key_path  = key_path
        else:
            self.cert_path = os.path.join(self._tmpdir, "server.crt")
            self.key_path  = os.path.join(self._tmpdir, "server.key")
            self._generate_cert()

        self._write_config()
        self._proc = self._start_server()
        self._wait_ready()

    # ── Internal setup ────────────────────────────────────────────────────────

    def _generate_cert(self):
        subprocess.run(
            [
                "openssl", "req", "-x509",
                "-newkey", "rsa:2048",
                "-keyout", self.key_path,
                "-out",    self.cert_path,
                "-days",   "1",
                "-nodes",
                "-subj",   "/CN=localhost",
                "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )

    def _write_config(self):
        with open(self._conf_path, "w") as f:
            f.write(
                f"listen_host      = 127.0.0.1\n"
                f"listen_port      = {self.PORT}\n"
                f"data_dir         = {self._data_dir}\n"
                f"cert_pem_path    = {self.cert_path}\n"
                f"key_pem_path     = {self.key_path}\n"
                f"log_level        = DEBUG\n"
                f"max_connections  = 32\n"
                f"max_workers      = 4\n"
                f"admin_socket     = {self.admin_socket}\n"
                f"gc_interval_secs = 2\n"
                f"smtp_host        =\n"
            )

    def _start_server(self):
        return subprocess.Popen(
            [self.server_bin, "--config", self._conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _wait_ready(self, timeout=20):
        """Poll until admin socket exists and TCP port accepts connections."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                stdout, stderr = self._proc.communicate()
                raise RuntimeError(
                    f"server exited during startup\n"
                    f"stdout: {stdout.decode(errors='replace')}\n"
                    f"stderr: {stderr.decode(errors='replace')}"
                )
            if os.path.exists(self.admin_socket):
                try:
                    s = socket.create_connection(("127.0.0.1", self.PORT), timeout=1)
                    s.close()
                    return
                except OSError:
                    pass
            time.sleep(0.1)
        # Collect output for debugging
        self._proc.terminate()
        try:
            stdout, stderr = self._proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
        raise RuntimeError(
            f"server not ready after {timeout}s\n"
            f"stdout: {stdout.decode(errors='replace')}\n"
            f"stderr: {stderr.decode(errors='replace')}"
        )

    # ── Factory methods ───────────────────────────────────────────────────────

    def new_client(self):
        """Return a new VwClient connected to this server instance."""
        from vw_client import VwClient
        return VwClient("127.0.0.1", self.PORT, self.cert_path)

    def new_admin_client(self):
        """Return a new AdminClient connected to the admin socket."""
        from vw_client import AdminClient
        return AdminClient(self.admin_socket)

    # ── Teardown ──────────────────────────────────────────────────────────────

    def teardown(self):
        """Terminate the server and clean up the temp directory."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        shutil.rmtree(self._tmpdir, ignore_errors=True)
