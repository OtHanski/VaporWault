"""
conftest.py — pytest fixtures for the VaporWault end-to-end test suite.

Run with VW_TEST_E2E=1 and compiled client daemon:
    pytest tests/e2e/ -v -m e2e \
        --server-bin  build/bin/vapourwaultd \
        --admin-cli   build/bin/vapourwault-server-cli \
        --daemon-bin  build/bin/vapourwault-daemon \
        --client-cli  build/bin/vapourwault-cli \
        --test-cert   tests/integration/test.crt \
        --test-key    tests/integration/test.key
"""
import os
import sys

import pytest

# Make the integration helpers (vw_client.py, conftest fixtures) importable.
_INT_DIR = os.path.join(os.path.dirname(__file__), "..", "integration")
if _INT_DIR not in sys.path:
    sys.path.insert(0, _INT_DIR)


def pytest_addoption(parser):
    # Re-declare integration options so they work here too.
    for opt, hlp in [
        ("--server-bin",  "Path to vapourwaultd binary"),
        ("--admin-cli",   "Path to vapourwault-server-cli binary"),
        ("--test-cert",   "Path to TLS certificate (PEM)"),
        ("--test-key",    "Path to TLS private key (PEM)"),
        ("--daemon-bin",  "Path to vapourwault-daemon binary"),
        ("--client-cli",  "Path to vapourwault-cli binary"),
    ]:
        try:
            parser.addoption(opt, default=None, help=hlp)
        except ValueError:
            pass  # already registered by integration conftest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "e2e: requires compiled client daemon and a running server (VW_TEST_E2E=1)"
    )


# ── Binary discovery ───────────────────────────────────────────────────────────

class E2EBinaries:
    def __init__(self, config):
        def _get(opt):
            val = config.getoption(opt, default=None)
            if val and os.path.isfile(val):
                return os.path.abspath(val)
            return None

        def _find(*names):
            for name in names:
                for d in ("build/bin", "build-release/bin", "../build/bin"):
                    p = os.path.join(d, name)
                    if os.path.isfile(p):
                        return os.path.abspath(p)
            return None

        self.server_bin  = _get("--server-bin")  or _find("vapourwaultd")
        self.admin_cli   = _get("--admin-cli")   or _find("vapourwault-server-cli")
        self.test_cert   = _get("--test-cert")
        self.test_key    = _get("--test-key")
        self.daemon_bin  = _get("--daemon-bin")  or _find("vapourwault-daemon")
        self.client_cli  = _get("--client-cli")  or _find("vapourwault-cli")

    def require_all(self):
        missing = []
        for attr, flag in [
            ("server_bin",  "--server-bin"),
            ("admin_cli",   "--admin-cli"),
            ("test_cert",   "--test-cert"),
            ("test_key",    "--test-key"),
            ("daemon_bin",  "--daemon-bin"),
            ("client_cli",  "--client-cli"),
        ]:
            val = getattr(self, attr)
            if not val or not os.path.isfile(val):
                missing.append(flag)
        if missing:
            pytest.skip(f"e2e binaries not found: {', '.join(missing)}")


@pytest.fixture(scope="session")
def e2e_bins(request):
    bins = E2EBinaries(request.config)
    return bins
