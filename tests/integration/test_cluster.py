"""
test_cluster.py — integration tests for cluster replication (TASK-086).

Stands up a real primary + replica vapourwaultd pair, pairs them exactly the
way docs/TUTORIAL.md instructs a real operator to (`cluster node-add` on the
primary, `cluster register-self` on the replica), and exercises:

  - pairing success (both sides' cluster-status reflect it)
  - oplog replication actually advancing sync_watermark
  - the auth boundary: register-self with a wrong token never lets the
    replica complete a NODE_HELLO handshake with the primary

All tests in this module require two real server processes and are marked
`cluster` (see conftest.py's marker registration) so they can be excluded
with `-m "not cluster"` for fast iteration; CI runs them in their own step.
"""

import os
import re
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.cluster


def _free_port():
    """Return an ephemeral free TCP port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_cluster_conf(path, data_dir, cert, key, admin_socket, port,
                         cluster_port, is_replica, primary_host, primary_port):
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
cluster_port               = {cluster_port}
cluster_is_replica         = {1 if is_replica else 0}
cluster_primary_host       = {primary_host or ""}
cluster_primary_port       = {primary_port or 0}
cluster_poll_interval_secs = 1
""")


class ClusterNode:
    """A vapourwaultd instance configured for cluster mode (primary or replica)."""

    def __init__(self, binaries, tmpdir, name, is_replica=False,
                 primary_host=None, primary_port=None):
        self.binaries = binaries
        self.tmpdir = os.path.join(tmpdir, name)
        self.data_dir = os.path.join(self.tmpdir, "data")
        self.admin_socket = os.path.join(self.tmpdir, "admin.sock")
        self.conf_path = os.path.join(self.tmpdir, "server.conf")
        self.log_path = os.path.join(self.tmpdir, "server.log")
        self.port = _free_port()
        self.cluster_port = _free_port()
        self.host = "127.0.0.1"
        self._proc = None
        self._logfile = None

        os.makedirs(self.data_dir, exist_ok=True)
        _write_cluster_conf(
            self.conf_path, self.data_dir, binaries.test_cert, binaries.test_key,
            self.admin_socket, self.port, self.cluster_port,
            is_replica, primary_host, primary_port,
        )

    def start(self, timeout=20):
        self._logfile = open(self.log_path, "wb")
        self._proc = subprocess.Popen(
            [self.binaries.server_bin, "--config", self.conf_path],
            stdout=self._logfile, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + timeout
        while not os.path.exists(self.admin_socket):
            if time.monotonic() > deadline:
                self.stop()
                raise RuntimeError(f"server did not create admin socket within {timeout}s")
            if self._proc.poll() is not None:
                raise RuntimeError(f"server process exited with code {self._proc.returncode}")
            time.sleep(0.1)

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._logfile:
            self._logfile.close()
            self._logfile = None

    def log_contents(self):
        """Read whatever the server has logged so far (safe while it's running)."""
        try:
            with open(self.log_path, "r", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def admin(self, *args, timeout=30):
        """Run vapourwault-server-cli with these args against this instance."""
        cmd = [self.binaries.admin_cli, "--admin-socket", self.admin_socket] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    def create_user(self, username, password, is_admin=False, timeout=120):
        """Register a user via the admin CLI. Argon2id is slow — use a generous timeout."""
        args = ["user-create", username, password]
        if is_admin:
            args.append("--admin")
        rc, out, err = self.admin(*args, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"user-create failed (rc={rc}): {err.strip()}")


@pytest.fixture
def cluster_pair(binaries, tmp_path_factory):
    """
    Stand up a primary + replica vapourwaultd pair (NOT yet paired via
    node-add/register-self — individual tests do that so the auth-failure
    test can supply a deliberately wrong token instead).
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_cluster"))
    primary = ClusterNode(binaries, tmpdir, "primary")
    replica = None
    try:
        primary.start()

        replica = ClusterNode(
            binaries, tmpdir, "replica",
            is_replica=True, primary_host="127.0.0.1", primary_port=primary.cluster_port,
        )
        replica.start()
    except BaseException:
        # If replica.start() (or anything after primary.start()) raises, the
        # primary process would otherwise be leaked — never reaching the
        # yield below means its teardown never runs either.
        if replica is not None:
            replica.stop()
        primary.stop()
        raise

    yield primary, replica

    replica.stop()
    primary.stop()
    shutil.rmtree(tmpdir, ignore_errors=True)


_NODE_ADD_RE = re.compile(
    r"registered node_id=(\d+) hostname=\S+ role=replica.*?\n"
    r"auth_token.*?\n([0-9a-f]{64})",
    re.DOTALL,
)


def _node_add(primary, hostname="replica.test"):
    """Run `cluster node-add` on the primary. Returns (node_id, token_hex)."""
    rc, out, err = primary.admin("cluster", "node-add", hostname)
    assert rc == 0, f"node-add failed: {err}"
    m = _NODE_ADD_RE.search(out)
    assert m, f"could not parse node-add output:\n{out}"
    return int(m.group(1)), m.group(2)


def _register_self(replica, node_id, token_hex, hostname="primary.test"):
    return replica.admin("cluster", "register-self", str(node_id), token_hex, hostname)


def _pair_nodes(primary, replica, hostname="replica.test"):
    """Run node-add on the primary + register-self on the replica — exactly
    the two-step operator flow docs/TUTORIAL.md documents. Returns node_id."""
    node_id, token = _node_add(primary, hostname)
    rc, out, err = _register_self(replica, node_id, token)
    assert rc == 0, f"register-self failed: {err}"
    return node_id


def _cluster_status(node):
    """Parse `cluster status` stdout into a list of dicts."""
    rc, out, err = node.admin("cluster", "status")
    assert rc == 0, f"cluster status failed: {err}"
    entries = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        entries.append({
            "node_id": int(parts[0]),
            "role": parts[1],
            "active": parts[2] == "yes",
            "hostname": parts[3],
            "sync_watermark": int(parts[4]),
        })
    return entries


# ── Tests ────────────────────────────────────────────────────────────────────

def test_pairing_registers_both_sides(cluster_pair):
    """node-add on the primary + register-self on the replica succeeds, and
    each side's cluster-status shows the pairing from its own perspective."""
    primary, replica = cluster_pair
    node_id = _pair_nodes(primary, replica)

    primary_entries = _cluster_status(primary)
    assert any(e["node_id"] == node_id and e["role"] == "replica" for e in primary_entries), \
        f"primary cluster-status missing replica node {node_id}: {primary_entries}"

    replica_entries = _cluster_status(replica)
    assert any(e["node_id"] == node_id and e["role"] == "self" for e in replica_entries), \
        f"replica cluster-status missing its own self-record {node_id}: {replica_entries}"


@pytest.mark.slow
def test_oplog_replication_advances_sync_watermark(cluster_pair):
    """After pairing, activity on the primary (a user-create, which appends
    an oplog entry) should eventually be pulled by the replica and reflected
    in the primary's sync_watermark for that node."""
    primary, replica = cluster_pair
    node_id = _pair_nodes(primary, replica)

    # Give the replica's poll thread a moment to complete its first
    # NODE_HELLO handshake before generating activity to replicate.
    time.sleep(2)

    primary.create_user("clustertest", "TestP@ssw0rd!")

    deadline = time.monotonic() + 20
    watermark = 0
    while time.monotonic() < deadline:
        entries = _cluster_status(primary)
        match = next((e for e in entries if e["node_id"] == node_id), None)
        if match and match["sync_watermark"] > 0:
            watermark = match["sync_watermark"]
            break
        time.sleep(0.5)

    assert watermark > 0, (
        "replica never pulled the oplog entry (sync_watermark stayed 0) — "
        f"primary log:\n{primary.log_contents()}"
    )


@pytest.mark.slow
def test_wrong_auth_token_never_replicates(cluster_pair):
    """
    register-self with a wrong auth_token must never let the replica
    complete a NODE_HELLO handshake with the primary — the actual auth
    boundary of cluster pairing.

    NODE_REGISTER_SELF_REQ only creates a local record on the replica (see
    handle_node_register_self / vw_cluster_node_add_self) — it does not
    itself validate the token against the primary. The real check happens
    later, when the replica's poll thread connects to the primary's
    cluster_port and sends NODE_HELLO; the primary compares the presented
    token against vw_cluster_node_add's stored one and responds
    NODE_HELLO_FAIL on mismatch (vw_cluster.c). So this test pairs with a
    deliberately wrong token, confirms register-self still succeeds locally
    (matching production behavior), then confirms replication never
    actually happens and the primary logs the auth failure.
    """
    primary, replica = cluster_pair

    node_id, real_token = _node_add(primary, "replica.test")
    wrong_token = "ab" * 32
    assert wrong_token != real_token

    rc, out, err = _register_self(replica, node_id, wrong_token)
    assert rc == 0, f"register-self (local record creation) unexpectedly failed: {err}"

    primary.create_user("clusterauthtest", "TestP@ssw0rd!")

    # Give the replica several poll cycles (poll_interval=1s) to attempt —
    # and fail — NODE_HELLO against the primary.
    deadline = time.monotonic() + 10
    watermark = None
    while time.monotonic() < deadline:
        entries = _cluster_status(primary)
        match = next((e for e in entries if e["node_id"] == node_id), None)
        watermark = match["sync_watermark"] if match else None
        if watermark:
            break
        time.sleep(0.5)

    assert not watermark, (
        f"replica replicated despite a wrong auth_token (sync_watermark={watermark}) — "
        "the auth check is not actually enforced"
    )
    assert "NODE_HELLO auth failed" in primary.log_contents(), (
        "primary never logged a NODE_HELLO auth failure for the wrong-token replica — "
        f"primary log:\n{primary.log_contents()}"
    )
