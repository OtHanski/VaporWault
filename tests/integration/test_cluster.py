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

import hashlib
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time

import pytest

from vw_client import VwClient, VW_PERM_VIEW

pytestmark = pytest.mark.cluster

# ── Minimal vw/1 wire client (TASK-172 acceptance criterion: a user created
# on the primary can authenticate against the replica) ─────────────────────
#
# Deliberately reimplements just enough of docs/PROTOCOL.md §7.1/§8.1 to
# drive one AUTH_REQUEST round-trip — HELLO negotiation, then AUTH_REQUEST
# with auth_token = SHA-256(password) (Phase-0 password transport, §8.1) —
# rather than pulling in the full C client library, since this test only
# needs to prove the replica's own normal client-facing listener can
# authenticate against the just-synced store/users.dat, independent of any
# fallback logic in the daemon (which doesn't exist yet — TASK-173).

_VW_HDR_SIZE = 8
_VW_PROTO_VERSION_CURRENT = 6
_VW_MSG_HELLO = 0x0001
_VW_MSG_HELLO_OK = 0x0002
_VW_MSG_AUTH_REQUEST = 0x0101
_VW_MSG_AUTH_OK = 0x0104
_VW_MSG_AUTH_FAIL = 0x0105


def _vw_send(sock, msg_type, payload=b""):
    total_len = _VW_HDR_SIZE + len(payload)
    hdr = struct.pack("<IHH", total_len, msg_type, _VW_PROTO_VERSION_CURRENT)
    sock.sendall(hdr + payload)


def _vw_recv(sock):
    hdr = _recv_exact(sock, _VW_HDR_SIZE)
    total_len, msg_type, _version = struct.unpack("<IHH", hdr)
    payload = _recv_exact(sock, total_len - _VW_HDR_SIZE)
    return msg_type, payload


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading")
        buf += chunk
    return buf


_VW_MSG_ERROR = 0x00FF
_VW_MSG_FILE_LIST = 0x0201
_VW_MSG_FILE_LIST_RESP = 0x0202
_VW_MSG_CLUSTER_FILE_SYNC_LIST = 0x0708
_VW_MSG_CLUSTER_FILE_SYNC_LIST_RESP = 0x0709
_VW_ERR_PROTO_INVALID = 200

# TASK-220: notify_prefs.db replication (docs/PROTOCOL.md §7.13/§7.7).
_VW_MSG_NOTIFY_PREFS_GET = 0x0A01
_VW_MSG_NOTIFY_PREFS_GET_RESP = 0x0A02
_VW_MSG_NOTIFY_PREFS_SET = 0x0A03
_VW_MSG_NOTIFY_PREFS_SET_ACK = 0x0A04
_VW_NOTIFY_SHARE_RECEIVED = 0x0001
_VW_NOTIFY_QUOTA_WARNING = 0x0002
_VW_NOTIFY_NEW_LOGIN = 0x0004


def _vw_connect_authed(host, port, username, password, timeout=10):
    """Like _vw_auth, but returns the live, authenticated TLS socket
    instead of closing it — for tests that need to send further raw
    messages on a real authenticated client session."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["vw/1"])

    raw = socket.create_connection((host, port), timeout=timeout)
    tls = ctx.wrap_socket(raw, server_hostname=host)
    tls.settimeout(timeout)

    _vw_send(tls, _VW_MSG_HELLO, struct.pack("<H", _VW_PROTO_VERSION_CURRENT))
    msg_type, _payload = _vw_recv(tls)
    assert msg_type == _VW_MSG_HELLO_OK, f"unexpected HELLO response 0x{msg_type:04x}"

    uname = username.encode("utf-8")
    auth_token = hashlib.sha256(password.encode("utf-8")).digest()
    payload = struct.pack("<H", len(uname)) + uname + auth_token
    _vw_send(tls, _VW_MSG_AUTH_REQUEST, payload)

    msg_type, payload = _vw_recv(tls)
    if msg_type != _VW_MSG_AUTH_OK:
        tls.close()
        raise AssertionError(f"AUTH_REQUEST did not succeed: 0x{msg_type:04x}")
    return tls, payload[0:32]  # (socket, session_token)


def _vw_auth(host, port, username, password, timeout=10):
    """Connect to a real vw/1 TLS listener, negotiate, AUTH_REQUEST with
    this username/password. Returns True on AUTH_OK, False on AUTH_FAIL."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["vw/1"])

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.settimeout(timeout)

            _vw_send(tls, _VW_MSG_HELLO, struct.pack("<H", _VW_PROTO_VERSION_CURRENT))
            msg_type, _payload = _vw_recv(tls)
            assert msg_type == _VW_MSG_HELLO_OK, f"unexpected HELLO response 0x{msg_type:04x}"

            uname = username.encode("utf-8")
            auth_token = hashlib.sha256(password.encode("utf-8")).digest()
            payload = struct.pack("<H", len(uname)) + uname + auth_token
            _vw_send(tls, _VW_MSG_AUTH_REQUEST, payload)

            msg_type, _payload = _vw_recv(tls)
            if msg_type == _VW_MSG_AUTH_OK:
                return True
            if msg_type == _VW_MSG_AUTH_FAIL:
                return False
            raise AssertionError(f"unexpected AUTH response 0x{msg_type:04x}")


def _free_port():
    """Return an ephemeral free TCP port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_cluster_conf(path, data_dir, cert, key, admin_socket, port,
                         cluster_port, is_replica, primary_host, primary_port,
                         gc_interval_secs=None, trash_retention_days=None):
    extra = ""
    # TASK-178: only written when a caller actually wants fast/immediate GC
    # (the GC replica-safety regression test) — omitted otherwise so every
    # other test in this module keeps using the server's own defaults.
    if gc_interval_secs is not None:
        extra += f"gc_interval_secs     = {gc_interval_secs}\n"
    if trash_retention_days is not None:
        extra += f"trash_retention_days = {trash_retention_days}\n"
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
{extra}""")


class ClusterNode:
    """A vapourwaultd instance configured for cluster mode (primary or replica)."""

    def __init__(self, binaries, tmpdir, name, is_replica=False,
                 primary_host=None, primary_port=None,
                 gc_interval_secs=None, trash_retention_days=None):
        self.binaries = binaries
        self.tmpdir = os.path.join(tmpdir, name)
        self.data_dir = os.path.join(self.tmpdir, "data")
        self.admin_socket = os.path.join(self.tmpdir, "admin.sock")
        self.conf_path = os.path.join(self.tmpdir, "server.conf")
        self.log_path = os.path.join(self.tmpdir, "server.log")
        self.port = _free_port()
        self.cluster_port = _free_port()
        self.host = "127.0.0.1"
        # TASK-176: same attribute name/meaning as ServerInstance.cert in
        # conftest.py — lets a ClusterNode (an already cluster-paired
        # replica) be passed directly as GatewayInstance's `fallback` arg.
        self.cert = binaries.test_cert
        self._proc = None
        self._logfile = None

        os.makedirs(self.data_dir, exist_ok=True)
        _write_cluster_conf(
            self.conf_path, self.data_dir, binaries.test_cert, binaries.test_key,
            self.admin_socket, self.port, self.cluster_port,
            is_replica, primary_host, primary_port,
            gc_interval_secs=gc_interval_secs, trash_retention_days=trash_retention_days,
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
def test_file_sync_replicates_users_dat(cluster_pair):
    """
    TASK-172: oplog entries carry no usable content (bare notification
    payloads only — see docs/PROTOCOL.md §7.7) so replication correctness
    can't be inferred from sync_watermark alone; the actual proof is that
    the replica's own copy of a syncable metadata file becomes byte-
    identical to the primary's. store/users.dat is the simplest one to
    check here since create_user already triggers it.
    """
    primary, replica = cluster_pair
    _pair_nodes(primary, replica)
    time.sleep(2)

    primary.create_user("filesynctest", "TestP@ssw0rd!")

    primary_users_dat = os.path.join(primary.data_dir, "store", "users.dat")
    replica_users_dat = os.path.join(replica.data_dir, "store", "users.dat")

    deadline = time.monotonic() + 20
    matched = False
    while time.monotonic() < deadline:
        try:
            with open(primary_users_dat, "rb") as f:
                primary_bytes = f.read()
            with open(replica_users_dat, "rb") as f:
                replica_bytes = f.read()
            if primary_bytes == replica_bytes and len(primary_bytes) > 0:
                matched = True
                break
        except FileNotFoundError:
            pass
        time.sleep(0.5)

    assert matched, (
        "replica's store/users.dat never converged with the primary's — "
        f"primary log:\n{primary.log_contents()}\nreplica log:\n{replica.log_contents()}"
    )


def test_file_sync_replicates_notify_prefs_db(cluster_pair):
    """
    TASK-220: store/notify_prefs.db is file tag 9 in the fixed
    CLUSTER_FILE_SYNC_LIST table (docs/PROTOCOL.md §7.7) — before this
    task it wasn't synced at all, so a replica's copy was always a fresh,
    all-defaults-off file regardless of what the primary had on record.
    Same convergence proof as test_file_sync_replicates_users_dat above,
    for the newly-added tag.
    """
    primary, replica = cluster_pair
    _pair_nodes(primary, replica)
    time.sleep(2)

    primary.create_user("notifysynctest", "TestP@ssw0rd!")
    tls, token = _vw_connect_authed(primary.host, primary.port, "notifysynctest", "TestP@ssw0rd!")
    try:
        _vw_send(tls, _VW_MSG_NOTIFY_PREFS_SET, token + struct.pack("<I", _VW_NOTIFY_QUOTA_WARNING))
        msg_type, payload = _vw_recv(tls)
        assert msg_type == _VW_MSG_NOTIFY_PREFS_SET_ACK, f"unexpected response 0x{msg_type:04x}"
        assert struct.unpack("<I", payload[0:4])[0] == 0, "NOTIFY_PREFS_SET did not return VW_OK"
    finally:
        tls.close()

    primary_db = os.path.join(primary.data_dir, "store", "notify_prefs.db")
    replica_db = os.path.join(replica.data_dir, "store", "notify_prefs.db")

    deadline = time.monotonic() + 20
    matched = False
    while time.monotonic() < deadline:
        try:
            with open(primary_db, "rb") as f:
                primary_bytes = f.read()
            with open(replica_db, "rb") as f:
                replica_bytes = f.read()
            if primary_bytes == replica_bytes and len(primary_bytes) > 0:
                matched = True
                break
        except FileNotFoundError:
            pass
        time.sleep(0.5)

    assert matched, (
        "replica's store/notify_prefs.db never converged with the primary's — "
        f"primary log:\n{primary.log_contents()}\nreplica log:\n{replica.log_contents()}"
    )


@pytest.mark.slow
def test_replica_serves_synced_notify_prefs(cluster_pair):
    """
    TASK-220 acceptance criterion: NOTIFY_PREFS_GET served from a
    fallback-connected replica must return the real, current preference
    value, not always-default — proving the replica's own
    vw_store_notify_prefs_get sees the synced notify_prefs.db through
    vw_store_reload_users_and_quotas's rebuilt notify_prefs/notify_free
    in-memory state, not just a byte-identical file nobody queries (same
    proof shape as test_replica_authenticates_synced_user above, and the
    same bug class it would have caught: file-tag sync alone is not
    enough if the in-memory reload doesn't also pick up the new table).
    """
    primary, replica = cluster_pair
    _pair_nodes(primary, replica)
    time.sleep(2)

    primary.create_user("notifyreplicatest", "TestP@ssw0rd!")
    tls, token = _vw_connect_authed(primary.host, primary.port, "notifyreplicatest", "TestP@ssw0rd!")
    try:
        _vw_send(tls, _VW_MSG_NOTIFY_PREFS_SET,
                 token + struct.pack("<I", _VW_NOTIFY_SHARE_RECEIVED | _VW_NOTIFY_NEW_LOGIN))
        msg_type, payload = _vw_recv(tls)
        assert msg_type == _VW_MSG_NOTIFY_PREFS_SET_ACK
        assert struct.unpack("<I", payload[0:4])[0] == 0
    finally:
        tls.close()

    expected = _VW_NOTIFY_SHARE_RECEIVED | _VW_NOTIFY_NEW_LOGIN
    deadline = time.monotonic() + 20
    observed = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            rtls, rtoken = _vw_connect_authed(replica.host, replica.port,
                                               "notifyreplicatest", "TestP@ssw0rd!")
            try:
                _vw_send(rtls, _VW_MSG_NOTIFY_PREFS_GET, rtoken)
                msg_type, payload = _vw_recv(rtls)
                if msg_type == _VW_MSG_NOTIFY_PREFS_GET_RESP and struct.unpack("<I", payload[0:4])[0] == 0:
                    observed = struct.unpack("<I", payload[4:8])[0]
                    if observed == expected:
                        break
            finally:
                rtls.close()
        except (ConnectionError, OSError, AssertionError) as exc:
            last_err = exc
        time.sleep(0.5)

    assert observed == expected, (
        f"replica served notify_prefs={observed!r} (want {expected}) — "
        f"last_err={last_err}; primary log:\n{primary.log_contents()}\n"
        f"replica log:\n{replica.log_contents()}"
    )


@pytest.mark.slow
def test_replica_authenticates_synced_user(cluster_pair):
    """
    TASK-172 acceptance criterion: a user created on the primary can
    authenticate against the replica with the same password — proving the
    replica's normal client-facing AUTH_REQUEST handler (unconditionally
    running on every server regardless of cluster role) actually sees the
    synced store/users.dat through vw_store_reload_users_and_quotas's
    rebuilt username_ht/uid_to_slot, not just a byte-identical file nobody
    queries. Deliberately independent of any client-side fallback logic
    (TASK-173, not yet built) — this connects straight to the replica's own
    listen_port.
    """
    primary, replica = cluster_pair
    _pair_nodes(primary, replica)
    time.sleep(2)

    primary.create_user("replicaauthtest", "TestP@ssw0rd!")

    deadline = time.monotonic() + 20
    authenticated = False
    last_err = None
    while time.monotonic() < deadline:
        try:
            if _vw_auth(replica.host, replica.port, "replicaauthtest", "TestP@ssw0rd!"):
                authenticated = True
                break
        except (ConnectionError, OSError, AssertionError) as exc:
            last_err = exc
        time.sleep(0.5)

    assert authenticated, (
        f"replica never accepted the synced user's credentials (last_err={last_err}) — "
        f"primary log:\n{primary.log_contents()}\nreplica log:\n{replica.log_contents()}"
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


def _wait_until(fn, timeout=20, interval=0.5):
    """Retry fn() until it returns without raising, or fail with the last
    exception once timeout elapses. TASK-178: several assertions below can't
    succeed until an async replica sync pass has caught up, and there's no
    single watermark/signal to poll for all of users/files/shares/vaults/
    chunks at once — retrying the real operation itself is simpler and more
    honest than re-deriving a per-subsystem readiness check for each one."""
    deadline = time.monotonic() + timeout
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - re-raised below if it never succeeds
            last_exc = exc
            time.sleep(interval)
    raise AssertionError(f"condition never became true within {timeout}s: {last_exc}")


@pytest.mark.slow
def test_replica_hot_standby_full_lifecycle(cluster_pair):
    """
    TASK-178: end-to-end proof that a paired replica is a genuine hot
    standby, not just an oplog backup — everything a client can do against
    the primary (plain file upload/download, a vault-encrypted file, a
    user-to-user share grant, a public link) is created there, then
    verified as independently readable/downloadable/usable directly
    against the replica's own listener, with no involvement from the
    primary. Covers TASK-172's own acceptance criterion this task deferred
    ("a file uploaded to the primary can be listed and downloaded,
    byte-identical, from the replica") plus TASK-178's own explicit list
    of what a hot-standby correctness test must exercise.
    """
    primary, replica = cluster_pair
    _pair_nodes(primary, replica)
    time.sleep(2)

    owner_user = "hotstandby_owner"
    grantee_user = "hotstandby_grantee"
    password = "TestP@ssw0rd!"
    primary.create_user(owner_user, password)
    primary.create_user(grantee_user, password)

    owner = VwClient(primary.host, primary.port, primary.cert)
    grantee = VwClient(primary.host, primary.port, primary.cert)
    try:
        otoken = owner.login(owner_user, password)["session_token"]
        gtoken = grantee.login(grantee_user, password)["session_token"]

        # Plain file.
        plain_data = os.urandom(4096)
        plain_fid, _ = owner.upload_file(otoken, "/plain.bin", plain_data)

        # Vault-encrypted file (server-side storage only — see test_vault.py's
        # own note on why wrapped_vk/wrapped_dek here are opaque test bytes,
        # not real cryptographic material; that's not what this test proves).
        vault_folder_fid = owner.file_mkdir(otoken, "vault_folder")
        wrapped_vk = os.urandom(32)
        kdf_salt = os.urandom(16)
        kdf_params = b"argon2id-test-params"
        vault_id = owner.vault_create(otoken, vault_folder_fid, wrapped_vk, kdf_salt, kdf_params)
        encrypted_data = os.urandom(2048)  # "ciphertext" — server treats it opaquely
        echash = hashlib.sha256(encrypted_data).digest()
        owner.chunk_upload(otoken, encrypted_data)
        vault_fid, vault_vid = owner.file_commit(
            otoken, "/vault_folder/secret.bin", [echash],
            vault_id=vault_id, wrapped_dek=os.urandom(48),
        )

        # User-to-user share grant on the plain file.
        owner.share_grant(otoken, plain_fid, grantee_user, VW_PERM_VIEW)

        # Public (anonymous) link on the plain file.
        _, link_token = owner.link_create(otoken, plain_fid, VW_PERM_VIEW)
    finally:
        owner.close()
        grantee.close()

    # ── Everything above happened only on the primary. Now verify each of
    # it directly against the replica's own listener — new connections,
    # never touching the primary again from this point on. ──

    def check_plain_file_on_replica():
        c = VwClient(replica.host, replica.port, replica.cert)
        try:
            tok = c.login(owner_user, password)["session_token"]
            downloaded = c.download_file(tok, c.file_stat(tok, file_id=plain_fid)["version_id"])
            assert downloaded == plain_data, "replica's plain file content diverged from the primary's"
        finally:
            c.close()

    _wait_until(check_plain_file_on_replica, timeout=30)

    def check_vault_on_replica():
        c = VwClient(replica.host, replica.port, replica.cert)
        try:
            tok = c.login(owner_user, password)["session_token"]
            got_vk, got_salt, got_params = c.vault_key_fetch(tok, vault_id)
            assert got_vk == wrapped_vk
            assert got_salt == kdf_salt
            assert got_params == kdf_params
            hashes, got_vault_id, got_wrapped_dek = c.version_chunks_ex(tok, vault_vid)
            assert got_vault_id == vault_id
            assert hashes == [echash]
            downloaded = b"".join(c.chunk_download(tok, h) for h in hashes)
            assert downloaded == encrypted_data, "replica's vault-encrypted chunk content diverged"
        finally:
            c.close()

    _wait_until(check_vault_on_replica, timeout=30)

    def check_share_on_replica():
        c = VwClient(replica.host, replica.port, replica.cert)
        try:
            tok = c.login(grantee_user, password)["session_token"]
            stat = c.file_stat(tok, file_id=plain_fid)
            assert stat["perm"] == VW_PERM_VIEW
            downloaded = c.download_file(tok, stat["version_id"])
            assert downloaded == plain_data, "grantee's replica download diverged from the primary's content"
        finally:
            c.close()

    _wait_until(check_share_on_replica, timeout=30)

    def check_public_link_on_replica():
        c = VwClient(replica.host, replica.port, replica.cert)
        try:
            info = c.link_access(link_token)
            tok = info["session_token"]
            downloaded = c.download_file(tok, c.file_stat(tok, file_id=plain_fid)["version_id"])
            assert downloaded == plain_data, "public-link replica download diverged from the primary's content"
        finally:
            c.close()

    _wait_until(check_public_link_on_replica, timeout=30)


@pytest.mark.slow
def test_gc_does_not_delete_chunk_while_replica_lags(binaries, tmp_path_factory):
    """
    Regression test for TASK-171's GC replica-safety gate (vw_gc.c's
    `replica_lag_blocks_gc`), per CLAUDE.md's standing rule that every
    resolved SEC.07/correctness finding gets one. Pairs a replica, lets it
    pull a chunk, deliberately makes the replica lag behind (stops it,
    functionally identical to its pull loop pausing for the primary's own
    watermark-gating logic), deletes the file on the primary — dropping
    that chunk's refcount to zero — and confirms:
      1. the chunk is NOT removed from disk while the replica is still
         behind, across multiple real GC cycles, and
      2. it IS removed once the replica catches back up and acks past the
         watermark that existed when it was orphaned.
    Uses a real primary + replica pair and real GC cycles (short
    `gc_interval_secs`/`trash_retention_days`, not mocked), matching this
    project's established "no mocking the server" integration-test
    convention.
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_gc_replica_safety"))
    primary = ClusterNode(
        binaries, tmpdir, "primary",
        gc_interval_secs=2, trash_retention_days=0,
    )
    replica = None
    try:
        primary.start()
        replica = ClusterNode(
            binaries, tmpdir, "replica",
            is_replica=True, primary_host="127.0.0.1", primary_port=primary.cluster_port,
        )
        replica.start()
        _pair_nodes(primary, replica)

        username = "gcsafety_user"
        password = "TestP@ssw0rd!"
        primary.create_user(username, password)

        data = os.urandom(4096)
        chunk_hash = hashlib.sha256(data).digest()
        c = VwClient(primary.host, primary.port, primary.cert)
        try:
            token = c.login(username, password)["session_token"]
            file_id, _ = c.upload_file(token, "/gc_target.bin", data)
        finally:
            c.close()

        # Confirm the replica actually pulled this chunk before making it
        # lag — the scenario under test is "a replica that legitimately
        # needs this chunk falls behind", not "one that never had it".
        def replica_has_chunk():
            rc = VwClient(replica.host, replica.port, replica.cert)
            try:
                tok = rc.login(username, password)["session_token"]
                assert rc.chunk_query(tok, [chunk_hash]) == [True]
            finally:
                rc.close()

        _wait_until(replica_has_chunk, timeout=20)

        # ── Freeze the replica: stops its pull loop from ever acking past
        # this point, identical from the primary's watermark-gating
        # perspective to a pull loop that's merely fallen behind. ──
        replica.stop()

        # Delete the file on the primary — drops the chunk's refcount to
        # zero and produces oplog activity the frozen replica is now behind.
        c2 = VwClient(primary.host, primary.port, primary.cert)
        try:
            token2 = c2.login(username, password)["session_token"]
            c2.file_delete(token2, file_id=file_id)
        finally:
            c2.close()

        def chunk_present_on_primary():
            pc = VwClient(primary.host, primary.port, primary.cert)
            try:
                tok = pc.login(username, password)["session_token"]
                return pc.chunk_query(tok, [chunk_hash]) == [True]
            finally:
                pc.close()

        # Give the primary several full gc_interval_secs=2 cycles to (not)
        # run the file/chunk GC phase while the replica stays frozen.
        time.sleep(6)
        assert chunk_present_on_primary(), (
            "chunk was removed from the primary while a paired replica was "
            "still behind its watermark — TASK-171's GC replica-safety gate "
            f"regressed. primary log:\n{primary.log_contents()}"
        )

        # ── Bring the replica back; once it catches up and acks past the
        # delete's watermark, the primary's next GC cycle must collect the
        # now-zero-refcount chunk. ──
        replica.start()

        def chunk_eventually_removed():
            assert not chunk_present_on_primary()

        _wait_until(chunk_eventually_removed, timeout=30)
    finally:
        if replica is not None:
            replica.stop()
        primary.stop()


@pytest.mark.slow
def test_replica_reconciles_refcount_for_multiply_referenced_chunk(binaries, tmp_path_factory):
    """
    Regression test for TASK-181: replica_run_chunk_sync_pass only ever
    called vw_storage_chunk_put_replicated (the sole thing that sets a
    ref_count on a replica's own chunk store) for hashes not already
    present locally, so a hash a replica already fetched during an earlier
    pass never got its ref_count bumped when a second, later-synced version
    referenced it again — the replica's own refcounts.db under-counted true
    reference counts instead of tracking them from scratch each pass, as
    ARCHITECTURE.md/TASK-172 both say it should.

    There is no client-facing "delete one specific historical version"
    message (docs/PROTOCOL.md's VW_MSG_VERSION_* has no delete op), and a
    file's old, non-current versions stay genuinely live (version_restore/
    version_chunks/download all still work against them) until the whole
    file is hard-deleted, at which point vw_gc.c's GC pass 3 decrefs every
    one of that file's versions together — so there's no way to isolate
    "drop exactly one of two references held by the same file" through the
    client API. Two separate files, each holding one live reference to the
    identical (deduped) chunk content, is the client-observable equivalent
    this test exercises instead: file_delete on one drops exactly one true
    reference while the other file's live version still needs the chunk —
    the same shape of under-count TASK-181 fixes.

    Uploads are sequenced so the replica pulls and fetches the chunk (its
    only actual `chunk_put_replicated` call, setting ref_count=1) in one
    chunk-sync pass *before* the second file's dedup-only reference ever
    syncs — reproducing the bug's actual trigger (a hash already present
    from an earlier pass being skipped on a later one), not the harmless
    same-pass case where a repeated hash still gets fetched/put twice.
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_replica_refcount"))
    primary = ClusterNode(
        binaries, tmpdir, "primary",
        gc_interval_secs=2, trash_retention_days=0,
    )
    replica = None
    try:
        primary.start()
        replica = ClusterNode(
            binaries, tmpdir, "replica",
            is_replica=True, primary_host="127.0.0.1", primary_port=primary.cluster_port,
            gc_interval_secs=2, trash_retention_days=0,
        )
        replica.start()
        _pair_nodes(primary, replica)

        username = "refcount_user"
        password = "TestP@ssw0rd!"
        primary.create_user(username, password)

        shared_data = os.urandom(4096)
        chunk_hash = hashlib.sha256(shared_data).digest()

        c = VwClient(primary.host, primary.port, primary.cert)
        try:
            token = c.login(username, password)["session_token"]
            file_a_id, _ = c.upload_file(token, "/refcount_a.bin", shared_data)
        finally:
            c.close()

        def replica_has_file_a():
            rc = VwClient(replica.host, replica.port, replica.cert)
            try:
                tok = rc.login(username, password)["session_token"]
                assert rc.chunk_query(tok, [chunk_hash]) == [True]
                vid = rc.file_stat(tok, file_id=file_a_id)["version_id"]
                assert rc.download_file(tok, vid) == shared_data
            finally:
                rc.close()

        # Ensure the replica's chunk_put_replicated (ref_count=1) for this
        # hash has already happened in its own earlier pass before file_b
        # ever exists — see docstring on why this ordering matters.
        _wait_until(replica_has_file_a, timeout=30)

        c2 = VwClient(primary.host, primary.port, primary.cert)
        try:
            token2 = c2.login(username, password)["session_token"]
            # Dedups on the primary: chunk_query reports the hash already
            # present, so upload_file skips CHUNK_UPLOAD and file_commit
            # addrefs the existing chunk instead of writing it again — the
            # true reference count for chunk_hash is now 2.
            file_b_id, _ = c2.upload_file(token2, "/refcount_b.bin", shared_data)
        finally:
            c2.close()

        def replica_has_file_b():
            rc = VwClient(replica.host, replica.port, replica.cert)
            try:
                tok = rc.login(username, password)["session_token"]
                vid = rc.file_stat(tok, file_id=file_b_id)["version_id"]
                assert rc.download_file(tok, vid) == shared_data
            finally:
                rc.close()

        _wait_until(replica_has_file_b, timeout=30)

        # Drop exactly one of the chunk's two true references. file_b's
        # live version still needs it.
        c3 = VwClient(primary.host, primary.port, primary.cert)
        try:
            token3 = c3.login(username, password)["session_token"]
            c3.file_delete(token3, file_id=file_a_id)
        finally:
            c3.close()

        # Give the replica's own GC thread (gc_interval_secs=2) several real
        # cycles to decref+potentially collect the chunk against its own
        # (now reconciled, post-TASK-181) refcount.
        def chunk_still_present_and_downloadable_on_replica():
            rc = VwClient(replica.host, replica.port, replica.cert)
            try:
                tok = rc.login(username, password)["session_token"]
                assert rc.chunk_query(tok, [chunk_hash]) == [True], (
                    "replica dropped a chunk still referenced by file_b's "
                    "live version after file_a was deleted — TASK-181's "
                    "replica refcount under-count regressed. replica log:\n"
                    f"{replica.log_contents()}"
                )
                vid = rc.file_stat(tok, file_id=file_b_id)["version_id"]
                assert rc.download_file(tok, vid) == shared_data
            finally:
                rc.close()

        time.sleep(6)
        chunk_still_present_and_downloadable_on_replica()
    finally:
        if replica is not None:
            replica.stop()
        primary.stop()


def test_cluster_only_messages_rejected_on_normal_client_listener(server, unique_username):
    """
    Regression test for TASK-172's SEC.07 review finding (`docs/
    PROTOCOL.md` §7.9's "Handler reachability" row): CLUSTER_FILE_SYNC_*/
    CLUSTER_CHUNK_* must be dispatched only on the cluster (`vw-cluster/1`
    ALPN) channel, never reachable from the normal client-facing `vw/1`
    listener regardless of message-type value — even from a fully
    authenticated, otherwise-legitimate client session. Sends the raw
    CLUSTER_FILE_SYNC_LIST opcode on a real authenticated `vw/1` connection
    and confirms it gets a normal protocol-error response (not processed
    as a cluster sync request, not a crash, not a hang) — per CLAUDE.md's
    standing rule that every resolved SEC.07 finding gets a regression
    test. Uses a plain (non-clustered) server since this dispatch-table
    property holds on every server regardless of cluster role — it isn't
    itself a cluster-pairing test, so it isn't marked `slow`.
    """
    password = "TestP@ssw0rd!"
    server.create_user(unique_username, password)

    tls, session_token = _vw_connect_authed(server.host, server.port, unique_username, password)
    try:
        _vw_send(tls, _VW_MSG_CLUSTER_FILE_SYNC_LIST)
        msg_type, payload = _vw_recv(tls)

        assert msg_type != _VW_MSG_CLUSTER_FILE_SYNC_LIST_RESP, (
            "the normal client listener answered a cluster-only message type "
            "as if it were a legitimate cluster sync request"
        )
        assert msg_type == _VW_MSG_ERROR, (
            f"expected an ERROR response to an out-of-range message type, got 0x{msg_type:04x}"
        )
        error_code = struct.unpack_from("<I", payload, 0)[0] if len(payload) >= 4 else None
        assert error_code == _VW_ERR_PROTO_INVALID, (
            f"expected VW_ERR_PROTO_INVALID (200), got {error_code}"
        )

        # Connection must still be alive and usable afterward — a rejected
        # out-of-range message type must not silently kill the session. A
        # real FILE_LIST round-trip is a stronger liveness proof than just
        # "recv() didn't throw" above.
        _vw_send(tls, _VW_MSG_FILE_LIST,
                 session_token + struct.pack("<BBH", 0, 0, 1) + b"/")
        msg_type, _payload = _vw_recv(tls)
        assert msg_type == _VW_MSG_FILE_LIST_RESP, (
            f"connection did not survive the rejected cluster-only message: 0x{msg_type:04x}"
        )
    finally:
        tls.close()
