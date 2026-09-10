"""
test_corruption_repair.py — end-to-end regression coverage for Phase 22's
full corruption-detection-and-repair pipeline (TASK-253-261), closing
TASK-262's own acceptance criteria. Complements the individual unit/
integration tests each task already added (test_vw_scrub.c, test_vw_ecc.c,
test_vw_storage_parity.c, test_cluster_repair_fetch.c,
test_repair_pipeline.c — all in-process, against the linked library code
directly) with coverage against real, separately-running vapourwaultd
process(es), driven entirely over the real wire protocol (VwClient) and
the real admin CLI (`scrub run`) — the "real process, not the in-process
test harness" bar CLAUDE.md's Step 7 sets for QA.06.

Every test here fills exactly one parity group by committing
VW_ECC_MAX_DATA_SHARDS (16 — the production default; nothing here
overrides it the way the C unit tests do) distinct single-chunk files.
Registration into a parity group happens at first vw_storage_chunk_addref
(TASK-263), i.e. FILE_COMMIT, not CHUNK_UPLOAD — so each helper call below
does both, in order, on a freshly-created server where nothing else has
registered a chunk yet (so the first 16 registrations are exactly this
group, in commit order, and it seals synchronously on the 16th).

Coverage map against TASK-262's acceptance criteria:
  - Corrupt-then-repair (local, no replica):
        test_local_repair_via_scrub_run
  - Corrupt-then-replica-repair:
        test_replica_repair_when_local_reconstruction_impossible
  - Unrepairable case + chunk_unrepairable alert:
        test_unrepairable_chunk_alerts_and_stays_corrupt
  - Fuzz target for the Reed-Solomon decode path:
        tests/fuzz/fuzz_ecc_decode.c (not runnable as a real libFuzzer
        target in this environment — no Clang; see that file's own header
        comment and TASK-262's closing notes for the ASan/UBSan smoke-test
        substitute that was actually run, following TASK-202's own
        precedent for the identical environment limitation).
"""

import hashlib
import os
import time

import pytest

from conftest import ServerInstance
from test_cluster import ClusterNode, _pair_nodes
from vw_client import VwClient, VwProtocolError, VW_ERR_CHUNK_CORRUPT
from mock_smtp import MockSmtpServer

PASSWORD = "TestP@ssw0rd!"
GROUP_SIZE = 16  # VW_ECC_MAX_DATA_SHARDS production default (not overridden here)


def _chunk_path(data_dir, chunk_hash: bytes) -> str:
    hexs = chunk_hash.hex()
    return os.path.join(data_dir, "chunks", hexs[:2], f"{hexs}.chunk")


def _fill_one_parity_group(client, session_token, name_prefix="grp"):
    """Commit GROUP_SIZE distinct single-chunk files, each via its own
    CHUNK_UPLOAD + FILE_COMMIT. Registration happens at FILE_COMMIT's
    addref (TASK-263), so the first GROUP_SIZE registrations on a fresh
    server form and seal exactly one parity group, in this call order.
    Returns the GROUP_SIZE chunk hashes (bytes), in that order."""
    hashes = []
    for i in range(GROUP_SIZE):
        data = f"corruption-repair-test-{name_prefix}-{i}-".encode() + os.urandom(64)
        h = client.chunk_upload(session_token, data)
        client.file_commit(session_token, f"/{name_prefix}_{i}.bin", [h])
        hashes.append(h)
    return hashes


def _corrupt_chunk_file(data_dir, chunk_hash):
    """Flip bytes in an on-disk chunk file directly — the same class of
    real bit-rot the scrub pass is meant to catch, not a mocked failure."""
    path = _chunk_path(data_dir, chunk_hash)
    with open(path, "r+b") as f:
        data = bytearray(f.read())
        assert len(data) > 0
        data[0] ^= 0xFF
        data[-1] ^= 0xFF
        f.seek(0)
        f.write(data)


def _chunk_file_hash_ok(data_dir, chunk_hash) -> bool:
    try:
        with open(_chunk_path(data_dir, chunk_hash), "rb") as f:
            return hashlib.sha256(f.read()).digest() == chunk_hash
    except FileNotFoundError:
        return False


def _wait_until(predicate, timeout=15, interval=0.2):
    deadline = time.time() + timeout
    ok = False
    while time.time() < deadline:
        ok = predicate()
        if ok:
            return True
        time.sleep(interval)
    return ok


# ── Local repair (no cluster) ────────────────────────────────────────────────

def test_local_repair_via_scrub_run(binaries, tmp_path_factory, unique_username):
    """A single corrupted data shard in an otherwise-intact, sealed parity
    group is repaired in place by `scrub run` via local Reed-Solomon
    reconstruction alone — no cluster/replica configured at all."""
    binaries.require_server()
    binaries.require_tls()

    server = ServerInstance(
        binaries, str(tmp_path_factory.mktemp("vw_corrupt_local")),
        extra_conf="scrub_interval_secs = 0\n",
    )
    server.start()
    try:
        server.create_user(unique_username, PASSWORD)
        client = VwClient(server.host, server.port, server.cert)
        try:
            sess = client.login(unique_username, PASSWORD)["session_token"]
            hashes = _fill_one_parity_group(client, sess, "local")
        finally:
            client.close()

        target = hashes[5]
        _corrupt_chunk_file(server.data_dir, target)
        assert not _chunk_file_hash_ok(server.data_dir, target), (
            "test setup did not actually corrupt the chunk on disk"
        )

        rc, out, err = server.admin("scrub", "run")
        assert rc == 0, f"scrub run failed: {out}\n{err}"

        assert _chunk_file_hash_ok(server.data_dir, target), (
            f"chunk not repaired by local reconstruction after `scrub run`: {out}"
        )

        # Re-download over the real wire too — the actual client-facing
        # proof, not just an on-disk byte check.
        client2 = VwClient(server.host, server.port, server.cert)
        try:
            sess2 = client2.login(unique_username, PASSWORD)["session_token"]
            data = client2.chunk_download(sess2, target)
            assert hashlib.sha256(data).digest() == target
        finally:
            client2.close()
    finally:
        server.stop()


# ── Replica repair (local reconstruction impossible) ────────────────────────

@pytest.mark.cluster
@pytest.mark.slow
def test_replica_repair_when_local_reconstruction_impossible(
        binaries, tmp_path_factory, unique_username):
    """Two simultaneous faults in the same parity group defeat local
    single-parity Reed-Solomon reconstruction (it can only ever cover one);
    the primary must instead recover the requested chunk from a paired,
    reachable replica.

    Proven as a real causal A/B, not just "it worked": the identical
    corruption is confirmed still unrepairable while the replica is
    stopped (so local reconstruction genuinely cannot cover it — the test
    setup really did force a >1-fault case), then repairs cleanly once the
    same replica reconnects — a real observable signal that the replica is
    the one supplying the fix, since nothing else about the scenario
    changed.
    """
    binaries.require_server()
    binaries.require_tls()

    tmpdir = str(tmp_path_factory.mktemp("vw_corrupt_replica"))
    primary = ClusterNode(
        binaries, tmpdir, "primary",
        extra_conf="scrub_interval_secs = 0\n",
    )
    replica = None
    try:
        primary.start()
        replica = ClusterNode(
            binaries, tmpdir, "replica", is_replica=True,
            primary_host="127.0.0.1", primary_port=primary.cluster_port,
            extra_conf="scrub_interval_secs = 0\n",
        )
        replica.start()
        _pair_nodes(primary, replica)

        primary.create_user(unique_username, PASSWORD)
        client = VwClient(primary.host, primary.port, primary.cert)
        try:
            sess = client.login(unique_username, PASSWORD)["session_token"]
            hashes = _fill_one_parity_group(client, sess, "repl")
        finally:
            client.close()

        target = hashes[3]
        second_fault = hashes[9]  # a distinct member: forces a genuine >1-fault group

        # Wait for the replica to actually pull the real chunk bytes for
        # both (its own periodic FILE_SYNC_LIST -> CLUSTER_CHUNK_FETCH
        # pass; cluster_poll_interval_secs=1 in test_cluster.py's conf).
        for h in (target, second_fault):
            assert _wait_until(
                lambda h=h: os.path.isfile(_chunk_path(replica.data_dir, h)), timeout=20
            ), f"replica never pulled chunk {h.hex()}"

        # Corrupt BOTH members on the primary only.
        _corrupt_chunk_file(primary.data_dir, target)
        _corrupt_chunk_file(primary.data_dir, second_fault)

        # ── Control: stop the replica and confirm the chunk stays corrupt.
        # Proves local reconstruction genuinely cannot cover this case on
        # its own (a real two-fault group), not that the test accidentally
        # only corrupted one member. ──
        replica.stop()
        time.sleep(2)  # let the primary's connection handler notice the drop
        rc, out, err = primary.admin("scrub", "run", timeout=45)
        assert rc == 0, f"scrub run failed: {out}\n{err}"
        assert not _chunk_file_hash_ok(primary.data_dir, target), (
            "chunk was repaired locally despite two simultaneous faults in its "
            "group while the replica was stopped — test setup did not actually "
            "force a >1-fault case, or local reconstruction incorrectly covered it"
        )

        # ── Bring the replica back: the SAME corruption is now repairable,
        # and only the replica can be the source (local repair still can't
        # cover two faults; nothing else about the scenario changed). ──
        replica.start()

        def _repaired():
            # A single pass can legitimately take close to
            # VW_REPAIR_FETCH_TIMEOUT_MS (15s, vw_repair.c) if the replica
            # hasn't reconnected/resumed its OPLOG_PULL cycle yet — so
            # each attempt here needs real headroom, not just the overall
            # _wait_until budget below.
            rc2, out2, err2 = primary.admin("scrub", "run", timeout=60)
            return rc2 == 0 and _chunk_file_hash_ok(primary.data_dir, target)

        assert _wait_until(_repaired, timeout=90, interval=1.0), (
            f"chunk never repaired via replica fetch once the replica reconnected — "
            f"primary log:\n{primary.log_contents()}\nreplica log:\n{replica.log_contents()}"
        )

        # Re-download over the real wire too.
        client2 = VwClient(primary.host, primary.port, primary.cert)
        try:
            sess2 = client2.login(unique_username, PASSWORD)["session_token"]
            data = client2.chunk_download(sess2, target)
            assert hashlib.sha256(data).digest() == target
        finally:
            client2.close()
    finally:
        if replica is not None:
            replica.stop()
        primary.stop()


# ── Unrepairable: alert fires, chunk stays cleanly rejected ─────────────────

def test_unrepairable_chunk_alerts_and_stays_corrupt(
        binaries, tmp_path_factory, unique_username):
    """Beyond both local and replica recovery (no cluster configured here
    at all, plus two simultaneous faults in the same parity group defeat
    local single-parity reconstruction on their own regardless): the
    chunk_unrepairable admin alert (TASK-261) fires exactly once, and the
    chunk keeps returning VW_ERR_CHUNK_CORRUPT to a real client rather
    than bad bytes or a crash — proven via a real CHUNK_DOWNLOAD_REQ, not
    just scrub's own internal accounting."""
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_corrupt_unrepairable")),
            extra_conf=(
                "scrub_interval_secs = 0\n"
                f"smtp_host = {smtp.host}\n"
                f"smtp_port = {smtp.port}\n"
                "smtp_tls_mode = none\n"
                "smtp_verify_cert = 0\n"
                "smtp_username =\n"
                "smtp_password =\n"
                "smtp_from_addr = vaporwault@example.invalid\n"
                "smtp_from_name = VaporWault Test\n"
                "notify.admin_email = admin@example.invalid\n"
                "notify.chunk_unrepairable = 1\n"
            ),
        )
        server.start()
        try:
            server.create_user(unique_username, PASSWORD)
            client = VwClient(server.host, server.port, server.cert)
            try:
                sess = client.login(unique_username, PASSWORD)["session_token"]
                hashes = _fill_one_parity_group(client, sess, "unrep")
            finally:
                client.close()

            target = hashes[0]
            second_fault = hashes[8]
            _corrupt_chunk_file(server.data_dir, target)
            _corrupt_chunk_file(server.data_dir, second_fault)

            rc, out, err = server.admin("scrub", "run")
            assert rc == 0, f"scrub run failed: {out}\n{err}"

            # Both corrupted chunks are unrepairable (each is the other's
            # second simultaneous fault, and there is no cluster at all
            # here) — scrub finds and reports on both, so two distinct
            # alerts are expected, one per broken hash.
            assert _wait_until(lambda: len(smtp.messages) >= 2, timeout=15), (
                f"expected 2 chunk_unrepairable emails (one per broken chunk), "
                f"got {len(smtp.messages)}"
            )
            time.sleep(0.5)
            assert len(smtp.messages) == 2, "must fire exactly once per distinct broken chunk"
            bodies = [m.body for m in smtp.messages]
            assert any(target.hex() in b for b in bodies), "no alert mentioned the target hash"
            assert any(second_fault.hex() in b for b in bodies), "no alert mentioned the second-fault hash"
            for msg in smtp.messages:
                assert "admin@example.invalid" in msg.to

            # Still genuinely corrupt on disk — not silently "fixed" by a
            # failed repair attempt.
            assert not _chunk_file_hash_ok(server.data_dir, target)

            # A real client download must fail cleanly, not serve bad
            # bytes or crash the connection.
            client2 = VwClient(server.host, server.port, server.cert)
            try:
                sess2 = client2.login(unique_username, PASSWORD)["session_token"]
                with pytest.raises(VwProtocolError) as exc_info:
                    client2.chunk_download(sess2, target)
                assert exc_info.value.code == VW_ERR_CHUNK_CORRUPT
            finally:
                client2.close()

            # Debounce: the client download above, plus a second `scrub
            # run` pass, both also drive a fresh vw_notify_chunk_unrepairable
            # attempt (TASK-261) for the same two hashes — must not
            # double-fire per hash.
            rc, out, err = server.admin("scrub", "run")
            assert rc == 0, f"scrub run failed: {out}\n{err}"
            time.sleep(1)
            assert len(smtp.messages) == 2, (
                "chunk_unrepairable must debounce per-hash, not re-fire on every "
                "subsequent failed attempt at the same still-broken chunks"
            )
        finally:
            server.stop()
