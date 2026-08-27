"""
test_notify_alerts.py — integration tests for TASK-213: the opt-in email
alert system (TASK-205-212) end to end against a real server, real
daemon/CLI, and a real (if minimal) SMTP server - not mocked at the
vw_smtp_send() call level like tests/unit/test_vw_notify.c's own
coverage (that file, 81+ assertions, already thoroughly covers the
per-category dispatch/debounce logic in isolation; this file's job is
proving the whole system wires together for real).

Per this task's own instruction, a test double SMTP endpoint backs
everything here - see mock_smtp.py. The real vapourwaultd process
connects to it over a real TCP socket and speaks real (plaintext,
unauthenticated) SMTP; every assertion below reads the actual bytes that
arrived, not an intercepted function call.

**Significant discovery made while writing this file, filed as its own
task rather than worked around silently in product code**: there is no
admin or self-service wire path anywhere in this codebase to set a
user's email address after account creation - USER_CREATE and
INVITE_REDEEM both omit an email field entirely, and USER_MODIFY
(0x0603/0x0604) is a reserved opcode with no handler (same finding
TASK-219 made independently for 2FA toggling). This means the already-
shipped password-recovery feature (TASK-046) and this task's own
user-facing notify categories are unreachable for any account created
through the only two paths that exist today - `rec.email[0] == '\\0'`
short-circuits every notify trigger before it ever reaches
vw_smtp_send(). Filed as TASK-222 (assigned ARCH.00 - this needs a
design decision, not a unilateral fix). For THIS file's own testing
purposes only, `_set_user_email_raw()` below patches users.dat directly
while the server is stopped, matching vw_store.h's documented on-disk
`vw_user_record_t` layout exactly - a test-only technique, explicitly
not a product code change, used only because no product API exists yet.

**Update (TASK-222, closed)**: a real self-service wire path now exists
(ACCOUNT_EMAIL_GET/SET, docs/PROTOCOL.md §7.14) - see
test_cli_account_email.py and test_gateway.py's account_email tests for
coverage of it directly, which is what TASK-222's own acceptance
criteria asked for ("verified by an integration test that does NOT need
to patch users.dat directly"). `_set_user_email_raw()` below is left in
place rather than retrofitted across this file's six call sites:
replacing raw-patch-while-stopped with a live daemon/CLI round trip in
every one of them is a mechanical but non-trivial rewrite of an already-
reviewed, already-passing security-sensitive suite, and doing so here
would risk exactly the kind of unreviewed churn this project's own
protocol warns against. Migrating this file to the real mechanism is a
reasonable future cleanup, not a blocker on TASK-222's closure.

Coverage map against TASK-213's own acceptance criteria:
  - Default-off regression:            test_default_off_no_email_for_any_user_category
  - Each user category, opted in:      test_user_category_share_received,
                                        test_user_category_new_login_never_fires_on_session_resume,
                                        test_user_category_quota_warning_edge_triggers_and_rearms
  - Content safety (no secrets):       test_no_email_body_ever_contains_a_secret
  - Admin: disk_capacity:              test_admin_disk_capacity
  - Admin: lockout_spike:              test_admin_lockout_spike
  - Admin: disabled category silent:   test_admin_disabled_category_never_fires
  - Fail-loud misconfiguration:        test_admin_alert_enabled_with_no_email_fails_startup
  - End-to-end via CLI:                every test below toggles preferences
                                        through the real vapourwault-cli
                                        binary, never a raw wire call.

Four things are NOT covered here, disclosed rather than silently skipped:
  - `account_security_change`'s real trigger (password recovery confirm)
    needs AUTH_RECOVER_REQUEST/CONFIRM support that vw_client.py's
    VwClient has never implemented (no existing test anywhere in this
    suite exercises password recovery at all - confirmed by grepping).
    Building that raw protocol support is a real chunk of new test
    infrastructure on its own; deferred rather than rushed. Unit-covered
    (test_vw_notify.c) at the dispatch-logic level.
  - `crash_recovery`'s real trigger needs an oplog file left with a
    genuinely unconfirmed tail entry at the moment of an unclean
    shutdown. Forcing that from outside the process is either a real
    kill-timing race (flaky by nature - this project's own tests
    consistently avoid exactly that class of flakiness) or hand-forging
    a raw oplog entry byte-for-byte (fragile, tightly coupled to an
    internal on-disk format that unit tests already cover more
    directly). `test_admin_disabled_category_never_fires` still performs
    a real SIGKILL + restart to prove the disabled-category path stays
    silent regardless; the "genuinely detected, category-enabled" path
    is unit-covered only.
  - `replica_lag` needs a real primary+replica cluster pair
    (test_cluster.py's ClusterNode/cluster_pair fixtures) with SMTP/notify
    config threaded into the *primary*; neither fixture has that
    plumbing today. Unit-covered only.
  - `acme_renewal_failure` needs a real (or realistically-faked) ACME
    directory endpoint to fail against; no ACME test double exists
    anywhere in this project. Unit-covered only.
  - End-to-end via the web gateway/frontend is not separately re-proven
    here: TASK-211's own test_gateway.py tests already prove the
    gateway's NOTIFY_PREFS_SET reaches identical server-side state to a
    CLI-issued SET (vw_client_notify_prefs_set() is the one function
    both paths call into - gateway directly, daemon via IPC); since this
    file already proves a CLI-set preference produces a real email, the
    gateway path does too, transitively, without a redundant second full
    email-delivery harness wired to a browser client.
"""

import os
import socket
import subprocess
import time

from conftest import ServerInstance
from mock_smtp import MockSmtpServer
from vw_client import VwClient, VwAuthError

PASSWORD = "TestP@ssw0rd!"

# Must match src/core/vw_proto.h's VW_NOTIFY_* bit values.
VW_NOTIFY_SHARE_RECEIVED = 0x0001
VW_NOTIFY_QUOTA_WARNING = 0x0002
VW_NOTIFY_NEW_LOGIN = 0x0004
VW_NOTIFY_ACCOUNT_SECURITY_CHANGE = 0x0008

# vw_store.h's on-disk vw_user_record_t layout (256 bytes total) - only
# the fields _set_user_email_raw needs.
_USER_RECORD_SIZE = 256
_USERNAME_OFFSET, _USERNAME_LEN = 8, 64
_EMAIL_OFFSET, _EMAIL_LEN = 72, 128


def _set_user_email_raw(server: ServerInstance, username: str, email: str) -> None:
    """TEST-ONLY workaround for a real, filed gap (TASK-222): see this
    module's own docstring. Stops the server, patches users.dat directly,
    restarts it - vw_store_open() rebuilds its in-memory indexes fresh
    from disk on every open, so a clean stop/edit/start cycle is safe."""
    server.stop()
    users_path = os.path.join(server.data_dir, "store", "users.dat")
    with open(users_path, "r+b") as f:
        data = bytearray(f.read())
        uname_bytes = username.encode("utf-8")
        found = False
        for offset in range(0, len(data) - len(data) % _USER_RECORD_SIZE, _USER_RECORD_SIZE):
            user_id = int.from_bytes(data[offset:offset + 8], "little")
            if user_id == 0:
                continue
            rec_uname = bytes(data[offset + _USERNAME_OFFSET:
                                    offset + _USERNAME_OFFSET + _USERNAME_LEN]).split(b"\x00", 1)[0]
            if rec_uname == uname_bytes:
                email_bytes = email.encode("utf-8")
                assert len(email_bytes) <= _EMAIL_LEN
                padded = email_bytes + b"\x00" * (_EMAIL_LEN - len(email_bytes))
                data[offset + _EMAIL_OFFSET: offset + _EMAIL_OFFSET + _EMAIL_LEN] = padded
                found = True
                break
        assert found, f"user {username!r} not found in users.dat"
        f.seek(0)
        f.write(data)
    server.start()


def _cli(cli_bin, ipc_port, *args, timeout=15):
    result = subprocess.run(
        [cli_bin, "--ipc-port", str(ipc_port)] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _spawn_daemon(daemon_bin, state_dir, ipc_port):
    (state_dir / "daemon.conf").write_text(f"ipc_port = {ipc_port}\nsync_interval_ms = 200\n")
    env = dict(os.environ)
    env["VW_LOG_LEVEL"] = "DEBUG"
    proc = subprocess.Popen([daemon_bin, "--state-dir", str(state_dir)], env=env)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", ipc_port), timeout=0.5):
                return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("daemon did not open its IPC port in time")


def _notify_conf(smtp: MockSmtpServer, **notify_overrides) -> str:
    """Server.conf `extra` block: points smtp_* at the real mock SMTP
    server (plaintext, unauthenticated - see mock_smtp.py's own header
    comment for why this is enough for vw_smtp.c's real client) plus
    whatever notify.* keys the caller wants. gc_interval_secs is set very
    short so admin categories only checked once per GC cycle
    (disk_capacity) don't need the test to wait out the 30-minute
    production default.
    """
    lines = [
        f"smtp_host = {smtp.host}",
        f"smtp_port = {smtp.port}",
        "smtp_tls_mode = none",
        "smtp_verify_cert = 0",
        "smtp_username =",
        "smtp_password =",
        "smtp_from_addr = vaporwault@example.invalid",
        "smtp_from_name = VaporWault Test",
        "notify.admin_email = admin@example.invalid",
        "gc_interval_secs = 2",
        "trash_retention_days = 0",
    ]
    for key, value in notify_overrides.items():
        lines.append(f"notify.{key} = {value}")
    return "\n".join(lines) + "\n"


def _wait_until(predicate, timeout=15, interval=0.2):
    deadline = time.time() + timeout
    ok = False
    while time.time() < deadline:
        ok = predicate()
        if ok:
            return True
        time.sleep(interval)
    return ok


def _daemon_idle(cli_bin, ipc_port, account):
    _, out, _ = _cli(cli_bin, ipc_port, "--account", account, "status")
    return "0 uploads, 0 downloads" in out


# ── Default-off regression ──────────────────────────────────────────────────

def test_default_off_no_email_for_any_user_category(
        binaries, tmp_path_factory, daemon_bin, cli_bin, unique_username):
    """With every preference left at its default (off), triggering real
    share_received and new_login conditions sends zero email."""
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_off_server")),
            extra_conf=_notify_conf(smtp),
        )
        server.start()
        try:
            owner = unique_username
            other = f"{unique_username}_other"
            server.create_user(owner, PASSWORD)
            server.create_user(other, PASSWORD)
            _set_user_email_raw(server, owner, f"{owner}@example.invalid")
            _set_user_email_raw(server, other, f"{other}@example.invalid")

            state_dir = tmp_path_factory.mktemp("vw_notify_off_daemon")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                ipc_port = s.getsockname()[1]
            daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)
            try:
                rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                     server.host, str(server.port), owner, PASSWORD,
                                     "--ca-cert", server.cert)
                assert rc == 0, f"account add failed: {out}\n{err}"

                # new_login: a second, fresh AUTH_REQUEST for the same
                # underlying user (a distinct account slot/label).
                rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                     server.host, str(server.port), owner, PASSWORD,
                                     "--ca-cert", server.cert, "--label", f"{owner}_2")
                assert rc == 0, f"second login failed: {out}\n{err}"

                # share_received: owner shares a real file with `other`.
                local_root = tmp_path_factory.mktemp("vw_notify_off_root")
                (local_root / "shared.txt").write_text("hello")
                rc, out, err = _cli(cli_bin, ipc_port, "--account", owner,
                                     "add-folder", str(local_root), "/")
                assert rc == 0, f"add-folder failed: {out}\n{err}"
                assert _wait_until(lambda: _daemon_idle(cli_bin, ipc_port, owner))
                rc, out, err = _cli(cli_bin, ipc_port, "--account", owner,
                                     "share", "/shared.txt", other, "view")
                assert rc == 0, f"share failed: {out}\n{err}"

                time.sleep(1.5)  # let any (wrongly-fired) async send land
                assert smtp.messages == [], (
                    f"expected zero emails with every preference at its default, "
                    f"got {[(m.to, m.subject) for m in smtp.messages]}"
                )
            finally:
                daemon_proc.terminate()
                try:
                    daemon_proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon_proc.kill()
                    daemon_proc.wait(timeout=5)
        finally:
            server.stop()


# ── User categories, opted in ───────────────────────────────────────────────

def test_user_category_share_received(binaries, tmp_path_factory, daemon_bin, cli_bin, unique_username):
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_share_server")),
            extra_conf=_notify_conf(smtp),
        )
        server.start()
        try:
            owner = unique_username
            grantee = f"{unique_username}_grantee"
            grantee_email = f"{grantee}@example.invalid"
            server.create_user(owner, PASSWORD)
            server.create_user(grantee, PASSWORD)
            _set_user_email_raw(server, grantee, grantee_email)

            state_dir = tmp_path_factory.mktemp("vw_notify_share_daemon")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                ipc_port = s.getsockname()[1]
            daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)
            try:
                for user in (owner, grantee):
                    rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                         server.host, str(server.port), user, PASSWORD,
                                         "--ca-cert", server.cert, "--label", user)
                    assert rc == 0, f"account add ({user}) failed: {out}\n{err}"

                rc, out, err = _cli(cli_bin, ipc_port, "--account", grantee,
                                     "notify", "set", "share_received", "on")
                assert rc == 0, f"notify set failed: {out}\n{err}"

                local_root = tmp_path_factory.mktemp("vw_notify_share_root")
                (local_root / "shared.txt").write_text("hello")
                rc, out, err = _cli(cli_bin, ipc_port, "--account", owner,
                                     "add-folder", str(local_root), "/")
                assert rc == 0, f"add-folder failed: {out}\n{err}"
                assert _wait_until(lambda: _daemon_idle(cli_bin, ipc_port, owner))

                rc, out, err = _cli(cli_bin, ipc_port, "--account", owner,
                                     "share", "/shared.txt", grantee, "view")
                assert rc == 0, f"share failed: {out}\n{err}"

                assert _wait_until(lambda: len(smtp.messages) >= 1), (
                    "share_received email never arrived"
                )
                time.sleep(0.5)  # settle - confirm no duplicate follows
                assert len(smtp.messages) == 1, "must fire exactly once per real trigger"
                msg = smtp.messages[0]
                assert grantee_email in msg.to
                assert owner in msg.body
                assert "shared.txt" in msg.body
            finally:
                daemon_proc.terminate()
                try:
                    daemon_proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon_proc.kill()
                    daemon_proc.wait(timeout=5)
        finally:
            server.stop()


def test_user_category_new_login_never_fires_on_session_resume(
        binaries, tmp_path_factory, daemon_bin, cli_bin, unique_username):
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_login_server")),
            extra_conf=_notify_conf(smtp),
        )
        server.start()
        try:
            user_email = f"{unique_username}@example.invalid"
            server.create_user(unique_username, PASSWORD)
            _set_user_email_raw(server, unique_username, user_email)

            state_dir = tmp_path_factory.mktemp("vw_notify_login_daemon")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                ipc_port = s.getsockname()[1]
            daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)
            try:
                # This account_add IS a fresh AUTH_REQUEST - but the
                # preference isn't on yet, so it must not fire.
                rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                     server.host, str(server.port), unique_username, PASSWORD,
                                     "--ca-cert", server.cert)
                assert rc == 0, f"account add failed: {out}\n{err}"
                assert smtp.messages == [], "must not fire before opting in"

                rc, out, err = _cli(cli_bin, ipc_port, "--account", unique_username,
                                     "notify", "set", "new_login", "on")
                assert rc == 0, f"notify set failed: {out}\n{err}"

                # Real SESSION_RESUME reconnect cycles happen in the
                # background (sync_interval_ms=200) - none of these are a
                # fresh AUTH_REQUEST.
                time.sleep(3)
                assert smtp.messages == [], (
                    f"SESSION_RESUME must never fire new_login, got "
                    f"{[(m.to, m.subject) for m in smtp.messages]}"
                )

                # A genuine second, fresh login must fire it.
                rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                     server.host, str(server.port), unique_username, PASSWORD,
                                     "--ca-cert", server.cert, "--label", f"{unique_username}_2")
                assert rc == 0, f"second login failed: {out}\n{err}"

                assert _wait_until(lambda: len(smtp.messages) >= 1), "new_login email never arrived"
                time.sleep(0.5)
                assert len(smtp.messages) == 1
                assert user_email in smtp.messages[0].to
            finally:
                daemon_proc.terminate()
                try:
                    daemon_proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon_proc.kill()
                    daemon_proc.wait(timeout=5)
        finally:
            server.stop()


def test_user_category_quota_warning_edge_triggers_and_rearms(
        binaries, tmp_path_factory, daemon_bin, cli_bin, unique_username):
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_quota_server")),
            extra_conf=_notify_conf(smtp),
        )
        server.start()
        try:
            user_email = f"{unique_username}@example.invalid"
            server.create_user(unique_username, PASSWORD)
            _set_user_email_raw(server, unique_username, user_email)
            rc, out, err = server.admin("set-quota", unique_username, "10000")
            assert rc == 0, f"set-quota failed: {out}\n{err}"

            state_dir = tmp_path_factory.mktemp("vw_notify_quota_daemon")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                ipc_port = s.getsockname()[1]
            daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)
            try:
                rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                     server.host, str(server.port), unique_username, PASSWORD,
                                     "--ca-cert", server.cert)
                assert rc == 0, f"account add failed: {out}\n{err}"
                rc, out, err = _cli(cli_bin, ipc_port, "--account", unique_username,
                                     "notify", "set", "quota_warning", "on")
                assert rc == 0, f"notify set failed: {out}\n{err}"

                local_root = tmp_path_factory.mktemp("vw_notify_quota_root")
                rc, out, err = _cli(cli_bin, ipc_port, "--account", unique_username,
                                     "add-folder", str(local_root), "/")
                assert rc == 0, f"add-folder failed: {out}\n{err}"

                # Cross into the warning zone: >9000 of 10000 bytes.
                (local_root / "big1.bin").write_bytes(os.urandom(9500))
                assert _wait_until(lambda: len(smtp.messages) >= 1, timeout=20), (
                    "quota_warning email never arrived after crossing 90%"
                )
                time.sleep(0.5)
                assert len(smtp.messages) == 1

                # Delete it and wait for the removal to sync down (drops
                # back under threshold - silent re-arm, no email).
                (local_root / "big1.bin").unlink()
                assert _wait_until(lambda: _daemon_idle(cli_bin, ipc_port, unique_username), timeout=20)
                time.sleep(1)
                assert len(smtp.messages) == 1, "must not fire again while merely re-arming"

                # Cross again - proof it re-armed rather than staying "used up".
                (local_root / "big2.bin").write_bytes(os.urandom(9500))
                assert _wait_until(lambda: len(smtp.messages) >= 2, timeout=20), (
                    "quota_warning did not re-fire after dropping back under threshold and crossing again"
                )
            finally:
                daemon_proc.terminate()
                try:
                    daemon_proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon_proc.kill()
                    daemon_proc.wait(timeout=5)
        finally:
            server.stop()


# ── Content safety ───────────────────────────────────────────────────────────

def test_no_email_body_ever_contains_a_secret(
        binaries, tmp_path_factory, daemon_bin, cli_bin, unique_username):
    """Grep the actual sent bodies for a real secret literal, across every
    category actually fired in this run - not code inspection."""
    binaries.require_server()
    binaries.require_tls()
    secret_password = PASSWORD  # the one real secret every trigger below could leak

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_secrets_server")),
            max_workers=4,  # 3 concurrent daemon connections (owner, grantee, owner_2)
            extra_conf=_notify_conf(smtp),
        )
        server.start()
        try:
            owner = unique_username
            grantee = f"{unique_username}_grantee"
            server.create_user(owner, PASSWORD)
            server.create_user(grantee, PASSWORD)
            _set_user_email_raw(server, owner, f"{owner}@example.invalid")
            _set_user_email_raw(server, grantee, f"{grantee}@example.invalid")

            state_dir = tmp_path_factory.mktemp("vw_notify_secrets_daemon")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                ipc_port = s.getsockname()[1]
            daemon_proc = _spawn_daemon(daemon_bin, state_dir, ipc_port)
            try:
                for user in (owner, grantee):
                    rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                         server.host, str(server.port), user, PASSWORD,
                                         "--ca-cert", server.cert, "--label", user)
                    assert rc == 0, f"account add ({user}) failed: {out}\n{err}"
                    for cat in ("share_received", "quota_warning", "new_login",
                                "account_security_change"):
                        rc, out, err = _cli(cli_bin, ipc_port, "--account", user,
                                             "notify", "set", cat, "on")
                        assert rc == 0, f"notify set {cat} failed: {out}\n{err}"

                local_root = tmp_path_factory.mktemp("vw_notify_secrets_root")
                (local_root / "f.txt").write_text("x")
                rc, out, err = _cli(cli_bin, ipc_port, "--account", owner,
                                     "add-folder", str(local_root), "/")
                assert rc == 0, f"add-folder failed: {out}\n{err}"
                assert _wait_until(lambda: _daemon_idle(cli_bin, ipc_port, owner))
                rc, out, err = _cli(cli_bin, ipc_port, "--account", owner,
                                     "share", "/f.txt", grantee, "view")
                assert rc == 0, f"share failed: {out}\n{err}"

                # A second login for `owner` (new_login already opted in
                # above) produces one more real email to check.
                rc, out, err = _cli(cli_bin, ipc_port, "account", "add",
                                     server.host, str(server.port), owner, PASSWORD,
                                     "--ca-cert", server.cert, "--label", f"{owner}_2")
                assert rc == 0, f"second login failed: {out}\n{err}"

                assert _wait_until(lambda: len(smtp.messages) >= 2, timeout=15)
                assert len(smtp.messages) >= 2, "expected at least share_received + new_login"
                for msg in smtp.messages:
                    assert secret_password not in msg.raw, (
                        f"password literal found in an email: subject={msg.subject!r}"
                    )
                    assert "session_token" not in msg.raw.lower()
                    assert "otp" not in msg.raw.lower()
            finally:
                daemon_proc.terminate()
                try:
                    daemon_proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon_proc.kill()
                    daemon_proc.wait(timeout=5)
        finally:
            server.stop()


# ── Admin categories ─────────────────────────────────────────────────────────

def test_admin_disabled_category_never_fires(binaries, tmp_path_factory, unique_username):
    """disk_capacity left disabled must never fire, even with a threshold
    (1%) that would trivially cross on real disk usage if it were on -
    proving the enable flag actually gates the check, not just the
    threshold math."""
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_admin_off_server")),
            extra_conf=_notify_conf(smtp, disk_capacity=0, disk_capacity_threshold_pct=1),
        )
        server.start()
        try:
            time.sleep(3)  # several GC cycles at gc_interval_secs=2
            assert smtp.messages == [], "disabled category must never fire"
        finally:
            server.stop()


def test_admin_disk_capacity(binaries, tmp_path_factory, unique_username):
    """Real vw_fs_disk_usage_pct() call, real statvfs/GetDiskFreeSpaceEx -
    a 1% threshold guarantees a real crossing on the very first GC cycle
    without needing to actually fill (or mock) the test machine's disk."""
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_disk_server")),
            extra_conf=_notify_conf(smtp, disk_capacity=1, disk_capacity_threshold_pct=1),
        )
        server.start()
        try:
            assert _wait_until(lambda: len(smtp.messages) >= 1, timeout=10), (
                "disk_capacity email never arrived with threshold_pct=1"
            )
            assert "admin@example.invalid" in smtp.messages[0].to
            assert "capacity" in smtp.messages[0].body.lower() or "%" in smtp.messages[0].body
        finally:
            server.stop()


def test_admin_lockout_spike(binaries, tmp_path_factory, unique_username):
    binaries.require_server()
    binaries.require_tls()

    with MockSmtpServer() as smtp:
        server = ServerInstance(
            binaries, str(tmp_path_factory.mktemp("vw_notify_lockout_server")),
            extra_conf=_notify_conf(
                smtp, lockout_spike=1,
                lockout_spike_threshold_count=2, lockout_spike_window_secs=300,
            ),
        )
        server.start()
        try:
            user_a = f"{unique_username}_a"
            user_b = f"{unique_username}_b"
            server.create_user(user_a, PASSWORD)
            server.create_user(user_b, PASSWORD)

            # Lock out two distinct accounts (server's own hardcoded
            # LOCKOUT_MAX_ATTEMPTS=6 wrong attempts each - see
            # test_auth.py::test_brute_force_lockout for this same
            # constant) within the 300s window above.
            for user in (user_a, user_b):
                for _ in range(6):
                    try:
                        with VwClient(server.host, server.port, server.cert) as c:
                            c.login(user, "wrong_password_attempt")
                    except VwAuthError:
                        pass

            assert _wait_until(lambda: len(smtp.messages) >= 1, timeout=10), (
                "lockout_spike email never arrived after two real account lockouts"
            )
            assert "admin@example.invalid" in smtp.messages[0].to
            assert "lockout" in smtp.messages[0].body.lower()
        finally:
            server.stop()


def test_admin_alert_enabled_with_no_email_fails_startup(binaries, tmp_path_factory):
    """Formalizes TASK-208's own manually-verified --check-config
    behavior as a real automated test, closing the gap that task's notes
    explicitly disclosed."""
    binaries.require_server()
    binaries.require_tls()

    tmpdir = tmp_path_factory.mktemp("vw_notify_misconfig")
    data_dir = tmpdir / "data"
    data_dir.mkdir()
    conf_path = tmpdir / "server.conf"
    conf_path.write_text(f"""\
listen_host = 127.0.0.1
listen_port = 4430
data_dir = {data_dir}
cert_pem_path = {binaries.test_cert}
key_pem_path = {binaries.test_key}
notify.crash_recovery = 1
""")
    result = subprocess.run(
        [binaries.server_bin, "--config", str(conf_path), "--check-config"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0, (
        "server must refuse to start with a notify.* category enabled and no notify.admin_email"
    )

    conf_path.write_text(f"""\
listen_host = 127.0.0.1
listen_port = 4430
data_dir = {data_dir}
cert_pem_path = {binaries.test_cert}
key_pem_path = {binaries.test_key}
notify.crash_recovery = 1
notify.admin_email = admin@example.invalid
""")
    result = subprocess.run(
        [binaries.server_bin, "--config", str(conf_path), "--check-config"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, (
        f"a correctly-configured admin alert must pass --check-config: {result.stdout}\n{result.stderr}"
    )
