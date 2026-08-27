"""
test_gateway.py — integration tests for TASK-127-141 (web gateway +
browser client feature), covering TASK-143's required coverage:

1. End-to-end round trips through the actual gateway (login/2FA-skip,
   file list/upload/download/delete, version list/restore, share
   grant/revoke, public link create/redeem/revoke).
2. Vault zero-knowledge structural verification: intercepts every
   outgoing request during a real vault create/unlock/upload/download
   run and asserts the passphrase never appears in any of them.
3. Multi-session concurrency/isolation: two simulated browser sessions
   against one gateway process.
4. Regression coverage for TASK-144's two blocking SEC.07 findings
   (stalled-connection DoS, cookie timing side-channel).
5. Malformed/adversarial HTTP and JSON input against vw_http/vw_json.

Drives the gateway's HTTP/JSON API directly with `requests` (not through
nginx — nginx is a dumb reverse proxy with no logic of its own to test;
TASK-142's deployment doc is the place that documents the nginx layer).

Every test that logs a client in MUST get it logged out again, even on
failure — the `clients` fixture below (not raw `GatewayClient(gateway)`
calls) handles this automatically via teardown. This isn't cosmetic:
`conftest.py`'s test server config pins `max_workers = 2` (deliberately
small, matching `test_sharing.py`'s own documented convention), and this
module's `server`/`gateway` fixtures are module-scoped (one long-lived
process for the whole file, to avoid re-paying Argon2id's cost per test).
A single leaked, never-logged-out session — most easily created by a
test that fails an assertion *before* reaching its own logout call —
permanently occupies one of only two available worker slots; leak both
and every subsequent test in the file hangs waiting for a slot that will
never free up, turning one real failure into a wall of unrelated-looking
timeouts. Confirmed this is exactly what was happening during this
suite's own development (see git history / TASK-143's note) before this
fixture existed.
"""
import hashlib
import json
import os
import socket
import time

import pytest
import requests

from conftest import GatewayInstance, ServerInstance
from vw_client import VW_PERM_VIEW

PASSWORD = "GatewayTestP@ss1"


# ── Small helpers ────────────────────────────────────────────────────────────

class GatewayClient:
    """One requests.Session per logical browser tab — mirrors web/src/api.ts's
    own fetch() conventions (JSON body, cookie-based session).

    Note on the Secure cookie attribute: in production, the browser only
    ever talks to the gateway through nginx over HTTPS (TASK-142's
    deployment model) - the gateway's own plain-HTTP listener is never
    hit directly by a browser, so a Secure cookie is always sent back
    correctly there. These tests deliberately bypass nginx (it's a dumb
    reverse proxy with no logic of its own worth testing here) and talk
    to the gateway directly over plain HTTP, which means Python's
    http.cookiejar (like every correct cookie-jar implementation) refuses
    to attach a Secure-flagged cookie to a non-HTTPS request - it stores
    it (confirmed: it's visible in the jar) but silently omits it from
    the Cookie header on every subsequent request. That's the cookie jar
    doing exactly what RFC 6265 says it should; it just means the naive
    "let requests.Session handle cookies automatically" approach silently
    breaks every test past login. Every login-like call below strips the
    Secure flag from the jar afterward so these tests can exercise the
    gateway's actual session logic without also standing up a real TLS
    listener in front of it just to satisfy the cookie jar.
    """

    def __init__(self, gateway):
        self.base_url = gateway.base_url
        self.session = requests.Session()
        # Which slot this client last logged into (default 0, matching the
        # gateway's own default) — logout()'s own default must track this,
        # not always 0, or logging out a non-default-slot client would
        # clear the wrong (empty) slot server-side and leave its real
        # session leaked. See this module's docstring on why a leaked
        # session is a real problem here (only 2 test-server workers).
        self.last_login_slot = 0

    def _strip_secure_flag(self):
        for cookie in self.session.cookies:
            cookie.secure = False

    def post(self, path, json_body=None, slot=None, **kwargs):
        # TASK-164: X-Vw-Slot tells the gateway which of this browser's
        # several slot cookies backs this one request. slot=None (the
        # default everywhere below) omits the header entirely, which is
        # exactly the "not yet updated to use it" case TASK-164's own
        # acceptance criteria requires to keep behaving as slot 0 —
        # every pre-existing call site in this file relies on that.
        headers = kwargs.pop("headers", {}) or {}
        if slot is not None:
            headers["X-Vw-Slot"] = str(slot)
        return self.session.post(self.base_url + path, json=json_body, timeout=10,
                                  headers=headers, **kwargs)

    def login(self, username, password, otp=None, slot=None, remember=None):
        body = {"username": username, "password": password}
        if otp is not None:
            body["otp"] = otp
        if slot is not None:
            body["slot"] = slot
        if remember is not None:
            body["remember"] = remember
        r = self.post("/api/login", body)
        self._strip_secure_flag()
        if r.status_code == 200 and r.json().get("status") == "ok":
            self.last_login_slot = slot if slot is not None else 0
        return r

    def logout(self, slot=None):
        target = slot if slot is not None else self.last_login_slot
        return self.post("/api/logout", {"slot": target})

    def accounts(self):
        return self.post("/api/accounts", {})

    def list_files(self, path="/", recursive=False, slot=None):
        return self.post("/api/files/list", {"path": path, "recursive": recursive}, slot=slot)

    def stat(self, path):
        return self.post("/api/files/stat", {"path": path})

    def mkdir(self, name, parent_dir_id=0, slot=None):
        return self.post("/api/files/mkdir", {"name": name, "parent_dir_id": parent_dir_id}, slot=slot)

    def delete(self, path):
        return self.post("/api/files/delete", {"path": path})

    def move(self, file_id, new_name=None, new_parent_dir_id=0):
        return self.post("/api/files/move", {
            "file_id": file_id, "new_name": new_name or "", "new_parent_dir_id": new_parent_dir_id,
        })

    def upload_chunk(self, chunk_hash_hex, data):
        return self.session.post(
            self.base_url + "/api/chunks/upload",
            headers={"X-Vw-Chunk-Hash": chunk_hash_hex},
            data=data, timeout=10,
        )

    def download_chunk(self, chunk_hash_hex):
        return self.post("/api/chunks/download", {"hash": chunk_hash_hex})

    def commit_file(self, path, logical_size, chunk_hashes, vault_id=None, wrapped_dek_hex=None):
        body = {"path": path, "logical_size": logical_size, "chunk_hashes": chunk_hashes}
        if vault_id:
            body["vault_id"] = vault_id
            body["wrapped_dek"] = wrapped_dek_hex
        return self.post("/api/files/commit", body)

    def version_chunks(self, version_id):
        return self.post("/api/versions/chunks", {"version_id": version_id})

    def version_list(self, path):
        return self.post("/api/versions/list", {"path": path})

    def version_restore(self, path, version_id):
        return self.post("/api/versions/restore", {"path": path, "version_id": version_id})

    def search(self, query):
        return self.post("/api/search", {"query": query})

    def notify_prefs(self):
        return self.post("/api/notify/prefs", {})

    def notify_prefs_set(self, prefs):
        return self.post("/api/notify/prefs/set", {"prefs": prefs})

    def account_email(self):
        return self.post("/api/account/email", {})

    def account_email_set(self, email):
        return self.post("/api/account/email/set", {"email": email})

    def share_grant(self, file_id, target_username, permission, expires_at=0):
        return self.post("/api/shares/grant", {
            "file_id": file_id, "target_username": target_username,
            "permission": permission, "expires_at": expires_at,
        })

    def share_revoke(self, share_id):
        return self.post("/api/shares/revoke", {"share_id": share_id})

    def share_list(self, mode):
        return self.post("/api/shares/list", {"mode": mode})

    def link_create(self, file_id, permission, expires_at=0, password=""):
        return self.post("/api/links/create", {
            "file_id": file_id, "permission": permission, "expires_at": expires_at,
            "password": password,
        })

    def link_revoke(self, share_id):
        return self.post("/api/links/revoke", {"share_id": share_id})

    def link_list(self, file_id_filter=0):
        return self.post("/api/links/list", {"file_id_filter": file_id_filter})

    def link_access(self, link_token_hex, slot=None, password=None):
        body = {"link_token": link_token_hex}
        if slot is not None:
            body["slot"] = slot
        if password is not None:
            body["password"] = password
        r = self.post("/api/links/access", body)
        self._strip_secure_flag()
        if r.status_code == 200 and r.json().get("status") == "ok":
            self.last_login_slot = slot if slot is not None else 0
        return r

    def vault_create(self, folder_file_id, wrapped_vk_hex, kdf_salt_hex, kdf_params_hex):
        return self.post("/api/vault/create", {
            "folder_file_id": folder_file_id, "wrapped_vk": wrapped_vk_hex,
            "kdf_salt": kdf_salt_hex, "kdf_params": kdf_params_hex,
        })

    def vault_key_fetch(self, vault_id):
        return self.post("/api/vault/key_fetch", {"vault_id": vault_id})

    def vault_list(self):
        return self.post("/api/vault/list", {})


class ClientFactory:
    """Creates GatewayClients and guarantees every one of them is logged
    out during fixture teardown, regardless of whether the test that
    created it passed or failed. See this module's own docstring for why
    that guarantee matters here specifically (small test-server worker
    pool + module-scoped server/gateway)."""

    def __init__(self, gateway):
        self.gateway = gateway
        self._clients = []

    def login(self, username, password=PASSWORD, create_user=True, server=None, slot=None, remember=None):
        if create_user:
            assert server is not None, "create_user=True requires passing server="
            server.create_user(username, password)
        client = GatewayClient(self.gateway)
        r = client.login(username, password, slot=slot, remember=remember)
        assert r.status_code == 200 and r.json()["status"] == "ok", r.text
        self._clients.append(client)
        return client

    def bare(self):
        """A GatewayClient not yet logged in (e.g. to test bad credentials,
        or to redeem a public link) - still tracked for logout-on-teardown
        once/if it does end up authenticated."""
        client = GatewayClient(self.gateway)
        self._clients.append(client)
        return client

    def logout_all(self):
        for c in self._clients:
            try:
                c.logout()
            except Exception:
                pass  # best-effort cleanup; a failed logout must not mask the test's real failure


@pytest.fixture
def clients(server, gateway):
    factory = ClientFactory(gateway)
    yield factory
    factory.logout_all()


def _upload_plaintext(client, path, data, chunk_size=4 * 1024 * 1024):
    """Chunk+upload+commit a plaintext file, mirroring web/src/api.ts's
    uploadFile loop exactly (one HTTP call per chunk)."""
    chunk_hashes = []
    for offset in range(0, max(len(data), 1), chunk_size):
        chunk = data[offset:offset + chunk_size]
        h = hashlib.sha256(chunk).hexdigest()
        r = client.upload_chunk(h, chunk)
        assert r.status_code == 200, r.text
        chunk_hashes.append(h)
        if not data:
            break
    r = client.commit_file(path, len(data), chunk_hashes)
    assert r.status_code == 200, r.text
    return r.json()


def _download_plaintext(client, version_id):
    r = client.version_chunks(version_id)
    assert r.status_code == 200, r.text
    chunks = r.json()
    assert chunks["vault_id"] == 0
    out = b""
    for h in chunks["chunk_hashes"]:
        r = client.download_chunk(h)
        assert r.status_code == 200, r.text
        out += r.content
    return out


# ── 1. End-to-end round trips ────────────────────────────────────────────────

def test_login_bad_credentials_rejected(clients):
    client = clients.bare()
    r = client.login("nonexistent_user_xyz", "wrong-password")
    assert r.status_code == 401
    assert r.json()["status"] == "bad_credentials"


def test_login_logout_round_trip(server, clients, unique_username):
    client = clients.login(unique_username, server=server)

    r = client.list_files("/")
    assert r.status_code == 200

    r = client.logout()
    assert r.status_code == 200 and r.json()["status"] == "ok"

    # Session must actually be gone after logout, not just cosmetically.
    r = client.list_files("/")
    assert r.status_code == 401
    assert r.json()["status"] == "auth_required"


def test_file_list_mkdir_delete_round_trip(server, clients, unique_username):
    client = clients.login(unique_username, server=server)

    r = client.mkdir("round_trip_dir")
    assert r.status_code == 200, r.text
    dir_id = r.json()["dir_id"]

    r = client.stat("/round_trip_dir")
    assert r.status_code == 200
    assert r.json()["file_id"] == dir_id
    assert r.json()["entry_type"] == 1  # folder

    r = client.list_files("/")
    assert r.status_code == 200
    assert any(e["name"] == "round_trip_dir" for e in r.json())

    r = client.delete("/round_trip_dir")
    assert r.status_code == 200, r.text

    r = client.stat("/round_trip_dir")
    assert r.status_code == 404
    assert r.json()["status"] == "not_found"


def test_move_renames_and_is_reflected_in_listing(server, clients, unique_username):
    """
    Covers TASK-143's move round-trip, plus a regression check for TASK-157
    (filed from this exact test failing during development, now fixed):
    FILE_MOVE used to never update the server's path_ht index, so FILE_STAT
    couldn't resolve a renamed item by either its old or new name until the
    server restarted, even though the record itself (and FILE_LIST, which
    doesn't use that index) was correctly updated. vw_store_file_update now
    removes the stale path_ht entry and inserts the new one whenever name/
    parent_dir_id changes (src/server/vw_store_files.c) - both the listing
    view and the stat-by-path view are asserted here so a regression in
    either would be caught.
    """
    client = clients.login(unique_username, server=server)

    r = client.mkdir("move_src_dir")
    assert r.status_code == 200, r.text
    dir_id = r.json()["dir_id"]

    r = client.move(dir_id, new_name="move_dst_dir")
    assert r.status_code == 200, r.text

    r = client.list_files("/")
    assert r.status_code == 200
    names = {e["name"] for e in r.json()}
    assert "move_dst_dir" in names
    assert "move_src_dir" not in names
    moved_entry = next(e for e in r.json() if e["name"] == "move_dst_dir")
    assert moved_entry["file_id"] == dir_id

    # TASK-157 regression: the new path must resolve on the first stat call,
    # no restart required, and the old path must stay a clean 404.
    r = client.stat("/move_dst_dir")
    assert r.status_code == 200, r.text
    assert r.json()["file_id"] == dir_id

    r = client.stat("/move_src_dir")
    assert r.status_code == 404
    assert r.json()["status"] == "not_found"


def test_move_with_oversized_new_name_decodes_safely(server, clients, unique_username):
    """
    Regression test for a real memory-safety bug found during the CQR.08/
    SEC.07 review pass on TASK-133: vw_json_string_decode only NUL-
    terminated its output buffer on the success path. handle_file_move's
    `new_name` field is optional and was read via
    `(void)get_json_string_field(...)` followed by a `new_name[0]` content
    check rather than checking the return code - so a `new_name` value long
    enough to make the decode fail (> 255 bytes, the stack buffer's size)
    left the buffer non-empty and non-terminated. The immediate caller,
    vw_client_file_move, then strlen()s that buffer and reads past its
    256-byte bound into adjacent stack memory until it happens to find a
    zero byte - a stack-memory-disclosure/DoS primitive reachable by any
    authenticated user with one crafted request, on a single-threaded
    gateway process where a resulting crash takes down every logged-in
    user, not just the attacker.

    Fixed in two places: vw_json_string_decode now NUL-terminates its
    output buffer on every return path (not just success), and
    handle_file_move/handle_file_commit explicitly reset their optional
    string fields to empty on a decode failure instead of trusting
    whatever partial bytes a failed decode left behind.
    """
    client = clients.login(unique_username, server=server)

    r = client.mkdir("move_oversized_dir")
    assert r.status_code == 200, r.text
    dir_id = r.json()["dir_id"]

    # 1000 bytes is far past the 256-byte new_name buffer - decode must
    # fail partway through, well before the buffer's own bound.
    oversized_name = "A" * 1000
    r = client.move(dir_id, new_name=oversized_name)
    # An oversized optional field is *not* the same as a malformed request;
    # it's treated as "no rename requested" - this call succeeds as a
    # move to the same parent (a no-op relocation), not a 400/500.
    assert r.status_code == 200, r.text

    # The directory's name must be exactly what it was - never renamed to
    # a truncated fragment of the oversized value, and never containing
    # any byte of adjacent stack memory that a pre-fix overread could have
    # pulled in.
    r = client.list_files("/")
    assert r.status_code == 200
    entry = next(e for e in r.json() if e["file_id"] == dir_id)
    assert entry["name"] == "move_oversized_dir"

    # The gateway (single-threaded) must still be alive and responsive -
    # the actual failure mode this bug could cause was a process crash
    # that would hang every subsequent request in this test session.
    r = client.list_files("/")
    assert r.status_code == 200


def test_upload_download_multi_chunk_round_trip(server, clients, unique_username):
    client = clients.login(unique_username, server=server)

    data = b"integration-test-content" * 400_000  # > one 4 MiB chunk
    assert len(data) > 4 * 1024 * 1024

    commit = _upload_plaintext(client, "/big_file.bin", data)
    assert "version_id" in commit

    downloaded = _download_plaintext(client, commit["version_id"])
    assert downloaded == data


def test_version_list_and_restore(server, clients, unique_username):
    client = clients.login(unique_username, server=server)

    v1 = _upload_plaintext(client, "/versioned.txt", b"version one content")
    v2 = _upload_plaintext(client, "/versioned.txt", b"version two, different and shorter")

    r = client.version_list("/versioned.txt")
    assert r.status_code == 200
    versions = {v["version_id"] for v in r.json()}
    assert v1["version_id"] in versions and v2["version_id"] in versions

    r = client.version_restore("/versioned.txt", v1["version_id"])
    assert r.status_code == 200, r.text

    r = client.stat("/versioned.txt")
    assert r.status_code == 200
    restored_version_id = r.json()["version_id"]
    assert restored_version_id not in (v1["version_id"], v2["version_id"])  # a NEW version, not an in-place revert

    downloaded = _download_plaintext(client, restored_version_id)
    assert downloaded == b"version one content"


def test_share_grant_list_revoke(server, clients, unique_username):
    owner = clients.login(f"{unique_username}_owner", server=server)
    grantee_name = f"{unique_username}_grantee"
    server.create_user(grantee_name, PASSWORD)

    r = owner.mkdir("shared_dir")
    dir_id = r.json()["dir_id"]

    r = owner.share_grant(dir_id, grantee_name, VW_PERM_VIEW)
    assert r.status_code == 200, r.text
    share_id = r.json()["share_id"]

    r = owner.share_list(mode=0)
    assert any(s["share_id"] == share_id and not s["revoked"] for s in r.json())

    r = owner.share_revoke(share_id)
    assert r.status_code == 200, r.text

    r = owner.share_list(mode=0)
    matching = [s for s in r.json() if s["share_id"] == share_id]
    assert matching and matching[0]["revoked"] is True


def test_search_permission_scoped_results(server, clients, unique_username):
    """
    TASK-201's gateway passthrough of SEARCH/SEARCH_RESP (docs/PROTOCOL.md
    §7.12), verified at the actual HTTP/JSON layer web/src/api.ts's
    search() calls — not re-proving the server's own permission logic
    from scratch (that's TASK-198's test_search.py, at the wire level);
    this proves the gateway's /api/search correctly carries the same
    property through: owner sees both of their files, a grantee sees
    only the one shared with them, and a stranger's search succeeds with
    zero results rather than an error (the match must be invisible, not
    merely denied).
    """
    # Logged in and out one at a time, never more than one concurrently:
    # the shared server/gateway fixtures' test server only has 2 workers,
    # and each logged-in gateway session holds its own persistent
    # connection to it for the session's lifetime (CLAUDE.md's WEB.09
    # charter) - three held open at once here previously hung the third
    # login outright (same worker-pool-exhaustion class of issue TASK-198/
    # 199's own tests each hit and fixed the same way).
    grantee_name = f"{unique_username}_grantee"
    stranger_name = f"{unique_username}_stranger"
    # Created via the admin socket directly (cheap; not a live gateway
    # session, so it doesn't tie up one of the test server's 2 workers)
    # so share_grant below has a real target_username to resolve, without
    # actually logging the grantee in until owner is done with it.
    server.create_user(grantee_name, PASSWORD)
    server.create_user(stranger_name, PASSWORD)

    owner = clients.login(f"{unique_username}_owner", server=server)
    _upload_plaintext(owner, "/findme_owned.txt", b"owner only")
    _upload_plaintext(owner, "/findme_shared.txt", b"shared with grantee")
    shared_file_id = owner.stat("/findme_shared.txt").json()["file_id"]
    r = owner.share_grant(shared_file_id, grantee_name, VW_PERM_VIEW)
    assert r.status_code == 200, r.text

    r = owner.search("findme")
    assert r.status_code == 200, r.text
    owner_names = {e["name"] for e in r.json()["results"]}
    assert {"findme_owned.txt", "findme_shared.txt"} <= owner_names
    owner.logout()

    grantee = clients.login(grantee_name, create_user=False)
    r = grantee.search("findme")
    assert r.status_code == 200, r.text
    grantee_results = {e["name"]: e for e in r.json()["results"]}
    assert "findme_shared.txt" in grantee_results
    assert grantee_results["findme_shared.txt"]["is_shared"] == 1
    assert "findme_owned.txt" not in grantee_results
    grantee.logout()

    stranger = clients.login(stranger_name, create_user=False)
    r = stranger.search("findme")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["results"] == []
    assert body["truncated"] is False


def test_search_html_special_characters_survive_as_literal_data(server, clients, unique_username):
    """
    Security note on TASK-201: a filename is attacker-controllable (it's
    whatever the uploader named it, and search surfaces matches across
    everyone who's shared something with you) and must never be
    interpreted as markup by the frontend. This test proves the half of
    that guarantee an HTTP/JSON test actually can: the gateway's JSON
    encoding (vw_json_write_string) round-trips HTML-special characters
    byte-for-byte, neither corrupting nor stripping them — `response.json()`
    decoding this into the exact original string is what makes the other
    half true. The other half — that web/src/main.ts's renderSearchRow
    only ever assigns this string to `.textContent`, never `.innerHTML` or
    any other markup-interpreting sink — isn't something a JSON-only test
    can observe (there's no browser DOM here); it's verified by code
    review instead (see TASK-201's own notes), the same way this
    project's pre-existing renderFileRow already documents doing for
    every other filename-displaying code path.
    """
    client = clients.login(unique_username, server=server)
    # No '/' in this name deliberately - '/' is this protocol's path
    # separator (same as any hierarchical filesystem), not an
    # HTML-special character, and a name containing one would be parsed
    # as a nested path rather than a literal filename (confirmed while
    # first writing this test: an HTML closing tag like "</b>" contains
    # a '/', which made FILE_COMMIT treat everything before it as a
    # parent directory to resolve - genuinely correct behavior for a
    # path-based API, not a bug, but the wrong test string for what this
    # test is actually checking). <, >, &, ", ' below cover the actual
    # HTML-special characters relevant to the XSS concern.
    tricky_name = "<img src=x onerror=alert('xss')>&\".txt"
    _upload_plaintext(client, f"/{tricky_name}", b"gotcha")

    r = client.search("onerror")
    assert r.status_code == 200, r.text
    names = [e["name"] for e in r.json()["results"]]
    assert tricky_name in names


# ── Notification preferences (TASK-206/207/211; docs/PROTOCOL.md §7.13) ─────

VW_NOTIFY_SHARE_RECEIVED = 0x0001
VW_NOTIFY_QUOTA_WARNING = 0x0002


def test_notify_prefs_default_off_and_roundtrip(server, clients, unique_username):
    """
    TASK-211's gateway passthrough of NOTIFY_PREFS_GET/SET
    (docs/PROTOCOL.md §7.13), verified at the actual HTTP/JSON layer
    web/src/api.ts's getNotifyPrefs()/setNotifyPrefs() calls — the
    server-side bitmask semantics themselves (default off, per-bit
    gating) are TASK-207's own already-tested territory
    (tests/unit/test_vw_notify.c); this proves the gateway carries that
    state through correctly: a fresh account reads back 0, a SET is
    reflected by a subsequent independent GET (not just the SET
    response's own echo), and toggling one bit leaves the others alone.
    """
    client = clients.login(unique_username, server=server)

    r = client.notify_prefs()
    assert r.status_code == 200, r.text
    assert r.json()["prefs"] == 0, "a fresh account must default to every category off"

    r = client.notify_prefs_set(VW_NOTIFY_QUOTA_WARNING)
    assert r.status_code == 200, r.text
    assert r.json()["prefs"] == VW_NOTIFY_QUOTA_WARNING

    # Independent fetch, not the SET call's own echoed response — proves
    # this is real server-side state, not something only the one
    # connection that set it would see.
    r = client.notify_prefs()
    assert r.status_code == 200, r.text
    assert r.json()["prefs"] == VW_NOTIFY_QUOTA_WARNING

    # Setting a second category must not disturb the first (the gateway
    # is a thin passthrough — this is exercising the same
    # read-modify-write discipline web/src/main.ts's toggleNotifyCategory
    # performs, not a new server-side merge behavior).
    r = client.notify_prefs_set(VW_NOTIFY_QUOTA_WARNING | VW_NOTIFY_SHARE_RECEIVED)
    assert r.status_code == 200, r.text
    assert r.json()["prefs"] == (VW_NOTIFY_QUOTA_WARNING | VW_NOTIFY_SHARE_RECEIVED)

    client.logout()


def test_notify_prefs_scoped_to_the_calling_session_only(server, clients, unique_username):
    """
    Security note on TASK-211: neither endpoint accepts any account/user
    identifier in its request body — require_session() derives the
    account entirely from the caller's own session cookie (same as every
    other gateway endpoint). This test proves that by construction rather
    than by inspecting source: two different logged-in accounts each set
    a distinct preference, and neither observes the other's value.
    """
    other_username = f"{unique_username}_other"
    server.create_user(other_username, PASSWORD)

    a = clients.login(unique_username, server=server)
    a_result = a.notify_prefs_set(VW_NOTIFY_QUOTA_WARNING)
    assert a_result.status_code == 200, a_result.text
    a.logout()

    b = clients.login(other_username, create_user=False)
    r = b.notify_prefs()
    assert r.status_code == 200, r.text
    assert r.json()["prefs"] == 0, "a different account must never see another account's preference"
    b.logout()


def test_account_email_default_empty_and_roundtrip(server, clients, unique_username):
    """
    TASK-222's gateway passthrough of ACCOUNT_EMAIL_GET/SET
    (docs/PROTOCOL.md §7.14), verified at the actual HTTP/JSON layer
    web/src/api.ts's getAccountEmail()/setAccountEmail() calls — the
    server-side storage/validation semantics are already unit- and
    CLI-integration-tested; this proves the gateway carries that state
    through correctly.
    """
    client = clients.login(unique_username, server=server)

    r = client.account_email()
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "", "a fresh account must have no email on file"

    address = f"{unique_username}@example.com"
    r = client.account_email_set(address)
    assert r.status_code == 200, r.text
    assert r.json()["email"] == address

    # Independent fetch, not the SET call's own echoed response.
    r = client.account_email()
    assert r.status_code == 200, r.text
    assert r.json()["email"] == address

    # A malformed address is rejected with 400, and does not clobber the
    # value already on file.
    r = client.account_email_set("not-an-email")
    assert r.status_code == 400, r.text
    r = client.account_email()
    assert r.json()["email"] == address

    client.logout()


def test_account_email_scoped_to_the_calling_session_only(server, clients, unique_username):
    """
    Security note on TASK-222: neither endpoint accepts any account/user
    identifier in its request body — require_session() derives the
    account entirely from the caller's own session cookie (same posture
    as notify prefs above). This also proves the server-side uniqueness
    check actually reaches the gateway caller: a second account cannot
    claim an address the first already owns.
    """
    other_username = f"{unique_username}_other"
    server.create_user(other_username, PASSWORD)

    a = clients.login(unique_username, server=server)
    address = f"{unique_username}@example.com"
    a_result = a.account_email_set(address)
    assert a_result.status_code == 200, a_result.text
    a.logout()

    b = clients.login(other_username, create_user=False)
    r = b.account_email()
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "", "a different account must never see another account's email"

    dup = b.account_email_set(address)
    assert dup.status_code == 409, dup.text
    b.logout()


def test_public_link_create_redeem_revoke(server, clients, unique_username):
    owner = clients.login(unique_username, server=server)
    r = owner.mkdir("link_test_dir")
    dir_id = r.json()["dir_id"]

    r = owner.link_create(dir_id, VW_PERM_VIEW)
    assert r.status_code == 200, r.text
    link_data = r.json()
    assert len(link_data["link_token"]) == 64  # 32 bytes hex

    # Redeem with NO prior session/cookie at all.
    anon_client = clients.bare()
    r = anon_client.link_access(link_data["link_token"])
    assert r.status_code == 200, r.text

    # Scoped session can browse the link's scope.
    r = anon_client.list_files("/")
    assert r.status_code == 200

    # Revoke, then confirm the ALREADY-ESTABLISHED scoped session's next
    # request fails live (not just that a fresh redemption attempt would).
    r = owner.link_revoke(link_data["share_id"])
    assert r.status_code == 200, r.text

    r = anon_client.list_files("/")
    assert r.status_code == 401
    assert r.json()["status"] == "auth_required"


def test_public_link_password_via_gateway(server, clients, unique_username):
    """
    TASK-190: the gateway's own passthrough of TASK-186/187's password
    protection — distinct from test_link_password.py, which drives the
    raw wire protocol directly and already covers the server-side
    enforcement itself.
    """
    owner = clients.login(unique_username, server=server)
    r = owner.mkdir("link_pw_test_dir")
    dir_id = r.json()["dir_id"]

    r = owner.link_create(dir_id, VW_PERM_VIEW, password="hunter2")
    assert r.status_code == 200, r.text
    link_data = r.json()

    r = owner.link_list()
    entry = next(e for e in r.json() if e["share_id"] == link_data["share_id"])
    assert entry["has_password"] is True

    # No password at all.
    anon_no_pw = clients.bare()
    r = anon_no_pw.link_access(link_data["link_token"])
    assert r.status_code == 401, r.text
    assert r.json()["status"] == "link_password_required"

    # Wrong password.
    anon_wrong = clients.bare()
    r = anon_wrong.link_access(link_data["link_token"], password="wrong")
    assert r.status_code == 401, r.text
    assert r.json()["status"] == "link_password_wrong"

    # Correct password — succeeds exactly like a no-password link.
    anon_ok = clients.bare()
    r = anon_ok.link_access(link_data["link_token"], password="hunter2")
    assert r.status_code == 200, r.text
    r = anon_ok.list_files("/")
    assert r.status_code == 200


# ── 2. Vault zero-knowledge structural verification ─────────────────────────

def test_vault_passphrase_never_sent_to_gateway(server, clients, unique_username):
    """
    Structural check, not just "decryption works": intercepts every
    request this test makes to the gateway during a realistic vault
    create/key_fetch/list flow and asserts a passphrase string never
    appears in any request body, and that no request body ever has a
    field literally named "passphrase".

    Deliberately does NOT re-derive real Argon2id/AES-GCM key material in
    Python — that correctness question (does deriving a KEK from THIS
    passphrase and wrapping/unwrapping actually work, does it match the
    native implementation byte-for-byte) is TASK-141's own scripted
    verification (smoke_task141_e2e.mjs, smoke_wasm_kdf.mjs,
    smoke_aesgcm_crosscheck.mjs), already run against the real WASM
    module and cross-checked against native C output. This test's job is
    narrower and purely structural: given a realistic vault registry
    flow using an opaque (random-bytes) wrapped-key blob — exactly what
    TASK-135's endpoints promise to treat opaquely regardless of content —
    does the passphrase string ever cross the wire to the gateway, under
    any field name, in any request.

    SEC.07/CQR.08 review note (TASK-157 review pass): the first version of
    this test only asserted the literal `passphrase` variable string never
    appeared in a captured body. Since this test never plumbs `passphrase`
    into `vault_create`'s arguments to begin with (`wrapped_vk` is
    `os.urandom(60)`, unrelated to it), that assertion was true by
    construction regardless of what the gateway does — it verified this
    test script, not the gateway's contract. Strengthened below with an
    explicit allow-list check on every vault-request body's field names:
    that catches ANY unexpected field (a real passphrase leak included),
    not just one specific presupposed name.
    """
    passphrase = "vault-zero-knowledge-test-passphrase"
    client = clients.login(unique_username, server=server)

    seen_bodies = []
    original_post = client.session.post

    def recording_post(url, *args, **kwargs):
        body = kwargs.get("json")
        if body is not None:
            seen_bodies.append(json.dumps(body))
        data = kwargs.get("data")
        if isinstance(data, (bytes, str)):
            seen_bodies.append(data if isinstance(data, str) else data.decode("latin-1"))
        return original_post(url, *args, **kwargs)

    client.session.post = recording_post

    wrapped_vk = os.urandom(60).hex()
    kdf_salt = os.urandom(16).hex()
    kdf_params = (19456).to_bytes(4, "little") + (2).to_bytes(4, "little") + (1).to_bytes(4, "little")

    r = client.mkdir("vault_zk_test")
    assert r.status_code == 200
    folder_id = r.json()["dir_id"]

    r = client.vault_create(folder_id, wrapped_vk, kdf_salt, kdf_params.hex())
    assert r.status_code == 200, r.text
    vault_id = r.json()["vault_id"]

    r = client.vault_key_fetch(vault_id)
    assert r.status_code == 200, r.text
    assert r.json()["wrapped_vk"] == wrapped_vk  # round-trips byte-for-byte

    r = client.vault_list()
    assert r.status_code == 200
    assert any(v["vault_id"] == vault_id for v in r.json())

    all_bodies = " ".join(seen_bodies)
    assert passphrase not in all_bodies, (
        "passphrase string appeared in a request body sent to the gateway - "
        "zero-knowledge boundary violated"
    )

    # Structural check, independent of any specific string this test
    # happens to hold: every vault-request body must contain ONLY the
    # documented opaque/descriptor fields (docs/PROTOCOL.md's vault
    # registry ops) - anything else, including a hypothetical passphrase-
    # carrying field this test never constructed itself, fails here.
    VAULT_REQUEST_ALLOWED_FIELDS = {
        "folder_file_id", "wrapped_vk", "kdf_salt", "kdf_params", "vault_id",
    }
    vault_shaped_bodies_checked = 0
    for body in seen_bodies:
        if not body.startswith("{"):
            continue
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            continue
        assert "passphrase" not in parsed, "a request body has a 'passphrase' field at all"
        if not (set(parsed) & VAULT_REQUEST_ALLOWED_FIELDS):
            continue  # not a vault-related body (e.g. the mkdir call above)
        vault_shaped_bodies_checked += 1
        unexpected = set(parsed) - VAULT_REQUEST_ALLOWED_FIELDS
        assert not unexpected, (
            f"vault request body has field(s) {unexpected} outside the "
            f"documented opaque/descriptor set {VAULT_REQUEST_ALLOWED_FIELDS}"
        )
    # Guard against the allow-list check silently checking nothing at all
    # (e.g. if a future refactor changes field names and the intersection
    # test above stops matching any recorded body).
    assert vault_shaped_bodies_checked >= 2  # vault_create + vault_key_fetch, at least


def test_file_list_vault_id_survives_move_out_of_vault_folder(server, clients, unique_username):
    """
    TASK-159 regression. `web/src/main.ts` used to infer a listed file's
    encrypted-vs-plaintext status from whether its *containing folder*
    was a registered vault (`currentFolderVaultId`), because
    `FILE_LIST_RESP` didn't carry a per-entry `vault_id` yet (TASK-141's
    documented limitation). `TASK-156` closed that wire gap by adding one;
    the gateway's `write_file_entry()` already forwards
    `vw_client_file_entry_t.vault_id` into `/api/files/list` JSON
    unchanged, so this exercises that it actually arrives correctly, not
    just that the field exists.

    This is the concrete case the old folder-level inference gets wrong:
    `FILE_MOVE` never touches version metadata, so a file's `vault_id`
    must survive being moved out of the vault's own registered folder -
    a plain "is the containing folder a registered vault" check would
    wrongly report it as plaintext (0) at the new location.
    """
    client = clients.login(unique_username, server=server)

    r = client.mkdir("vault_home")
    assert r.status_code == 200, r.text
    vault_folder_id = r.json()["dir_id"]
    r = client.mkdir("plain_elsewhere")
    assert r.status_code == 200, r.text
    plain_folder_id = r.json()["dir_id"]

    wrapped_vk = os.urandom(60).hex()
    kdf_salt = os.urandom(16).hex()
    kdf_params = (19456).to_bytes(4, "little") + (2).to_bytes(4, "little") + (1).to_bytes(4, "little")
    r = client.vault_create(vault_folder_id, wrapped_vk, kdf_salt, kdf_params.hex())
    assert r.status_code == 200, r.text
    vault_id = r.json()["vault_id"]

    data = b"opaque ciphertext-shaped payload, content is irrelevant here"
    h = hashlib.sha256(data).hexdigest()
    r = client.upload_chunk(h, data)
    assert r.status_code == 200, r.text
    wrapped_dek_hex = os.urandom(48).hex()
    r = client.commit_file("/vault_home/secret.bin", len(data), [h],
                            vault_id=vault_id, wrapped_dek_hex=wrapped_dek_hex)
    assert r.status_code == 200, r.text
    file_id = r.json()["file_id"]

    r = client.list_files("/vault_home")
    assert r.status_code == 200, r.text
    entry = next(e for e in r.json() if e["name"] == "secret.bin")
    assert entry["vault_id"] == vault_id

    # Move it OUT of the vault's own registered folder.
    r = client.move(file_id, new_parent_dir_id=plain_folder_id)
    assert r.status_code == 200, r.text

    r = client.list_files("/plain_elsewhere")
    assert r.status_code == 200, r.text
    entry = next(e for e in r.json() if e["name"] == "secret.bin")
    assert entry["vault_id"] == vault_id, (
        "a moved file's vault_id must survive the move - the old "
        "containing-folder inference would have reported 0 here"
    )


# ── 3. Multi-session concurrency / isolation ─────────────────────────────────

def test_multi_session_isolation(server, clients, unique_username):
    user_a = f"{unique_username}_a"
    user_b = f"{unique_username}_b"
    client_a = clients.login(user_a, server=server)
    client_b = clients.login(user_b, server=server)

    r = client_a.mkdir("a_only_dir")
    assert r.status_code == 200
    r = client_b.mkdir("b_only_dir")
    assert r.status_code == 200

    r = client_a.list_files("/")
    names_a = {e["name"] for e in r.json()}
    r = client_b.list_files("/")
    names_b = {e["name"] for e in r.json()}

    assert "a_only_dir" in names_a and "b_only_dir" not in names_a
    assert "b_only_dir" in names_b and "a_only_dir" not in names_b

    # Logging out A must not affect B's still-live session.
    client_a.logout()
    r = client_b.list_files("/")
    assert r.status_code == 200

    r = client_a.list_files("/")
    assert r.status_code == 401


def test_multi_slot_same_browser(server, clients, unique_username):
    """
    TASK-164 acceptance criterion: one requests.Session (one simulated
    browser) logs in as two different accounts into two different slots
    and makes authenticated calls against both concurrently, without
    either affecting the other's session — the multi-*slot* case, as
    opposed to test_multi_session_isolation's multi-*browser* case above
    (two entirely separate cookie jars, which was already possible before
    this task; this test is what's actually new).
    """
    user_a = f"{unique_username}_a"
    user_b = f"{unique_username}_b"
    client = clients.bare()

    server.create_user(user_a, PASSWORD)
    server.create_user(user_b, PASSWORD)

    # Explicit slot 0, then an unspecified ("next free") slot for the
    # second login — both through the SAME cookie jar, so "next free"
    # must see slot 0 as already occupied and land on slot 1.
    r = client.login(user_a, PASSWORD, slot=0)
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text
    r = client.login(user_b, PASSWORD)
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text

    slot_names = {c.name for c in client.session.cookies}
    assert "vw_session_0" in slot_names and "vw_session_1" in slot_names

    # No X-Vw-Slot header at all must behave exactly like slot 0 (the
    # acceptance criterion's own "non-breaking for anything not yet
    # updated" case) - every call below that omits slot= relies on this.
    r = client.mkdir("a_only_dir")  # slot=None -> slot 0 (user_a)
    assert r.status_code == 200
    r = client.mkdir("b_only_dir", slot=1)
    assert r.status_code == 200

    names_0 = {e["name"] for e in client.list_files("/").json()}
    names_1 = {e["name"] for e in client.list_files("/", slot=1).json()}
    assert "a_only_dir" in names_0 and "b_only_dir" not in names_0
    assert "b_only_dir" in names_1 and "a_only_dir" not in names_1

    # /api/accounts reports exactly these two occupied slots + usernames,
    # read from this same browser's own cookies only.
    accounts = {s["slot"]: s["username"] for s in client.accounts().json()["slots"]}
    assert accounts == {0: user_a, 1: user_b}

    # Logging out slot 1 must not affect slot 0's still-live session.
    r = client.logout(slot=1)
    assert r.status_code == 200
    assert client.list_files("/", slot=1).status_code == 401
    assert client.list_files("/").status_code == 200

    r = client.logout(slot=0)
    assert r.status_code == 200
    assert client.list_files("/").status_code == 401


def test_login_no_free_slot_is_rejected(binaries, tmp_path_factory, unique_username):
    """Filling every one of VW_GATEWAY_MAX_SLOTS (6) slots in one browser,
    then trying a 7th unspecified-slot login, must fail cleanly rather
    than silently overwrite an existing slot.

    Uses its own dedicated server+gateway (not the module-scoped
    server/gateway fixtures used by every other test in this file) with a
    higher max_workers: holding 6 simultaneously-live sessions open at
    once against the shared fixtures' max_workers=2 test server would
    itself hang (the 3rd login's vw_client_connect blocking forever
    waiting for a server worker that only frees up once an earlier
    session logs out) — a test-server capacity limit, unrelated to the
    gateway's own 6-slot cap this test actually means to exercise.
    """
    binaries.require_server()
    binaries.require_tls()
    binaries.require_gateway()

    srv = ServerInstance(binaries, str(tmp_path_factory.mktemp("vw_gw_slots_srv")), max_workers=8)
    srv.start()
    gw = GatewayInstance(binaries, srv)
    gw.start()
    try:
        client = GatewayClient(gw)
        for i in range(6):
            username = f"{unique_username}_slot{i}"
            srv.create_user(username, PASSWORD)
            r = client.login(username, PASSWORD, slot=i)
            assert r.status_code == 200 and r.json()["status"] == "ok", r.text

        overflow_username = f"{unique_username}_overflow"
        srv.create_user(overflow_username, PASSWORD)
        r = client.login(overflow_username, PASSWORD)  # no explicit slot -> "next free"
        assert r.status_code == 507
        assert r.json()["status"] == "no_free_slot"

        for i in range(6):
            assert client.logout(slot=i).status_code == 200
    finally:
        gw.stop()
        srv.stop()


# ── 3b. TASK-165: persistent "remember me" ───────────────────────────────────
#
# All four tests here need a gateway launched with --state-dir (the shared
# module-scoped `gateway` fixture never sets one, so `remember: true` is a
# no-op against it - see main.c's own opt-in framing), and need to kill +
# relaunch that exact gateway process, so each spins up its own dedicated
# GatewayInstance against the shared module `server` fixture (cheap to
# reuse - only the gateway process, not the Argon2id-backed server, gets
# restarted) rather than the shared `gateway` fixture.

def test_remember_me_survives_gateway_restart(binaries, server, tmp_path_factory, unique_username):
    binaries.require_gateway()
    server.create_user(unique_username, PASSWORD)

    state_dir = str(tmp_path_factory.mktemp("vw_gw_remember"))
    gw = GatewayInstance(binaries, server, state_dir=state_dir)
    gw.start()
    try:
        client = GatewayClient(gw)
        r = client.login(unique_username, PASSWORD, remember=True)
        assert r.status_code == 200 and r.json()["status"] == "ok", r.text
        assert client.list_files("/").status_code == 200

        gw.restart()

        # Same cookie, same browser, no re-authentication - the whole
        # point of this feature (acceptance criterion #1).
        r = client.list_files("/")
        assert r.status_code == 200

        assert client.logout().status_code == 200
    finally:
        gw.stop()


def test_non_remember_login_does_not_survive_restart(binaries, server, tmp_path_factory, unique_username):
    """Opt-in only (acceptance criterion #2): a plain login, even with a
    --state-dir-enabled gateway, creates no on-disk entry."""
    binaries.require_gateway()
    server.create_user(unique_username, PASSWORD)

    state_dir = str(tmp_path_factory.mktemp("vw_gw_no_remember"))
    gw = GatewayInstance(binaries, server, state_dir=state_dir)
    gw.start()
    try:
        client = GatewayClient(gw)
        r = client.login(unique_username, PASSWORD)  # remember omitted -> False
        assert r.status_code == 200 and r.json()["status"] == "ok", r.text
        assert client.list_files("/").status_code == 200

        gw.restart()

        r = client.list_files("/")
        assert r.status_code == 401
    finally:
        gw.stop()


def test_logout_removes_remembered_entry(binaries, server, tmp_path_factory, unique_username):
    """Acceptance criterion #3: logging out a remembered slot removes both
    the in-memory pool entry AND the on-disk one - a restart afterward
    must not resurrect it."""
    binaries.require_gateway()
    server.create_user(unique_username, PASSWORD)

    state_dir = str(tmp_path_factory.mktemp("vw_gw_remember_logout"))
    gw = GatewayInstance(binaries, server, state_dir=state_dir)
    gw.start()
    try:
        client = GatewayClient(gw)
        r = client.login(unique_username, PASSWORD, remember=True)
        assert r.status_code == 200 and r.json()["status"] == "ok", r.text

        assert client.logout().status_code == 200

        gw.restart()

        r = client.list_files("/")
        assert r.status_code == 401
    finally:
        gw.stop()


def test_remember_resume_then_immediate_second_request_both_succeed(
        binaries, server, tmp_path_factory, unique_username):
    """
    SEC.07's own required check for the "resume-rotation race": two
    requests presenting the same remembered cookie right after a restart.
    vw_gateway_dispatch() is only ever driven by main.c's single-threaded,
    one-request-at-a-time accept loop, so these two requests from one
    `requests.Session` are handled strictly sequentially by construction -
    there is no way for both to reach vw_client_resume() with the same
    single-use token. The first resumes and rotates the token, re-inserting
    a live pool entry; the second must succeed too, but via that ordinary
    live-session path, not a second resume. Both succeeding (rather than
    the second one failing, or the gateway crashing/hanging) is exactly
    what "handled cleanly" means here.

    TASK-168's own stronger version of this check: read the on-disk store
    "back" afterward - not by parsing vw_gateway_remember.c's private
    192-byte record format directly (that's the kind of test-to-
    implementation coupling this project avoids elsewhere - test_vw_
    gateway_remember.c's own unit tests already exercise that layer
    directly), but behaviorally: restart the gateway a SECOND time and
    confirm the SAME cookie still resumes cleanly. That is only possible
    if the race left the store with exactly one coherent, genuinely
    resumable entry for this cookie - a corrupted write, a lost update, or
    two conflicting entries from the earlier race would all show up here
    as this second resume failing (a 401) instead of succeeding.
    """
    binaries.require_gateway()
    server.create_user(unique_username, PASSWORD)

    state_dir = str(tmp_path_factory.mktemp("vw_gw_remember_race"))
    gw = GatewayInstance(binaries, server, state_dir=state_dir)
    gw.start()
    try:
        client = GatewayClient(gw)
        r = client.login(unique_username, PASSWORD, remember=True)
        assert r.status_code == 200 and r.json()["status"] == "ok", r.text

        gw.restart()

        r1 = client.list_files("/")
        r2 = client.list_files("/")
        assert r1.status_code == 200
        assert r2.status_code == 200

        # Second restart: proves the store still holds exactly one valid,
        # resumable entry for this cookie after the race above, not a
        # corrupted or duplicated one.
        gw.restart()
        r3 = client.list_files("/")
        assert r3.status_code == 200

        assert client.logout().status_code == 200
    finally:
        gw.stop()


# ── 4. Regression tests for TASK-144's blocking findings ────────────────────

@pytest.mark.slow
def test_stalled_connection_does_not_permanently_hang_gateway(gateway):
    """
    Regression test for TASK-144 finding #1: a connection that opens and
    sends nothing must eventually be dropped (recv timeout), and MUST NOT
    prevent the gateway from serving other, well-behaved requests forever.
    Takes >30s (the production timeout) by design - marked slow.
    """
    stalled = socket.create_connection((gateway.host, gateway.port), timeout=5)
    try:
        start = time.monotonic()
        # A normal request queued behind the single-threaded accept loop
        # must still eventually complete - this is the actual regression
        # assertion. Give it up to 40s (30s timeout + slack).
        r = requests.post(
            gateway.base_url + "/api/login",
            json={"username": "nonexistent", "password": "x"},
            timeout=40,
        )
        elapsed = time.monotonic() - start
        assert r.status_code == 401
        # Proves it really did queue behind the stall (not suspiciously
        # instant) without hanging forever (bounded by the assert above).
        assert elapsed > 1.0
    finally:
        stalled.close()


def test_invalid_cookie_is_rejected(gateway):
    """
    Functional regression test for TASK-144 finding #2 (cookie comparison
    switched from strcmp to constant-time): confirms the *observable*
    behavior the fix preserves — a well-formed-but-wrong cookie is
    rejected, not just a malformed one. (The timing-safety property
    itself isn't meaningfully assertable in a portable, non-flaky CI
    test; this covers the functional contract the fix must not break.)

    Uses "vw_session_0" (TASK-164's slot-0 cookie name, what a request
    with no X-Vw-Slot header resolves to) rather than the pre-TASK-164
    bare "vw_session" — the latter no longer names any real cookie at
    all post-TASK-164, so setting it would make this a "missing cookie"
    test in disguise, not the "wrong but well-formed cookie" case this
    test is actually meant to cover.
    """
    client = GatewayClient(gateway)
    client.session.cookies.set("vw_session_0", "0" * 64)
    r = client.list_files("/")
    assert r.status_code == 401
    assert r.json()["status"] == "auth_required"


# ── 5. Adversarial HTTP / JSON input ─────────────────────────────────────────

def test_truncated_headers_rejected_cleanly(gateway):
    """A connection that sends a partial header block then closes must not
    crash the gateway - confirmed by making a normal request immediately
    afterward on a fresh connection."""
    s = socket.create_connection((gateway.host, gateway.port), timeout=5)
    s.sendall(b"POST /api/login HTTP/1.1\r\nContent-Type: appl")
    s.close()

    time.sleep(0.2)
    r = requests.post(
        gateway.base_url + "/api/login",
        json={"username": "nonexistent", "password": "x"},
        timeout=10,
    )
    assert r.status_code == 401  # gateway is still alive and correct


def test_oversized_content_length_rejected(gateway):
    """A Content-Length far exceeding VW_HTTP_MAX_BODY_BYTES must be
    rejected without the gateway trying to allocate/read that much."""
    s = socket.create_connection((gateway.host, gateway.port), timeout=5)
    try:
        request = (
            b"POST /api/login HTTP/1.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 999999999\r\n"
            b"\r\n"
        )
        s.sendall(request)
        s.settimeout(5)
        # Gateway should close the connection rather than wait forever for
        # 999999999 bytes that will never arrive.
        data = s.recv(4096)
        # Either a clean HTTP error response or a closed connection (empty
        # read) are both acceptable "rejected cleanly" outcomes; hanging
        # until the socket timeout would fail this test.
    finally:
        s.close()

    # Confirm the gateway process is still alive and serving afterward.
    r = requests.post(
        gateway.base_url + "/api/login",
        json={"username": "nonexistent", "password": "x"},
        timeout=10,
    )
    assert r.status_code == 401


@pytest.mark.parametrize("malformed_body", [
    "not json at all",
    "{",
    '{"username": }',
    '{"username": "a", "password": ' + ("x" * 100) + "",  # truncated
    "[]",
    "null",
    '{"username": 12345, "password": "x"}',  # wrong type
])
def test_malformed_json_rejected_cleanly(gateway, malformed_body):
    r = requests.post(
        gateway.base_url + "/api/login",
        data=malformed_body,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert r.status_code == 400
    assert r.json()["status"] == "bad_request"

    # Gateway must still be responsive after each malformed payload.
    r2 = requests.post(
        gateway.base_url + "/api/login",
        json={"username": "nonexistent", "password": "x"},
        timeout=10,
    )
    assert r2.status_code == 401
