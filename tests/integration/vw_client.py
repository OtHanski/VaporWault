"""
vw_client.py — Python VaporWault wire-protocol client for integration testing.

Implements the full auth handshake and file-operation messages directly over
TLS.  Does NOT shell out to any client binary — this is an independent
reference implementation of the protocol.

Protocol version: 6 (VW_PROTO_VERSION_CURRENT).
All integers are little-endian on the wire.
"""

import hashlib
import socket
import ssl
import struct

# ── Constants ──────────────────────────────────────────────────────────────────

PROTO_VERSION = 6
TOKEN_BYTES   = 32
HASH_BYTES    = 32
CHUNK_SIZE    = 4 * 1024 * 1024   # 4 MiB

# Message types
MSG_HELLO              = 0x0001
MSG_HELLO_OK           = 0x0002
MSG_VERSION_REJECT     = 0x0003
MSG_GOODBYE            = 0x000F
MSG_ERROR              = 0x00FF
MSG_AUTH_REQUEST       = 0x0101
MSG_AUTH_CHALLENGE     = 0x0102
MSG_AUTH_OTP           = 0x0103
MSG_AUTH_OK            = 0x0104
MSG_AUTH_FAIL          = 0x0105
MSG_SESSION_RESUME     = 0x0106
MSG_AUTH_LOGOUT        = 0x0107
MSG_FILE_LIST          = 0x0201
MSG_FILE_LIST_RESP     = 0x0202
MSG_FILE_STAT          = 0x0203
MSG_FILE_STAT_RESP     = 0x0204
MSG_CHUNK_QUERY        = 0x0205
MSG_CHUNK_QUERY_RESP   = 0x0206
MSG_CHUNK_UPLOAD       = 0x0207
MSG_CHUNK_UPLOAD_ACK   = 0x0208
MSG_CHUNK_DOWNLOAD_REQ = 0x0209
MSG_CHUNK_DATA         = 0x020A
MSG_FILE_COMMIT        = 0x020B
MSG_FILE_COMMIT_ACK    = 0x020C
MSG_FILE_DELETE        = 0x020D
MSG_FILE_DELETE_ACK    = 0x020E
MSG_VERSION_LIST       = 0x0301
MSG_VERSION_LIST_RESP  = 0x0302
MSG_VERSION_RESTORE    = 0x0303
MSG_VERSION_RESTORE_ACK = 0x0304
MSG_VERSION_CHUNKS     = 0x0305
MSG_VERSION_CHUNKS_RESP = 0x0306

# Admin message types (AF_UNIX admin socket, same 8-byte frame format)
ADMIN_USER_CREATE_REQ  = 0x9001
ADMIN_USER_CREATE_RESP = 0x9002
ADMIN_USER_LIST_REQ    = 0x9003
ADMIN_USER_LIST_RESP   = 0x9004
ADMIN_SET_QUOTA_REQ    = 0x9005
ADMIN_SET_QUOTA_RESP   = 0x9006
ADMIN_OPLOG_TAIL_REQ   = 0x9007
ADMIN_OPLOG_TAIL_RESP  = 0x9008

# Error codes
VW_OK                  = 0
VW_ERR_AUTH_BAD_CREDS  = 300
VW_ERR_AUTH_LOCKED     = 304


class VwProtocolError(RuntimeError):
    """Server returned MSG_ERROR."""
    def __init__(self, code, msg=""):
        super().__init__(f"server error code={code}: {msg}")
        self.code = code


class VwAuthError(RuntimeError):
    """AUTH_FAIL received during login or session resume."""
    def __init__(self, code, lockout_secs=0):
        super().__init__(f"AUTH_FAIL code={code} lockout_secs={lockout_secs}")
        self.code = code
        self.lockout_secs = lockout_secs


# ── Low-level framing helpers ──────────────────────────────────────────────────

def _recvall(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed before all bytes received")
        buf += chunk
    return bytes(buf)


def _make_frame(msg_type, payload, version=PROTO_VERSION):
    total = 8 + len(payload)
    return struct.pack("<IHH", total, msg_type, version) + payload


def _read_frame(sock):
    hdr = _recvall(sock, 8)
    total, msg_type, _ver = struct.unpack("<IHH", hdr)
    plen = total - 8
    payload = _recvall(sock, plen) if plen > 0 else b""
    return msg_type, payload


def _encode_str(s):
    b = s.encode("utf-8") if isinstance(s, str) else s
    return struct.pack("<H", len(b)) + b


# ── VwClient ──────────────────────────────────────────────────────────────────

class VwClient:
    """
    VaporWault wire-protocol client over TLS.

    Establishes TLS connection and negotiates protocol version in __init__.
    Caller must call close() (or use as context manager) to send GOODBYE.
    """

    def __init__(self, host, port, ca_cert):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=ca_cert)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        raw = socket.create_connection((host, port), timeout=30)
        self._sock = ctx.wrap_socket(raw, server_hostname="localhost")
        self._version = PROTO_VERSION

        # Version negotiation: send HELLO, receive HELLO_OK
        self._send(MSG_HELLO, struct.pack("<H", PROTO_VERSION))
        mt, payload = self._recv()
        if mt == MSG_VERSION_REJECT:
            lo, hi = struct.unpack_from("<HH", payload, 0)
            raise VwProtocolError(0, f"version rejected: server wants {lo}..{hi}")
        if mt != MSG_HELLO_OK:
            raise VwProtocolError(0, f"expected HELLO_OK, got 0x{mt:04X}")
        self._version = struct.unpack_from("<H", payload, 0)[0]

    # ── Internal send/recv ──────────────────────────────────────────────────

    def _send(self, msg_type, payload=b""):
        self._sock.sendall(_make_frame(msg_type, payload, self._version))

    def _recv(self):
        return _read_frame(self._sock)

    def _check_not_error(self, mt, payload):
        if mt == MSG_ERROR:
            code = struct.unpack_from("<I", payload, 0)[0]
            msg_len = struct.unpack_from("<H", payload, 4)[0] if len(payload) >= 6 else 0
            msg = payload[6:6 + msg_len].decode("utf-8", errors="replace")
            raise VwProtocolError(code, msg)

    def _expect(self, expected_type, mt, payload):
        self._check_not_error(mt, payload)
        if mt != expected_type:
            raise VwProtocolError(0, f"expected 0x{expected_type:04X}, got 0x{mt:04X}")

    # ── Auth ────────────────────────────────────────────────────────────────

    def login(self, username, password):
        """
        Authenticate with username + password.

        Returns dict: session_token (bytes[32]), expires_at (int), is_admin (bool),
        quota_bytes (int), used_bytes (int), user_id (int).

        Raises VwAuthError on AUTH_FAIL.
        """
        auth_token = hashlib.sha256(password.encode("utf-8")).digest()
        payload = _encode_str(username) + auth_token
        self._send(MSG_AUTH_REQUEST, payload)
        mt, resp = self._recv()
        if mt == MSG_AUTH_FAIL:
            code = struct.unpack_from("<I", resp, 0)[0] if len(resp) >= 4 else 0
            lockout = struct.unpack_from("<H", resp, 4)[0] if len(resp) >= 6 else 0
            raise VwAuthError(code, lockout)
        self._expect(MSG_AUTH_OK, mt, resp)
        return self._parse_auth_ok(resp)

    def session_resume(self, session_token):
        """
        Resume a session using an existing token. Returns new session info dict.
        The old token is invalidated (single-use invariant).

        Raises VwAuthError on failure.
        """
        self._send(MSG_SESSION_RESUME, bytes(session_token))
        mt, resp = self._recv()
        if mt == MSG_AUTH_FAIL:
            code = struct.unpack_from("<I", resp, 0)[0] if len(resp) >= 4 else 0
            lockout = struct.unpack_from("<H", resp, 4)[0] if len(resp) >= 6 else 0
            raise VwAuthError(code, lockout)
        self._expect(MSG_AUTH_OK, mt, resp)
        return self._parse_auth_ok(resp)

    def _parse_auth_ok(self, resp):
        token      = resp[0:32]
        expires_at = struct.unpack_from("<q", resp, 32)[0]
        is_admin   = bool(resp[40])
        quota_bytes, used_bytes, user_id = struct.unpack_from("<QQQ", resp, 41)
        return {
            "session_token": token,
            "expires_at":    expires_at,
            "is_admin":      is_admin,
            "quota_bytes":   quota_bytes,
            "used_bytes":    used_bytes,
            "user_id":       user_id,
        }

    # ── Chunk operations ────────────────────────────────────────────────────

    def chunk_query(self, session_token, chunk_hashes):
        """
        Ask server which of the given chunk hashes are already stored.

        chunk_hashes: list of bytes[32].
        Returns list of bool (same length), True = server already has it.
        """
        count = len(chunk_hashes)
        payload = bytes(session_token) + struct.pack("<H", count) + b"".join(chunk_hashes)
        self._send(MSG_CHUNK_QUERY, payload)
        mt, resp = self._recv()
        self._expect(MSG_CHUNK_QUERY_RESP, mt, resp)
        bitmask_len = (count + 7) // 8
        bitmask = resp[2:2 + bitmask_len]
        present = []
        for i in range(count):
            byte_idx = i // 8
            # Big-endian within byte: bit 7 = index 0, bit 0 = index 7
            bit_shift = 7 - (i % 8)
            present.append(bool(bitmask[byte_idx] & (1 << bit_shift)))
        return present

    def chunk_upload(self, session_token, data):
        """
        Upload one chunk of data. Computes SHA-256 hash internally.

        Returns chunk_hash (bytes[32]).
        Raises VwProtocolError if server reports error in ACK.
        """
        chunk_hash = hashlib.sha256(data).digest()
        payload = bytes(session_token) + chunk_hash + struct.pack("<I", len(data)) + data
        self._send(MSG_CHUNK_UPLOAD, payload)
        mt, resp = self._recv()
        self._expect(MSG_CHUNK_UPLOAD_ACK, mt, resp)
        error_code = struct.unpack_from("<I", resp, 32)[0]
        if error_code != VW_OK:
            raise VwProtocolError(error_code, "chunk upload rejected")
        return chunk_hash

    def chunk_download(self, session_token, chunk_hash):
        """
        Download one chunk by SHA-256 hash.

        Verifies SHA-256 on receipt. Returns raw bytes.
        """
        payload = bytes(session_token) + bytes(chunk_hash)
        self._send(MSG_CHUNK_DOWNLOAD_REQ, payload)
        mt, resp = self._recv()
        self._check_not_error(mt, resp)
        self._expect(MSG_CHUNK_DATA, mt, resp)
        recv_hash  = resp[0:32]
        chunk_len  = struct.unpack_from("<I", resp, 32)[0]
        data       = resp[36:36 + chunk_len]
        if hashlib.sha256(data).digest() != recv_hash:
            raise VwProtocolError(0, "chunk SHA-256 mismatch on download")
        return data

    # ── File operations ─────────────────────────────────────────────────────

    def file_commit(self, session_token, path, chunk_hashes, file_id=0, logical_size=None):
        """
        Finalise a file upload.

        chunk_hashes: ordered list of bytes[32].
        logical_size: total file size; defaults to sum of chunk sizes if None.
        Returns (file_id, version_id).
        """
        if logical_size is None:
            logical_size = 0
        path_b = path.encode("utf-8")
        payload = (
            bytes(session_token)
            + struct.pack("<QQI", file_id, logical_size, len(chunk_hashes))
            + _encode_str(path_b)
            + b"".join(chunk_hashes)
        )
        self._send(MSG_FILE_COMMIT, payload)
        mt, resp = self._recv()
        self._expect(MSG_FILE_COMMIT_ACK, mt, resp)
        new_file_id, version_id, error_code = struct.unpack_from("<QQI", resp, 0)
        if error_code != VW_OK:
            raise VwProtocolError(error_code, "file commit failed")
        return new_file_id, version_id

    def file_list(self, session_token, path="/", recursive=False, include_deleted=False):
        """
        List directory contents.

        Returns list of dicts: name, file_id, size_bytes, mtime_unix, entry_type, perm.
        """
        path_b = path.encode("utf-8")
        payload = (
            bytes(session_token)
            + struct.pack("<BB", 1 if recursive else 0, 1 if include_deleted else 0)
            + _encode_str(path_b)
        )
        self._send(MSG_FILE_LIST, payload)
        mt, resp = self._recv()
        self._expect(MSG_FILE_LIST_RESP, mt, resp)
        count  = struct.unpack_from("<I", resp, 0)[0]
        offset = 4
        entries = []
        for _ in range(count):
            name_len = struct.unpack_from("<H", resp, offset)[0]
            offset  += 2
            name     = resp[offset:offset + name_len].decode("utf-8")
            offset  += name_len
            file_id, size_bytes = struct.unpack_from("<QQ", resp, offset)
            offset  += 16
            mtime_unix = struct.unpack_from("<q", resp, offset)[0]
            offset  += 8
            entry_type, perm = struct.unpack_from("<BB", resp, offset)
            offset  += 2
            entries.append({
                "name":       name,
                "file_id":    file_id,
                "size_bytes": size_bytes,
                "mtime_unix": mtime_unix,
                "entry_type": entry_type,
                "perm":       perm,
            })
        return entries

    def file_stat(self, session_token, file_id=0, path=None):
        """
        Stat a file or folder.

        Provide file_id OR path. Returns metadata dict.
        """
        path_b = (path or "").encode("utf-8")
        payload = bytes(session_token) + struct.pack("<Q", file_id)
        if file_id == 0:
            payload += _encode_str(path_b)
        self._send(MSG_FILE_STAT, payload)
        mt, resp = self._recv()
        self._check_not_error(mt, resp)
        self._expect(MSG_FILE_STAT_RESP, mt, resp)
        entry_type = resp[0]
        fid, size_bytes = struct.unpack_from("<QQ", resp, 1)
        mtime_unix = struct.unpack_from("<q", resp, 17)[0]
        version_id, owner_id = struct.unpack_from("<QQ", resp, 25)
        perm = resp[41]
        path_len = struct.unpack_from("<H", resp, 42)[0]
        vpath = resp[44:44 + path_len].decode("utf-8")
        return {
            "entry_type":   entry_type,
            "file_id":      fid,
            "size_bytes":   size_bytes,
            "mtime_unix":   mtime_unix,
            "version_id":   version_id,
            "owner_id":     owner_id,
            "perm":         perm,
            "virtual_path": vpath,
        }

    def file_delete(self, session_token, file_id=0, path=None):
        """Delete a file by file_id or path."""
        if file_id == 0 and path is None:
            raise ValueError("file_delete requires file_id or path")
        path_b = (path or "").encode("utf-8")
        payload = bytes(session_token) + struct.pack("<Q", file_id)
        if file_id == 0:
            payload += _encode_str(path_b)
        self._send(MSG_FILE_DELETE, payload)
        mt, resp = self._recv()
        self._expect(MSG_FILE_DELETE_ACK, mt, resp)
        error_code = struct.unpack_from("<I", resp, 0)[0]
        if error_code != VW_OK:
            raise VwProtocolError(error_code, "file delete failed")

    # ── Version history ─────────────────────────────────────────────────────

    def version_chunks(self, session_token, version_id):
        """Return ordered list of chunk hashes (bytes[32]) for a version."""
        payload = bytes(session_token) + struct.pack("<Q", version_id)
        self._send(MSG_VERSION_CHUNKS, payload)
        mt, resp = self._recv()
        self._expect(MSG_VERSION_CHUNKS_RESP, mt, resp)
        count = struct.unpack_from("<I", resp, 0)[0]
        return [resp[4 + i * 32:4 + (i + 1) * 32] for i in range(count)]

    def version_list(self, session_token, file_id, offset=0, limit=0):
        """
        List versions of a file.

        Returns (entries, total) where entries is a list of dicts:
        version_id, created_at, size_bytes, creator_user_id.
        """
        payload = bytes(session_token) + struct.pack("<QII", file_id, offset, limit)
        self._send(MSG_VERSION_LIST, payload)
        mt, resp = self._recv()
        self._expect(MSG_VERSION_LIST_RESP, mt, resp)
        count, total = struct.unpack_from("<II", resp, 0)
        off      = 8
        versions = []
        for _ in range(count):
            version_id, created_at, size_bytes, creator_id = struct.unpack_from("<QqQQ", resp, off)
            off += 32
            versions.append({
                "version_id":      version_id,
                "created_at":      created_at,
                "size_bytes":      size_bytes,
                "creator_user_id": creator_id,
            })
        return versions, total

    def version_restore(self, session_token, version_id, path):
        """
        Restore a specific version of a file.

        Returns the new version_id created by the restore.
        """
        path_b = path.encode("utf-8")
        payload = bytes(session_token) + struct.pack("<Q", version_id) + _encode_str(path_b)
        self._send(MSG_VERSION_RESTORE, payload)
        mt, resp = self._recv()
        self._expect(MSG_VERSION_RESTORE_ACK, mt, resp)
        new_version_id, error_code = struct.unpack_from("<QI", resp, 0)
        if error_code != VW_OK:
            raise VwProtocolError(error_code, "version restore failed")
        return new_version_id

    # ── High-level helpers ──────────────────────────────────────────────────

    def upload_file(self, session_token, path, data):
        """
        Upload data as a file at the given virtual path.

        Splits data into CHUNK_SIZE (4 MiB) chunks, queries the server for
        which chunks are already stored, uploads only missing ones, then
        commits the file.

        Returns (file_id, version_id).
        """
        chunks = [data[i:i + CHUNK_SIZE] for i in range(0, max(len(data), 1), CHUNK_SIZE)]
        chunk_hashes = [hashlib.sha256(c).digest() for c in chunks]

        present = self.chunk_query(session_token, chunk_hashes)
        for chunk, is_present in zip(chunks, present):
            if not is_present:
                self.chunk_upload(session_token, chunk)

        return self.file_commit(session_token, path, chunk_hashes, logical_size=len(data))

    def download_file(self, session_token, version_id):
        """
        Download all chunks for a version and reassemble.

        Returns the complete file bytes.
        """
        hashes = self.version_chunks(session_token, version_id)
        return b"".join(self.chunk_download(session_token, h) for h in hashes)

    # ── Connection lifecycle ─────────────────────────────────────────────────

    def close(self):
        try:
            self._send(MSG_GOODBYE)
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── AdminClient ───────────────────────────────────────────────────────────────

class AdminClient:
    """
    Admin channel client for vapourwaultd.

    Connects to the AF_UNIX admin socket.  Uses the same 8-byte framing as the
    main TLS protocol with admin-specific message types (0x9000-0x9FFF).
    Protocol version field is set to 0 (no version negotiation on admin socket).
    """

    def __init__(self, socket_path):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(15)
        self._sock.connect(socket_path)

    def _send(self, msg_type, payload=b""):
        self._sock.sendall(_make_frame(msg_type, payload, version=0))

    def _recv(self):
        return _read_frame(self._sock)

    def create_user(self, username, password, is_admin=False):
        """
        Create a new user via the admin socket.

        Returns user_id (int).
        Raises RuntimeError if the server returns a non-zero error code.
        """
        uname_b = username.encode("utf-8")
        pw_b    = password.encode("utf-8")
        payload = (
            struct.pack("<B", 1 if is_admin else 0)
            + _encode_str(uname_b)
            + _encode_str(pw_b)
        )
        self._send(ADMIN_USER_CREATE_REQ, payload)
        mt, resp = self._recv()
        if mt != ADMIN_USER_CREATE_RESP:
            raise RuntimeError(f"expected USER_CREATE_RESP (0x9002), got 0x{mt:04X}")
        error_code, user_id = struct.unpack_from("<IQ", resp, 0)
        if error_code != VW_OK:
            raise RuntimeError(f"create_user failed: error_code={error_code}")
        return user_id

    def set_quota(self, username, quota_bytes):
        """
        Set the quota for a user.

        quota_bytes=0 means unlimited. Raises RuntimeError on failure.
        """
        uname_b = username.encode("utf-8")
        payload = _encode_str(uname_b) + struct.pack("<Q", quota_bytes)
        self._send(ADMIN_SET_QUOTA_REQ, payload)
        mt, resp = self._recv()
        if mt != ADMIN_SET_QUOTA_RESP:
            raise RuntimeError(f"expected SET_QUOTA_RESP (0x9006), got 0x{mt:04X}")
        error_code = struct.unpack_from("<I", resp, 0)[0]
        if error_code != VW_OK:
            raise RuntimeError(f"set_quota failed: error_code={error_code}")

    def oplog_tail(self, count=10):
        """
        Return the most recent oplog entries.

        Returns list of dicts: entry_id (int), op_type (int).
        """
        self._send(ADMIN_OPLOG_TAIL_REQ, struct.pack("<I", min(count, 100)))
        mt, resp = self._recv()
        if mt != ADMIN_OPLOG_TAIL_RESP:
            raise RuntimeError(f"expected OPLOG_TAIL_RESP (0x9008), got 0x{mt:04X}")
        n      = struct.unpack_from("<I", resp, 0)[0]
        offset = 4
        entries = []
        for _ in range(n):
            entry_id = struct.unpack_from("<Q", resp, offset)[0]
            op_type  = resp[offset + 8]
            offset  += 16   # u64 entry_id + u8 op_type + u8[7] pad
            entries.append({"entry_id": entry_id, "op_type": op_type})
        return entries

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
