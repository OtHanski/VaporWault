# VaporWault Wire Protocol Specification

**Owner:** PRT.04  
**Current version:** 6  
**Status:** Draft — Phase 2 implementation

---

## 1. Overview

VaporWault uses a custom binary protocol over TLS 1.3. Two ALPN namespaces exist:

| ALPN token      | Usage                          |
|-----------------|--------------------------------|
| `vw/1`          | Client ↔ server connections    |
| `vw-cluster/1`  | Server ↔ server cluster links  |

The protocol is **always encrypted**. There is no plaintext fallback. The TLS session is established first; the VW protocol handshake runs inside TLS.

---

## 2. TLS Requirements

| Parameter       | Requirement                                                        |
|-----------------|--------------------------------------------------------------------|
| Version         | TLS 1.3 **only** (1.0, 1.1, 1.2 are disabled)                    |
| Cipher suites   | `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` only     |
| Cert verify     | Required for production; `VW_CERT_VERIFY_NONE` only for testing   |
| ALPN            | Must be negotiated; connection rejected if ALPN not present        |

---

## 3. Message Framing

Every message is preceded by an 8-byte header:

```
Offset  Size  Type    Field
0       4     u32 LE  total_len   — total byte count of header + payload
4       2     u16 LE  msg_type    — vw_msg_type_t
6       2     u16 LE  proto_version — sender's negotiated version
```

`total_len` includes the 8-byte header. Minimum value: 8 (header only, empty payload).  
Maximum value: 8 388 608 (8 MiB). Messages exceeding `VW_MAX_MSG_BYTES` **must** be rejected; the receiving side must close the connection without reading further.

All integers on the wire are **little-endian** unless specified otherwise.

---

## 4. Scalar Encoding

| Type      | Encoding                              |
|-----------|---------------------------------------|
| `uint8`   | 1 byte                                |
| `uint16`  | 2 bytes LE                            |
| `uint32`  | 4 bytes LE                            |
| `uint64`  | 8 bytes LE                            |
| `int64`   | 8 bytes LE two's complement           |
| `string`  | uint16 byte length + UTF-8 bytes (no null terminator) |
| `bytes`   | Fixed-length raw bytes; length is determined by context |

String maximum lengths:

| Field type  | Max bytes |
|-------------|-----------|
| Username    | 64        |
| Email       | 256       |
| Path        | 4096      |
| Generic     | 65535 (uint16 length field maximum) |

---

## 5. Connection Lifecycle

```
Client                          Server
  │                                │
  │─── TLS ClientHello ──────────► │
  │◄── TLS ServerHello + Finished ─│
  │         (TLS established)      │
  │─── HELLO {max_version=1} ────► │
  │◄── HELLO_OK {version=1} ───────│
  │         (VW session active)    │
  │                                │
  │─── AUTH_REQUEST ─────────────► │
  │◄── AUTH_OK or AUTH_FAIL ───────│
  │                                │
  │   ... application messages ... │
  │                                │
  │─── GOODBYE ──────────────────► │
  │    (TLS close_notify both ways)│
```

---

## 6. Version Negotiation

### 6.1 HELLO (client → server)  `0x0001`

| Field       | Type   | Description                    |
|-------------|--------|--------------------------------|
| max_version | uint16 | Highest protocol version supported by the client |

### 6.2 HELLO_OK (server → client)  `0x0002`

| Field              | Type      | Description                    |
|--------------------|-----------|--------------------------------|
| negotiated_version | uint16    | Version both sides will use    |
| server_id          | bytes[16] | Server UUID (informational)    |

Negotiation rule: the server selects `min(client_max, VW_PROTO_VERSION_CURRENT)`. If that value is less than the server's minimum supported version, a VERSION_REJECT is sent instead.

### 6.3 VERSION_REJECT (server → client)  `0x0003`

| Field       | Type   | Description               |
|-------------|--------|---------------------------|
| min_version | uint16 | Server's minimum version  |
| max_version | uint16 | Server's maximum version  |

After VERSION_REJECT the server closes the connection.

---

## 7. Message Catalogue

### 7.0 Meta / control

| Code   | Name            | Direction | Description              |
|--------|-----------------|-----------|--------------------------|
| 0x0001 | HELLO           | C → S     | Version proposal         |
| 0x0002 | HELLO_OK        | S → C     | Accepted version         |
| 0x0003 | VERSION_REJECT  | S → C     | No common version        |
| 0x000F | GOODBYE         | either    | Graceful disconnect      |
| 0x0010 | KEEPALIVE       | either    | No payload; keep TCP alive |
| 0x00FF | ERROR           | either    | Error response           |

**ERROR payload:**

| Field      | Type   |
|------------|--------|
| error_code | uint32 (vw_err_t) |
| message    | string |

### 7.1 Authentication

| Code   | Name            | Direction | Description              |
|--------|-----------------|-----------|--------------------------|
| 0x0101 | AUTH_REQUEST    | C → S     | Login with credentials   |
| 0x0102 | AUTH_CHALLENGE  | S → C     | 2FA prompt               |
| 0x0103 | AUTH_OTP        | C → S     | OTP response             |
| 0x0104 | AUTH_OK         | S → C     | Session established      |
| 0x0105 | AUTH_FAIL       | S → C     | Rejected                 |
| 0x0106 | SESSION_RESUME         | C → S     | Resume with stored token |
| 0x0107 | AUTH_LOGOUT            | C → S     | Invalidate session       |
| 0x0108 | AUTH_RECOVER_REQUEST   | C → S     | Initiate password recovery |
| 0x0109 | AUTH_RECOVER_CONFIRM   | C → S     | Confirm code + new password |
| 0x010A | AUTH_RECOVER_OK        | S → C     | Recovery successful      |
| 0x010B | AUTH_RECOVER_FAIL      | S → C     | Recovery failed          |

**AUTH_REQUEST payload:**

| Field      | Type      | Notes |
|------------|-----------|-------|
| username   | string    | Max 64 bytes |
| auth_token | bytes[32] | Password hash sent from client (see §8 for derivation) |

**AUTH_CHALLENGE payload:**

| Field          | Type   |
|----------------|--------|
| challenge_type | uint8 (1=EMAIL_OTP, 2=TOTP) |
| hint           | string (e.g. "Code sent to o***@example.com") |

**AUTH_OTP payload:**

| Field    | Type   |
|----------|--------|
| otp_code | string (6 ASCII digits) |

**AUTH_OK payload:**

| Field         | Type      |
|---------------|-----------|
| session_token | bytes[32] |
| expires_at    | int64 (Unix timestamp) |
| is_admin      | uint8 |
| quota_bytes   | uint64 |
| used_bytes    | uint64 |
| user_id       | uint64 |

**AUTH_FAIL payload:**

| Field                   | Type   |
|-------------------------|--------|
| error_code              | uint32 |
| lockout_remaining_secs  | uint16 (0 = not locked; max 65535s) |

**Security invariants:**
- AUTH_FAIL must not disclose whether the username exists or the password was wrong.
- The server always runs Argon2id (with a dummy hash if user not found) to normalise timing.
- Maximum 5 failed OTP attempts per 10-minute window before lockout.
- A session token is single-use for resumption; it is replaced on each successful resume.

**AUTH_RECOVER_REQUEST payload (new in v5):**

| Field | Type        | Notes |
|-------|-------------|-------|
| email | bytes[128]  | NUL-padded fixed-length (timing uniformity — always 128 bytes on the wire) |

The server always responds `AUTH_RECOVER_OK` regardless of whether the email exists
(prevents email enumeration). When the email exists and SMTP is configured, the server
sends a 6-digit one-time code with a 10-minute expiry. Rate-limit: 3 requests per email
per hour; further requests are silently accepted (same `AUTH_RECOVER_OK` response) but
no email is sent.

**AUTH_RECOVER_CONFIRM payload (new in v5):**

| Field              | Type       | Notes |
|--------------------|------------|-------|
| email              | bytes[128] | NUL-padded, identifies which account |
| code               | bytes[8]   | NUL-padded 6-digit ASCII (e.g. `"042718\0\0"`) |
| new_password_token | bytes[32]  | New password credential (same derivation as AUTH_REQUEST.auth_token) |

On success: existing sessions for this user are all invalidated; `AUTH_RECOVER_OK`
is sent. On failure: `AUTH_RECOVER_FAIL` is sent with a generic reason.

**AUTH_RECOVER_OK payload (new in v5):** No payload (empty).

**AUTH_RECOVER_FAIL payload (new in v5):**

| Field  | Type  | Notes |
|--------|-------|-------|
| reason | uint8 | Always 0 (generic failure — invalid code, expired code, and unknown email all use the same value to prevent information leakage) |

**SESSION_RESUME payload:**

| Field         | Type      |
|---------------|-----------|
| session_token | bytes[32] |

### 7.2 File operations

| Code   | Name               | Direction | Description              |
|--------|--------------------|-----------|--------------------------|
| 0x0201 | FILE_LIST          | C → S     | List a directory         |
| 0x0202 | FILE_LIST_RESP     | S → C     | Directory entries        |
| 0x0203 | FILE_STAT          | C → S     | Stat a file/folder       |
| 0x0204 | FILE_STAT_RESP     | S → C     | Metadata                 |
| 0x0205 | CHUNK_QUERY        | C → S     | Which chunks does server have? |
| 0x0206 | CHUNK_QUERY_RESP   | S → C     | Bitmask of present chunks |
| 0x0207 | CHUNK_UPLOAD       | C → S     | Upload one 4MiB chunk    |
| 0x0208 | CHUNK_UPLOAD_ACK   | S → C     | Chunk stored             |
| 0x0209 | CHUNK_DOWNLOAD_REQ | C → S     | Request a chunk          |
| 0x020A | CHUNK_DATA         | S → C     | Chunk bytes              |
| 0x020B | FILE_COMMIT        | C → S     | Finalise file from chunks |
| 0x020C | FILE_COMMIT_ACK    | S → C     | File committed           |
| 0x020D | FILE_DELETE        | C → S     | Delete a file            |
| 0x020E | FILE_DELETE_ACK    | S → C     | Deleted                  |
| 0x020F | FILE_MOVE          | C → S     | Move / rename            |
| 0x0210 | FILE_MOVE_ACK      | S → C     | Moved                    |

**Upload flow:**

```
Client                              Server
  │─── CHUNK_QUERY {hashes[N]} ───► │   "which of these do you already have?"
  │◄── CHUNK_QUERY_RESP {bitmask} ──│
  │─── CHUNK_UPLOAD {hash, data} ──► │   (repeat for each missing chunk)
  │◄── CHUNK_UPLOAD_ACK ────────────│
  │─── FILE_COMMIT {path, hash list}► │   "assemble these chunks into this file"
  │◄── FILE_COMMIT_ACK ─────────────│
```

**CHUNK_QUERY payload:**

| Field         | Type                                                          |
|---------------|---------------------------------------------------------------|
| session_token | bytes[32]                                                     |
| count         | uint16 (max 1024; server rejects larger with PROTO_INVALID)   |
| hashes        | bytes[count × 32] (SHA-256 of each chunk, in chunk order)     |

**CHUNK_QUERY_RESP payload:**

| Field    | Type                                                                             |
|----------|----------------------------------------------------------------------------------|
| count    | uint16 (mirrors request count)                                                   |
| bitmask  | bytes[⌈count/8⌉] — bit i (big-endian within byte) is 1 if chunk i already present |

**CHUNK_UPLOAD payload:**

| Field         | Type                                        |
|---------------|---------------------------------------------|
| session_token | bytes[32]                                   |
| chunk_hash    | bytes[32]                                   |
| chunk_len     | uint32 (actual bytes; ≤ 4 194 304)          |
| data          | bytes[chunk_len]                            |

Server must verify `SHA-256(data) == chunk_hash` and reject with `VW_ERR_CHUNK_HASH_MISMATCH` if not equal.

**FILE_COMMIT payload:**

| Field         | Type                                       |
|---------------|--------------------------------------------|
| session_token | bytes[32]                                  |
| file_id       | uint64 (0 = new file)                      |
| logical_size  | uint64                                     |
| chunk_count   | uint32 (max 65535)                         |
| virtual_path  | string                                     |
| chunk_hashes  | bytes[chunk_count × 32] (ordered)          |

**FILE_COMMIT_ACK payload:**

| Field      | Type              |
|------------|-------------------|
| file_id    | uint64            |
| version_id | uint64            |
| error_code | uint32 (vw_err_t) |

**Download flow:**

```
Client                                Server
  │─── VERSION_CHUNKS {version_id} ──► │   "give me the chunk list for this version"
  │◄── VERSION_CHUNKS_RESP {hashes} ───│
  │─── CHUNK_DOWNLOAD_REQ {hash} ─────► │   (repeat for each needed chunk)
  │◄── CHUNK_DATA {hash, len, data} ───│
```

**CHUNK_DOWNLOAD_REQ payload:**

| Field         | Type      | Notes                                   |
|---------------|-----------|-----------------------------------------|
| session_token | bytes[32] |                                         |
| chunk_hash    | bytes[32] | SHA-256 hash of the requested chunk     |

**CHUNK_DATA payload:**

| Field      | Type               | Notes                               |
|------------|--------------------|-------------------------------------|
| chunk_hash | bytes[32]          | SHA-256 hash of the chunk (echo)    |
| chunk_len  | uint32             | Actual byte count; ≤ 4 194 304      |
| data       | bytes[chunk_len]   | Chunk bytes                         |

The receiver must verify `SHA-256(data) == chunk_hash` and treat a mismatch as a fatal protocol error (close the connection). If the server does not have the requested chunk, it responds with an ERROR message (`VW_ERR_NOT_FOUND`).

### 7.3 Version history

| Code   | Name                 | Direction | Description                              |
|--------|----------------------|-----------|------------------------------------------|
| 0x0301 | VERSION_LIST         | C → S     | List versions of a file                  |
| 0x0302 | VERSION_LIST_RESP    | S → C     | Version entries                          |
| 0x0303 | VERSION_RESTORE      | C → S     | Restore a version                        |
| 0x0304 | VERSION_RESTORE_ACK  | S → C     | Restored                                 |
| 0x0305 | VERSION_CHUNKS       | C → S     | Get ordered chunk hash list for a version |
| 0x0306 | VERSION_CHUNKS_RESP  | S → C     | Chunk hash array                         |

**VERSION_LIST payload:**

| Field         | Type   |
|---------------|--------|
| session_token | bytes[32] |
| file_id       | uint64 |
| offset        | uint32 (pagination start; 0-based) |
| limit         | uint32 (max entries; 0 = server default of 50) |

**VERSION_LIST_RESP payload:**

| Field   | Type   |
|---------|--------|
| count   | uint32 |
| total   | uint32 |
| entries | repeated count times: {version_id:uint64, created_at:int64, size_bytes:uint64, creator_user_id:uint64} |

**VERSION_RESTORE payload:**

| Field         | Type      |
|---------------|-----------|
| session_token | bytes[32] |
| version_id    | uint64    |
| virtual_path  | string    |

**VERSION_RESTORE_ACK payload:**

| Field      | Type              |
|------------|-------------------|
| version_id | uint64 (new version created by restore) |
| error_code | uint32 (vw_err_t) |

**VERSION_CHUNKS payload:**

| Field         | Type      |
|---------------|-----------|
| session_token | bytes[32] |
| version_id    | uint64    |

**VERSION_CHUNKS_RESP payload:**

| Field       | Type                                            |
|-------------|-------------------------------------------------|
| chunk_count | uint32                                          |
| hashes      | bytes[chunk_count × 32] (ordered SHA-256 hashes) |

If `version_id` does not exist or belongs to a file the caller does not own, the server responds with ERROR / `VW_ERR_VERSION_NOT_FOUND`.

### 7.4 Sync

| Code   | Name        | Direction | Description              |
|--------|-------------|-----------|--------------------------|
| 0x0401 | SYNC_STATE  | C → S     | Client's local snapshot  |
| 0x0402 | SYNC_DIFF   | S → C     | Delta ops to apply       |
| 0x0403 | SYNC_ACK    | C → S     | Client applied the diff  |

**SYNC_STATE payload:**

| Field       | Type   |
|-------------|--------|
| entry_count | uint32 |
| entries     | repeated: {file_id:uint64, version_id:uint64, content_hash:bytes[32]} |

The server responds with SYNC_DIFF listing files that differ (new server state, deleted, or modified). Conflict resolution is last-write-wins; the server's version always takes precedence. The losing version is preserved as a version-history entry.

**SYNC_DIFF payload:**

| Field     | Type   | Notes |
|-----------|--------|-------|
| op_count  | uint32 | Number of diff operations |
| ops       | repeated op_count times (see below) | |

Each op record:

| Field         | Type               | Notes                                              |
|---------------|--------------------|----------------------------------------------------|
| op_type       | uint8              | 0x01 = UPSERT (new or modified), 0x02 = DELETE     |
| file_id       | uint64             |                                                    |
| version_id    | uint64             | Latest server version; 0 for DELETE ops            |
| virtual_path  | string             |                                                    |
| chunk_count   | uint32             | 0 for DELETE ops                                   |
| chunk_hashes  | bytes[chunk_count × 32] | Ordered chunk SHA-256 list; absent for DELETE ops |

**SYNC_ACK payload:** No payload.

### 7.5 Sharing / permissions

| Code   | Name             | Direction | Description              |
|--------|------------------|-----------|--------------------------|
| 0x0501 | SHARE_GRANT      | C → S     | Grant access             |
| 0x0502 | SHARE_GRANT_ACK  | S → C     | Granted                  |
| 0x0503 | SHARE_REVOKE     | C → S     | Revoke access            |
| 0x0504 | SHARE_REVOKE_ACK | S → C     | Revoked                  |
| 0x0505 | SHARE_LIST       | C → S     | List sharing entries     |
| 0x0506 | SHARE_LIST_RESP  | S → C     | Sharing entries          |
| 0x0507 | SUB_CREATE       | C → S     | Subscribe to shared path |
| 0x0508 | SUB_CREATE_ACK   | S → C     | Subscribed               |
| 0x0509 | SUB_DELETE       | C → S     | Unsubscribe              |
| 0x050A | SUB_DELETE_ACK   | S → C     | Done                     |

**SHARE_GRANT payload:**

| Field          | Type   |
|----------------|--------|
| is_file        | uint8 (1=file, 0=folder) |
| target_id      | uint64 (file_id or folder path hash) |
| grantee_user_id | uint64 |
| perm           | uint8 (1=VIEW, 2=EDIT) |
| inherit        | uint8 (folder only: propagate to children) |
| path           | string (folder path; empty for files) |

Permission checks on the server must verify both the target item **and** all parent folders. A user can only grant up to their own permission level.

### 7.6 Admin

All messages in `0x06xx` require an admin session (`is_admin == 1` in AUTH_OK).

| Code   | Name               | Direction | Description              |
|--------|--------------------|-----------|--------------------------|
| 0x0601 | USER_CREATE        | C → S     | Create user account      |
| 0x0602 | USER_CREATE_ACK    | S → C     |                          |
| 0x0603 | USER_MODIFY        | C → S     | Change user fields       |
| 0x0604 | USER_MODIFY_ACK    | S → C     |                          |
| 0x0605 | USER_SUSPEND       | C → S     | Suspend/unsuspend        |
| 0x0606 | USER_SUSPEND_ACK   | S → C     |                          |
| 0x0607 | USER_LIST          | C → S     | Paginated user list      |
| 0x0608 | USER_LIST_RESP     | S → C     |                          |
| 0x0609 | INVITE_CREATE      | C → S     | Generate invite token (admin only) |
| 0x060A | INVITE_CREATE_ACK  | S → C     | Code returned                      |
| 0x060B | INVITE_REDEEM      | C → S     | Redeem invite (unauthenticated)    |
| 0x060C | INVITE_REDEEM_ACK  | S → C     | Session established                |
**INVITE_CREATE payload (v5, admin session required):**

| Field       | Type   | Notes |
|-------------|--------|-------|
| quota_bytes | uint64 | Storage quota for the new account; 0 = unlimited |
| ttl_secs    | uint32 | Invite validity period in seconds; 0 = no expiry |

**INVITE_CREATE_ACK payload:**

| Field | Type      | Notes |
|-------|-----------|-------|
| code  | bytes[32] | Base32-encoded 128-bit random invite code (26 ASCII chars, NUL-padded to 32) |

**INVITE_REDEEM payload (unauthenticated — sent before AUTH_REQUEST):**

| Field              | Type      | Notes |
|--------------------|-----------|-------|
| code               | bytes[32] | The code from INVITE_CREATE_ACK |
| username           | string    | Desired username; 1–63 bytes, `[A-Za-z0-9_.-]` |
| password_token     | bytes[32] | Credential (same derivation as AUTH_REQUEST.auth_token) |

On success: the user account is created, the invite is consumed, and the server
responds with INVITE_REDEEM_ACK.  
On failure (unknown code / expired / already used / username taken): `AUTH_FAIL`.

**INVITE_REDEEM_ACK payload:** Same as AUTH_OK (session established immediately).

| 0x060D | QUOTA_ADJUST       | C → S     | Set user quota           |
| 0x060E | QUOTA_ADJUST_ACK   | S → C     |                          |
| 0x060F | AUDIT_QUERY        | C → S     | Query audit log          |
| 0x0610 | AUDIT_RESP         | S → C     | Log entries              |
| 0x0611 | DRIVE_CONFIG       | C → S     | Get/set server config    |
| 0x0612 | DRIVE_CONFIG_RESP  | S → C     |                          |

### 7.7 Cluster (server ↔ server, ALPN `vw-cluster/1`)

| Code   | Name                | Direction       | Description                  |
|--------|---------------------|-----------------|------------------------------|
| 0x0701 | NODE_HELLO          | Replica → Primary | Identify and request sync  |
| 0x0702 | NODE_HELLO_OK       | Primary → Replica |                            |
| 0x0703 | OPLOG_PULL          | Replica → Primary | Request oplog batch        |
| 0x0704 | OPLOG_DATA          | Primary → Replica | Batch of oplog entries     |
| 0x0705 | OPLOG_ACK           | Replica → Primary | Confirm consumed up to N   |
| 0x0706 | CLUSTER_STATUS      | either          | Request node status          |
| 0x0707 | CLUSTER_STATUS_RESP | either          | Status response              |
| 0x07FF | NODE_HELLO_FAIL     | Primary → Replica | Auth rejected; primary closes connection |

**Replication model:** pull-based. The replica connects to the primary, sends NODE_HELLO, and the primary authenticates it. The replica then repeatedly sends OPLOG_PULL with its current watermark; the primary responds with OPLOG_DATA entries. The replica applies them locally and sends OPLOG_ACK. The primary uses the minimum ACK watermark across all active replicas to determine the safe oplog truncation offset.

### 7.8 File Transfer Security Model

#### 7.8.1 Session token requirement

Every C→S message in the file operations (0x02xx) and version history (0x03xx) groups begins with a `session_token[32]` field. The server **must**:

1. Extract `session_token` before doing any other processing.
2. Look up the session in the sessions table.
3. If not found or expired: send `VW_MSG_ERROR` with `VW_ERR_AUTH_REQUIRED` and return. **Do not process the rest of the payload.**
4. Bind the `user_id` from the session record for all subsequent authorization checks.

An authenticated but non-admin user must only access their own files. The server enforces this by comparing the file record's `owner_id` against the session's `user_id` before returning any data on the wire. The session token field is the same 32-byte opaque value from `AUTH_OK.session_token`.

#### 7.8.2 Virtual path validation

The server **must** validate every virtual path before passing it to the storage layer. A path is invalid if any of the following is true:

| Rule | Condition |
|------|-----------|
| No root prefix | Does not begin with `/` |
| Traversal | Contains a `..` path component |
| Null byte | Contains a NUL character (`\0`) |
| Backslash | Contains a `\` character |
| Double slash | Contains `//` (empty component) |
| Too long | Encoded UTF-8 length > 4096 bytes |

Any invalid path returns `VW_ERR_PATH_INVALID`. Path validation is performed by `vw_server_core` before any call into `vw_store` or `vw_storage_files`. The storage layer does not re-validate paths.

Clients should also validate paths locally (before sending) to improve UX, but must not rely on client-side validation for security — the server's check is authoritative.

#### 7.8.3 Chunk authorization

A client may only download chunks that are referenced by at least one version of a file they own (or that is shared with them, Phase 4). The server enforces this in the `CHUNK_DOWNLOAD_REQ` handler by verifying the requesting `user_id` owns a file whose current version references the requested chunk. An unauthorized chunk download returns `VW_ERR_NOT_FOUND` (not `VW_ERR_PERMISSION` — to avoid confirming the chunk's existence).

**NODE_HELLO payload (new in v6):**

| Field          | Type      | Notes |
|----------------|-----------|-------|
| node_id        | uint64    | Unique node identifier assigned at registration |
| auth_token     | bytes[32] | 256-bit pre-shared node secret; verified with constant-time compare |
| sync_watermark | uint64    | Last oplog `entry_id` durably applied by this replica (0 = none) |
| proto_version  | uint16    | Cluster protocol version; must equal negotiated version |
| hostname       | string    | Human-readable label for admin UI (max 127 bytes) |

Security invariants:
- The primary verifies `auth_token` with `vw_crypto_const_eq`. Timing leak on comparison allows online brute-force.
- Unknown `node_id` and wrong `auth_token` both produce `NODE_HELLO_FAIL` with the same `error_code = 0` and within ±1 ms of each other — no enumeration of node IDs via timing.
- A node with `is_active == 0` also receives `NODE_HELLO_FAIL`.
- The primary enforces an IP-based rate limit: 5 failures per 60 s from one source IP causes the connection to be silently dropped (no reply).

**NODE_HELLO_OK payload (new in v6):**

| Field                | Type   | Notes |
|----------------------|--------|-------|
| primary_node_id      | uint64 | Primary's own node_id |
| current_last_entry_id | uint64 | Primary's current oplog tail at the time of handshake |

**NODE_HELLO_FAIL payload (new in v6):**

| Field      | Type   | Notes |
|------------|--------|-------|
| error_code | uint32 | Always 0 (generic — prevents node_id enumeration) |

After NODE_HELLO_FAIL the primary closes the TLS connection.

**OPLOG_PULL payload:**

| Field          | Type   | Notes |
|----------------|--------|-------|
| from_entry_id  | uint64 | Exclusive lower bound; 0 = from the beginning |
| max_entries    | uint32 | Max entries in one OPLOG_DATA response; server may return fewer |

**OPLOG_DATA payload:**

| Field         | Type   | Notes |
|---------------|--------|-------|
| count         | uint32 | Number of oplog entries in this batch; 0 = replica is caught up |
| last_entry_id | uint64 | entry_id of the last entry in this batch (0 if count == 0) |
| entries       | bytes  | Concatenated serialised `vw_oplog_entry_t` records (header + payload each); absent if count == 0 |

If `count == 0` the replica must wait for `replica_poll_interval_secs` (default 5 s) before sending another OPLOG_PULL to avoid busy-looping.

The replica must verify the CRC32 embedded in each `vw_oplog_entry_t` header before applying the entry. A CRC mismatch is treated as a fatal protocol error: the replica logs a WARN, discards the batch, and reconnects from the last ACK'd watermark.

**OPLOG_ACK payload (new in v6):**

| Field              | Type   | Notes |
|--------------------|--------|-------|
| confirmed_entry_id | uint64 | Last oplog entry_id durably applied and fsync'd by this replica |

The primary updates the stored `sync_watermark` for this node in `nodes.db` upon receiving OPLOG_ACK. The GC uses `min(sync_watermark)` across all active replicas as the safe truncation watermark.

**CLUSTER_STATUS payload:** No payload (request only).

**CLUSTER_STATUS_RESP payload (new in v6):**

| Field      | Type   | Notes |
|------------|--------|-------|
| role       | uint8  | 0 = PRIMARY, 1 = REPLICA |
| node_count | uint32 | Number of node entries that follow |
| nodes      | repeated node_count times (see below) | |

Each node entry:

| Field           | Type   | Notes |
|-----------------|--------|-------|
| node_id         | uint64 | |
| is_active       | uint8  | 1 = currently connected and replicating |
| sync_watermark  | uint64 | Last confirmed entry_id from this node |
| lag_entries     | uint64 | primary current_last_entry_id − sync_watermark |
| hostname        | string | Human-readable label (max 127 bytes) |

`auth_token` is **never** included in CLUSTER_STATUS_RESP. Only fields required for the admin UI are present.

---

## 7.9 Cluster Channel Security Model

The `vw-cluster/1` ALPN channel has the same TLS requirements as `vw/1`:
TLS 1.3 only, cipher suites `TLS_AES_256_GCM_SHA384` and
`TLS_CHACHA20_POLY1305_SHA256`, certificate verification required in
production.

Authentication model: the primary presents its TLS server certificate. The
replica authenticates via `NODE_HELLO.auth_token` — a 256-bit random secret
generated at node registration time by `vw_crypto_random`. This is a
pre-shared credential: it is created once by the admin, stored in `nodes.db`
on the primary, and securely communicated to the replica out-of-band
(e.g. copied into the replica's config file at provisioning time).

**Security properties:**

| Property | Implementation |
|----------|----------------|
| Transport confidentiality | TLS 1.3 |
| Primary identity | TLS server cert verification by replica |
| Replica identity | NODE_HELLO auth_token (constant-time compare on primary) |
| Brute-force resistance | 256-bit token space; IP rate-limit (5 failures / 60 s) |
| Enumeration resistance | NODE_HELLO_FAIL is indistinguishable for unknown node_id vs wrong token |
| Integrity of replicated log | CRC32 verified by replica per entry before application |
| Token secrecy | auth_token never logged, never included in any response payload |

**What the cluster channel does NOT protect against:**
- A compromised replica node: once authenticated, a replica can pull the
  entire oplog. Admin-level trust is implied by node registration.
- Primary–replica relationship forgery: there is no mechanism for a replica
  to verify that the primary it connected to is the correct primary (no
  cluster membership certificate). A DNS or ARP spoofing attack could direct
  a replica to a rogue primary. Mitigate with strict IP allowlisting at the
  network layer.

---

## 8. Authentication Design

### 8.1 Password transport

The client does **not** send the raw password. Before sending AUTH_REQUEST, the client:

1. Derives a 32-byte value using Argon2id locally (or, in simple implementations, sends `SHA-256(password)` as the token — see Security Note below).
2. Sends `auth_token[32]` in AUTH_REQUEST.

The server then verifies against its stored Argon2id hash of the password.

> **Security Note (Phase 1 issue TASK-009):** For Phase 0 the wire token is `SHA-256(password)` sent from client. Phase 1 will define a proper SRP or client-side Argon2id derivation so the raw hash is never transmitted.

### 8.2 Session tokens

Session tokens are 32 random bytes generated by `vw_crypto_random`. They are stored server-side in the sessions table with an expiry timestamp. Tokens are single-use for SESSION_RESUME (replaced on each successful resume). The token is never logged.

### 8.3 2FA flow

1. Server sends AUTH_CHALLENGE with `challenge_type` and a hint string.
2. Client presents the OTP code in AUTH_OTP.
3. Server verifies and responds AUTH_OK or AUTH_FAIL.
4. OTP state is invalidated immediately after verification (successful or not) — no reuse window.
5. After 5 consecutive AUTH_OTP failures within 10 minutes the account is locked for 10 minutes. AUTH_FAIL carries `lockout_remaining_secs`.

---

## 9. Chunk Deduplication

- Chunk size: 4 MiB (configurable at build time, `VW_CHUNK_SIZE`).
- Chunk identity: SHA-256 of raw chunk bytes.
- Ref-counted on the server: ref count is incremented **before** FILE_COMMIT is acknowledged.
- GC frees chunks only when `ref_count == 0`.
- CHUNK_QUERY lets the client discover which chunks are already present, enabling both delta sync and resumable uploads.

---

## 10. Error Handling

All application-level errors are reported with an `ERROR` message (`0x00FF`). The `error_code` field carries a `vw_err_t` value. The connection remains open after an ERROR response unless the error is fatal (connection/TLS/protocol errors close the connection).

### 10.1 Normative `vw_err_t` enumeration

| Code | Name                        | Category       | Description                                  |
|------|-----------------------------|----------------|----------------------------------------------|
| 0    | `VW_OK`                     | —              | Success (never appears in an ERROR message)  |
| 1    | `VW_ERR_IO`                 | General        | I/O failure (disk, socket)                   |
| 2    | `VW_ERR_OOM`                | General        | Out of memory                                |
| 3    | `VW_ERR_INVALID_ARG`        | General        | Caller supplied a bad argument or field      |
| 4    | `VW_ERR_TIMEOUT`            | General        | Operation timed out                          |
| 5    | `VW_ERR_NOT_FOUND`          | General        | Requested resource does not exist            |
| 6    | `VW_ERR_ALREADY_EXISTS`     | General        | Resource already exists                      |
| 7    | `VW_ERR_PERMISSION`         | General        | Caller lacks required permission             |
| 8    | `VW_ERR_QUOTA_EXCEEDED`     | General        | User storage quota exceeded                  |
| 9    | `VW_ERR_NOT_IMPL`           | General        | Feature not implemented in this build        |
| 100  | `VW_ERR_NET_CONNECT`        | Network        | TCP connection failed                        |
| 101  | `VW_ERR_NET_TLS`            | Network        | TLS handshake or certificate error           |
| 102  | `VW_ERR_NET_CLOSED`         | Network        | Connection closed by remote peer             |
| 103  | `VW_ERR_NET_TIMEOUT`        | Network        | Network operation timed out                  |
| 200  | `VW_ERR_PROTO_INVALID`      | Protocol       | Malformed or unexpected message              |
| 201  | `VW_ERR_PROTO_VERSION`      | Protocol       | No mutually supported protocol version       |
| 202  | `VW_ERR_PROTO_TOO_LARGE`    | Protocol       | Message exceeds `VW_MAX_MSG_BYTES` (8 MiB)  |
| 203  | `VW_ERR_PROTO_TRUNCATED`    | Protocol       | Message ends before all fields were read     |
| 300  | `VW_ERR_AUTH_BAD_CREDS`     | Auth           | Invalid username or password                 |
| 301  | `VW_ERR_AUTH_2FA_REQUIRED`  | Auth           | 2FA challenge must be completed              |
| 302  | `VW_ERR_AUTH_2FA_INVALID`   | Auth           | OTP code incorrect or expired                |
| 303  | `VW_ERR_AUTH_SESSION_EXPIRED` | Auth         | Session token has expired; re-authenticate   |
| 304  | `VW_ERR_AUTH_LOCKED`         | Auth           | Account locked due to repeated failures      |
| 305  | `VW_ERR_AUTH_2FA_LOCKED`     | Auth           | 2FA locked due to repeated OTP failures      |
| 306  | `VW_ERR_AUTH_REQUIRED`       | Auth           | File op sent without a valid session token   |
| 400  | `VW_ERR_STORE_CORRUPT`       | Storage        | Data store integrity check failed            |
| 401  | `VW_ERR_STORE_FULL`          | Storage        | Server storage capacity exhausted            |
| 500  | `VW_ERR_CRYPTO`              | Crypto         | Cryptographic operation failed               |
| 600  | `VW_ERR_CHUNK_HASH_MISMATCH` | File transfer  | Uploaded chunk SHA-256 does not match declared hash |
| 601  | `VW_ERR_PATH_INVALID`        | File transfer  | Virtual path fails validation rules (see §7.8.2) |
| 602  | `VW_ERR_PATH_CONFLICT`       | File transfer  | File/directory type collision at path        |
| 603  | `VW_ERR_VERSION_NOT_FOUND`   | File transfer  | Version ID absent or belongs to another file |
| 604  | `VW_ERR_DIR_NOT_EMPTY`       | File transfer  | Directory delete: non-empty directory        |

**Wire encoding:** `error_code` is transmitted as a `uint32` (LE). Unknown codes must be treated as fatal errors by the receiver; the connection should be closed.

---

## 11. Version History

| Version | Date       | Author  | Changes                    |
|---------|------------|---------|----------------------------|
| 6       | 2026-07-13 | PRT.04  | Phase 7 cluster: full payload specs for `NODE_HELLO` (0x0701), `NODE_HELLO_OK` (0x0702), `NODE_HELLO_FAIL` (0x07FF, new), `OPLOG_PULL` (0x0703), `OPLOG_DATA` (0x0704), `OPLOG_ACK` (0x0705, new), `CLUSTER_STATUS_RESP` (0x0707, new); §7.9 cluster channel security model added; resolves TASK-047 |
| 5       | 2026-07-12 | PRT.04  | Phase 6 invite + recovery: `AUTH_RECOVER_REQUEST` (0x0108), `AUTH_RECOVER_CONFIRM` (0x0109), `AUTH_RECOVER_OK` (0x010A), `AUTH_RECOVER_FAIL` (0x010B) added; `INVITE_CREATE`/`_ACK`/`INVITE_REDEEM`/`_ACK` (0x0609–0x060C) payload specs published; resolves TASK-044 |
| 4       | 2026-07-11 | PRT.04  | Phase 2 file transfer spec: `session_token[32]` added to all C→S file op payloads; `CHUNK_QUERY` count widened from uint32 to uint16 (max 1024); `VERSION_CHUNKS` / `VERSION_CHUNKS_RESP` (0x0305/0x0306) added; §7.8 File Transfer Security Model added; error codes 305–306 and 600–604 added; resolves TASK-021 |
| 3       | 2026-07-10 | PRT.04  | AUTH_OK: `user_id` (uint64 LE) appended after `used_bytes`; resolves TASK-020 / CQR.08-B-2 |
| 2       | 2026-07-06 | PRT.04  | AUTH_FAIL: `lockout_remaining_secs` widened from u8 to u16; 10-minute (600s) OTP lockout window exceeds u8 max (255s) |
| 1       | 2026-06-23 | PRT.04  | Initial specification      |
