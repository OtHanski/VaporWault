# VaporWault Wire Protocol Specification

**Owner:** PRT.04  
**Wire protocol version (`VW_PROTO_VERSION_CURRENT`, `src/core/vw_proto.h`):** 6 — the value actually negotiated in the `HELLO`/`HELLO_OK` handshake. Bumped only for changes that break an *existing* message's byte layout for a client that doesn't know about the change; last bumped for Phase 7 cluster support (§11 revision 6, `TASK-047`).  
**Document revision (§11 Version History, below):** 29 — increments for every change recorded in this document, whether or not it required a wire version bump. Most revisions since 6 (new message types, purely-additive trailing fields) explicitly did **not** require one — see each entry's own "no protocol version bump required" note — which is why this number has kept climbing while the wire version above has stayed at 6 since Phase 7.  
*(2026-08-05, `TASK-118`: the two numbers above used to be conflated under one "Current version" field reading "10" — a number that matched neither of them. Split into two clearly-labeled fields instead of picking one, since both are real and both matter for different audiences: implementers checking wire compatibility need the first; anyone reading this doc's edit history needs the second. Proposed by ARCH.00, reviewed and confirmed accurate by PRT.04 per `CLAUDE.md`'s document-ownership rule.)*  
**Status:** Living document — hardening phase (see `ARCHITECTURE.md` Phase 8). §7.5/§7.10 (sharing) and §7.11 (vault/E2EE) are both fully implemented, client through GUI, as of `TASK-097`/`TASK-101` — see `ARCHITECTURE.md` Phases 4 and 9.

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

**AUTH_LOGOUT payload (documented `TASK-237` — behavior was implicit/unimplemented
before):** No payload (empty). Fire-and-forget: the client sends it and closes the
connection without waiting for a response; the server sends none.

The server revokes the session token this connection authenticated with (from the
AUTH_OK/SESSION_RESUME that started this connection, not a token in the message
itself — there is none) via the same revocation path AUTH_RECOVER_CONFIRM and
SESSION_RESUME's own token-rotation already use. Once revoked, that token is
rejected by any subsequent request on *any* connection, not just this one — a
stolen token cannot outlive an explicit logout the way it previously could when
this message went unhandled. As with every other rejection of a bad/expired/
revoked token, the wire-visible code does not distinguish *why* the token was
rejected (matching the anti-oracle invariant above): a further SESSION_RESUME
attempt with the revoked token gets `AUTH_FAIL`/`VW_ERR_AUTH_BAD_CREDS` like any
other resume failure, and a revoked token used mid-session on a still-open
connection gets `ERROR`/`VW_ERR_AUTH_REQUIRED` like any other rejected token —
neither ever surfaces a distinct "this token was explicitly revoked" code.

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
| 0x0211 | FILE_MKDIR         | C → S     | Create a directory       |
| 0x0212 | FILE_MKDIR_ACK     | S → C     | Created                  |

**FILE_LIST payload:**

| Field          | Type                                                        |
|----------------|--------------------------------------------------------------|
| session_token  | bytes[32]                                                    |
| recursive      | uint8 (1 = walk subdirectories)                               |
| include_deleted | uint8 (reserved; always treated as 0)                        |
| virtual_path   | string (directory to list; empty/"/" = root)                 |
| dir_file_id    | uint64 (TASK-106, optional trailing field; 0/absent = use `virtual_path` as today) |

`dir_file_id`, when present and nonzero, lists a folder the caller doesn't
own but has at least VIEW access to (a share grant), resolved via the same
permission helper `FILE_COMMIT`'s directory-target branch uses —
`virtual_path` is ignored in that case. This exists because path-based
listing is namespaced by the caller's own owner_id and can never resolve
into someone else's tree; before this, the only way to navigate a shared
subtree was the unauthenticated scoped-link case (`LINK_ACCESS`), which
uses its own fixed scope target rather than a caller-supplied id. Rejected
(`VW_ERR_PATH_INVALID`) for an already-scoped session, which has no
legitimate use for it. No protocol version bump: old clients never send
this field, and reading it is gated on the payload actually being long
enough to contain it.

**FILE_LIST_RESP payload:**

| Field  | Type                                                                  |
|--------|-----------------------------------------------------------------------|
| count  | uint32                                                                 |
| —      | `count *` { string `name`, uint64 `file_id`, uint64 `size_bytes`, int64 `mtime_unix`, uint8 `entry_type`, uint8 `perm` } |
| —      | `count *` uint64 `version_id` (TASK-109, trailing; 0 for a directory) |
| —      | `count *` uint64 `vault_id` (TASK-156, trailing, after `version_id`; 0 = unencrypted or a directory) |

`version_id` is `current_version_id` — the exact same field `FILE_STAT_RESP`
reports — appended as a **trailing, parallel array** after all `count`
fixed-size entries, not interleaved into each entry's own byte range. This
matters: `TASK-109` was originally filed because `FILE_LIST_RESP` shipped
(`TASK-021`) with no `version_id` at all, silently breaking the sync
engine's ongoing remote-change detection (`vw_sync.c`'s `compute_actions`
compared it against a value that was always 0 on both sides — see
`TASK-109`). Fixing a *repeated* structure's per-entry layout looked
at first like it would need an entry-length wrapper (so an old client could
skip unknown per-entry trailing bytes) and therefore a protocol version
bump — but a trailing parallel array avoids that: an old client's decode
loop reads exactly `count` fixed-size entries via its own hardcoded byte
counts and simply stops, never touching bytes after them; a new client
checks the payload is long enough for the trailing array before reading it.
No protocol version bump required, same as every other extension in this
document.

**FILE_STAT payload:**

| Field         | Type                                                        |
|---------------|-------------------------------------------------------------|
| session_token | bytes[32]                                                    |
| file_id       | uint64 (0 = resolve by `virtual_path` instead)               |
| virtual_path  | string (only meaningful when `file_id` is 0)                 |

**FILE_STAT_RESP payload:**

| Field       | Type                                          |
|-------------|------------------------------------------------|
| entry_type  | uint8 (`VW_ENTRY_FILE`=0, `VW_ENTRY_DIR`=1)     |
| file_id     | uint64                                          |
| size_bytes  | uint64                                          |
| mtime_unix  | int64                                           |
| version_id  | uint64 (current HEAD; 0 for a directory)        |
| owner_id    | uint64                                          |
| perm        | uint8 (`vw_perm_t`; caller's effective permission) |
| name        | string (leaf name)                              |
| vault_id    | uint64 (TASK-100; 0 = unencrypted, or `entry_type == VW_ENTRY_DIR`) |

`vault_id` is the file's *current version's* vault, added so a browser can
show an encrypted-item indicator from a single `FILE_STAT` rather than an
extra `VERSION_CHUNKS` round-trip. Unlike `FILE_COMMIT`/`VERSION_CHUNKS_RESP`'s
absent-when-zero convention, this field is always present — there are no
further optional fields after it to disambiguate, so appending it
unconditionally is simpler with no behavioral difference (an old client
stops reading after `name` regardless). `FILE_LIST_RESP` **also** carries
`vault_id` per entry, as of `TASK-156` (revision 19) — see that section's
trailing-array row above, and revision 19's own entry below for why
revision 14's original "listing doesn't populate this" call was revisited.

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

**FILE_MOVE payload (TASK-094 — 0x020F/0x0210 existed as reserved opcodes
with no payload or handler defined before this; defined here):**

| Field             | Type                                          |
|-------------------|------------------------------------------------|
| session_token     | bytes[32]                                      |
| file_id           | uint64 (the file or folder to move)            |
| new_parent_dir_id | uint64 (0 = mover's own root)                  |
| new_name          | string (empty = keep the current name)         |

Supports move-only, rename-only, or both in one call. See §7.5's
"FILE_MOVE ownership and cycle rules" for the permission/ownership/cycle
checks applied before the move is performed.

**FILE_MOVE_ACK payload:** `error_code` (uint32).

**FILE_MKDIR payload (TASK-104 — 0x0211/0x0212, first-ever definition; no
prior reserved meaning to preserve):**

| Field             | Type                                          |
|-------------------|------------------------------------------------|
| session_token     | bytes[32]                                      |
| new_parent_dir_id | uint64 (0 = caller's own root)                 |
| name              | string (bare leaf name — no `/`, 1–63 bytes)   |

Creates exactly one new directory record under `new_parent_dir_id`. This is
`mkdir`, not `mkdir -p` — deliberately does not auto-create missing
intermediate ancestors, matching this protocol's existing preference for
explicit single-record operations over implicit multi-record side effects
(e.g. `FILE_MOVE` never silently creates its destination either). A client
that needs a nested path created must issue one `FILE_MKDIR` per path
component, checking each `FILE_MKDIR_ACK` before issuing the next.

Permission rule: same as `FILE_COMMIT`'s "creating a new file under a
shared folder" case (§7.5) — `VW_PERM_EDIT` is required on
`new_parent_dir_id` (or, for `new_parent_dir_id == 0`, the caller must be
an authenticated user creating in their own root; an anonymous scoped
session can never target `0`, since it has no root of its own, matching
§7.5's existing scoped-session root-navigation restriction). The new
directory's `owner_id` is the parent's `owner_id` (or the caller's own
`user_id` for a root-level create) — same quota/ownership-resolution rule
as every other content-creation message. Also subject to the same
per-scoped-session write-count rate limit as `FILE_COMMIT`/`CHUNK_UPLOAD`/
`FILE_DELETE`/`FILE_MOVE` (§7.5) — unbounded directory creation is the same
small-object abuse shape that limit already bounds.

**FILE_MKDIR_ACK payload:** `file_id` (uint64, the new directory's id; 0 on
failure), `error_code` (uint32). `VW_ERR_ALREADY_EXISTS` if a sibling with
the same name already exists under that parent.

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

**Shared-file addressing (`TASK-214`, corrected from `TASK-182`'s own
assumption)**: `VERSION_LIST` already takes `file_id` directly (never a
path) and its handler already calls `effective_permission()` requiring
`VW_PERM_VIEW` — checked by reading `handle_version_list` in full, not
assumed — so it has always worked correctly for a shared file, for any
caller that has the right `file_id` in hand. `VERSION_RESTORE` similarly
resolves `version_id → file_id` and requires `VW_PERM_EDIT` via
`effective_permission()`, **never** using its own `virtual_path` field
for resolution or authorization at all — that field is read and
shape-validated but otherwise unused by the handler. `TASK-182`'s own
filing of this gap (repeated in `TASK-214`'s original text) claimed the
server resolves `VERSION_RESTORE` by path "the same [owner-namespaced]
way" `FILE_STAT` does; that turned out to be incorrect once the actual
handler was read line by line — corrected here rather than silently
carried forward into a design built on it.

The **real** gap, once the above was actually verified: `virtual_path`
is a *mandatory*, shape-validated (`vw_path_validate` — rejects
zero-length) field on the wire even though the server never uses its
contents — and `vw_client_version_list`/`vw_client_version_restore`
(`src/client/vw_client_core.c`) only ever obtain a `file_id`/`version_id`
by resolving a path via `FILE_STAT` first, which is owner-namespaced and
so never succeeds for a grantee. Every actual blocker is **client-side**;
the wire protocol needed exactly one small loosening, documented below,
to make a `file_id`-only round trip possible at all — no new fields, no
version bump.

**`VERSION_RESTORE`'s `virtual_path` may now be an empty string**
(`path_len == 0`) to mean "no meaningful path — addressing by
`version_id`/`file_id` alone," e.g. a grantee restoring a version of a
file shared with them, which has no path in their own namespace. The
server skips `vw_path_validate` entirely in this case (todo before this
revision: always ran validation, rejecting a zero-length string with
`VW_ERR_PATH_INVALID` before ever reaching the permission check) and
proceeds exactly as it already did for the `version_id`/`effective_permission()`
resolution — nothing else about the handler's behavior changes. A caller
that does supply a real path continues to get it shape-validated exactly
as before (`VW_ERR_PATH_INVALID` on a malformed one) — **byte-for-byte
unchanged for a caller that doesn't opt into this**, since a non-empty
path always used to be required and still works identically. This is a
purely permissive server-side relaxation (accepting a previously-always-
rejected zero-length string), not a new field, so no protocol version
bump is required.

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

| Field         | Type      | Notes |
|---------------|-----------|-------|
| session_token | bytes[32] | |
| version_id    | uint64    | |
| virtual_path  | string    | Not used for resolution or authorization — the server resolves entirely from `version_id`'s own `file_id`. Shape-validated (`vw_path_validate`) when non-empty; **may be an empty string** (`TASK-214`) to mean "no meaningful path," e.g. addressing a shared item by `file_id`/`version_id` alone — see this section's own note above. |

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

| Field        | Type                                              |
|--------------|---------------------------------------------------|
| chunk_count  | uint32                                            |
| hashes       | bytes[chunk_count × 32] (ordered SHA-256 hashes)  |
| vault_id     | uint64 (TASK-099; **absent** if the version is unencrypted) |
| wrapped_dek  | string (only present if `vault_id` is present and nonzero) |

`vault_id`/`wrapped_dek` are optional trailing fields, added by TASK-099 to
close the gap flagged in §7.11.4: a downloading client needs its version's
wrapped DEK to decrypt the chunks it is about to fetch. Old clients never
read past `hashes` and are unaffected; old servers never emit the trailing
fields, so an old server's response is indistinguishable from an
unencrypted version's response — this is safe because unencrypted versions
were the only kind an old server could ever produce. Hashes in `hashes` are
always of the bytes actually stored (ciphertext for an encrypted version,
plaintext otherwise) — the server content-addresses whatever it is given
and never distinguishes the two.

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

**Design status (2026-07-29):** fully specified below per `TASK-088`.
**Implementation status (2026-07-30):** the server side (`vw_share` module,
permission-check integration in `vw_file_handlers.c`, all messages below)
is implemented — `TASK-094`. Client (`TASK-095`) and GUI (`TASK-096`)
support, and the joint integration test suite (`TASK-097`), are still
pending. One implementation note not in the original design: `FILE_MOVE`
(0x020F/0x0210) had never had a payload defined or a handler implemented
before `TASK-094` — see its entry below for the wire format, defined as
part of this task since the sharing rules explicitly govern it. This
replaces the earlier unimplemented skeleton, which
had only `SHARE_GRANT`'s payload defined and a speculative, never-built
`SUB_CREATE`/`SUB_DELETE` "subscription" concept. That concept is dropped —
nothing in the settled requirements needs it, and a client can always tell
whether an item is shared-with-it via `SHARE_LIST`/`FILE_LIST` without a
separate subscribe step. `SUB_CREATE`/`SUB_CREATE_ACK`/`SUB_DELETE`/
`SUB_DELETE_ACK`'s opcodes (0x0507–0x050A) are **repurposed** below for
`LINK_CREATE`/`LINK_CREATE_ACK`/`LINK_REVOKE`/`LINK_REVOKE_ACK` — safe to
reuse because no code anywhere ever implemented a handler for the old names
(confirmed by source inspection during `TASK-088`'s design phase); the
`VW_MSG_SUB_*` enumerators in `vw_proto.h` must be renamed to
`VW_MSG_LINK_CREATE`/`VW_MSG_LINK_REVOKE` (same numeric values) as part of
`TASK-094`.

Two independent sharing mechanisms are supported, per the product
requirement that both be available:

1. **User-to-user grants** (`SHARE_GRANT`/`SHARE_REVOKE`/`SHARE_LIST`) — an
   authenticated user grants another authenticated user access to a file or
   folder they own.
2. **Public links** (`LINK_CREATE`/`LINK_REVOKE`/`LINK_LIST`/`LINK_ACCESS`) —
   an owner mints an unguessable token; anyone possessing it gets scoped,
   anonymous (no account needed) read or edit access to that one item and
   its descendants, mirroring the existing `INVITE_REDEEM` pattern of an
   unauthenticated pre-`AUTH_REQUEST` message producing a session (§7.6).

Both a file and a folder can be the target of either mechanism — folders are
identified by `file_id` the same way files are (this codebase already
represents directories as rows in the same file table,
`vw_file_record_t.entry_type == VW_ENTRY_DIR`; there is no separate ID
namespace to reconcile).

**Reconciling with the existing `vw_perm_t` enum (CQR.08 finding, fixed
2026-07-29):** `vw_proto.h` already defines `vw_perm_t` (`VW_PERM_NONE=0,
VW_PERM_VIEW=1, VW_PERM_EDIT=2, VW_PERM_OWNER=3`), and it is already on the
wire today — `FILE_LIST_RESP`/`FILE_STAT_RESP` each carry a per-entry `perm`
byte, currently hardcoded to `VW_PERM_OWNER` in `vw_file_handlers.c` since no
sharing exists yet. The `permission` field everywhere below in §7.5 **reuses
`vw_perm_t` directly** — `VW_PERM_VIEW` (1) and `VW_PERM_EDIT` (2); a share
or link is never created with `VW_PERM_NONE` or `VW_PERM_OWNER`, only VIEW or
EDIT. `TASK-094` must also stop hardcoding `VW_PERM_OWNER` in
`FILE_LIST_RESP`/`FILE_STAT_RESP` and instead populate that field from the
caller's actually-resolved effective permission (own → `VW_PERM_OWNER`;
via grant/scope → whatever permission the grant/scope carries) — this is
also what `TASK-096`'s file-browser permission indicator reads from, so it
must reflect reality rather than always claiming ownership.

| Code   | Name              | Direction | Description                             |
|--------|-------------------|-----------|------------------------------------------|
| 0x0501 | SHARE_GRANT       | C → S     | Grant a user access to a file/folder     |
| 0x0502 | SHARE_GRANT_ACK   | S → C     | Granted                                  |
| 0x0503 | SHARE_REVOKE      | C → S     | Revoke a user-to-user grant              |
| 0x0504 | SHARE_REVOKE_ACK  | S → C     | Revoked                                  |
| 0x0505 | SHARE_LIST        | C → S     | List grants (created by me / to me)      |
| 0x0506 | SHARE_LIST_RESP   | S → C     | Grant entries                            |
| 0x0507 | LINK_CREATE       | C → S     | Mint a public link for a file/folder     |
| 0x0508 | LINK_CREATE_ACK   | S → C     | Link created; token returned once        |
| 0x0509 | LINK_REVOKE       | C → S     | Revoke a public link                     |
| 0x050A | LINK_REVOKE_ACK   | S → C     | Revoked                                  |
| 0x050B | LINK_LIST         | C → S     | List public links I've created           |
| 0x050C | LINK_LIST_RESP    | S → C     | Link entries (no raw tokens included)    |
| 0x050D | LINK_ACCESS       | C → S     | Redeem a public link (**unauthenticated**, sent before AUTH_REQUEST) |
| 0x050E | LINK_ACCESS_ACK   | S → C     | Scoped session established               |

**Server-side data model (`vw_share_record_t`, new `vw_share` module, 128
bytes/slot — matches this codebase's fixed-size-record convention):**

| Field            | Type      | Notes |
|------------------|-----------|-------|
| share_id         | uint64    | Monotonic; 0 = free slot |
| file_id          | uint64    | The shared file or folder |
| owner_id         | uint64    | Copied from the file's `owner_id` at grant time — the authority for the "can only grant up to your own permission level" rule below, and for quota resolution |
| target_user_id   | uint64    | User-to-user grants only; 0 for public links |
| link_token       | bytes[32] | Public links only; 256-bit CSPRNG (`vw_crypto_random`, same generator as cluster `auth_token`/session tokens). Zero for user grants. |
| link_password_hash | bytes[32] | Public links only (`TASK-186`/187`). Argon2id output; all-zero = no password (this codebase's established convention for "reserved bytes, zero = not set," e.g. `vw_store.h`'s `vault_id`/`deleted_at`). **The Argon2id salt is not stored** — it is derived on demand as `HMAC-SHA256(key=link_token, "vw-link-pw-salt")[0:16]`, since `link_token` is already a unique, unpredictable 256-bit value per link; this fits the field into the share record's existing reserved-byte budget with no on-disk format/size change (see the "why no stored salt" note below) |
| has_link_password | uint8    | Public links only; explicit flag rather than relying solely on the all-zero-hash sentinel, so a (cryptographically inconceivable but not worth reasoning about at 2 a.m.) genuine all-zero Argon2id output is never misread as "no password" |
| share_type       | uint8     | 0 = user grant, 1 = public link |
| permission       | uint8     | `vw_perm_t`: `VW_PERM_VIEW` (1, = list/stat/download) or `VW_PERM_EDIT` (2, = VIEW + create/modify/delete). Never `VW_PERM_NONE`/`VW_PERM_OWNER`. |
| revoked          | uint8     | 1 = revoked. Rows are never hard-deleted — kept for audit trail, matching this project's soft-delete convention elsewhere (`TASK-090`) |
| created_at       | int64     | |
| expires_at       | int64     | 0 = never expires |

Two in-memory indexes are rebuilt on startup by scanning, matching every
other table in this codebase: `file_id → [share_id...]` (permission checks)
and `link_token → share_id` (O(1) `LINK_ACCESS` redemption, avoiding a linear
scan over every link on every anonymous request).

**Why the link password's Argon2id salt is derived, not stored
(`TASK-186`, added 2026-08-26):** `vw_share_record_t` is a fixed 128-byte
record with exactly 40 bytes of `_reserved` headroom, by design, so that
fields like this can be added without changing the on-disk record size —
growing the record would silently corrupt every existing `shares.dat`
written before the change (`nslots = file_len / sizeof(record)` would
compute the wrong slot count and misalign every read). A full
Argon2id hash (32 bytes) plus a real salt (`VW_ARGON2_SALT_BYTES` = 16)
would need 48 of those 40 bytes — doesn't fit. Rather than shrink the
salt (which would need a second, bespoke Argon2id API distinct from the
one real account passwords use) or grow the record (which would need a
migration), the salt is derived on demand from data already in the
record: `HMAC-SHA256(key=link_token, "vw-link-pw-salt")[0:16]`.
`link_token` is already a unique, unpredictable 256-bit CSPRNG value
per link, so it satisfies a salt's actual requirements (uniqueness,
unpredictability — a salt has never needed to be *secret*; it sits
right next to the hash in every conventional password-storage scheme).
The HMAC step, not raw truncation of `link_token` itself, keeps the
bearer-capability value and the KDF input cryptographically distinct
constructions even though they're derived from the same underlying
secret, for review hygiene. `vw_crypto_argon2id_hash`/`_verify` are used
completely unmodified — no new hashing/comparison code, only a
salt-derivation step ahead of the existing calls.

**SHARE_GRANT payload:**

| Field          | Type   | Notes |
|----------------|--------|-------|
| session_token  | bytes[32] | |
| file_id        | uint64 | File or folder to share |
| target_username | string | Server resolves to `user_id` internally — avoids a separate username-lookup round trip, consistent with how admin CLI commands already take usernames directly |
| permission     | uint8  | `vw_perm_t`: `VW_PERM_VIEW` (1) or `VW_PERM_EDIT` (2) |
| expires_at     | int64  | 0 = never |

**SHARE_GRANT_ACK payload:** `error_code` (uint32), `share_id` (uint64).

**SHARE_REVOKE payload:** `session_token[32]`, `share_id` (uint64). Only the
`owner_id` of the underlying share may revoke it.

**SHARE_LIST payload:** `session_token[32]`, `mode` (uint8: 0 = shares I
created, 1 = shares granted to me).

**SHARE_LIST_RESP payload:** `count` (uint32), then `count` repetitions of
`{share_id, file_id, name, share_type, target_username-or-empty, permission,
created_at, expires_at, revoked}`. `name` is the shared item's own leaf name
(`vw_file_record_t.name`), not a full path — implementation note added
2026-07-30 (`TASK-094`): path lookups in this codebase are namespaced by
`owner_id` (see `vw_store_file_get_by_path`), so a full path wouldn't be
resolvable in a non-owner viewer's own namespace anyway; this field is
display-only.

**LINK_CREATE payload:** `session_token[32]`, `file_id` (uint64), `permission`
(uint8), `expires_at` (int64, 0 = never), `password` (string, optional
trailing field — `TASK-186`, empty or absent = no password; additive,
no version bump, same precedent as `FILE_LIST`'s `dir_file_id`
extension, `TASK-106`). Sent over the already-authenticated, already-TLS
connection — not client-side hashed the way `AUTH_REQUEST`'s real
account password is (§8.1): a link password isn't a user credential and
doesn't need that zero-knowledge treatment. The server hashes it
(Argon2id, derived salt — see the share-record note above) and never
stores or logs the plaintext.

**LINK_CREATE_ACK payload:** `error_code` (uint32), `share_id` (uint64),
`link_token[32]`. The raw token is returned **exactly once**, at creation —
the server never re-displays it (same convention as `INVITE_CREATE_ACK`'s
invite code and the cluster `auth_token`). If the owner loses the token they
must revoke and re-create the link.

**LINK_REVOKE payload:** `session_token[32]`, `share_id` (uint64).

**LINK_LIST payload:** `session_token[32]`, `file_id` (uint64, 0 = all of my
links).

**LINK_LIST_RESP payload:** `count` (uint32), then `count` repetitions of
`{share_id, file_id, name, permission, created_at, expires_at, revoked,
has_password}` — **never** the raw `link_token`, and never the password
or its hash (same "never re-disclose a secret token" rule as
CLUSTER_STATUS_RESP omitting `auth_token`, §7.9). `has_password`
(uint8, trailing field, `TASK-186`) lets the owner's own UI show which
of their links are password-protected. `name` is the same display-only
leaf name as `SHARE_LIST_RESP` (see its note above).

**LINK_ACCESS payload (unauthenticated — sent before AUTH_REQUEST):**

| Field      | Type      | Notes |
|------------|-----------|-------|
| link_token | bytes[32] | The token from `LINK_CREATE_ACK` |
| password   | string    | Optional trailing field (`TASK-186`) — length-prefixed, empty or absent if the caller has none to offer. The server's existing strict `plen != 32` payload-length check becomes `plen < 32`, so a caller sending exactly 32 bytes (no password) behaves byte-for-byte as before. |

On success: same shape and semantics as `INVITE_REDEEM_ACK` — the server
establishes a session immediately. Except this session is **scoped** (see
§7.10) rather than a normal user session: `user_id = 0` (anonymous),
`is_admin = 0`, and the session is bound to exactly the one `share_id` that
was redeemed. On failure (unknown / expired / revoked token): `AUTH_FAIL`
with the same generic error code used for bad credentials — a client must
not be able to distinguish "token never existed" from "token was revoked"
(enumeration resistance, same rationale as `NODE_HELLO_FAIL`, §7.9).

**Password check ordering (`TASK-186`/`187`):** the token lookup
(unknown/expired/revoked, all collapsed to the same generic failure
above) happens first, exactly as before this feature existed — a caller
gets no distinguishable signal about whether a password would have
mattered for a token that's already dead. Only once a *live* token is
found does the server check `has_link_password`: unset → proceed exactly
as before (any submitted password is ignored, even if the caller sent
one). Set and no password submitted → `VW_ERR_LINK_PASSWORD_REQUIRED`.
Set and wrong password → `VW_ERR_LINK_PASSWORD_WRONG`. Both are new,
distinguishable codes (§10.1) — unlike the token-validity checks, this
step does not need to hide "protected" vs "not protected" from the
caller, since knowing a link needs a password is not itself a
meaningful enumeration primitive (the caller already possesses the
token, which is the actual secret; the password is a second factor on
top of it, not instead of it). Every `LINK_ACCESS` outcome — including a
wrong-password rejection — still runs through the existing per-IP
`vw_share_link_access_is_blocked`/`_record_failure` rate limiter
(5 failures/60s, unchanged); no second lockout mechanism was added.

**LINK_ACCESS_ACK payload:** Same as `AUTH_OK`, with `user_id = 0` and
`is_admin = 0` signaling an anonymous scoped session; `quota_bytes`/
`used_bytes` are zeroed (not meaningful for an anonymous caller — quota is
always resolved against the file's real owner server-side, never the
session's nominal user, see below).

**Permission-check rule (extends the existing owner-only check in
`vw_file_handlers.c`, §7.8.1):** for every file operation, access is granted
if **any** of the following holds, checked in this order:

1. `file.owner_id == session.user_id` (existing check, unchanged).
2. An active (`revoked == 0`, not expired) `SHARE_GRANT` exists whose
   `target_user_id == session.user_id` and whose `file_id` is `file_id`
   itself **or an ancestor of it** (walk `parent_dir_id` up to the root,
   checking each ancestor for a grant — matches the pre-existing skeleton
   note "must verify both the target item and all parent folders"), with
   `permission >= permission_needed_for_this_op`.
3. The session is a scoped public-link session (`session.scope_file_id !=
   0`) whose `scope_file_id` is `file_id` itself or an ancestor of it, and
   `session.scope_permission >= permission_needed_for_this_op`.
4. Otherwise: `VW_ERR_PERMISSION`.

A user can only grant (`SHARE_GRANT`) or link (`LINK_CREATE`) up to their
**own effective permission level** on the target — e.g. a user who only has
`VW_PERM_VIEW` access via someone else's grant cannot `SHARE_GRANT`
`VW_PERM_EDIT` to a third party. The server must compute the granter's own
effective permission via this same rule before allowing `SHARE_GRANT`/
`LINK_CREATE` to proceed on a file the caller does not own outright.

**Required permission per operation (CQR.08 finding, added 2026-07-29 — the
rule above referenced `permission_needed_for_this_op` without defining it):**

| Operation | Required permission | Notes |
|-----------|---------------------|-------|
| `FILE_LIST`, `FILE_STAT`, `CHUNK_DOWNLOAD_REQ`, `VERSION_LIST`, `VERSION_CHUNKS`, `SEARCH` | `VW_PERM_VIEW` | Read-only ops. `SEARCH` (`TASK-196`/`197`) additionally requires a non-scoped session — see §7.12 |
| `CHUNK_UPLOAD`, `FILE_COMMIT` (modifying an existing file) | `VW_PERM_EDIT` on the file | |
| `FILE_COMMIT` (creating a new file under a shared folder) | `VW_PERM_EDIT` on the **parent folder** | The new file's `owner_id` is set to the **folder's** `owner_id` (matches the quota-resolution rule below) — the creator does not become the owner of a file it creates inside someone else's shared folder |
| `FILE_DELETE` | `VW_PERM_EDIT` on the file | Public/grant EDIT includes delete, matching common product conventions (Dropbox/Drive-style "editor" access) |
| `FILE_MOVE` | `VW_PERM_EDIT` on **both** the source file's current parent and the destination parent folder, **and** `destination_parent.owner_id == file.owner_id` | See "FILE_MOVE ownership and cycle rules" below (SEC.07 finding, 2026-07-29) |
| `VERSION_RESTORE` | `VW_PERM_EDIT` on the file | Restoring content is a modification, not a read, even though it doesn't create a new version's bytes from scratch |
| `SHARE_GRANT`, `LINK_CREATE` | Caller's own effective permission must be `>=` the permission being granted (see above) | |
| `SHARE_REVOKE`, `LINK_REVOKE` | Caller must be the `owner_id` of the share/link row itself (not merely have EDIT on the file) | Only the person who created the grant/link — i.e. the file's owner at grant time — can revoke it; an EDIT grantee cannot revoke another grantee's access |

**FILE_MOVE ownership and cycle rules (SEC.07 finding, added 2026-07-29):**
the naive rule "EDIT on source parent + EDIT on destination parent" has a
quota/visibility-hijack gap: a grantee with EDIT on Alice's shared folder
could move one of Alice's files into their own private folder. The file's
`owner_id` would stay Alice (so it still counts against her quota forever)
while its `parent_dir_id` chain no longer passes through anything Alice can
see — she silently loses all access to her own file. To close this:

1. `FILE_MOVE` requires `VW_PERM_EDIT` on both the source item's current
   parent and the destination parent, **and** requires
   `destination_parent.owner_id == file.owner_id`. A grantee may reorganize
   a file anywhere within the *same owner's* tree they have EDIT access to,
   but can never move a file (or folder) into a tree with a different
   `owner_id` — this applies symmetrically to the owner's own moves too
   (trivially satisfied, since `destination_parent.owner_id` is always their
   own `owner_id` for anything they own).
2. `FILE_MOVE` of a directory must reject any destination that is the
   directory itself or a descendant of it (walk the destination's
   `parent_dir_id` chain up to the root; if the moving directory's `file_id`
   appears anywhere in that chain, reject with `VW_ERR_INVALID_ARG`). This
   is a general correctness requirement independent of sharing — the
   walk-up permission check (§7.5 point 2) assumes an acyclic
   `parent_dir_id` tree, and an undetected cycle would hang or misevaluate
   every permission check for the affected subtree. `TASK-094` must
   implement this check even though it isn't strictly a sharing-specific
   bug, since it was discovered while specifying `FILE_MOVE`'s interaction
   with shares.

**Grant/link operations require a real authenticated session (SEC.07
finding, added 2026-07-29):** `SHARE_GRANT`, `SHARE_REVOKE`, `LINK_CREATE`,
and `LINK_REVOKE` all additionally require `session.user_id != 0` — an
anonymous scoped session (one established via `LINK_ACCESS`) may never call
any of these four messages, full stop, regardless of what
`scope_permission` it carries. Without this restriction, anyone holding a
leaked/forwarded EDIT public link could redeem it and then mint an
independent, persistent `SHARE_GRANT` or a brand-new `LINK_CREATE` — a
separate `share_id` from the one that leaked — which would survive
revocation of the original leaked link, defeating the live-revocation
property (§7.10) in precisely the scenario it exists to solve. The server
must reject any of these four messages carrying a scoped session with
`VW_ERR_PERMISSION`, checked before any other logic in the handler.

**Write-count rate limiting for scoped sessions (SEC.07 finding, added
2026-07-29):** quota resolution (below) bounds the *bytes* a scoped session
can cause to be written against the owner's quota, but bounds nothing about
the *count* of files/versions/oplog entries created — an anonymous holder
of a public EDIT link could `FILE_COMMIT` unbounded numbers of near-zero-
byte files, each consuming a storage slot and an oplog entry (replicated to
every cluster node), which is a genuinely new unauthenticated write-DoS
surface with no admin-suspend lever available (the actor has no account to
suspend). The server must apply a per-scoped-session rate limit on
write operations (`FILE_COMMIT`, `CHUNK_UPLOAD`, `FILE_DELETE`, `FILE_MOVE`)
distinct from and in addition to the byte-quota check — concrete threshold
(e.g. N writes per minute per scoped session, or a hard cap on total files
created per share/link) is left to `TASK-094` to set, but the requirement
that *some* count-based limit exists is not optional.

**Scoped-session navigation (CQR.08 finding, added 2026-07-29):** an
anonymous scoped session (redeemed via `LINK_ACCESS`) has no access to the
global root. `FILE_LIST` with `parent_dir_id == 0` for a scoped session is
special-cased: it returns exactly the single scoped item (`scope_file_id`)
if it is a file, or the immediate children of `scope_file_id` if it is a
folder — never the server's actual root. All subsequent `FILE_LIST` calls
with a non-zero `parent_dir_id` go through the normal permission-check rule
(§7.5 point 3), which already confines them to `scope_file_id` and its
descendants.

**Quota resolution:** storage always counts against the file's actual
`owner_id`, **never** the acting session's `user_id` — this is true whether
the acting session belongs to a different authenticated user via a
user-to-user EDIT grant, or an anonymous scoped public-edit-link session.
Every quota-check call site in the upload/commit path must resolve the quota
owner from `file.owner_id` (or, for a brand-new file being created under a
shared folder, from the **folder's** `owner_id`), not from the session.
This directly implements the settled requirement "files should count against
the owner's quota" and is also what bounds the abuse potential of a public
edit link — the owner's existing quota is the only cap, by design.

### 7.6 Admin

All messages in `0x06xx` require an admin session (`is_admin == 1` in AUTH_OK).

**Fine-grained capability requirements (added 2026-07-29, TASK-092 — CQR.08
finding: this section previously described only the blanket `is_admin`
gate, which stopped being the whole story once capability bits shipped):**
six of the admin-authenticated messages additionally require a specific
`vw_admin_cap_t` bit (`vw_proto.h`) on the caller's account, checked via
`vw_admin_has_cap()` (`vw_store.h`) after the base `is_admin` check. An
authenticated admin who lacks the required capability for a given message
receives `VW_ERR_PERMISSION` — distinct from `VW_ERR_AUTH_REQUIRED`, which
is still what a genuinely non-admin session gets.

| Message                          | Required capability   |
|-----------------------------------|------------------------|
| `USER_LIST` (0x0607)               | `VW_CAP_USER_MGMT`    |
| `USER_SUSPEND` (0x0605)            | `VW_CAP_USER_MGMT`    |
| `INVITE_CREATE` (0x0609)           | `VW_CAP_USER_MGMT`    |
| `QUOTA_ADJUST` (0x060D)            | `VW_CAP_QUOTA_MGMT`   |
| `AUDIT_QUERY` (0x060F)             | `VW_CAP_AUDIT_READ`   |
| `CLUSTER_STATUS` (0x0706, §7.7)    | `VW_CAP_CLUSTER_MGMT` |

`admin_caps == 0` on an admin account is treated as "full/legacy admin" (all
capabilities) rather than "no capabilities" — see `vw_admin_cap_t`'s comment
in `vw_proto.h` for why. `USER_CREATE`, `USER_MODIFY`, and `DRIVE_CONFIG`
are not yet implemented in `vw_file_handlers.c` (they fall through to
`VW_ERR_NOT_IMPL`), so they have no capability requirement to document yet;
whichever developer implements them should add one at that time.

This capability layer applies only to these network wire-protocol admin
messages (authenticated via `AUTH_OK`/`is_admin` over `vw/1`, exactly the
messages in this section and CLUSTER_STATUS in §7.7). It does **not** apply
to the separate local admin IPC channel (`vw_admin.c`, AF_UNIX
`admin.sock`, used by `vapourwault-server-cli`) — that channel is not part
of this document (see its own header comment in `vw_admin.h`) and remains
gated purely by OS-level trust (`SO_PEERCRED`, same UID as the server
operator), which a per-account capability bitmask could not meaningfully
narrow further. That local channel does gain one new message
(`VW_ADMIN_SET_CAPS_REQ`/`_RESP`) for the trusted operator to grant/revoke
these capabilities on other admin accounts — documented in `vw_admin.h`,
not here.

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

**AUDIT_QUERY payload:** `session_token[32]` + `max_entries(uint32)` (0 or > 256 clamps to 100; returns at most the last 256 confirmed entries).

**AUDIT_RESP payload:** `count(uint32)` + raw oplog entry bytes concatenated, `count` entries total. Entry byte layout (`crc32`/`payload_len`/`entry_id`/`ts_unix_secs`/`confirmed`/`op_type`/`op_payload`) is specified once in §7.7's "Oplog entry format" — the wire bytes here are exactly the on-disk entry bytes, `confirmed` forced to 1.

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

**Oplog entry format (v17 — breaking change, `TASK-121`/`TASK-122`):**

On-disk entries under `<data_dir>/oplog/*.log` (`vw_oplog.h`) and the `entries` bytes of `OPLOG_DATA` above and `AUDIT_RESP` (§7.6) are the same byte layout — all little-endian, packed, no padding:

| Offset | Size | Field       | Notes |
|--------|------|-------------|-------|
| 0      | 4    | crc32       | Covers `payload_len + entry_id + ts_unix_secs + op_type + op_payload`; `confirmed` is excluded (see below) |
| 4      | 4    | payload_len | = 1 (`op_type`) + caller payload length |
| 8      | 8    | entry_id    | Monotonic sequence number; remains the sole authority for replication ordering, dedup, and watermarks |
| 16     | 8    | ts_unix_secs | Wall-clock append time, **seconds** since Unix epoch (not milliseconds — see the implementation note below the table). Stamped **once**, by `vw_oplog_append()` on the node where the entry originates (always the primary in a cluster). `vw_oplog_append_raw()` (replica applying a primary-sent entry) does **not** re-stamp it — it copies the received entry bytes through as-is (only the `confirmed` byte is overwritten), so `ts_unix_secs` is part of the CRC-covered payload the replica already verifies before applying. This keeps a given `entry_id`'s timestamp identical on every node and avoids re-deriving a value that would silently invalidate the received CRC if changed post-verification. **Advisory only** — never consulted for ordering, dedup, GC cutoff, or any replication decision, so clock skew or adjustment across cluster nodes cannot affect correctness. Exists solely so `AUDIT_RESP` consumers (the admin audit log, `TASK-116`) can filter/sort by date/time. |
| 24     | 1    | confirmed   | NOT crc-covered — updated in place by `vw_oplog_confirm()`. Unchanged from the pre-v17 format. |
| 25     | 1    | op_type     | One of `vw_oplog_op_t` |
| 26     | N    | op_payload  | op-specific bytes, `N = payload_len - 1` |

Total entry size = `25 + payload_len` bytes (was `17 + payload_len` before this version — `ts_unix_secs` adds 8 header bytes).

*Implementation note (SRV.01, `TASK-123`):* the field was designed above as `ts_unix_ms` (milliseconds) but shipped as `ts_unix_secs` (seconds), same 8-byte width. The codebase has no precedent anywhere for a millisecond-precision clock — every existing timestamp (`mtime_unix`, session expiry, invite TTL) uses `time_t`/seconds via `time(NULL)` — and this field's only consumer (a date/time-range filter in the audit log UI) doesn't need sub-second resolution, so a new cross-platform ms-clock helper would have been unjustified complexity. Purely a naming/precision correction: offset, width, and every other property described above are unchanged.

**`op_type` changes (`TASK-122`):** `VW_OPLOG_FILE_WRITE` (0x02) is retired. Its bare 8-byte `uint64` payload was ambiguous — meaning `owner_id` on the create path but `file_id` on the rename/update and version-write paths in `vw_store_files.c`, with nothing in the entry to tell a reader which. Replaced by three explicit codes, same 8-byte `uint64` payload shape:

| Code | Name                     | Payload    | Call site (`vw_store_files.c`)      |
|------|--------------------------|------------|--------------------------------------|
| 0x08 | `VW_OPLOG_FILE_CREATE`   | `owner_id` | create path                          |
| 0x09 | `VW_OPLOG_FILE_UPDATE`   | `file_id`  | rename/update path                   |
| 0x0A | `VW_OPLOG_FILE_VERSION` | `file_id`  | version-write path                   |

`0x02` is retired, not reassigned — do not reuse it for a future op type. An entry bearing it (only reachable from before the upgrade cutover below) is still unresolvable and must be handled exactly as today: no subject attribution.

**Upgrade / compatibility note:** the oplog is not durable history — GC (`vw_oplog_truncate_before`, invoked once every active replica's ack watermark has passed a given entry) already reclaims segments once no longer needed. There is no version/magic field in the pre-v17 header letting a reader distinguish an old 17-byte-header entry from a new 25-byte-header one of the same nominal `payload_len`, so the two cannot coexist in one segment. This is therefore a **hard cutover, not an in-place migration**. Per node, in order:

1. Confirm the node is caught up (`lag_entries == 0` via `CLUSTER_STATUS_RESP`) or is the primary.
2. Stop the node.
3. Clear `<data_dir>/oplog/` (crash-recovery/replication state only; no other data is affected).
4. Start the node on the new binary.

A cluster must never run mixed pre-v17/post-v17 nodes against shared oplog segments; single-node deployments only need steps 2–4 applied locally. No rolling-upgrade path is provided, consistent with this project's other pre-1.0 breaking on-disk format changes. Step 2 ("stop the node") is safe with respect to in-flight appends: `vw_server_main.c`'s shutdown path drains all worker threads (`pool_shutdown_and_join`) before closing the oplog, and every `vw_oplog_append()` call site confirms or aborts its entry synchronously within the same handler call — so a fully-drained clean stop never leaves a `confirmed=0` entry behind for the wipe to lose.

**Implementation note — three independent call sites parse this header, not one:** besides `vw_oplog.c` itself (the only place that should own the layout), both `src/gui/server/views/vw_view_audit.cpp` (`OPLOG_ENTRY_HDR = 17u`, parsing `AUDIT_RESP`) and `src/server/vw_cluster.c` (the replica's `OPLOG_DATA`-batch-splitting loop, `entry_total = 17u + entry_plen` around its `vw_oplog_append_raw()` call) each hardcode their own private copy of the pre-v17 17-byte header size to find entry boundaries in a concatenated buffer. All three must move to the new 25-byte size together, or replication/audit parsing silently misaligns (the replica loop in particular would under-read each entry by 8 bytes and desync the next one — a correctness bug in the exact path this format change is tagged `security-sensitive` for). To prevent this class of divergent-copy bug recurring, `vw_oplog.h` should expose the header-size constant publicly (e.g. `VW_OPLOG_ENTRY_HDR_BYTES`) for both external call sites to use instead of redefining it privately. Tracked in `TASK-123`.

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

**Hot-standby data replication (`TASK-169`/`170`, replaces "replica has an
oplog backup only"):** the flow above (`OPLOG_PULL`/`_DATA`/`_ACK`) gives a
replica an oplog *copy*, not a queryable copy of the primary's actual
data — every `vw_oplog_op_t` payload is a bare id (e.g.
`VW_OPLOG_FILE_CREATE`'s payload is `owner_id` alone, written before
`file_id` is even assigned — see `vw_store_files.c`), never the full
record, so a reader cannot reconstruct *what* changed from the entry
alone. The eight messages below give a replica genuine, independently
queryable data by syncing the small fixed-record metadata files
wholesale (triggered by oplog activity as a doorbell, never read for
their content) plus the actual chunk bytes those files reference
(content-addressed, incrementally, by hash).

| Code   | Name                     | Direction         | Description                       |
|--------|--------------------------|--------------------|------------------------------------|
| 0x0708 | CLUSTER_FILE_SYNC_LIST      | Replica → Primary | List syncable metadata files + hashes |
| 0x0709 | CLUSTER_FILE_SYNC_LIST_RESP | Primary → Replica | Per-file size + content hash        |
| 0x070A | CLUSTER_FILE_SYNC_FETCH     | Replica → Primary | Request one file's full content     |
| 0x070B | CLUSTER_FILE_SYNC_DATA      | Primary → Replica | That file's full current bytes      |
| 0x070C | CLUSTER_CHUNK_QUERY         | Replica → Primary | Which of these chunk hashes exist   |
| 0x070D | CLUSTER_CHUNK_QUERY_RESP    | Primary → Replica | Bitmask (same shape as `CHUNK_QUERY_RESP`, §7.2) |
| 0x070E | CLUSTER_CHUNK_FETCH         | Replica → Primary | Request one chunk's bytes           |
| 0x070F | CLUSTER_CHUNK_DATA          | Primary → Replica | Chunk bytes (same shape as `CHUNK_DATA`, §7.2) |

**Syncable metadata files** (`vw_cluster_file_tag_t`, one byte, a fixed
enum — deliberately never a free-form path string, which would otherwise
be a new path-traversal surface to review even though the replica is
already admin-trusted per §7.9's existing trust model):

| Tag | File | Holds |
|-----|------|-------|
| 1 | `store/users.dat` | User records (incl. password hash, 2FA secret) |
| 2 | `store/quotas.db` | Per-user quota/usage |
| 3 | `files/meta.dat` | File/directory records |
| 4 | `files/versions.dat` | Version records (chunk_count, blob_offset, vault_id, wrapped-DEK offset/len) |
| 5 | `files/versions.blob` | Chunk hash arrays + wrapped DEK bytes referenced by `versions.dat`'s `blob_offset` |
| 6 | `shares.db` | User-to-user share grants |
| 7 | `vaults.db` | Vault registry records |
| 8 | `vaults.blob` | Vault registry blob storage (wrapped VKs, KDF params) |
| 9 | `store/notify_prefs.db` | Per-user notification-preference bitmasks (TASK-207/220) |

`files/versions.dat` and `files/versions.blob` are always synced as a
pair — `versions.dat`'s `blob_offset` field is only meaningful relative
to a `versions.blob` fetched at the same time, so the replica must apply
both together (fetch tag 4, then tag 5, before running the chunk sweep
below) rather than treating a mid-pair failure as "partially applied."

**Deliberately never synced this way:**
- `store/sessions.dat` — per-server; a client failing over to a replica
  does a fresh `AUTH_REQUEST`/`vw_client_connect`, never
  `vw_client_resume` (a primary-issued resume token is meaningless on a
  different server).
- `chunks/refcounts.db` — the replica computes its OWN refcounts from the
  file/vault records it holds after each sync pass; it never copies the
  primary's raw refcounts, which are transiently different during any
  catch-up window and would be wrong to overwrite with anyway.
- `invites.db`, `recovery.db` — not needed for this feature's read-only
  surface (`FILE_LIST`/`FILE_STAT`/`CHUNK_DOWNLOAD_REQ`/`SHARE_LIST`/
  `VERSION_LIST`/`VERSION_CHUNKS`/vault list+key-fetch); invite redemption
  and password recovery are writes anyway, which stay primary-only
  regardless of whether a client is currently failed over.

**CLUSTER_FILE_SYNC_LIST payload:** none (request only; scoped to the
already-authenticated connection).

**CLUSTER_FILE_SYNC_LIST_RESP payload:**

| Field       | Type   | Notes |
|-------------|--------|-------|
| file_count  | uint8  | Always 8 today (one per row in the table above); a future addition to the syncable set only ever grows this, both ends ship together so no negotiation needed |
| files       | repeated file_count times (see below) | |

Each file entry:

| Field          | Type      | Notes |
|----------------|-----------|-------|
| file_tag       | uint8     | See table above |
| size           | uint64    | Current size in bytes on the primary |
| content_sha256 | bytes[32] | SHA-256 of the file's full current content |

**CLUSTER_FILE_SYNC_FETCH payload:** `file_tag` (uint8).

**CLUSTER_FILE_SYNC_DATA payload:**

| Field    | Type      | Notes |
|----------|-----------|-------|
| file_tag | uint8     | Echoes the request |
| size     | uint64    | Byte count that follows |
| data     | bytes[size] | The file's entire current content |

The replica replaces its own copy of that file atomically (write-temp,
rename-over — the same crash-safe primitive `vw_fs_atomic_write` already
provides for other metadata writes in this codebase), then re-opens/
re-indexes whichever server module owns that file from the new content —
it never patches that module's live in-memory state field-by-field to
match. If the primary's copy was deleted or renamed since
`CLUSTER_FILE_SYNC_LIST_RESP` was sent (a narrow race — these files are
never deleted in normal operation, only rewritten), the primary responds
with an ERROR (`VW_ERR_NOT_FOUND`) instead; the replica retries the whole
`CLUSTER_FILE_SYNC_LIST` pass on its next sync trigger rather than
treating this as fatal.

**CLUSTER_CHUNK_QUERY / CLUSTER_CHUNK_QUERY_RESP payload:** byte-identical
to `CHUNK_QUERY`/`CHUNK_QUERY_RESP` (§7.2) — `session_token` is replaced
by nothing (this connection is already authenticated by `NODE_HELLO`'s
`auth_token`, not a session token), everything else (`count`, `hashes`,
response `bitmask`) is unchanged. Sent by the replica after refreshing
`versions.dat` (tag 4) + `versions.blob` (tag 5), scanning its new content for every referenced chunk
hash, in batches of up to 1024 per the existing `CHUNK_QUERY` cap.

**CLUSTER_CHUNK_FETCH / CLUSTER_CHUNK_DATA payload:** byte-identical to
`CHUNK_DOWNLOAD_REQ`/`CHUNK_DATA` (§7.2) minus the `session_token` field,
same reasoning as above. The replica writes each fetched chunk into its
own content-addressed store (`{chunks_dir}/{2-hex}/{64-hex}.chunk`, same
layout the primary uses) and sets its own local refcount from its own
now-current `versions.dat`/`versions.blob` content — never from any value the primary sends.

**Sync trigger and ordering:** after appending a pulled `OPLOG_DATA` batch
to its own oplog (unchanged — the oplog entries themselves are never read
for content by this mechanism, only used as a "something changed, go
check" signal), if `count > 0` the replica runs one
`CLUSTER_FILE_SYNC_LIST` pass, fetches whatever changed, then the chunk
sweep above if either `versions.dat` or `versions.blob` was among the changed files. The replica must
NOT advance/persist its oplog watermark or send `OPLOG_ACK` until this
entire sync pass (files, then any needed chunks) has completed
successfully — a crash mid-sync simply re-detects the same file(s) as
changed (hash mismatch against last-known) and redoes the fetch on
reconnect; idempotent by construction, matching this protocol's existing
preference (`FILE_COMMIT`, chunk dedup) for idempotent-by-content over
bespoke resume logic.

**GC interaction (`TASK-171`):** the primary's chunk garbage collection is
gated on `vw_cluster_min_sync_watermark()` — the same primitive that
already protects oplog segments from premature truncation now also
protects chunk content from being deleted out from under a replica that
hasn't caught up to the oplog position that existed when the current GC
cycle started.

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
| Integrity of synced files/chunks (`TASK-170`) | `CLUSTER_FILE_SYNC_DATA` has no separate checksum on the wire beyond TLS's own integrity guarantee — the replica trusts `CLUSTER_FILE_SYNC_LIST_RESP`'s `content_sha256` was for the bytes it then receives, both over the same authenticated TLS stream; `CLUSTER_CHUNK_DATA` bytes are additionally verified against the requested hash before being written (same rule as `CHUNK_DATA`, §7.2/7.8.3) |
| Handler reachability (`TASK-170`) | `CLUSTER_FILE_SYNC_*`/`CLUSTER_CHUNK_*` (§7.7) are dispatched only on the `vw-cluster/1` ALPN listener, never the normal `vw/1` client listener, regardless of message-type value — there is no code path from a normal client-authenticated session into these handlers |

**What the cluster channel does NOT protect against:**
- A compromised replica node: once authenticated, a replica can pull the
  entire oplog, and — as of `TASK-170` — every local user's password hash
  and 2FA secret via `CLUSTER_FILE_SYNC_DATA` for the `USERS` file, plus
  the full content of every file it can enumerate a chunk hash for.
  Admin-level trust is implied by node registration; this task did not
  change that trust boundary, it changed how much data crosses it once a
  node is inside it.
- Primary–replica relationship forgery: there is no mechanism for a replica
  to verify that the primary it connected to is the correct primary (no
  cluster membership certificate). A DNS or ARP spoofing attack could direct
  a replica to a rogue primary. Mitigate with strict IP allowlisting at the
  network layer.

---

## 7.10 Sharing & Public Link Security Model

**Design status (2026-07-29):** specified per `TASK-088`; not yet
implemented (see §7.5).

| Property | Implementation |
|----------|-----------------|
| Link token secrecy | 256-bit CSPRNG (`vw_crypto_random`), shown once in `LINK_CREATE_ACK`, never re-displayed in `LINK_LIST_RESP` |
| Link token guessing resistance | 256-bit space; `LINK_ACCESS` is IP rate-limited identically to `NODE_HELLO` (5 failures / 60 s → silent drop, §7.9) — reusing the existing rate-limit mechanism rather than inventing a second one |
| Enumeration resistance | Unknown / expired / revoked `link_token` all produce the same `AUTH_FAIL`, indistinguishable from each other |
| Live revocation | A scoped session's validity is re-checked against the live `vw_share_record_t.revoked`/`expires_at` fields on **every** request, not just cached at `LINK_ACCESS` time — revoking a link must take effect immediately even against an already-issued scoped session token, the same request later. This is a stronger property than a normal session token (which is only checked for its own expiry) and must be implemented as an explicit extra lookup keyed by the scoped session's `share_id`, not skipped as "the session is already valid." |
| Privilege escalation via re-grant | Restricted to authenticated, non-scoped sessions only (`session.user_id != 0`) — an anonymous scoped session can never call `SHARE_GRANT`/`SHARE_REVOKE`/`LINK_CREATE`/`LINK_REVOKE` (§7.5), closing the path where a leaked link could mint an independent grant surviving revocation of the original. Among authenticated grantors, a user can only `SHARE_GRANT`/`LINK_CREATE` up to their own effective permission on the target — prevents a VIEW-only grantee from re-sharing EDIT access to themselves or a third party. |
| Quota abuse via public edit link | Storage bytes are bounded by the owner's existing quota (§7.5). Storage **counts** (files/versions/oplog entries) are separately bounded by a per-scoped-session write-count rate limit (§7.5), independent of the byte quota — closes an unauthenticated write-DoS surface where an anonymous editor could create unbounded near-zero-byte files without meaningfully touching the owner's byte quota. |
| Cross-owner move hijack | `FILE_MOVE` requires `destination_parent.owner_id == file.owner_id` in addition to EDIT on both parents (§7.5) — prevents a grantee from moving a shared file out of the owner's tree into their own, which would otherwise leave the file permanently consuming the owner's quota while the owner loses all visibility/access to it. |
| Anonymous write attribution | Oplog/audit entries for writes made through a scoped session must record the acting identity as anonymous (`user_id = 0`) **and** the `share_id`/owner separately, so the file's real owner can see "modified via link X" in their own audit trail rather than the write appearing to come from themselves. Exact oplog payload shape is an implementation detail for `TASK-094`, not fixed here. |
| Cross-user data exposure via mis-scoped grant | Every file operation must re-derive access via the full ordered rule in §7.5 (own the file → walk-up share grant → scoped-session match → deny) on **every** request; nothing may be cached across requests except within a single already-validated session's lifetime. |

**What this model does NOT protect against:**
- **Link sharing outside the application** (forwarding a public link's token
  via email/chat): by design — a public link's entire security model is
  "possession of the token grants access," identical to how e.g. Dropbox/
  Google Drive public links work. This must be disclosed in the GUI at link
  creation time (e.g. "anyone with this link can access this item").
- **Revocation of already-downloaded content**: if a recipient (grantee or
  link holder) already downloaded a file before access was revoked, nothing
  can retroactively delete their local copy. This is inherent to any
  file-sharing design and should be disclosed, not solved.

## 7.11 Vault / End-to-End Encryption

**Design status (2026-07-29):** specified per `TASK-089`; not yet
implemented (`vw_vault` client module, server-side wrapped-key storage, and
chunk-pipeline integration are tracked as `TASK-098` through `TASK-101`).

### 7.11.1 Key model

Recommendation (industry-standard **envelope encryption**, the same shape
used by AWS KMS, age, and Cryptomator's vault format — chosen over
alternatives below):

| Term | Definition |
|------|------------|
| **Encryption passphrase** | A secret the user chooses, entered only client-side. **Never** transmitted to the server in any form — not raw, not hashed, not derived — this is what makes the encryption genuinely end-to-end rather than server-recoverable. Deliberately a *separate* secret from the account login password (which the server *does* verify a derivation of, per §8.1); reusing the login password here would make the "true encryption" requirement false the moment an admin or attacker obtains the server-side Argon2id verifier. |
| **Vault** | One encrypted folder, or a single encrypted file treated as a one-item vault. The unit the user opts in at ("the user can decide to opt in to encrypt specific files/folders"). |
| **Vault Key (VK)** | A random 256-bit key, one per vault, generated client-side the moment a folder/file is first opted into encryption. Never leaves the client in unwrapped form. |
| **Key-Encryption-Key (KEK)** | Derived client-side from the encryption passphrase via Argon2id (reusing the primitive already vendored for password hashing — no new KDF implementation needed). Never transmitted or stored anywhere. |
| **Wrapped Vault Key** | `VK` encrypted under the `KEK` (AES-256-GCM), stored alongside the Argon2id salt and parameters. This blob — and *only* this blob — is what may be stored server-side; to the server it is opaque random-looking bytes. Multi-device access works by fetching this blob to a new device and re-deriving the KEK from a locally re-entered passphrase. |
| **Data Encryption Key (DEK)** | A fresh random 256-bit key generated per **file** (not reused across versions — see security note below), wrapped by that file's vault's VK, travels with the file's version metadata. |

A user may protect multiple vaults with the *same* passphrase (convenience)
or different passphrases per vault (compartmentalization) — this is a
client-side UX choice, not an architectural constraint, because each vault's
VK is independently random and independently wrapped. This directly
satisfies the settled requirement "lost keys shouldn't result in loss of
data beyond the files/folders that specific key was used for": losing
passphrase A only loses access to vaults wrapped under A.

**Why envelope encryption over the alternatives considered:**
- *Convergent encryption* (deriving the key from the plaintext hash, as some
  E2EE-plus-dedup systems do) was rejected: it is explicitly incompatible
  with the settled requirement to disable dedup for encrypted content, and
  it has a well-known confirmation-of-plaintext attack (an attacker who
  guesses a candidate plaintext can confirm a match without decrypting).
- *One global key for all of a user's encrypted content* was rejected: it
  violates "lost keys shouldn't result in loss of data beyond the specific
  key's files" — a single lost/compromised key would affect everything.
- *Per-chunk keys instead of per-file* were rejected as unnecessary
  complexity: chunk-level granularity exists for dedup and delta-sync, which
  encrypted content deliberately does not participate in (§7.11.2); a
  per-file DEK is the natural unit once dedup is out of the picture.

### 7.11.2 Content encryption & dedup interaction

- **Cipher:** AES-256-GCM, matching the cipher suite already mandated for
  TLS (§2) — reuses an already-audited primitive rather than introducing a
  second AEAD construction.
- **Granularity:** applied per existing 4 MiB chunk (§9), using the file's
  DEK, with a 12-byte GCM nonce.
- **Nonce derivation (revised 2026-07-29, SEC.07 finding):** the original
  design ("4-byte random per-file prefix + 8-byte monotonic chunk-index
  counter") is **rejected** — it is entirely client-trusted with zero
  protocol-level guardrail, and an upload retry/resume that restarts the
  chunk-index counter under the same DEK+prefix (e.g. after a dropped
  connection mid-`FILE_COMMIT`) produces an exact GCM nonce reuse, which is
  catastrophic (plaintext recovery via XOR, forged auth tags for the
  colliding chunks). Instead: **the nonce for chunk `i` of a file is derived
  deterministically as `HKDF(DEK, info = "vw-chunk-nonce" || i)[0:12]`** —
  a pure function of the (already-unique-per-file) DEK and the chunk index,
  with no independent random or counter state to desynchronize across a
  retry. Resuming an interrupted upload re-derives the identical nonce for
  a given chunk index every time, which is safe *only if* that chunk's
  plaintext (and therefore ciphertext) is also identical on retry — the
  client must guarantee this by never changing a file's content mid-upload
  without also rolling to a new DEK (i.e., a retry resumes the *same*
  upload attempt; any edit to the file starts a genuinely new version with
  a new DEK per the rule below, never a "resume" of the old one under the
  old DEK).
- **DEK scoping guardrail (SEC.07 finding):** a DEK must be generated fresh
  **per file**, never per-vault. A per-vault DEK bug would make identical
  plaintext across different files silently produce identical ciphertext —
  reproducing exactly the confirmation-of-plaintext leak this design
  explicitly rejected when ruling out convergent encryption (§7.11.1) — and
  because dedup "succeeding" looks identical to normal operation, such a
  bug would never surface on its own. `TASK-099`'s implementation and
  `TASK-101`'s tests must both explicitly verify DEK uniqueness is per-file
  (e.g. by confirming two different files under the same vault, with
  identical plaintext, produce different ciphertext), not just infer it
  from dedup behaving as expected.
- **Dedup is disabled for encrypted content as a natural consequence, not a
  special-cased flag:** each file gets a unique random DEK, so ciphertext is
  unique per file even for byte-identical plaintext across users or
  versions. The chunk store still content-addresses by SHA-256 of the
  *stored* (ciphertext) bytes exactly as it does today (§9) — no change to
  `vw_storage.c`'s dedup mechanism itself is needed; encrypted chunks simply
  never collide with anything, satisfying "deduplication should be disabled
  for files which have been opted in for encryption" with zero new
  dedup-bypass logic to get wrong.
- **Security note — DEK reuse across versions:** a new version of an
  encrypted file must get a **new** random DEK, not the old DEK with a fresh
  nonce counter — this avoids any possibility of nonce-counter overlap
  between versions sharing a key, and keeps "delete/lose one version's key"
  scoped to that version rather than the whole vault's history.

### 7.11.3 Metadata scope

Per the settled requirement ("just encrypting the file content should be
fine"), the following are **NOT** encrypted and remain visible to the
server: filenames, folder structure/hierarchy, file sizes, chunk counts,
timestamps, and version history metadata. This must be disclosed plainly in
the GUI wherever a vault's protection is described (e.g. "file names and
folder structure are visible to the server; only file contents are
encrypted") — an overstated security claim here is a trust bug in its own
right, distinct from any implementation bug.

### 7.11.4 Wire protocol

| Code   | Name                  | Direction | Description                        |
|--------|-----------------------|-----------|-------------------------------------|
| 0x0801 | VAULT_CREATE          | C → S     | Register a new vault + wrapped VK   |
| 0x0802 | VAULT_CREATE_ACK      | S → C     | Vault registered                    |
| 0x0803 | VAULT_KEY_FETCH       | C → S     | Fetch wrapped VK (new-device unlock)|
| 0x0804 | VAULT_KEY_FETCH_RESP  | S → C     | Wrapped VK blob returned            |
| 0x0805 | VAULT_LIST            | C → S     | List my vaults                      |
| 0x0806 | VAULT_LIST_RESP       | S → C     | Vault entries (opaque blobs never included) |

**VAULT_CREATE payload:**

| Field            | Type   | Notes |
|------------------|--------|-------|
| session_token    | bytes[32] | |
| folder_file_id   | uint64 | The folder (or file) being opted into encryption |
| wrapped_vk       | bytes  | AES-256-GCM(VK) — opaque to the server |
| kdf_salt         | bytes[16] | Argon2id salt |
| kdf_params       | bytes  | Argon2id (m_cost, t_cost, parallelism) — opaque, client-chosen; server stores as-is |

**VAULT_CREATE_ACK payload:** `error_code` (uint32), `vault_id` (uint64).

**VAULT_KEY_FETCH payload:** `session_token[32]`, `vault_id` (uint64).

**VAULT_KEY_FETCH_RESP payload:** `error_code`, `wrapped_vk`, `kdf_salt`,
`kdf_params`, `folder_file_id` (uint64) — the first four mirror
`VAULT_CREATE`, letting a new device unwrap the VK locally after the user
re-enters their encryption passphrase there. `folder_file_id` was added
after `TASK-100`'s review found that unlocking a vault (as opposed to
creating it) left the client with no way to learn which folder a new file
should be created under — `vw_vault_upload_file`'s create-new-file path
needs it. No protocol version bump: nothing optional follows it in this
response, so it is appended unconditionally, and an old client simply
never reads that far.

**VAULT_LIST / VAULT_LIST_RESP:** as named; list entries include `vault_id`,
`folder_file_id`, `created_at` — never the wrapped-key material itself
(no legitimate client need to enumerate other vaults' key blobs in a list
view).

**FILE_COMMIT extension (finalized 2026-07-31, `TASK-098`):** `FILE_COMMIT`
(§7.2) gains two optional trailing fields, appended after the existing
`chunk_hashes` array:

| Field       | Type              | Notes |
|-------------|-------------------|-------|
| vault_id    | uint64 (optional) | Absent (payload simply ends after `chunk_hashes`) = unencrypted, identical to every pre-`TASK-098` client. 0 is not a valid non-absent value here — a client either omits this field or sends a real nonzero `vault_id`. |
| wrapped_dek | string (only present if `vault_id` is present and nonzero) | Opaque bytes, server never inspects content — only presence and a size ceiling (`VW_VAULT_MAX_WRAPPED_VK_BYTES`-equivalent, checked server-side). |

Purely additive and optional in both directions — no protocol version bump:
an old server ignores trailing bytes it never reads past `chunk_hashes`
(unaffected by a hypothetical future client sending them); an old client
never sends them at all. The server validates `vault_id` (if present)
references a real vault owned by the file's actual owner (`file_rec.
owner_id`, not necessarily the acting session's `user_id` — same
quota/ownership resolution rule as everything else in §7.5) before
accepting the commit.

`vw_version_record_t`'s former 32 reserved bytes (`_reserved[32]`) are now:
`vault_id` (uint64, 0 = not encrypted), `wrapped_dek_offset` (uint64, byte
offset into `versions.blob` immediately following that version's chunk
hashes), `wrapped_dek_len` (uint32, 0 when `vault_id == 0`), and 12
remaining reserved bytes. A version record written before this field
existed reads back with `vault_id == 0` for free — every prior write path
already zeroed this exact byte range (`memset(w._reserved, 0, ...)` in
`vw_store_version_create`), so no migration is needed; confirmed by
`test_vw_vault.c`'s dedicated layout test. `_Static_assert(sizeof(
vw_version_record_t) == 80, ...)` (unchanged) enforces the on-disk
compatibility claim at compile time, reviewed by CQR.08 matching how
`TASK-090`'s `deleted_at` field was finalized and reviewed.

**Gap closed by `TASK-099`:** `VERSION_CHUNKS_RESP` (§7.3) now carries
optional trailing `vault_id`/`wrapped_dek` fields, mirroring this
section's `FILE_COMMIT` extension exactly. A downloading client already
calls `VERSION_CHUNKS` immediately before fetching chunks, so this was the
natural place to surface the wrapped DEK rather than adding a new
round-trip. See §7.3 for the wire layout.

### 7.11.5 Security properties for review

| Property | Requirement |
|----------|-------------|
| Passphrase never transmitted | No wire message may carry the raw encryption passphrase or any value computed directly from it other than the final wrapped-VK ciphertext. `TASK-099` must give `derive_login_token()` and `derive_kek()` distinct, non-interchangeable function signatures/types (not just a naming convention) so the two code paths cannot be pointer-substituted or copy-pasted into each other undetected — a structural guardrail, not just a review checklist item, per SEC.07's advisory that a documented review gate alone is insufficient defense against a future copy-paste. |
| KDF parameters tuned for a stolen-blob threat model | Unlike the server-side login Argon2id (which only needs to resist *online* guessing, since the server rate-limits attempts), the vault-wrapping Argon2id runs against a threat model where the wrapped blob itself may be exfiltrated wholesale (a compromised server is explicitly in-scope here, since the whole point of E2EE is protecting against that). **Minimum parameter floor (pinned 2026-07-29 rather than deferred to implementation, per SEC.07 advisory):** at least the OWASP-recommended memory-hard baseline for offline-attack resistance — Argon2id, `m_cost >= 19456` KiB (19 MiB), `t_cost >= 2`, `parallelism = 1` — as a floor; `TASK-099` may increase these but must not ship below them. Client-side latency at this floor (roughly sub-second on typical hardware) is an acceptable, one-time-per-vault-unlock cost. |
| DEK freshness per version | New version ⇒ new DEK (§7.11.2) — never nonce-counter continuation of an old DEK. |
| No server-side plaintext recoverability | The server must never see an unwrapped VK or DEK, or plaintext content, at any point in any code path — including crash-recovery/oplog replay, which must operate on already-encrypted bytes exactly as it does for any other opaque chunk today. |
| DEK uniqueness is per-file, not per-vault | A per-vault-scoped DEK bug would silently reproduce the confirmation-of-plaintext leak this design rejected when ruling out convergent encryption (§7.11.1), and would never surface on its own since dedup "succeeding" looks identical to normal operation. `TASK-101` must explicitly test this (two different files, same vault, identical plaintext, distinct ciphertext) rather than inferring it from dedup behavior. |

**Accepted tradeoff (ARCH.00 sign-off, 2026-07-29, per SEC.07 advisory):**
per-version DEK rotation (required for the nonce-safety and key-scoping
properties above) means no chunk of a re-uploaded encrypted file's new
version can ever match a chunk of that same file's own previous version,
even for byte-identical regions — every edit to an encrypted file forces a
full-file re-upload, unlike plaintext files which benefit from delta sync.
This is accepted as the correct tradeoff: the settled requirement was for
"true encryption," and weakening DEK freshness to preserve delta-sync
bandwidth would reintroduce exactly the nonce-reuse and key-scoping risks
flagged above. Large, frequently-edited encrypted files (e.g. a database or
VM image kept in a vault) will have materially worse sync bandwidth than
the same file unencrypted — this should be disclosed in the GUI vault
setup wizard (`TASK-100`) as a known characteristic, not hidden as a
surprise.

---

## 7.12 Filename Search (TASK-196/197)

Server-side substring search over filenames, scoped to exactly what the
caller can already see via `FILE_LIST`/`effective_permission()` — owned
files and folders, plus anything shared with them (grant-based; a
`LINK_ACCESS`-redeemed scoped session cannot search, see below).
Filename/leaf-name matching only, never content: vault contents are
opaque ciphertext to the server by design (§7.11), and non-vault content
search would need an index this flat-file store doesn't have. Neither is
in scope for this feature.

**Implementation note**: the server has no `owner_id`-indexed enumeration
of "every file this user owns" — file lookup is either by exact path
(owner-namespaced) or by one directory level at a time (`FILE_LIST`).
Rather than a recursive per-directory walk mirroring the client's own
sync-engine BFS, `SEARCH` is implemented as a single linear scan over the
entire file table, calling the already-reviewed `effective_permission()`
per record (the same function every other file operation's access check
already goes through — no new permission logic). This is the same
accepted complexity tradeoff already on record for `vw_share_scan`
("O(total shares) scan per call — acceptable at Phase-8 scale, candidate
follow-up if this becomes a hot path"): fine at this project's
personal-scale target, and a real, disclosed limitation rather than a
hidden one if the file count ever grows large enough to matter.

| Opcode | Message      | Direction | Purpose |
|--------|--------------|-----------|---------|
| 0x0901 | SEARCH       | C → S     | Search filenames across everything the caller can see |
| 0x0902 | SEARCH_RESP  | S → C     | Matching entries |

**SEARCH payload:**

| Field         | Type   | Notes |
|---------------|--------|-------|
| session_token | bytes[32] | Must be a real, non-scoped session — same restriction §7.5 already places on `SHARE_GRANT`/`LINK_CREATE`. A `LINK_ACCESS`-redeemed anonymous session gets `VW_ERR_PERMISSION`: it already sees only the one subtree it was scoped to, directly browsable via `FILE_LIST`, so "search everything visible" adds nothing for it and isn't worth a second permission model to reason about. |
| query         | string | Case-insensitive substring match against each candidate's leaf name (`vw_file_record_t.name`), not the full path. Empty query is valid (matches everything the caller can see, subject to the cap below) — the client's own UI is expected to debounce/gate this, not the server. Rejected with `VW_ERR_INVALID_ARG` (before any table scan) if longer than 256 bytes. |

**SEARCH_RESP payload:**

| Field     | Type   | Notes |
|-----------|--------|-------|
| error_code | uint32 | `VW_OK`, `VW_ERR_AUTH_REQUIRED` (no session), `VW_ERR_PERMISSION` (scoped session), or `VW_ERR_INVALID_ARG` (oversized query) |
| count      | uint32 | 0 if error_code != 0 |
| truncated  | uint8  | 1 = more matches existed than `count` — the cap below was hit. Not an error; the client should suggest narrowing the query. |
| *count* × entry | — | see below |

Each entry: `file_id` (uint64), `name` (string — leaf name, display-only,
same convention `SHARE_LIST_RESP`/`LINK_LIST_RESP` already use for their
own `name` field), `is_dir` (uint8), `size_bytes` (uint64), `mtime_unix`
(int64), `vault_id` (uint64, 0 = unencrypted or unknown — same convention
as `FILE_LIST_RESP`'s per-entry `vault_id`, `TASK-158`), `is_shared`
(uint8, 1 = the caller sees this via a grant rather than owning it —
`effective_permission() != VW_PERM_OWNER`).

**No virtual path in either direction.** An owned match's path is
reconstructable by the caller via repeated `FILE_STAT_BY_ID`/parent
lookups if truly needed; a shared match has no meaningful path in the
caller's own namespace at all (the same reason `FILE_LIST`'s
`dir_file_id` extension, `TASK-106`, addresses shared content by
`file_id` rather than path) — fabricating one would mean either guessing
at the owner's directory structure above the shared root (never shown to
the grantee) or inventing something that isn't real. `file_id` already
round-trips through every existing file-id-addressed operation
(`TASK-095`/`106`), which is enough for a client to act on a result
(open it, list its parent via `dir_file_id`, etc.).

**Result cap**: 200 entries per call. No pagination — checked
`docs/PROTOCOL.md` (this document) for an existing cursor convention to
reuse before designing one; there isn't one anywhere in this protocol.
Every other multi-entry response (`FILE_LIST_RESP`, `SHARE_LIST_RESP`,
`LINK_LIST_RESP`) returns its whole result set in one response with a
hard entry cap instead (`FILE_LIST`'s BFS caps at 65535). `SEARCH`
follows that actual existing convention rather than introducing
pagination as a new paradigm this protocol has never used — the
`truncated` flag above is the entire mechanism for "there were more."

**Security**: a match on a file the caller cannot see must never be
observable in any form — not in the result set, not in `count`, not in
`truncated`, not in response timing (same SEC-ADV posture recorded early
in this project for the original chunk endpoints). Achieved structurally,
not by a special case: the scan evaluates `effective_permission()` for
*every* candidate record and only ever appends a match the caller has at
least `VW_PERM_VIEW` on — an invisible file is filtered before it's ever
compared against the query, the same as it would be if it simply didn't
exist in the scan at all.

---

## 7.13 Notification Preferences (TASK-206)

Per-user, opt-in email alert preferences (`TASK-205`'s design) for the four
user-facing categories: `share_received`, `quota_warning`, `new_login`,
`account_security_change`. Operates **only on the calling session's own
account** — there is no `user_id` parameter anywhere in either message, and
no `VW_PERM_*`/admin-capability concept applies. Same trust bar as an
authenticated session changing its own password: any real, non-scoped
session may read or write its own preferences, full stop.

Admin-category alert configuration (`replica_lag`, `acme_renewal_failure`,
`disk_capacity`, `lockout_spike`, `crash_recovery`) is **not** part of this
wire protocol at all — per `TASK-205`'s design, those are
`vapourwaultd.conf`-only operator settings, read at startup, with no live
socket/wire toggle in v1.

| Opcode | Message              | Direction | Purpose |
|--------|----------------------|-----------|---------|
| 0x0A01 | NOTIFY_PREFS_GET      | C → S     | Fetch the caller's own notification preference bitmask |
| 0x0A02 | NOTIFY_PREFS_GET_RESP | S → C     | Current bitmask |
| 0x0A03 | NOTIFY_PREFS_SET      | C → S     | Replace the caller's own notification preference bitmask |
| 0x0A04 | NOTIFY_PREFS_SET_ACK  | S → C     | New bitmask, echoed back for confirmation |

**Category bit assignments** (`uint32`, one bit per category, extensible —
same "leave room to grow" spirit as the 2FA provider interface; bits 4–31
reserved for future categories):

| Bit    | Value  | Category                  |
|--------|--------|----------------------------|
| 0      | 0x0001 | `share_received`           |
| 1      | 0x0002 | `quota_warning`             |
| 2      | 0x0004 | `new_login`                 |
| 3      | 0x0008 | `account_security_change`   |

Default value for a new account (no `NOTIFY_PREFS_SET` ever sent): `0`
(every category off) — per `TASK-205`'s hard "default off everywhere"
requirement.

**NOTIFY_PREFS_GET payload:**

| Field         | Type      | Notes |
|---------------|-----------|-------|
| session_token | bytes[32] | Must be a real, non-scoped session. |

**NOTIFY_PREFS_GET_RESP payload:**

| Field       | Type   | Notes |
|-------------|--------|-------|
| error_code  | uint32 | `VW_OK`, `VW_ERR_AUTH_REQUIRED` (no session), or `VW_ERR_PERMISSION` (a `LINK_ACCESS`-redeemed scoped session — it has no "own account" preferences to fetch, same restriction §7.12 already places on `SEARCH`) |
| prefs_bitmask | uint32 | 0 if error_code != 0 |

**NOTIFY_PREFS_SET payload:**

| Field         | Type      | Notes |
|---------------|-----------|-------|
| session_token | bytes[32] | Must be a real, non-scoped session. |
| prefs_bitmask | uint32    | The caller's **complete new** preference bitmask — this replaces the stored value, it does not toggle one bit. A client that wants to flip a single category must `NOTIFY_PREFS_GET` first, flip the one bit locally, and send the full result back; this keeps the wire message itself stateless and trivial rather than inventing a second "set one bit" shape. Any bit outside the currently-defined range above (bits 4–31) is rejected with `VW_ERR_INVALID_ARG` rather than silently accepted-and-stored — consistent with this project's existing fail-loud-on-unrecognized-input posture (e.g. the CA-store `VW_ERR_INVALID_ARG` decision, `ARCHITECTURE.md`'s Architectural Decisions table) rather than the alternative of forward-compatibly storing bits a future version might define; revisit this rejection rule the day a real second wave of categories ships, since a mixed-version client/daemon pair would otherwise be unable to round-trip an unknown-to-it bit it didn't set itself. |

**NOTIFY_PREFS_SET_ACK payload:**

| Field       | Type   | Notes |
|-------------|--------|-------|
| error_code  | uint32 | `VW_OK`, `VW_ERR_AUTH_REQUIRED`, `VW_ERR_PERMISSION` (scoped session), or `VW_ERR_INVALID_ARG` (reserved bit set) |
| prefs_bitmask | uint32 | The stored value after this call — identical to the request's value on `VW_OK`, unchanged-from-before on any error. Echoed back (rather than leaving the client to assume its own request applied) so a client never has to issue a follow-up `GET` just to confirm what it just set. |

**Storage**: a new `notify_prefs` `uint32` field on the user record
(`vw_user_record_t`/`vw_store`), same precedent as the existing
`otp_enabled` flag — see `TASK-207`.

---

## 7.14 Account Self-Service: Email Address (TASK-222)

Neither `USER_CREATE_REQ` (admin socket) nor `INVITE_REDEEM` carry an
email field, and `USER_MODIFY` (`0x0603`/`0x0604`) is a reserved opcode
with no handler — so before this section, **no wire or admin path
anywhere could ever put a non-empty email on a user record**. That
silently made the already-shipped password-recovery feature
(`TASK-046`, `vw_store_user_get_by_email`) and the notify-preferences
system above (§7.13, `TASK-207`) unreachable for every real account —
`rec.email[0] == '\0'` short-circuits both, and it always was, for any
account created through either existing path.

This section is the fix: a self-service pair, operating **only on the
calling session's own account**, same trust bar and shape as §7.13 —
no `user_id` field, no `VW_PERM_*` concept, any real non-scoped session
may read or write its own email, full stop.

| Opcode | Message                | Direction | Purpose |
|--------|-------------------------|-----------|---------|
| 0x0B01 | ACCOUNT_EMAIL_GET       | C → S     | Fetch the caller's own email address |
| 0x0B02 | ACCOUNT_EMAIL_GET_RESP  | S → C     | Current address (`""` if none on file) |
| 0x0B03 | ACCOUNT_EMAIL_SET       | C → S     | Set (or clear) the caller's own email address |
| 0x0B04 | ACCOUNT_EMAIL_SET_ACK   | S → C     | New address, echoed back for confirmation |

**ACCOUNT_EMAIL_GET payload:**

| Field         | Type      | Notes |
|---------------|-----------|-------|
| session_token | bytes[32] | Must be a real, non-scoped session. |

**ACCOUNT_EMAIL_GET_RESP payload:**

| Field      | Type   | Notes |
|------------|--------|-------|
| error_code | uint32 | `VW_OK`, `VW_ERR_AUTH_REQUIRED` (no session), or `VW_ERR_PERMISSION` (a scoped `LINK_ACCESS` session — same restriction §7.12/§7.13 already place on `SEARCH`/`NOTIFY_PREFS_GET`) |
| email      | string | `""` if no email is on file — the default state for every account today, not an error |

**ACCOUNT_EMAIL_SET payload:**

| Field         | Type      | Notes |
|---------------|-----------|-------|
| session_token | bytes[32] | Must be a real, non-scoped session. |
| email         | string    | Up to 128 bytes. `""` clears the email back to unset — exempt from the format check below (an empty value can never fail validation). Any non-empty value must pass `vw_email_validate` (server-side, `vw_store.c`): exactly one `@`, non-empty local and domain parts, domain contains at least one `.`, every byte restricted to a conservative allow-list — no whitespace, no control characters, nothing that could be interpreted as an SMTP command terminator. This is a hard security requirement, not cosmetic: `vw_smtp.c`'s `MAIL FROM`/`RCPT TO` lines interpolate `rec.email` with no escaping of their own, so an unvalidated address would be CRLF/SMTP-command injection into the server's own authenticated outbound relay session the moment `TASK-207`'s notify triggers (or `TASK-046`'s recovery flow) tried to mail it. |

**ACCOUNT_EMAIL_SET_ACK payload:**

| Field      | Type   | Notes |
|------------|--------|-------|
| error_code | uint32 | `VW_OK`, `VW_ERR_AUTH_REQUIRED`, `VW_ERR_PERMISSION` (scoped session), `VW_ERR_INVALID_ARG` (malformed address or over 128 bytes), or `VW_ERR_ALREADY_EXISTS` (a *different* account already owns that exact address) |
| email      | string | The stored value after this call — identical to the request's value on `VW_OK`, unchanged-from-before on any error. Echoed back so a client never has to issue a follow-up `GET` just to confirm what it just set (same pattern as `NOTIFY_PREFS_SET_ACK`, §7.13). |

**Storage**: `vw_store_user_set_email` (`vw_store.c`) — unlike the
generic `vw_store_user_update_field` (which explicitly forbids email:
see its own doc comment), this correctly maintains the `email_ht`
uniqueness index across a change, evicting the old address before
inserting the new one. Fixed alongside this task: `email_ht_insert`
previously still counted every *empty*-email account against the
index's growth threshold (an empty string always reported "not found"
by `email_ht_find`'s own existing guard, so it was harmless in effect,
but wasted unbounded table growth — every account lacked an email until
this task shipped, i.e. this bug fired on every single account created
before today). Empty emails are now never inserted into the index at
all, matching `email_ht_find`'s existing treatment of `""` as "no
email," and the index correctly supports multiple simultaneous
no-email accounts.

**Deliberately out of scope**: `USER_CREATE_REQ` and `INVITE_REDEEM`
still do not carry an email field — an admin provisioning an account,
or a user redeeming an invite, still needs a separate
`ACCOUNT_EMAIL_SET` call afterward. This self-service pair alone fully
satisfies `TASK-222`'s acceptance criteria (a real, documented,
implemented path exists), so adding email to either creation path is
left as a possible future enhancement rather than folded into this
task. Client-core/daemon-IPC/CLI/GUI/web surfacing shipped directly
alongside this section as part of closing `TASK-222` — see
`vw_client_account_email_get`/`_set`, `vapourwault-cli account email`,
the desktop GUI's Settings view, and the web gateway's
`/api/account/email` endpoints.

---

## 7.15 Account Self-Service: Two-Factor Enrollment (TASK-219)

Before this section, there was no self-service **or** admin-driven way
to change a user's 2FA (email-OTP, §8.3) enrollment after account
creation at all — `otp_enabled` was write-once at zero (`vw_store_user_
create` zeroes a fresh record; nothing else ever set it to 1 anywhere in
the codebase). `TASK-207`'s `account_security_change` alert category was
designed to fire on "password changed, or 2FA enabled/disabled," but
until this section shipped, the 2FA half of that had no real trigger to
fire from — see §7.14's password-recovery analog for the sibling gap
(email) this same milestone closed.

Single dedicated message pair, same account-scoped shape as §7.13/§7.14
above (no `user_id` field, no `VW_PERM_*` concept) — but additionally
requiring the caller to re-prove their current password, since this is
a security-sensitive toggle, not a preference (same bar a real password
change should have; recommended and implemented per this task's own
design note). A single parameterized `SET` was chosen over the two
separate `2FA_ENABLE`/`2FA_DISABLE` opcodes this task's own filed design
question raised as an option — both directions need identical re-auth
handling and payload shape, differing only in the stored boolean, so one
message covers both without the duplication two near-identical opcodes
would add; this still avoids the rejected alternative (reviving the
reserved, unimplemented `USER_MODIFY` as a generic field-patch message)
for the same reason that task gave: a security-sensitive, single-purpose
action should not become a general field-patch operation just because
its payload happens to include one flag.

| Opcode | Message              | Direction | Purpose |
|--------|-----------------------|-----------|---------|
| 0x0B05 | ACCOUNT_2FA_SET       | C → S     | Enable or disable the caller's own 2FA enrollment |
| 0x0B06 | ACCOUNT_2FA_SET_ACK   | S → C     | New `otp_enabled` value, echoed back for confirmation |

**ACCOUNT_2FA_SET payload:**

| Field          | Type      | Notes |
|----------------|-----------|-------|
| session_token  | bytes[32] | Must be a real, non-scoped session. |
| password_token | bytes[32] | Re-proof of the current password — `SHA-256(password)`, identical shape and derivation to `AUTH_REQUEST`'s own `auth_token` (§8.1 Phase 0). Verified server-side against the account's stored Argon2id hash via the same primitive `AUTH_REQUEST` itself uses. |
| enable         | uint8     | `1` = enable, `0` = disable. Any other value is rejected with `VW_ERR_INVALID_ARG`. |

**ACCOUNT_2FA_SET_ACK payload:**

| Field       | Type   | Notes |
|-------------|--------|-------|
| error_code  | uint32 | `VW_OK`, `VW_ERR_AUTH_REQUIRED`, `VW_ERR_PERMISSION` (scoped session), `VW_ERR_INVALID_ARG` (malformed `enable` byte, **or** enabling with no email on file — see below), or `VW_ERR_AUTH_BAD_CREDS` (`password_token` does not match the account's current password) |
| otp_enabled | uint8  | The stored value after this call — identical to the request's `enable` value on `VW_OK`, unchanged-from-before on any error. |

**Enabling requires an email on file.** 2FA here is delivered by
emailing a one-time code (the existing `AUTH_CHALLENGE`/`AUTH_OTP` flow,
§8.3 — this section adds no new delivery mechanism). Enabling it for an
account with no email on file (§7.14 — still the default state for any
account that hasn't run `ACCOUNT_EMAIL_SET`) would lock that account out
of every future login the instant it tried to send a code nowhere, so
`ACCOUNT_2FA_SET` with `enable=1` and an empty `rec.email` is rejected
with `VW_ERR_INVALID_ARG` rather than silently creating an unrecoverable
account. Disabling has no such precondition.

**Storage**: reuses the existing `otp_enabled` field on `vw_user_
record_t` (`vw_store.h`) — already explicitly supported by `vw_store_
user_update_field`'s generic single-field setter (its own doc comment
lists `otp_enabled` as an intended use, alongside `is_active`), so no
new store-layer function was needed here (unlike email in §7.14, which
required a bespoke setter for its uniqueness-index side effects —
`otp_enabled` has no index of its own).

---

## 8. Authentication Design

### 8.1 Password transport

The client does **not** send the raw password. Before sending AUTH_REQUEST, the client:

1. Computes `auth_token[32] = SHA-256(password)`. This is the sole scheme —
   every client (desktop, web, Android) does exactly this; there is no
   client-side-Argon2id alternative, live or planned (see note below on why
   not).
2. Sends `auth_token[32]` in AUTH_REQUEST.

The server verifies `auth_token` via Argon2id against its own stored
`(argon2id_hash, salt)` for the account — i.e. the server's Argon2id input is
`SHA-256(password)`, not the raw password.

> **Note on client-side Argon2id (not planned):** `AUTH_REQUEST` is a single
> round trip, so the client has no way to learn the server's per-account
> Argon2id salt before computing `auth_token` — there is no salt-exchange
> message in the handshake. Client-side Argon2id derivation was never
> implementable under this shape, not merely unimplemented so far; achieving
> it would require a real protocol change (e.g. SRP, or an explicit
> salt-exchange round trip added to the handshake). No such change is
> currently planned — this is a known, accepted limitation of the Phase 0
> handshake shape, not a near-term TODO. (Previously tracked as a "Phase 1"
> upgrade under `TASK-009`; that framing was stale by Phase 21 and has been
> corrected here per `TASK-240`.)

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
| 605  | `VW_ERR_RATE_LIMITED`        | File transfer  | Scoped-session write-count rate limit exceeded (§7.5, `TASK-094`) |
| 606  | `VW_ERR_READ_ONLY_REPLICA`   | File transfer  | Write-shaped request rejected: this server is a cluster replica (`TASK-179`) |
| 607  | `VW_ERR_LINK_PASSWORD_REQUIRED` | File transfer | `LINK_ACCESS` against a password-protected link with no password supplied (`TASK-186`) |
| 608  | `VW_ERR_LINK_PASSWORD_WRONG`  | File transfer | `LINK_ACCESS` against a password-protected link with an incorrect password (`TASK-186`) |
| 700  | `VW_ERR_IPC_NOT_RUNNING`     | IPC            | Daemon not listening on its IPC port (client-daemon transport only; never sent over `vw/1`) |
| 800  | `VW_ERR_SYNC_TREE_TOO_LARGE` | Client-local   | Shared-folder BFS exceeded the client's resource ceiling for one sync cycle (`TASK-111`); never sent over the wire, daemon-internal/IPC only |
| 801  | `VW_ERR_READ_ONLY_FALLBACK`  | Client-local   | Daemon rejected a write-shaped IPC request because this account is currently on its read-only fallback server (`TASK-173`); never sent over the wire, IPC-response only |

**`VW_ERR_READ_ONLY_REPLICA` (`TASK-179`):** a server configured as a
cluster replica (`cluster_is_replica = 1`, §6) runs its full normal
client-facing `vw/1` listener unconditionally (§7.7's hot-standby
replication note) — nothing about being a replica closes that listener or
makes it reject connections. This code is the server-side backstop that
actually enforces the read-only property `TASK-173`'s client-side fallback
logic is named after: `vw_server_dispatch_file_op`'s single dispatch
choke point (`vw_file_handlers.c`) rejects every write-shaped message
(`FILE_COMMIT`, `CHUNK_UPLOAD`, `FILE_DELETE`, `FILE_MOVE`, `FILE_MKDIR`,
`VERSION_RESTORE`, `SHARE_GRANT`/`REVOKE`, `LINK_CREATE`/`REVOKE`,
`VAULT_CREATE`, `USER_SUSPEND`, `QUOTA_ADJUST`, `INVITE_CREATE`) with this
code, before the corresponding handler runs — no on-disk state is
mutated. Every read-shaped message (`FILE_LIST`/`STAT`,
`CHUNK_DOWNLOAD_REQ`, `SHARE_LIST`, `LINK_LIST`, `VERSION_LIST`/`CHUNKS`,
vault list/key-fetch, `CLUSTER_STATUS`) is unaffected, on a replica or
not. This closes the gap the amended "Client-side automatic fallback"
decision in `ARCHITECTURE.md` flagged as a known, bounded sharp edge:
previously, only the daemon's own good behavior (queuing instead of
sending) kept a write off a fallback session — a hand-rolled client, or
`vapourwault-cli` pointed manually at a replica's `host:port`, had nothing
stopping it. A client that gets this error while intentionally connected
to a fallback (`TASK-173`) treats it exactly like a network error — queue
the write locally, don't count it as an action failure — since from that
client's perspective the effect (this write cannot reach the primary
through this connection) is the same either way.

**Wire encoding:** `error_code` is transmitted as a `uint32` (LE). Unknown codes must be treated as fatal errors by the receiver; the connection should be closed.

---

## 11. Version History

| Version | Date       | Author  | Changes                    |
|---------|------------|---------|----------------------------|
| 30      | 2026-09-03 | PRT.04  | §8.1 (password transport) reworded, resolving `TASK-240` (a SEC.07 advisory filed during `TASK-234`'s Android review): the prior text presented "Argon2id locally" as a live client-side alternative to `SHA-256(password)`, which is structurally impossible under `AUTH_REQUEST`'s single-round-trip shape (no salt-exchange message exists for the client to learn the server's per-account salt before computing the token) — never actually implementable, not merely not-yet-implemented. Also replaced the stale "Phase 1 will define a proper SRP or client-side Argon2id derivation" note (open since `TASK-009`, Phase 0) — 20+ phases shipped since with no such change — with an explicit "not planned" framing. Verified against `src/server/vw_auth.c`'s actual verification call and `src/client/vw_client_core.c`'s implementation: every client (desktop, web, Android) sends `SHA-256(password)`; the server verifies it via Argon2id against its own stored hash+salt. Documentation-only; no wire format, message, or byte layout changed; no protocol version bump required (this table tracks spec-revision count, not wire version, per revision 16's own clarifying note). |
| 29      | 2026-09-03 | SRV.01  | Documented `AUTH_LOGOUT` (§7.1) for the first time, resolving `TASK-237`: the message existed on the wire since Phase 1 but the server never handled it (a client-initiated logout never actually invalidated the session token — it just sat valid until natural expiry), so there was nothing correct to document until now. No payload; revokes the session token the connection authenticated with; wire-visible rejection codes for that revoked token match every other bad-token case (`AUTH_FAIL`/`VW_ERR_AUTH_BAD_CREDS` on `SESSION_RESUME`, `ERROR`/`VW_ERR_AUTH_REQUIRED` mid-session), per the existing anti-oracle invariant — verified empirically rather than assumed. Purely a behavior fix + doc addition, no existing byte layout changed; no protocol version bump required. |
| 28      | 2026-08-27 | PRT.04  | Account self-service two-factor enrollment (§7.15), resolving `TASK-219`: new `ACCOUNT_2FA_SET`/`_SET_ACK` (0x0B05–0x0B06). Before this, there was no self-service or admin-driven way to change a user's 2FA enrollment after creation at all, so `TASK-207`'s `account_security_change` alert had no real trigger for its "2FA enabled/disabled" half. Requires re-proving the current password (same shape as `AUTH_REQUEST`'s `auth_token`) before touching the flag — a security-sensitive toggle, not a preference. Enabling with no email on file is rejected (`VW_ERR_INVALID_ARG`): 2FA codes are emailed, so enabling without one would lock the account out of every future login. Chose one parameterized `SET` over this task's own alternative of two separate `2FA_ENABLE`/`2FA_DISABLE` opcodes (identical re-auth handling and shape on both directions, differing only in one stored bit) while still avoiding its rejected alternative (reviving `USER_MODIFY` as a generic field-patch message) for the reason that task itself gave. Storage reuses the existing `otp_enabled` field via `vw_store_user_update_field` — already an explicitly-supported use per that function's own doc comment — no new store-layer setter needed. Entirely new message pair, no existing byte layout changed; no protocol version bump required. |
| 27      | 2026-08-27 | PRT.04  | Hot-standby replication of `notify_prefs.db` (§7.7), resolving `TASK-220`: new file tag 9 (`store/notify_prefs.db`) added to the fixed `CLUSTER_FILE_SYNC_LIST`/`_FETCH` file-tag table (`vw_cluster_file_tag_t`), `VW_CLUSTER_FILE_TAG_COUNT` 8→9. Before this, a replica's own `notify_prefs.db` was always a fresh, all-defaults-off copy, never synced from the primary — a `NOTIFY_PREFS_GET` served from a fallback-connected replica (TASK-173) always read back 0 regardless of the real preference on file at the primary (stale-but-safe: under-reports opt-in, never over-reports, so no security issue, but a real correctness gap). Also fixed in the same pass, found while implementing rather than deferred: `vw_store_reload_users_and_quotas` (the function the replica's sync pass calls to refresh in-memory state after fetching new files) didn't reload `notify_prefs`/`notify_free` at all — so even with the file tag fixed, a long-running replica process's in-memory preference table would still have gone stale until its next restart. `notify_prefs` reload folded into that existing function rather than a new one, same reasoning already used for quotas sharing it with users. `CLUSTER_FILE_SYNC_LIST_RESP`'s entry count is purely additive (driven entirely by the `VW_CLUSTER_FILE_TAG_COUNT` constant in both the primary and replica implementations); no protocol version bump required. |
| 26      | 2026-08-27 | PRT.04  | Account self-service email address (§7.14), resolving `TASK-222`: new `ACCOUNT_EMAIL_GET`/`_GET_RESP`/`SET`/`_SET_ACK` (0x0B01–0x0B04). The first real wire path that can ever put a non-empty email on a user record — neither `USER_CREATE_REQ` nor `INVITE_REDEEM` carry one, which silently made the already-shipped `TASK-046` password recovery and `TASK-207`'s notify-preferences system unreachable for every real account. Server-side format validation (`vw_email_validate`) is a hard security requirement, not cosmetic: `vw_smtp.c`'s `MAIL FROM`/`RCPT TO` lines do no escaping of their own, so this is the sole gate against SMTP command injection into the outbound relay. Also fixed in the same pass: `email_ht_insert`'s pre-existing bug where every empty-email account (i.e. every account, until this task) still counted against the index's growth threshold. Entirely new message pair-of-pairs, no existing byte layout changed; no protocol version bump required. |
| 25      | 2026-08-27 | PRT.04  | Shared-file version history (§7.3), resolving `TASK-214` — **corrects `TASK-182`'s own filed assumption** that `VERSION_RESTORE` resolves by path server-side the same owner-namespaced way `FILE_STAT` does; reading `handle_version_restore` in full found it already resolves `version_id → file_id` and requires `VW_PERM_EDIT` via `effective_permission()`, never using `virtual_path` for anything but shape validation. `VERSION_LIST` was already fully correct too (`file_id` + `VW_PERM_VIEW`). The one real, small gap: `virtual_path` was a *mandatory* non-empty field even though unused — now may be an empty string, meaning "no meaningful path, resolve by `version_id`/`file_id` alone" (a grantee's own case). A caller supplying a real path is completely unaffected; this is a pure server-side permissive relaxation (a previously-always-rejected zero-length string is now accepted), not a new field — no protocol version bump required. The server-side relaxation itself was small enough to land directly in `TASK-214` rather than a separate SRV.01 follow-up; filed the remaining CLI.02 follow-up (`TASK-223`) for the client-core/daemon-IPC/CLI/GUI work needed to actually reach it. |
| 24      | 2026-08-26 | PRT.04  | Notification preferences (§7.13), resolving `TASK-206`: new `NOTIFY_PREFS_GET`/`_GET_RESP`/`SET`/`_SET_ACK` (0x0A01–0x0A04). Account-scoped only (no `user_id` field, no `VW_PERM_*` concept — same trust bar as a session changing its own password), covering the four user-facing alert categories from `TASK-205`'s design (`share_received`/`quota_warning`/`new_login`/`account_security_change`) as bits 0–3 of a `uint32` bitmask, bits 4–31 reserved. `SET` replaces the whole bitmask rather than toggling one bit, and rejects any reserved bit with `VW_ERR_INVALID_ARG`. Admin-category alerts (`replica_lag` etc.) are deliberately **not** part of this wire protocol — `vapourwaultd.conf`-only per `TASK-205`. Entirely new message pair-of-pairs, no existing byte layout changed; no protocol version bump required. |
| 23      | 2026-08-26 | PRT.04  | Filename search (§7.12), resolving `TASK-197`: new `SEARCH`/`SEARCH_RESP` (0x0901/0x0902). Server-side, scoped to `effective_permission()`'s existing visibility rule; no scoped-session support; no pagination (a 200-entry cap + `truncated` flag instead — checked this document for a cursor convention to reuse first and found none exist anywhere in it, correcting `TASK-196`'s design assumption that one did). Entirely new message pair, no existing byte layout changed; no protocol version bump required. |
| 22      | 2026-08-26 | PRT.04  | Public link password protection (§7.5), resolving `TASK-186`: `LINK_CREATE` gains an optional trailing `password` field; `LINK_ACCESS` gains an optional trailing `password` field (its previous strict `plen != 32` check becomes `plen < 32`); `LINK_LIST_RESP` gains a trailing `has_password` boolean; two new error codes `VW_ERR_LINK_PASSWORD_REQUIRED`/`_WRONG` (607/608, §10.1). The share record's Argon2id password hash is stored in previously-`_reserved` bytes with no record-size change (its salt is derived from `link_token` rather than stored, to fit — see the share-record note in §7.5); brute-force mitigation reuses the existing `LINK_ACCESS` per-IP rate limiter rather than adding a new one. Purely additive; no protocol version bump required (this table tracks spec-revision count, not wire version, per revision 16's own clarifying note below). **Note, corrected 2026-08-26**: an earlier version of this task's own design mistakenly also proposed adding `expires_at` to `LINK_CREATE` — that field already existed and was already enforced (`vw_share.c:505`) before this revision; nothing here touches expiration. |
| 21      | 2026-08-17 | SRV.01  | New error code `VW_ERR_READ_ONLY_REPLICA` (606, §10.1), resolving `TASK-179`: `vw_server_dispatch_file_op`'s single dispatch choke point now rejects every write-shaped message with this code when the server is configured as a cluster replica, before the corresponding handler runs — closes the gap `ARCHITECTURE.md`'s "Client-side automatic fallback" decision flagged, where read-only was previously enforced only by the daemon's own good behavior (`TASK-173`). Purely additive (a new error code, no existing message's byte layout changed); no protocol version bump required. Also backfills this table with two pre-existing but previously undocumented codes (`VW_ERR_IPC_NOT_RUNNING` = 700, `VW_ERR_READ_ONLY_FALLBACK` = 801) found missing while adding this row. |
| 20      | 2026-08-14 | PRT.04  | Hot-standby data replication (§7.7) published, resolving `TASK-169`/`170`: eight new cluster-channel messages (`CLUSTER_FILE_SYNC_LIST`/`_LIST_RESP`/`_FETCH`/`_DATA`, `CLUSTER_CHUNK_QUERY`/`_QUERY_RESP`/`_FETCH`/`_DATA`, `0x0708`–`0x070F`) let a replica fetch and apply the actual record each oplog entry points to — previously a replica only replicated the bare-ID oplog notification stream itself (see §7.7's own note on `vw_oplog_op_t` payloads), giving it an audit trail but no independently queryable copy of the primary's data. §7.9 (cluster channel security model) extended with this exchange's integrity/reachability guarantees and an amended "what this does NOT protect against" entry (a compromised replica now also receives password hashes/2FA secrets and full file content, not just the oplog). Cluster-channel-only (`vw-cluster/1` ALPN, never the client-facing `vw/1` listener) — no existing client-facing message's byte layout changed, no protocol version bump required. Backfilled into this table by `SRV.01` (`TASK-179`, 2026-08-17) after being found missing — the §7.7/§7.9 prose was already present in this document, but this revision's own Version History row was not. |
| 19      | 2026-08-12 | PRT.04  | `FILE_LIST_RESP` (§7.2) gains a second trailing `count * uint64 vault_id` parallel array, appended after revision 16's `version_id` array, resolving `TASK-156`. **Reverses revision 14's explicit decision** not to add this field, on the strength of concrete evidence that decision's own reasoning didn't hold up in practice: revision 14 argued populating per-entry `vault_id` for a whole listing "would mean one version lookup per entry" and that callers wanting this should `FILE_STAT` each entry of interest instead — but both real consumers that have since needed exactly this (the native GUI's `refresh_vault_badges`, capped at 200 lookups specifically *because* a real network round-trip per file is far more expensive than the in-process version lookup this array now does instead; the web gateway's folder-level-only workaround, `TASK-141`) prove the "just `FILE_STAT` it" alternative was actually costlier than the one-lookup-per-entry cost it was avoiding — doing that same lookup server-side, in-process, during the already-in-flight `FILE_LIST` call turns out to be cheaper than the escape hatch recommended instead of it. Same trailing-parallel-array technique as revision 16, for the same reason: an old client's decode loop stops after `version_id`'s array (or after the fixed-size entries, if even older) and never touches these new trailing bytes; a new client checks the payload is long enough before reading it, gated on `version_id`'s own array having been read successfully first. No protocol version bump required, matching every other purely-additive extension in this document. Directories and files with no current version encode `0` without any lookup; anything else costs exactly one `vw_store_version_get` call, the same cost `FILE_STAT` (revision 14) already pays for a single entry. |
| 18      | 2026-08-05 | ARCH.00 | Doc-only clarification (`TASK-118`): split the header's single "Current version: 10" field — which matched neither `VW_PROTO_VERSION_CURRENT` (6) nor this table's own latest row (17) — into two separately labeled fields: the actual wire-negotiated version (`VW_PROTO_VERSION_CURRENT`, still 6, unchanged) and this table's revision counter (17 at the time, now 18). No wire behavior changed. Also corrected the header's **Status** line, which still said sharing's client/GUI support (`TASK-095`/`TASK-096`) and vault (§7.11, `TASK-089`) were pending — both finished and closed (`TASK-097`, `TASK-101`) well before this correction. Reviewed and confirmed by PRT.04 (document owner) per `CLAUDE.md`. |
| 17      | 2026-08-04 | PRT.04  | **Breaking change** to the oplog entry format (§7.7), resolving `TASK-121` and `TASK-122` (both filed by GUI.03/CQR.08 out of `TASK-116`'s audit-log work): entry header gains an 8-byte `ts_unix_secs` append timestamp (advisory only — `entry_id` remains authoritative for ordering/replication), and the ambiguous `VW_OPLOG_FILE_WRITE` (0x02, meant `owner_id` on create but `file_id` on rename/update/version-write with no way to tell which) is retired in favor of explicit `VW_OPLOG_FILE_CREATE`/`VW_OPLOG_FILE_UPDATE`/`VW_OPLOG_FILE_VERSION` (0x08–0x0A). Total entry size grows from `17 + payload_len` to `25 + payload_len` bytes. This is a hard cutover, not an in-place migration — see §7.7's upgrade note; `AUDIT_RESP` (§7.6) and `OPLOG_DATA` (§7.7) both carry the new layout since they serialise raw entry bytes. Design-stage SEC.07 review (same day) found and closed a blocking gap in the initial draft: the text implied `vw_oplog_append_raw()` (replica applying a primary-sent entry) re-stamps the timestamp itself, and the draft's implementation notes missed that `src/server/vw_cluster.c`'s replica-side `OPLOG_DATA` batch-splitting loop independently hardcodes the pre-v17 17-byte header size (a third copy alongside `vw_oplog.c` and `vw_view_audit.cpp`) — left as-is, that loop would under-read every entry by 8 bytes and desync replication. Implemented as `TASK-123` (SRV.01) and `TASK-124` (GUI.03): the field shipped as `ts_unix_secs` rather than the originally-drafted `ts_unix_ms` (see §7.7's implementation note — no precedent in this codebase for ms-precision timestamps, and this field's filter-UI consumer doesn't need it), and implementation review found two *more* independent hardcoded-header-size copies beyond the three already caught (`handle_audit_query` in `vw_file_handlers.c`, and the primary-side `OPLOG_PULL` handler in `vw_cluster.c`) — all five now reference the single public `VW_OPLOG_ENTRY_HDR_BYTES` constant (`vw_oplog.h`). Full local build (MSVC, `/W4 /WX`) and unit test suite pass with no regressions. |
| 16      | 2026-08-01 | CLI.02  | `FILE_LIST_RESP` (§7.2) gains a trailing `count * uint64 version_id` parallel array, resolving `TASK-109`: the response shipped with `TASK-021` never carried `version_id` at all, silently breaking `vw_sync.c`'s ongoing remote-change detection (both sides of its comparison were permanently 0). A trailing parallel array — rather than the entry-length wrapper originally assumed necessary — lets an old client's fixed-size-per-entry decode loop simply stop after `count` entries without ever touching the new bytes, so no protocol version bump is required, matching every other extension in this document. `compute_actions` now compares the real `version_id` (same source field as `FILE_STAT_RESP`'s) alongside `mtime_unix`/`size_bytes` as defense-in-depth. |
| 15      | 2026-07-31 | CLI.02  | `FILE_LIST` (§7.2) gains an optional trailing `dir_file_id` field, resolving `TASK-106`'s core blocker: no wire mechanism let an authenticated grant-holder list a shared folder's children by file_id (only the anonymous scoped-link case could navigate a shared subtree, via its own fixed scope target). Resolved via `effective_permission()`, the same helper `FILE_COMMIT`'s directory-target branch already uses. Purely additive: old clients never send it, so `virtual_path`-based listing is unaffected; rejected for an already-scoped session, which has no legitimate use for it. No protocol version bump required. |
| 14      | 2026-07-31 | GUI.03  | `FILE_STAT_RESP` (§7.2) gains a trailing `vault_id` field, resolving a gap found implementing `TASK-100`'s encrypted-item indicators: no existing response let a browser learn a file's vault_id without a `VERSION_CHUNKS` round-trip. Always present (not absent-when-zero like `FILE_COMMIT`/`VERSION_CHUNKS_RESP`, since nothing optional follows it). `FILE_LIST_RESP` deliberately does not get the same field — see §7.2's note on why a whole-directory listing doesn't populate per-entry `vault_id`. No protocol version bump required. |
| 13      | 2026-07-31 | SRV.01  | `VERSION_CHUNKS_RESP` (§7.3) extended with optional trailing `vault_id`/`wrapped_dek` fields, resolving `TASK-099`'s download-direction wire gap flagged in version 12 (§7.11.4): a downloading client already calls `VERSION_CHUNKS` immediately before fetching chunks, so the wrapped DEK rides along on that existing round-trip rather than needing a new message. Purely additive/optional, mirroring the `FILE_COMMIT` extension exactly: an old client never reads past the hash array and is unaffected; an old server never emits the trailing fields, indistinguishable from an unencrypted version's response. No protocol version bump required. |
| 12      | 2026-07-31 | SRV.01  | Vault/E2EE (§7.11) implemented server-side, resolving `TASK-098`: `VAULT_CREATE`/`_ACK`, `VAULT_KEY_FETCH`/`_RESP`, `VAULT_LIST`/`_RESP` (0x0801–0x0806, first-ever handlers for opcodes reserved since version 8) plus the `FILE_COMMIT` `vault_id`/`wrapped_dek` extension and `vw_version_record_t`'s finalized `_reserved[32]` layout (see §7.11.4 for both). The server never sees unwrapped key material or plaintext at any point — SEC.07 confirmed no code path (including oplog replay) logs, caches, or persists anything beyond the opaque blobs the client sends. Purely additive/optional: no existing message's byte layout changed for any client that omits the two new optional `FILE_COMMIT` fields, no protocol version bump required. Client-side vault module (`TASK-099`) and the download-direction wire gap noted in §7.11.4 remain open. |
| 11      | 2026-07-31 | PRT.04  | `FILE_MKDIR`/`FILE_MKDIR_ACK` (0x0211/0x0212) defined and implemented server-side, resolving `TASK-104` — the first wire mechanism to create a `VW_ENTRY_DIR` record at all (previously only reachable via direct `vw_store_file_create` calls, bypassing the wire; see §7.2 for the full payload spec and its permission/rate-limit rules). Purely additive: no existing message's byte layout changed, no protocol version bump required. |
| 10      | 2026-07-30 | SRV.01  | Sharing (§7.5/§7.10) implemented server-side, resolving `TASK-094`. No existing message's wire byte layout changed — every SHARE_*/LINK_* message here is newly used (previous `SUB_CREATE`/`SUB_DELETE` never had a handler), and existing messages (`FILE_LIST`, `FILE_STAT`, `FILE_COMMIT`, `FILE_DELETE`, `VERSION_LIST`/`_RESTORE`/`_CHUNKS`, `CHUNK_UPLOAD`/`_DOWNLOAD_REQ`) keep their exact prior byte layout — only the server's permission-check and quota-attribution logic behind them changed. Two purely additive definitions: `FILE_MOVE`/`FILE_MOVE_ACK` (0x020F/0x0210) gets its first-ever payload (see §7.2) — the opcode existed but no handler did; error code 605 (`VW_ERR_RATE_LIMITED`, §10.1) added for the new scoped-session write-count limit. No protocol version bump required since no existing client-observable byte layout changed. |
| 9       | 2026-07-29 | SRV.01  | §7.6 documents fine-grained admin capability requirements (TASK-092, implemented — not design-stage): `USER_LIST`/`USER_SUSPEND`/`INVITE_CREATE` require `VW_CAP_USER_MGMT`, `QUOTA_ADJUST` requires `VW_CAP_QUOTA_MGMT`, `AUDIT_QUERY` requires `VW_CAP_AUDIT_READ`, `CLUSTER_STATUS` (§7.7) requires `VW_CAP_CLUSTER_MGMT`; an authenticated admin lacking the required capability now gets `VW_ERR_PERMISSION` rather than succeeding. No wire payload shapes changed — this documents new server-side authorization behavior on existing messages. CQR.08 finding: the doc previously described only the blanket `is_admin` gate |
| 8       | 2026-07-29 | ARCH.00 | Vault/E2EE design published (§7.11): `VAULT_CREATE`/`_ACK` (0x0801/0x0802), `VAULT_KEY_FETCH`/`_RESP` (0x0803/0x0804), `VAULT_LIST`/`_RESP` (0x0805/0x0806); envelope-encryption key model, per-file DEK/nonce scheme, dedup interaction, and metadata-scope boundary specified. Same-day revision after SEC.07 design review: nonce derivation changed from random-prefix+counter to deterministic `HKDF(DEK, chunk_index)` (closes a retry-triggered GCM-nonce-reuse gap); explicit DEK-per-file (not per-vault) guardrail added; Argon2id parameter floor pinned; per-version-DEK/delta-sync tradeoff explicitly accepted (ARCH.00 sign-off). Design-stage only — resolves the design half of `TASK-089`; implementation tracked as `TASK-098`–`TASK-101` |
| 7       | 2026-07-29 | ARCH.00 | Sharing + public links design published (§7.5, §7.10): full `SHARE_GRANT`/`SHARE_REVOKE`/`SHARE_LIST` payloads specified (previously only `SHARE_GRANT` had a payload); `SUB_CREATE`/`SUB_DELETE` (0x0507–0x050A, never implemented) repurposed as `LINK_CREATE`/`LINK_REVOKE`; new `LINK_LIST`/`_RESP` (0x050B/0x050C) and unauthenticated `LINK_ACCESS`/`LINK_ACCESS_ACK` (0x050D/0x050E) added for public read/edit links, reusing the `INVITE_REDEEM` unauthenticated-session-establishment pattern; permission-check rule and quota-resolution rule specified. Same-day revision after CQR.08/SEC.07 design review: `permission` field reconciled with the existing `vw_perm_t` enum instead of a parallel READ/EDIT scheme; per-operation required-permission table added; `FILE_MOVE` ownership/cycle rules added (closes a quota/visibility-hijack gap); `SHARE_GRANT`/`_REVOKE`/`LINK_CREATE`/`_REVOKE` restricted to authenticated (non-scoped) sessions; scoped-session write-count rate limiting added (closes an unauthenticated write-DoS gap); scoped-session root-navigation behavior specified. Design-stage only — resolves the design half of `TASK-088`; implementation tracked as `TASK-094`–`TASK-097` |
| 6       | 2026-07-13 | PRT.04  | Phase 7 cluster: full payload specs for `NODE_HELLO` (0x0701), `NODE_HELLO_OK` (0x0702), `NODE_HELLO_FAIL` (0x07FF, new), `OPLOG_PULL` (0x0703), `OPLOG_DATA` (0x0704), `OPLOG_ACK` (0x0705, new), `CLUSTER_STATUS_RESP` (0x0707, new); §7.9 cluster channel security model added; resolves TASK-047 |
| 5       | 2026-07-12 | PRT.04  | Phase 6 invite + recovery: `AUTH_RECOVER_REQUEST` (0x0108), `AUTH_RECOVER_CONFIRM` (0x0109), `AUTH_RECOVER_OK` (0x010A), `AUTH_RECOVER_FAIL` (0x010B) added; `INVITE_CREATE`/`_ACK`/`INVITE_REDEEM`/`_ACK` (0x0609–0x060C) payload specs published; resolves TASK-044 |
| 4       | 2026-07-11 | PRT.04  | Phase 2 file transfer spec: `session_token[32]` added to all C→S file op payloads; `CHUNK_QUERY` count widened from uint32 to uint16 (max 1024); `VERSION_CHUNKS` / `VERSION_CHUNKS_RESP` (0x0305/0x0306) added; §7.8 File Transfer Security Model added; error codes 305–306 and 600–604 added; resolves TASK-021 |
| 3       | 2026-07-10 | PRT.04  | AUTH_OK: `user_id` (uint64 LE) appended after `used_bytes`; resolves TASK-020 / CQR.08-B-2 |
| 2       | 2026-07-06 | PRT.04  | AUTH_FAIL: `lockout_remaining_secs` widened from u8 to u16; 10-minute (600s) OTP lockout window exceeds u8 max (255s) |
| 1       | 2026-06-23 | PRT.04  | Initial specification      |
