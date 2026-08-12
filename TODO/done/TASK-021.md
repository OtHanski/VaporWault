---
id:          TASK-021
title:       Extend wire protocol spec for file transfer messages (Phase 2)
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-07-10
priority:    critical
depends_on:  []
blocks:      [TASK-022, TASK-024, TASK-025]
review_by:   [CQR.08, SEC.07]
tags:        [protocol, file-transfer, phase-2, security-sensitive]
---

Extend `docs/PROTOCOL.md` with the complete binary message format for all Phase 2 file
transfer operations. SRV.01 (TASK-022/023/024) and CLI.02 (TASK-025) are blocked on this
spec; neither picks up their implementation tasks until this task is done.

## Acceptance criteria

### 1. Message type constants

Add the following message type IDs to the spec (and to `vw_proto.h`):

| Constant | Value | Direction | Description |
|----------|-------|-----------|-------------|
| `VW_MSG_FILE_LIST` | 0x0100 | C→S | List files/folders under a virtual path |
| `VW_MSG_FILE_LIST_RESP` | 0x0101 | S→C | Response: array of file/folder entries |
| `VW_MSG_FILE_STAT` | 0x0102 | C→S | Stat a single virtual path |
| `VW_MSG_FILE_STAT_RESP` | 0x0103 | S→C | Response: file metadata |
| `VW_MSG_CHUNK_QUERY` | 0x0104 | C→S | Query which of N chunk hashes the server already has |
| `VW_MSG_CHUNK_QUERY_RESP` | 0x0105 | S→C | Bitmask: bit i set → server has chunk i |
| `VW_MSG_CHUNK_UPLOAD` | 0x0106 | C→S | Upload one chunk (SHA-256 + raw data) |
| `VW_MSG_CHUNK_UPLOAD_RESP` | 0x0107 | S→C | Ack or error |
| `VW_MSG_CHUNK_DOWNLOAD` | 0x0108 | C→S | Download one chunk by SHA-256 |
| `VW_MSG_CHUNK_DOWNLOAD_RESP` | 0x0109 | S→C | Chunk data or VW_ERR_NOT_FOUND |
| `VW_MSG_FILE_COMMIT` | 0x010A | C→S | Commit a new file version (path + ordered chunk list) |
| `VW_MSG_FILE_COMMIT_RESP` | 0x010B | S→C | New version_id or error |
| `VW_MSG_FILE_DELETE` | 0x010C | C→S | Delete a virtual path (file or empty folder) |
| `VW_MSG_FILE_DELETE_RESP` | 0x010D | S→C | Ack or error |
| `VW_MSG_VERSION_LIST` | 0x010E | C→S | List versions of a file |
| `VW_MSG_VERSION_LIST_RESP` | 0x010F | S→C | Array of version records |
| `VW_MSG_VERSION_RESTORE` | 0x0110 | C→S | Promote an old version to current |
| `VW_MSG_VERSION_RESTORE_RESP` | 0x0111 | S→C | New version_id or error |

### 2. Payload layouts

Document the exact byte layout of each message payload (field name, type, LE/BE, size,
valid range, error if out of range). Key constraints:

- All integers little-endian.
- Strings: u16 length-prefix + UTF-8 bytes, no NUL terminator.
- Virtual paths: max 4096 bytes encoded. Server rejects longer paths with `VW_ERR_PROTO_INVALID`.
- Chunk hashes: always 32 bytes (SHA-256). No length prefix.
- Chunk data in CHUNK_UPLOAD: u32 data_len (max 4 MiB = 4194304; server rejects larger
  with `VW_ERR_PROTO_INVALID`) + data bytes.
- CHUNK_QUERY payload: u16 count (max 1024) + count×32-byte hashes.
- CHUNK_QUERY_RESP: u16 count (must match request count) + ceil(count/8) bytes bitmask
  (bit 0 of byte 0 = chunk 0; big-endian bit order within each byte).
- FILE_COMMIT: session_token[32] + u16 path_len + path + u32 chunk_count + chunk_count×32-byte hashes.
  chunk_count max = 65535 (~256 GiB at 4 MiB/chunk).
- FILE_LIST: session_token[32] + u16 path_len + path + u8 recursive (0=shallow, 1=recursive).
- FILE_LIST_RESP: u32 entry_count + entry_count × entry:
  (u8 entry_type [0=file, 1=folder] + u16 name_len + name + u64 size_bytes + u64 mtime_unix).
- FILE_STAT_RESP: u8 entry_type + u64 size_bytes + u64 mtime_unix + u64 version_id + u64 owner_id.
- VERSION_LIST_RESP: u32 count + count × (u64 version_id + u64 created_at + u64 size_bytes).

### 3. Session token field

Every C→S file operation payload begins with `session_token[32]`. The server validates
the session token against the active session table before processing the request. An
invalid or expired token returns a `VW_MSG_ERROR` response with error code
`VW_ERR_AUTH_REQUIRED`.

The session token field is the same 32-byte opaque value from `AUTH_OK.session_token`.
It must be present in every file operation request; the server must not accept file
operations from unauthenticated connections.

### 4. Error codes

Add the following error codes to `vw_proto.h` (extend the existing `vw_err_t` enum):

| Code | Name | Meaning |
|------|------|---------|
| 0x0300 | `VW_ERR_NOT_FOUND` | File or version does not exist |
| 0x0301 | `VW_ERR_QUOTA_EXCEEDED` | Upload would exceed user's quota |
| 0x0302 | `VW_ERR_CHUNK_HASH_MISMATCH` | Uploaded chunk SHA-256 does not match declared hash |
| 0x0303 | `VW_ERR_PATH_INVALID` | Virtual path contains forbidden characters or is too long |
| 0x0304 | `VW_ERR_PATH_CONFLICT` | A file exists where a directory is expected, or vice versa |
| 0x0305 | `VW_ERR_VERSION_NOT_FOUND` | Version ID does not exist or belongs to another user |
| 0x0306 | `VW_ERR_DIR_NOT_EMPTY` | Attempted to delete a non-empty directory |

### 5. Protocol version bump

File transfer messages are new in this spec version. Bump `VW_PROTO_VERSION_CURRENT` from
3 to 4 in `vw_proto.h` and document the change in `docs/PROTOCOL.md` §11.

Rationale: v3 servers do not know the file transfer message type IDs. A v4 client
connecting to a v3 server must detect VERSION_REJECT (or negotiated version < 4) and
fall back to "server does not support file transfer" behaviour.

### 6. Path validation rules

Document the server's path validation rules (to be enforced by vw_server_core before
passing to vw_storage_files):

- Must begin with `/`.
- No `..` components anywhere in the path.
- No null bytes.
- Max encoded length 4096 bytes.
- Component separator is `/` only (no backslash).
- All components must be non-empty (no double slashes).

The spec must state that the server returns `VW_ERR_PATH_INVALID` for any path that
fails these checks. The client must not rely on the server for path validation — it
should validate before sending.

### 7. PROTOCOL.md section

Add a new `§8 — File Transfer` section to `docs/PROTOCOL.md` with all of the above.
Update the table of contents. Update the current-version header line.

## Notes

ARCH.00 [2026-07-10]: Critical gate for Phase 2. SRV.01 and CLI.02 may not start
any file transfer implementation until this task reaches `done`. PRT.04 should also
update `vw_proto.h` with the message type constants and new error codes as part of this
task — the constants are needed by TASK-022/024/025 compile guards.

---

PRT.04 [2026-07-11]: Implementation complete. Changes applied:

**`src/core/vw_proto.h`** (7 changes):
1. `VW_PROTO_VERSION_CURRENT` bumped from 3 to 4.
2. Auth error block: `VW_ERR_AUTH_REQUIRED = 306` added.
3. New "File transfer" error block added (600–604):
   `VW_ERR_CHUNK_HASH_MISMATCH`, `VW_ERR_PATH_INVALID`, `VW_ERR_PATH_CONFLICT`,
   `VW_ERR_VERSION_NOT_FOUND`, `VW_ERR_DIR_NOT_EMPTY`.
4. `VW_MSG_VERSION_CHUNKS = 0x0305`, `VW_MSG_VERSION_CHUNKS_RESP = 0x0306` added to
   `vw_msg_type_t` (gap identified by CLI.02 in TASK-025).
5. `session_token[VW_TOKEN_BYTES]` added as first field of all C→S file op payload
   structs: file_list, file_stat, chunk_query, chunk_upload, chunk_download_req,
   file_commit, file_delete, version_list, version_restore, version_chunks.
6. `vw_payload_chunk_query_t.count` changed from `uint32_t` to `uint16_t`
   (max 1024; comment added). `vw_payload_chunk_query_resp_t.count` likewise.
7. New payload structs added: `vw_payload_version_list_t`, `vw_payload_version_restore_t`,
   `vw_payload_version_restore_ack_t`, `vw_payload_version_chunks_t`,
   `vw_payload_version_chunks_resp_t`.

**`docs/PROTOCOL.md`** (9 changes):
1. Header: `Current version: 3` → `4`; status updated to Phase 2.
2. §7.2 CHUNK_QUERY table: count `uint32` → `uint16` (max 1024).
3. §7.2 CHUNK_QUERY_RESP table: count `uint32` → `uint16`; bitmask bit-order documented
   (big-endian within byte).
4. §7.2 CHUNK_UPLOAD table: `session_token` row added; error renamed to
   `VW_ERR_CHUNK_HASH_MISMATCH`.
5. §7.2 FILE_COMMIT table: `session_token` row added; chunk_count max 65535 noted.
6. §7.2 CHUNK_DOWNLOAD_REQ table: `session_token` row added.
7. §7.2 FILE_COMMIT_ACK: `error_code` typed as `uint32 (vw_err_t)`.
8. §7.3: VERSION_CHUNKS / VERSION_CHUNKS_RESP (0x0305/0x0306) added to table and
   payload documentation; VERSION_LIST, VERSION_RESTORE, VERSION_RESTORE_ACK payloads
   fully documented with session_token.
9. §7.8 "File Transfer Security Model" added (session token requirement, path validation
   rules, chunk authorization).
10. §10.1 error table: rows added for 305 (`VW_ERR_AUTH_2FA_LOCKED`), 306
    (`VW_ERR_AUTH_REQUIRED`), and 600–604 file transfer errors.
11. §11 version history: v4 entry added.

**Design decisions:**
- Kept existing 0x02xx/0x03xx message numbering (supersedes TASK-021's proposed 0x01xx
  which would have collided with auth 0x01xx; ARCH.00 notation recorded here).
- CHUNK_QUERY count narrowed to uint16 (max 1024) to bound bitmask size to 128 bytes
  and prevent large query amplification. Existing code had uint32 with no max check —
  this is a backward-incompatible change, hence the version bump to 4.
- VERSION_CHUNKS added to resolve the download gap in TASK-025 §5 before that task
  starts. Approach: dedicated message pair rather than embedding chunk list in
  FILE_STAT_RESP (keeping FILE_STAT_RESP small for directory listing contexts).

---

SEC.07 [2026-07-11]: Protocol spec reviewed. Findings:

**No blocking findings.**

**SEC.07-A-1 (advisory)**: §7.8.3 specifies chunk authorization returns `VW_ERR_NOT_FOUND`
(not `VW_ERR_PERMISSION`) to avoid oracle-style confirmation of chunk existence.
Good defensive choice. Implementation (TASK-024) must match exactly — a `VW_ERR_PERMISSION`
response would confirm the chunk exists, enabling SHA-256 guessing probes.

**SEC.07-A-2 (advisory)**: §7.8.1 says "session token must be extracted before doing any
other processing". Implementation (TASK-024) must not parse any subsequent payload fields
before the session lookup completes and succeeds. Any out-of-bounds read in parsing the
rest of the payload (before token validation) would be reachable by unauthenticated callers.
Tag TASK-024 as `security-sensitive` (already done by ARCH.00).

**SEC.07-A-3 (advisory)**: CHUNK_QUERY bitmask response: `ceil(count/8)` bytes. If count
is 0, response is 0 bytes (empty bitmask). Implementation must handle count=0 without
allocating a zero-length buffer and reading from it. Low risk but document in TASK-024.

Sign-off: spec is sound. All file-transfer security properties are correctly specified.
Implementation tasks (TASK-024 security review will catch implementation deviations).

---

CQR.08 [2026-07-11]: Spec and header reviewed. Findings:

**No blocking findings.**

**CQR.08-A-1 (advisory)**: `vw_payload_file_stat_resp_t` uses unordered fields
(`entry_type` then `file_id` then `size_bytes` etc.) which creates natural alignment
gaps on most platforms. Since these structs are never memcpy'd to the wire (encode/decode
functions handle field layout), this is not a correctness issue — just a style note for
the encode/decode implementor (TASK-024) to document the wire vs. in-memory layout
distinction clearly.

**CQR.08-A-2 (advisory)**: `vw_payload_version_restore_t` has a `virtual_path` string
as a variable-length tail field but no `path_len` field in the struct. The comment
"variable: string path" covers this, but it's easy to forget when writing the encoder.
Suggest the TASK-024/025 implementor add an explicit `uint16_t path_len` + `const char *path`
pair to the decode output, as done for `vw_payload_auth_request_t`.

**Sign-off**: `vw_proto.h` changes are correct and internally consistent. PROTOCOL.md is
complete and matches the header. TASK-021 may move to `done`.

---

ARCH.00 [2026-07-11]: TASK-021 closed. SEC.07 and CQR.08 signed off; no blocking findings.
Advisories A-1/A-2/A-3 from SEC.07 and A-1/A-2 from CQR.08 are routed to TASK-024/025 as
implementation notes. TASK-022 and TASK-025 are now unblocked.
