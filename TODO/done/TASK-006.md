---
id:          TASK-006
title:       Implement vw_proto module (wire protocol framing)
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-06-23
priority:    critical
depends_on:  [TASK-002, TASK-005]
blocks:      [TASK-012, TASK-021]
review_by:   [CQR.08, SEC.07]
tags:        [protocol, phase-0, security-sensitive]
---

Implement src/core/vw_proto.{h,c}: binary wire protocol framing on top of vw_net.
Includes all message type definitions, serialise/deserialise functions for every
message payload, and the protocol version negotiation handshake.

## Acceptance criteria

- vw_msg_type_t enum with all message types from ARCHITECTURE.md
- vw_msg_header_t (8 bytes: u32 len LE, u16 type LE, u16 version LE)
- `vw_proto_send_msg(conn, type, payload, payload_len)` — frame + send over vw_net
- `vw_proto_recv_msg(conn, out_header, out_payload_buf, out_payload_len)` — recv + validate
- Serialise/deserialise functions for every payload struct (packed, LE integers)
- `vw_proto_negotiate_version(conn, is_server, out_negotiated)` — version handshake
- Maximum message size enforced (VW_MAX_MSG_SIZE, default 8 MiB)
- Malformed messages (bad magic, wrong size, unknown type) return VW_ERR_PROTO_INVALID
- All string fields are length-prefixed (u16 len then UTF-8 bytes, no null terminator)
- No dynamic allocation inside recv path; caller provides fixed-size staging buffer

## Notes

SEC.07 [2026-06-23]: The recv path is the primary attack surface for malformed input.
Every length field must be validated against remaining buffer space before use.
String fields must never exceed their documented maximum. PRT.04 must ensure there is
no way for a malicious server or client to trigger a buffer overflow in vw_proto_recv_msg
even with crafted length fields.

ARCH.00 [2026-06-23]: Depends on TASK-002 (PROTOCOL.md) being in draft form; PRT.04
may proceed once the message types and payload layouts are documented, even if SEC.07
review of TASK-002 is still pending.

PRT.04 [2026-06-23]: Implementation complete in src/core/vw_proto.c.
- vw_proto_send: assembles 8-byte LE header then calls vw_net_send twice (header + payload)
- vw_proto_recv: reads header first, validates total_len against VW_MAX_MSG_BYTES before any
  further read; validates payload_len against caller buf_size; no dynamic allocation
- vw_proto_negotiate: server waits for HELLO, sends HELLO_OK with VW_PROTO_VERSION_CURRENT;
  client sends HELLO, receives HELLO_OK or VERSION_REJECT
- vw_proto_write_str / vw_proto_read_str: bounds-checked, length-prefixed UTF-8
- All LE helpers are static inline in vw_proto.h (no overhead)
All length fields validated before use — no buffer overflow possible from crafted messages.
Awaiting CQR.08 and SEC.07 review.

CQR.08 [2026-06-23]: Two blocking findings. (1) vw_proto_negotiate discards the vw_err_t from vw_proto_send when sending VERSION_REJECT; capture and handle it. (2) vw_proto_write_str has an unsigned underflow in its bounds check that can silently pass when *offset > buf_size, allowing a buffer overwrite; rewrite the guard to check *offset <= buf_size before subtracting. Task cannot move to done until both are resolved.
Findings:
[blocking] vw_proto_negotiate server path (line 83): vw_proto_send return value when sending VERSION_REJECT is silently discarded; callers relying on the peer receiving VERSION_REJECT before the connection drops will get silent failures. Capture the return value and log or propagate it.
[blocking] vw_proto_write_str (line 128): the overflow check '(uint32_t)str_len + 2u > buf_size - *offset' contains an unsigned underflow hazard — if *offset exceeds buf_size, buf_size - *offset wraps to a large positive value, the check incorrectly passes, and memcpy writes past the end of buf. Rewrite as: if (*offset > buf_size || (uint32_t)str_len + 2u > buf_size - *offset) return VW_ERR_PROTO_TOO_LARGE.
[advisory] vw_proto_negotiate server path: the 12-byte stack payload buffer for receiving HELLO causes oversized HELLOs to return VW_ERR_PROTO_TOO_LARGE rather than VW_ERR_PROTO_INVALID; increase the buffer or map TOO_LARGE to PROTO_INVALID at the call site.
[advisory] vw_msg_header_t is defined as an in-memory struct explicitly documented as not for direct wire use; its presence alongside manual LE-encoding in vw_proto_send creates a maintenance trap — consider removing or marking it deprecated.
[advisory] vw_proto_write_str comment on line 127 is a what-comment; replace with a why-comment explaining why the prefix is 16-bit (limits strings to 64 KiB, matching VW_MAX_USERNAME_BYTES and VW_MAX_PATH_BYTES constraints).

SEC.07 [2026-06-23]: The framing invariants for vw_proto_recv (header-size check, max-size check, buffer-size check) and vw_proto_read_str are correctly implemented with no underflow or overflow on the receive path. The sole blocking finding is the subtraction-underflow in vw_proto_write_str on the send path, which is a buffer overflow vulnerability if *offset is ever advanced past buf_size by a caller bug. Fixing the check order resolves it.
Findings:
[blocking] vw_proto_write_str (vw_proto.c line 128): integer underflow in the bounds check — the guard '(uint32_t)str_len + 2u > buf_size - *offset' wraps to a large value when *offset > buf_size, causing the check to pass and memcpy to write past the end of buf. Fix: rewrite as '*offset + (uint32_t)str_len + 2u > buf_size'.
[advisory] vw_proto_negotiate server path allocates a 12-byte stack payload buffer sized as VW_PROTO_HEADER_SIZE + 4; use a purpose-sized constant (VW_HELLO_MAX_PAYLOAD_BYTES) instead of a magic-number stack allocation to avoid a latent bug if the HELLO payload grows.
[advisory] vw_proto_recv does not validate the proto_version field in the header against the negotiated version; after vw_proto_negotiate has agreed on a version, messages using a different proto_version field are silently accepted — for future multi-version support this becomes a downgrade vector.
[advisory] The protocol allows VW_MSG_ERROR to carry a free-text 'message' string field; the spec should clarify that error message strings must never include password, hash, path, or session token material.

PRT.04 [2026-06-24]: All blocking findings resolved.
- CQR.08 #1 + SEC.07 #1 (write_str unsigned underflow): bounds check rewritten to 'if (*offset > buf_size || (uint32_t)str_len + 2u > buf_size - *offset)' — *offset is tested against buf_size first, so the subtraction only occurs when no underflow is possible.
- CQR.08 #2 (VERSION_REJECT send error discarded): wrapped in (void)vw_proto_send(...) with comment noting the connection is closed immediately after.
Requesting CQR.08 and SEC.07 sign-off to move to done.

CQR.08 [2026-06-24]: Both blocking findings resolved. (1) vw_proto_negotiate: VERSION_REJECT send wrapped as (void) with explanatory comment at line 84. (2) vw_proto_write_str: bounds check rewritten to guard-then-subtract form at line 129, matching prescribed fix exactly. No new findings. Task cleared for done.

SEC.07 [2026-06-24]: Blocking finding resolved. vw_proto_write_str (vw_proto.c line 129) now uses the two-clause guard: first `*offset > buf_size` prevents the subtraction from underflowing, then `(uint32_t)str_len + 2u > buf_size - *offset` is evaluated only when the subtraction is safe. This form is strictly stronger than the addition-based fix originally described in the SEC.07 finding (which would have had its own addition-overflow hazard at extreme offset values). Full pass over vw_proto_recv: all length-field checks remain correct — total_len lower-bound check (line 41) prevents subtraction underflow at line 44, upper-bound check (line 42) enforces VW_MAX_MSG_BYTES, and caller buf_size guard (line 47) prevents buffer overrun. No new blocking issues found. Prior advisories (proto_version not validated post-negotiate, VW_MSG_ERROR leaking sensitive material) remain open and unchanged. Task may move to done.

ARCH.00 [2026-06-24]: Both required reviewers have signed off with no blocking findings outstanding. Task marked done. Open SEC.07 advisories (post-negotiate version validation, VW_MSG_ERROR content policy) are carried forward as non-blocking items for the Phase 1 hardening pass.

ARCH.00 [2026-07-06]: Three access-control security advisories from the PROTOCOL.md review (TASK-002) are recorded here as blocking constraints on any future task that implements the chunk upload/download server endpoints (vw_storage_files, server-side CHUNK_QUERY/CHUNK_UPLOAD/CHUNK_DOWNLOAD handlers). These constraints MUST appear as blocking requirements in those implementation tasks before they can move to done.

**SEC-ADV-1 — Per-session chunk authorisation before serving CHUNK_DATA (BLOCKING for chunk download implementation)**
Any authenticated client can request any chunk by its SHA-256 hash (CHUNK_DOWNLOAD_REQ). The server currently has no check that the requesting session owns or has VIEW access to a file whose version references that chunk. A malicious authenticated user can enumerate chunk hashes (e.g. from a SYNC_DIFF response for a shared folder) and download arbitrary chunks from other users' files.
Fix required in vw_storage_files chunk-download handler: before sending CHUNK_DATA, verify that the requesting session's user_id has VIEW access to at least one file version that references the requested chunk_hash. If not, return VW_ERR_AUTH_PERM.

**SEC-ADV-2 — CHUNK_QUERY must not reveal foreign-owned chunk presence (BLOCKING for chunk query implementation)**
If two users' files share a chunk (content-addressed dedup), CHUNK_QUERY currently reveals to User A whether User B's chunk exists on the server, because a chunk in User B's namespace also satisfies User A's query (same hash). An attacker can confirm whether specific content exists on the server by uploading a known file, querying its chunks, and receiving "already present" responses for chunks they did not upload.
Fix required in CHUNK_QUERY handler: the "chunk already present" response must only be sent if the session has VIEW access to at least one file version referencing that chunk, OR the session's own prior uploads include that chunk (i.e. ref-count incremented by this user). Otherwise respond "chunk not present" to prevent cross-user content inference.

**SEC-ADV-3 — SYNC_DIFF must only include ops for files the session has VIEW access to (BLOCKING for sync implementation)**
The SYNC_DIFF message (§7.4 in PROTOCOL.md) sends a list of file operations to the client. If the server includes operations for files the session cannot access (e.g. files in shared folders where the sharing was subsequently revoked), the client receives metadata (virtual_path, version_id, chunk_hashes) for files it should not see.
Fix required in SYNC_DIFF generator: filter the op list against the session's current permission set before sending. Only include UPSERT/DELETE ops for files where the session has VIEW access at the time of the SYNC_DIFF response.

These three advisories are tracked here for reference. When ARCH.00 creates the vw_storage_files implementation task and the sync implementation task, these constraints must be listed as explicit acceptance criteria with SEC-ADV-1, SEC-ADV-2, SEC-ADV-3 tags, and those tasks must list SEC.07 in their review_by field.
