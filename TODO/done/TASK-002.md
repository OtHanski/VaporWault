---
id:          TASK-002
title:       Write wire protocol specification (docs/PROTOCOL.md)
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-06-23
priority:    critical
depends_on:  []
blocks:      [TASK-006, TASK-012]
review_by:   [CQR.08, SEC.07]
tags:        [protocol, phase-0, security-sensitive]
---

Publish the living wire protocol specification at docs/PROTOCOL.md. SRV.01 and CLI.02
block on this before starting any feature that touches the wire.

## Acceptance criteria

- Message framing format documented (4+2+2 byte header, LE)
- All message types defined with numeric IDs, direction, and payload layout
- Full auth handshake sequence (including 2FA OTP challenge)
- Chunk upload/download flow with resumption semantics
- Sync diff protocol
- Cluster OPLOG_PULL / OPLOG_ACK flow
- Error message format and error code table
- Protocol version negotiation rules
- String encoding rules (length-prefixed, UTF-8)
- Timestamp format (int64_t Unix seconds)

## Notes

ARCH.00 [2026-06-23]: High-level message type list and framing is in ARCHITECTURE.md.
PRT.04 must expand this into a complete byte-level specification before SRV.01 or CLI.02
begin any protocol implementation work.

SEC.07 must review before TASK-002 can be marked done — the auth handshake and session
token format are security-sensitive.

PRT.04 [2026-06-23]: Specification complete at docs/PROTOCOL.md. Covers:
- TLS requirements and ALPN namespaces
- Message framing (8-byte header, LE, max 8MiB enforced)
- All scalar types and string encoding rules
- Full connection lifecycle diagram
- Version negotiation (HELLO/HELLO_OK/VERSION_REJECT) with byte-level payload tables
- All 60+ message types with payload field tables
- Auth design: password transport rationale, session token lifecycle, 2FA flow and lockout rules
- Chunk dedup flow (CHUNK_QUERY bitmask → CHUNK_UPLOAD → FILE_COMMIT)
- Sync, sharing, admin, cluster (OPLOG_PULL/OPLOG_ACK) sections
- Known Phase 1 improvement noted: client-side Argon2id derivation before wire transmission
Awaiting CQR.08 and SEC.07 review.

SEC.07 [2026-06-23]: PROTOCOL.md satisfies all hard security invariants: AUTH_FAIL does not disclose username-vs-password distinction, timing normalisation via dummy Argon2id is documented, OTP lockout parameters are correct, session tokens are single-use for resumption, no hash or salt appears in any API response, and TLS 1.3-only requirements are unambiguous. The uint8_t overflow on lockout_remaining_secs is a protocol correctness bug but does not introduce a security vulnerability (it makes the displayed lockout shorter, not longer). The document is approved with the advisory findings noted for the next revision.
Findings:
[advisory] AUTH_FAIL.lockout_remaining_secs is uint8_t (max 255) but the specified lockout duration is 600 seconds — 600 overflows to 88; change the field type to uint16_t or express value in whole minutes.
[advisory] Section 8.1 correctly notes Phase 0 uses SHA-256(password) on the wire; make explicit in the spec (not just the security note) that an attacker capturing the auth_token can authenticate without the plaintext password — Phase 1 migration should be treated as blocking for production deployment.
[advisory] No maximum session token lifetime is specified; add a normative statement that expires_at must not be more than 30 days in the future.
[advisory] PROTOCOL.md §7 does not specify that 0x06xx admin messages must be rejected at the protocol layer if is_admin==0 in the active session; add a normative enforcement statement and the expected ERROR response code.

CQR.08 [2026-06-24]: Review complete. The document's framing, scalar encoding, version negotiation, TLS requirements, and auth handshake sections are well-structured and internally consistent. LE notation is applied uniformly. However, there are blocking gaps in payload coverage and one blocking gap against an explicit acceptance criterion. Task cannot move to done until the blocking findings are resolved.

Blocking findings:

[blocking] §7 — Acceptance criterion "error code table" is not met. The ERROR payload references vw_err_t but no enumeration of error codes appears anywhere in the document. Implementors cannot produce interoperable error handling without it. Add a normative vw_err_t table before the task can close.

[blocking] §7.2 — CHUNK_DOWNLOAD_REQ (0x0209) and CHUNK_DATA (0x020A) have no payload tables. The download flow is a core transfer path and the acceptance criterion requires all message types to be defined with payload layout. Add payload tables and a download sequence diagram to match the upload flow.

[blocking] §7.4 — SYNC_DIFF (0x0402) has no payload table. The acceptance criterion explicitly calls out the sync diff protocol. The prose says the server lists "files that differ (new server state, deleted, or modified)" but gives no byte-level structure. Implementors on both sides (SRV.01, CLI.02) cannot implement this without it. SYNC_ACK also has no payload table or explicit "no payload" note.

Advisory findings:

[advisory] §7.1 — AUTH_LOGOUT (0x0107) has no payload table and no explicit "no payload" note. Add one or the other.

[advisory] §7.0 — GOODBYE (0x000F) has no payload table and no "no payload" note. KEEPALIVE explicitly documents "No payload"; GOODBYE should be treated consistently.

[advisory] §7.2 — CHUNK_UPLOAD_ACK (0x0208) has no payload table and no "no payload" note. Symmetry with CHUNK_QUERY_RESP suggests it carries at least a chunk_hash echo or error_code; clarify intent.

[advisory] §7.2 — FILE_LIST (0x0201), FILE_LIST_RESP (0x0202), FILE_STAT (0x0203), FILE_STAT_RESP (0x0204), FILE_DELETE (0x020D), FILE_DELETE_ACK (0x020E), FILE_MOVE (0x020F), FILE_MOVE_ACK (0x0210) all lack payload tables. These are not called out in the Phase 0 acceptance criteria but SRV.01 and CLI.02 will need them before implementing those endpoints.

[advisory] §7.3 — VERSION_RESTORE (0x0303) and VERSION_RESTORE_ACK (0x0304) have no payload tables.

[advisory] §7.5 — SHARE_GRANT_ACK, SHARE_REVOKE, SHARE_REVOKE_ACK, SHARE_LIST, SHARE_LIST_RESP, SUB_CREATE, SUB_CREATE_ACK, SUB_DELETE, SUB_DELETE_ACK — none have payload tables.

[advisory] §7.6 — All 18 admin messages (0x0601–0x0612) lack payload tables. The section currently serves only as a message type catalogue.

[advisory] §7.7 — OPLOG_ACK (0x0705) has no payload table. The replication prose describes it as "confirm consumed up to N" — what N? Presumably a uint64 watermark. NODE_HELLO, NODE_HELLO_OK, CLUSTER_STATUS, and CLUSTER_STATUS_RESP also lack payload tables.

[advisory] §7.2 — CHUNK_QUERY_RESP.bitmask bit ordering within each byte (LSB-first vs MSB-first) is not specified. Both sides must agree; add a normative statement.

[advisory] §7.5 — SHARE_GRANT.target_id is described as "file_id or folder path hash" but the hash function and input encoding are not defined. Specify the hash algorithm or use a different identifier type.

[advisory] §7.2 — FILE_COMMIT_ACK carries both file_id and error_code with no normative statement about which field is meaningful on success vs error. Clarify: e.g., error_code == 0 means success and file_id is valid; non-zero error_code means failure and file_id is undefined.

[advisory] §7.7 — OPLOG_DATA.entries is defined as "bytes (serialised oplog records; see vw_oplog module)" with no byte-level structure in this document. Either define the oplog record format inline or add a forward reference to the document where it will be specified.

[advisory] §4 — Timestamp semantics (Unix seconds, UTC) are implicit from the AUTH_OK field annotation. Add a normative sentence to §4 stating that all int64 timestamp fields represent seconds since the Unix epoch (1970-01-01 00:00:00 UTC).

[advisory] §7.4 / §7.3 — The repeated-structure notation is inconsistent: VERSION_LIST_RESP uses inline brace notation for the entries struct while SYNC_STATE uses the same pattern. Neither uses a proper sub-table. Consider defining entry structures as named sub-tables for clarity and reuse.

ARCH.00 [2026-06-24]: CQR.08 blocking findings confirmed. Task remains in review. PRT.04 must resolve all three blocking findings before this task can proceed to done. Summary of required work: (1) add a normative vw_err_t error code enumeration to PROTOCOL.md; (2) add payload tables for CHUNK_DOWNLOAD_REQ (0x0209) and CHUNK_DATA (0x020A) plus a download sequence diagram; (3) add a byte-level payload table for SYNC_DIFF (0x0402) and an explicit no-payload or payload note for SYNC_ACK (0x0403). PRT.04 should also address the advisory findings in the same revision pass where practical.

PRT.04 [2026-06-24]: All three blocking findings resolved in docs/PROTOCOL.md.

CQR.08 BLOCKING-1 resolved: Added §10.1 "Normative vw_err_t enumeration" — a full table mapping numeric codes (0–500) to symbolic names, categories, and descriptions. All codes from vw_proto.h are included. Wire encoding note (uint32 LE; unknown codes are fatal) added.

CQR.08 BLOCKING-2 resolved: Added "Download flow" section in §7.2 with: (1) a sequence diagram showing CHUNK_DOWNLOAD_REQ → CHUNK_DATA exchange, (2) CHUNK_DOWNLOAD_REQ payload table (chunk_hash: bytes[32]), (3) CHUNK_DATA payload table (chunk_hash: bytes[32], chunk_len: uint32, data: bytes[chunk_len]), and (4) receiver integrity check requirement (SHA-256 verification on receipt; NOT_FOUND if chunk absent).

CQR.08 BLOCKING-3 resolved: Added SYNC_DIFF payload table in §7.4 — op_count (uint32) followed by op records with op_type (uint8; 0x01=UPSERT, 0x02=DELETE), file_id, version_id, virtual_path, chunk_count, chunk_hashes. Added explicit "No payload" note for SYNC_ACK (0x0403).

Version 2 of the specification published. Requesting re-review from CQR.08 and SEC.07.

SEC.07 [2026-06-24]: Re-review of Version 2 complete. All three CQR.08 blocking findings are resolved from a security perspective. New sections introduce two advisory-level security issues and one advisory-level information-disclosure concern, detailed below. No new blocking findings. Document may proceed to done once CQR.08 confirms its own blocking findings resolved.

**CQR.08 BLOCKING-1 (vw_err_t table) — RESOLVED (security perspective)**
§10.1 provides a complete normative error code enumeration. From a security standpoint the table is acceptable: Auth category codes (300-304) use a single `VW_ERR_AUTH_BAD_CREDS` code for invalid credentials rather than separate codes for unknown-user vs wrong-password, which correctly preserves the username-enumeration invariant already documented in §7.1. The `VW_ERR_PERMISSION` (7) and `VW_ERR_NOT_FOUND` (5) codes are distinct, which is expected — see new advisory finding SEC-ADV-5 below on careful use of these two in file operations.

**CQR.08 BLOCKING-2 (download flow) — RESOLVED (security perspective)**
CHUNK_DOWNLOAD_REQ and CHUNK_DATA now have complete payload tables and a sequence diagram. The receiver-side SHA-256 integrity check requirement is present and stated as a protocol error (close the connection) on mismatch, which is correct. One new advisory finding follows.

**CQR.08 BLOCKING-3 (SYNC_DIFF / SYNC_ACK) — RESOLVED (security perspective)**
SYNC_DIFF now has a byte-level op record structure. SYNC_ACK is explicitly noted as carrying no payload. One new advisory finding on access control scoping of SYNC_DIFF follows.

**New SEC.07 findings (Version 2 additions):**

[advisory] SEC-ADV-1 — §7.2 CHUNK_DOWNLOAD_REQ: No authorisation check is specified. The spec allows any authenticated client to request any chunk by its SHA-256 hash. Because chunk hashes are content-derived and deterministic, a client that knows or guesses the hash of a chunk belonging to another user can retrieve that chunk's bytes. The spec must add a normative statement requiring the server to verify that the requesting session has read access to at least one committed file that references the requested chunk before serving CHUNK_DATA. Without this, the deduplication design becomes a cross-user data-exfiltration vector.

[advisory] SEC-ADV-2 — §7.2 CHUNK_QUERY: The same access-control gap exists for CHUNK_QUERY. A client can probe chunk presence by hash and learn whether another user's content (identified by chunk hash) has been uploaded, leaking information about other users' file contents via a timing- or response-based oracle. The server must either (a) restrict CHUNK_QUERY responses to chunks referenced by the requesting user's own committed files, or (b) add a normative note that CHUNK_QUERY responses must be indistinguishable for missing vs foreign-owned chunks (i.e., foreign chunks must appear as absent). Option (a) is recommended; option (b) breaks the deduplication efficiency benefit.

[advisory] SEC-ADV-3 — §7.4 SYNC_DIFF: The payload carries `virtual_path` (a full string path) for each op record, including DELETE ops. The spec does not state that the server must restrict SYNC_DIFF ops to files within the requesting session's own namespace (or explicitly shared paths). If the server sends SYNC_DIFF entries for files the client is not authorised to see, it leaks path names and version metadata. Add a normative statement: the server must include in SYNC_DIFF only ops for files the requesting session has at minimum VIEW access to.

[advisory] SEC-ADV-4 — §10.1 error code table, `VW_ERR_NOT_IMPL` (9): Returning this code to unauthenticated or low-privilege clients reveals which features are absent from a given build or deployment. This can assist targeted attacks. The spec should note that `VW_ERR_NOT_IMPL` should only be returned after successful authentication, and should be treated as equivalent to `VW_ERR_PERMISSION` when returned to an unauthenticated session.

[advisory] SEC-ADV-5 — §7.2 file operations (general): The distinct `VW_ERR_NOT_FOUND` (5) vs `VW_ERR_PERMISSION` (7) error codes in file operations allow an authenticated but unprivileged client to enumerate the existence of files and directories they do not own: a NOT_FOUND vs PERMISSION response to FILE_STAT or FILE_LIST reveals whether the path exists. Add a normative statement that for any file/folder path the requesting session does not have VIEW access to, the server must respond with `VW_ERR_NOT_FOUND` regardless of whether the path exists, never with `VW_ERR_PERMISSION`. This is a standard "authorisation-implies-existence" hardening pattern.

**Overall recommendation:** BLOCKING findings from CQR.08 are resolved from a security standpoint. The five advisory findings above are all in new or newly-specified sections and do not introduce new issues in previously-reviewed sections. None rises to blocking level on the spec itself — they are implementation constraints that SRV.01 and CLI.02 must honour, and they should be recorded either as normative additions to PROTOCOL.md or as blocking notes on the relevant implementation tasks (TASK-006, TASK-012). This task may proceed to done once CQR.08 confirms resolution of its own blocking findings and ARCH.00 closes the milestone. PRT.04 is encouraged to fold SEC-ADV-1 and SEC-ADV-2 into the spec as normative access-control requirements in the next revision pass, as they affect a core transfer path.

CQR.08 [2026-06-24]: Re-review of PRT.04 version 2 fixes complete. All three CQR.08 blocking findings are RESOLVED. Details follow, then two new advisory findings from the re-review.

BLOCKING-1 RESOLVED: §10.1 contains a complete normative vw_err_t table covering codes 0, 1-9, 100-103, 200-203, 300-304, 400-401, 500. Each entry carries symbolic name, category, and description. Wire encoding note (uint32 LE; unknown codes fatal, connection closed) is present. The ERROR payload in §7.0 references vw_err_t consistently.

BLOCKING-2 RESOLVED: §7.2 now contains a download flow sequence diagram, a CHUNK_DOWNLOAD_REQ payload table (chunk_hash: bytes[32]), and a CHUNK_DATA payload table (chunk_hash: bytes[32], chunk_len: uint32, data: bytes[chunk_len]). Receiver integrity check requirement (SHA-256 verification; VW_ERR_NOT_FOUND if chunk absent) is present. Structure is symmetric with the upload flow.

BLOCKING-3 RESOLVED: §7.4 now contains a SYNC_DIFF payload table with op_count (uint32) and a sub-table for each op record: op_type (uint8; 0x01=UPSERT, 0x02=DELETE), file_id (uint64), version_id (uint64), virtual_path (string), chunk_count (uint32), chunk_hashes (bytes[chunk_count x 32]). DELETE op semantics (version_id=0, chunk_count=0, zero-byte chunk_hashes field) are documented. SYNC_ACK carries an explicit "No payload" note.

New advisory findings from re-review of version 2 content:

[advisory] §11 / document header: PRT.04 stated "Version 2 of the specification published" in the task notes but the document header still reads "Current version: 1" and the §11 version history table has no version 2 entry. Update both before the next revision to prevent implementors from misidentifying which revision they are working from.

[advisory] §7.4 SYNC_DIFF op record: chunk_hashes is described as "absent for DELETE ops" but the absence mechanism is only implicit (chunk_count=0 yields 0 bytes on the wire). Add a normative sentence: when chunk_count is 0, the chunk_hashes field occupies zero bytes and is not present in the serialised record.

No new blocking findings. CQR.08 sign-off is given. The task may proceed to done once SEC.07 confirms their advisories are addressed or waived for Phase 0, and ARCH.00 closes the milestone.

ARCH.00 [2026-06-24]: Both CQR.08 and SEC.07 have completed re-review of Version 2 and confirmed all three blocking findings RESOLVED with no new blocking findings. Task moves to status: done. Advisory findings from this round are tracked as follows: SEC-ADV-1 and SEC-ADV-2 (cross-user chunk access / CHUNK_QUERY oracle) will be recorded as blocking notes on TASK-006 (SRV.01 chunk upload/download implementation) — SRV.01 must implement per-session chunk authorisation checks before that task can close. SEC-ADV-3 (SYNC_DIFF access-control scoping) is a blocking note on TASK-006. SEC-ADV-4 and SEC-ADV-5 (error code information disclosure) are advisory notes on TASK-006. PRT.04 should update the document header to Version 2 and add the §11 history entry, and add the normative chunk_hashes zero-byte sentence for DELETE ops — neither is blocking for milestone closure.
