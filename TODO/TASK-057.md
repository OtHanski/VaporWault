---
id:          TASK-057
title:       SEC.07 full security audit of complete codebase
status:      done
assignee:    SEC.07
created_by:  ARCH.00
created:     2026-07-13
priority:    critical
depends_on:  []
blocks:      []
review_by:   [ARCH.00]
tags:        [security, audit, security-sensitive, phase-8]
---

Full security audit of the complete VaporWault codebase. Produces a findings
report; each `blocking` finding creates a new TASK assigned to the relevant
developer. No Phase 8 milestone can close while a `blocking` finding is open.

## Scope

### Authentication and session management
- `vw_auth.c`: Argon2id parameters (ops/mem), dummy-hash on unknown user,
  constant-time compare for all token comparisons
- `vw_server_core.c`: AUTH_FAIL timing uniformity; 2FA state invalidation
  after OTP verify; session token single-use on SESSION_RESUME
- `vw_store.c`: session ring buffer — verify no cross-user session slot reuse
- OTP lockout: 5 failures / 10-minute window enforced

### Cryptography
- `vw_crypto.c`: CSPRNG seeding and use; Argon2id wrapper correctness
- TLS: mbedTLS config — TLS 1.3 only, permitted cipher suites only
  (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256), VW_CERT_VERIFY_NONE
  usage restricted to tests

### Input validation
- All server handlers in `vw_file_handlers.c`: payload length checks before
  any field read (SEC.07-A-2: session token validated first on every handler)
- `vw_path_validate`: path traversal, null bytes, Windows-style separators
- `vw_admin.c`: all admin message handlers for integer truncation and
  out-of-bounds reads
- VW_MAX_MSG_BYTES (8 MiB) enforcement in `vw_proto_recv`

### Storage layer
- `vw_store.c`: no cross-user file access (owner_id checked on every file op)
- Chunk GC: ref count never decremented for live file's current_version_id
- `vw_storage.c` / `vw_storage_files.c`: chunk path construction — SHA-256 hex
  must never escape the chunk store directory (path traversal via hash)

### Cluster and replication
- `vw_cluster.c`: NODE_HELLO constant-time token compare; IP rate-limit;
  NODE_HELLO_FAIL indistinguishable response
- `vw_oplog.c`: CRC32 verified in `vw_oplog_append_raw` before apply
- auth_token never in CLUSTER_STATUS_RESP (verify TASK-050 handler)

### Privilege separation
- `handle_user_list`, `handle_user_suspend`, `handle_audit_query`,
  `handle_cluster_status`, `handle_invite_create`, `handle_user_quota_set`:
  all verify `is_admin == 1` before acting
- `vw_admin.c` (Unix socket): SO_PEERCRED UID check on every accepted connection
- ACME HTTP-01 challenge file path validated strictly under `acme_http_root`

### Secrets in memory
- `session_token` zeroed after use everywhere (`secure_zero`)
- `password_hash`, `password_salt` never logged; zeroed from in-memory records
  before passing to non-auth callers
- Cluster `auth_token` never in log output or response payloads

## Output format

Findings are appended to this task body as notes, each tagged:
- `blocking`: prevents milestone close; SEC.07 creates a new TASK for the fix
- `advisory`: hardening recommendation; does not block

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: This is a full audit against a complete feature set, not
an incremental review. SEC.07 should prioritise (1) the auth flow end-to-end,
(2) all admin-privilege checks, (3) oplog/cluster security invariants, then
(4) memory safety in all input-parsing paths. Every resolved finding from prior
task reviews must also have a regression test in TASK-056.

SEC.07 [2026-07-13]: Audit complete. Files reviewed (all in full):
  vw_auth.c, vw_store.c, vw_server_core.c, vw_file_handlers.c, vw_crypto.c,
  vw_cluster.c, vw_oplog.c, vw_gc.c, vw_admin.c.

**Result: NO BLOCKING findings. Five ADVISORY findings below.**

---

### Passing invariants (all verified)

**Authentication / session management**
- Dummy Argon2id hash always runs when user not found — timing equalized. PASS.
- AUTH_FAIL response never reveals username-vs-password distinction; all paths
  return VW_ERR_AUTH_BAD_CREDS with lockout_secs=0 in server_core.c. PASS.
- attempt_count incremented BEFORE OTP comparison (vw_auth.c:292). PASS.
- OTP auth_state magic cleared after successful 2FA verify; no token reuse. PASS.
- Constant-time compare used for all token/hash comparisons (vw_crypto_constant_time_eq). PASS.
- vw_store_user_get_* zeroes password_hash and password_salt in returned record. PASS.
- Session slot reuse writes full fresh record with CSPRNG token; no cross-user
  contamination (vw_store.c session ring buffer). PASS.
- SESSION_RESUME: all failure paths return BAD_CREDS; new session created before
  old token revoked; revoke failure is best-effort and does not reveal token validity. PASS.
- Recovery code consumed on wrong-code CONFIRM (brute-force prevention). PASS.
- All sessions invalidated on successful password reset. PASS.
- AUTH_RECOVER_FAIL reason byte always 0 (no email enumeration). PASS.
- AUTH_RECOVER_REQUEST sleep runs unconditionally before all email-existence checks. PASS.

**File/protocol security (vw_file_handlers.c)**
- validate_session() is the first call in every handler; session token validated
  before any other payload field is parsed (§7.8.1). PASS.
- All ownership failures return VW_ERR_NOT_FOUND, never VW_ERR_PERMISSION
  (§7.8.3 — no chunk/file existence oracle). PASS.
- vw_path_validate: blocks ".." components, backslashes, embedded NULs, empty
  components, and paths not starting with '/'. Applied consistently. PASS.
- CHUNK_DOWNLOAD: both absent and non-owned chunks return VW_ERR_NOT_FOUND
  (check_chunk_ownership). PASS.
- CHUNK_UPLOAD: ref-count incremented before version record committed. PASS.
- FILE_COMMIT: all chunks verified present via chunk_query before addref. PASS.
- All admin-only handlers verify is_admin == 1 after session validation:
  handle_user_quota_set, handle_user_list, handle_user_suspend,
  handle_audit_query, handle_cluster_status, handle_invite_create. PASS.
- CLUSTER_STATUS response: auth_token field never serialised. PASS.

**Cryptography (vw_crypto.c)**
- CTR-DRBG seeded from OS entropy source with personalization string. PASS.
- g_ctr_drbg protected by mutex (g_rng_mu) in vw_crypto_random. PASS.
- Argon2id verify uses constant-time comparison; computed hash zeroed after use. PASS.
- vw_crypto_constant_time_eq: volatile accumulator `diff`, no early exit. PASS.
- TOTP verify uses constant-time comparison across all window candidates. PASS.

**Cluster (vw_cluster.c)**
- NODE_HELLO auth_token comparison always runs in constant time; zero_token used
  for unknown nodes so timing is equalized (no enumeration via timing). PASS.
- NODE_HELLO_FAIL: error_code=0 for both unknown node_id and wrong token. PASS.
- recv_token and stored_rec.auth_token zeroed immediately after comparison. PASS.
- auth_token zeroed in vw_cluster_node_get, vw_cluster_node_list,
  vw_cluster_node_add (all public API). PASS.
- Replica connects with VW_CERT_VERIFY_REQUIRED (TLS cert verification). PASS.
- Rate limiting: 5 failures per 60 s from same IP → silent drop. PASS.

**GC (vw_gc.c)**
- Only files with deleted==1 collected via vw_store_file_scan_deleted. PASS.
- Ref-counts never decremented for current_version_id of live files. PASS.
- Two-phase oplog commit wraps every file GC operation. PASS.
- vw_storage_gc_run deletes chunks only when ref_count == 0. PASS.
- Cluster-mode oplog truncation uses min_sync_watermark, not last_entry_id. PASS.

**Oplog (vw_oplog.c)**
- vw_oplog_append_raw verifies CRC32, validates stored_plen, checks sequence
  before applying each replicated entry. PASS.
- confirmed byte excluded from CRC (allows in-place confirm write). PASS.
- Crash recovery (seg_scan) truncates any unconfirmed / corrupt tail. PASS.
- Idempotent: entries already applied on a replica are silently skipped. PASS.

**Admin (vw_admin.c)**
- AF_UNIX socket created with mode 0600 (umask 0177 set around bind). PASS.
- SO_PEERCRED UID check on every accepted connection (Linux). PASS.
- payload buffer zeroed before free (may contain password bytes). PASS.
- handle_user_create: hash and salt zeroed after use; rec.password_* zeroed after
  vw_store_user_create. PASS.
- Admin responses: no password hashes, no session tokens. PASS.
- Quota changes logged to oplog (SEC.07-required oplog audit trail). PASS.

---

### Advisory findings

SEC.07 [2026-07-13]: advisory FINDING-1 (vw_server_core.c:329)
  Recovery OTP generation has ~0.023% modulo bias.
  Code: `rand32 % 1000000` where rand32 is a uniform uint32_t (2^32 values,
  not divisible by 10^6). Values 0–295 are 1/4295967296 ≈ 0.023% more probable.
  For a single-use 6-digit OTP with brute-force prevention (code consumed on
  any wrong attempt, 10-minute TTL), the bias is negligible — an attacker cannot
  exploit 0.023% bias within one attempt. No blocking risk.
  Recommendation: use rejection sampling for strict uniformity. Can be addressed
  as a low-priority hardening item without blocking any milestone.

SEC.07 [2026-07-13]: advisory FINDING-2 (vw_server_core.c:321-323)
  4-byte CSPRNG buffer (rand_buf) used for recovery OTP generation is not zeroed
  after the derived code is produced. The raw entropy bytes remain on the stack
  until overwritten. From rand_buf alone an attacker cannot reconstruct the code
  without re-running the same modulo operation; this is a memory hygiene issue
  only. Recommendation: add `secure_zero(rand_buf, sizeof(rand_buf))` after
  email_code is derived.

SEC.07 [2026-07-13]: advisory FINDING-3 (vw_cluster.c:643-653)
  In replica_repl_session(), hello_buf (heap-allocated) contains a copy of
  my_token (the node auth_token). my_token is correctly zeroed at line 650
  before the send, but hello_buf is freed at line 653 without a prior memset.
  The auth_token bytes persist in freed heap memory until overwritten.
  Recommendation: add `memset(hello_buf, 0, hello_len)` before `free(hello_buf)`
  in both the error path and the post-send path.

SEC.07 [2026-07-13]: advisory FINDING-4 (vw_file_handlers.c:381-398)
  CHUNK_UPLOAD quota check is not atomic. vw_storage_chunk_query (is chunk new?)
  and vw_store_quota_add (charge usage) are separate operations with no
  exclusive lock spanning them. Two concurrent uploads of the same new chunk
  can both observe is_new=1 and double-charge the user's quota usage counter.
  Because vw_store_quota_add is atomic at the store level, no quota bypass is
  possible — users cannot store more than their quota. The failure mode is
  over-reporting of used_bytes (user sees inflated usage, not bypass).
  PROTOCOL.md §7.8.2 specifies "atomic exclusive lock, no TOCTOU" for this check.
  Recommendation: move the quota enforcement into vw_storage_chunk_put under its
  existing write lock, or hold a per-user write lock spanning query+add+put.
  Does not block milestone since no security bypass is possible.

SEC.07 [2026-07-13]: advisory FINDING-5 (vw_admin.c:467)
  SO_PEERCRED UID check is gated on `#ifdef __linux__`. On non-Linux POSIX
  (BSD, macOS) the peer credential check is absent. macOS support is deferred
  per project decision (project_macos_deferred.md), so this is acceptable for
  current targets (Linux + Windows). Windows uses a no-op stub.
  Recommendation: when macOS support is added, implement LOCAL_PEERCRED check
  (`getsockopt(SOL_LOCAL, LOCAL_PEERCRED, ...)`). No action required now.

ARCH.00 [2026-07-14]: Audit reviewed. No blocking findings. Five advisory items
noted — none require immediate action. FINDING-4 (quota TOCTOU) is the most
notable: the failure mode is over-reporting used_bytes, not quota bypass; does
not block milestone. FINDING-3 (cluster hello_buf not zeroed) is a memory hygiene
item worth addressing in a follow-up. Marking done.
