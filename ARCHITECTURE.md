# VaporWault — System Architecture

**Owner**: ARCH.00  
**Last updated**: 2026-07-14 (Phase 10 complete — gap-fill tasks done. TASK-066: pytest.ini (declares cluster/slow/e2e marks), tests/integration/gen_test_cert.sh, CMake vw_integration_test target. TASK-067: client daemon Linux packaging — packaging/linux/vapourwault-daemon.service (systemd user service), client.conf.example, client_install.sh (no-root installer), CMakeLists.txt updated with lib/systemd/user install. TASK-068: client daemon Windows packaging — Install-VaporWaultClient.ps1 (Task Scheduler logon trigger, ACL restriction, idempotent), client.conf.example. TASK-069: end-to-end sync test suite — tests/e2e/test_sync.py with DaemonProcess class; 4 tests covering connect, upload sync, delete sync, conflict handling; gated by VW_TEST_E2E=1.)

---

## Overview

VaporWault is a self-hosted cloud file hosting system. It consists of:

- **Server** (Linux only): stores and serves files, manages users, replicates across cluster nodes
- **Client daemon** (Linux + Windows): background process that syncs local folders to the server
- **GUIs** (C++ / Dear ImGui): thin clients that connect to the server GUI process or local client daemon via IPC
- **CLIs** (pure C): also thin clients connecting to the server process or local client daemon via IPC

All network transport uses TLS 1.3 via mbedTLS. All other implementation is pure C except the Dear ImGui GUIs (C++).

---

## Approved External Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| mbedTLS | latest stable | TLS 1.3, SHA-256, AES, ECDSA (for ACME CSR), RNG |
| SDL2 | latest stable | Windowing + OpenGL context for Dear ImGui |
| Dear ImGui | vendored | GUI rendering (C++) |
| Argon2 reference | vendored (~600 lines, public domain) | Password hashing (Argon2id) |

**No SQLite. No other external libraries.**

---

## Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Transport encryption | mbedTLS, TLS 1.3 | Battle-tested; avoids custom crypto handshake |
| Metadata storage | Custom flat-file (no SQLite) | Zero extra deps; design documented below |
| Conflict resolution | Last-write-wins + auto-history | Simplest correct behaviour; users recover via version history |
| Server GUI backend | Dear ImGui + SDL2 + OpenGL | Consistent with client GUI; server is Linux-only |
| TLS certificates | ACME v2 / Let's Encrypt (DNS-01 primary, HTTP-01 fallback); manual PEM fallback | Non-technical admins need automatic cert renewal |
| Two-factor auth | Optional per-user; email OTP v1; extensible provider interface | Reuses SMTP infrastructure; TOTP/hardware keys added later |
| File deduplication | Block-level, 4MB content-addressed chunks, ref-counted | Enables delta sync, version storage efficiency, cross-user dedup |
| Email sending | SMTP relay client (admin configures outbound relay) | Reliable from any network; no port 25 / MX record issues |
| Sharing granularity | Files and folders | Flexibility; permission check at both levels per operation |
| Client architecture | Daemon + IPC (localhost TCP) | Sync runs without GUI; GUI and CLI are thin IPC clients |
| Primary failover | None (manual promotion) | Correct consensus is too complex; offline queue handles downtime |
| CA store (vw_net) | Option A: return VW_ERR_INVALID_ARG when verify_required && ca_cert_pem_path==NULL | mbedTLS does not load platform CA stores automatically; Option B (real CA store) deferred to Phase 3 |
| Oplog two-phase commit | confirmed byte (u8, NOT CRC-covered) at offset 16 in each entry header | Allows in-place atomic confirm write without CRC recomputation; seg_scan uses `continue` (not `break`) on confirmed==0 to preserve confirmed entries that follow unconfirmed holes in concurrent transaction patterns |
| vw_net recv timeout | Per-connection `_Atomic uint32_t recv_timeout_ms` in struct vw_conn; custom BIO callbacks read it directly | Allows per-connection deadlines without mutating the shared ssl_config; set via vw_net_conn_set_recv_timeout() post-accept |
| AUTH_FAIL lockout_remaining_secs | u16 (max 65535s) | u8 (max 255s) cannot represent the 600-second OTP lockout window; wire format change introduced in protocol v2 |

---

## Repository Structure

```
VaporWault/
  src/
    core/           # libvw_core — shared modules (vw_net, vw_proto, vw_crypto, vw_fs)
    server/         # Server modules (vw_server_core, vw_store, vw_storage_files, ...)
    client/         # Client daemon modules (vw_daemon, vw_sync, vw_cache, ...)
    gui/
      server/       # vw_server_gui (C++, Dear ImGui)
      client/       # vw_client_gui (C++, Dear ImGui)
  third_party/
    mbedtls/        # vendored
    imgui/          # vendored
    argon2/         # vendored (~600 lines, public domain)
  tests/
    unit/           # Per-module unit tests (pure C harness)
    integration/    # Client-server and cluster integration tests
  tools/
    vwdump/         # Admin tool: inspect flat-file storage tables
  docs/
    PROTOCOL.md     # Wire protocol specification (owned by PRT.04)
    STYLE.md        # C/C++ style decisions (owned by CQR.08)
  TODO/             # One TASK-NNN.md file per task
  CLAUDE.md         # Agent team definitions and coordination protocol
  ARCHITECTURE.md   # This file
  CMakeLists.txt    # Top-level CMake
```

---

## Module Map

### Shared core library (`libvw_core`)

| Module | File(s) | Owner | Language | Responsibility |
|--------|---------|-------|----------|----------------|
| `vw_net` | `src/core/vw_net.{h,c}` | PRT.04 | C | Socket abstraction, TLS via mbedTLS, token-bucket rate limiter |
| `vw_proto` | `src/core/vw_proto.{h,c}` | PRT.04 | C | Binary wire protocol encode/decode, version negotiation |
| `vw_crypto` | `src/core/vw_crypto.{h,c}` | PRT.04 | C | SHA-256, CSPRNG, Argon2id wrapper, TOTP base |
| `vw_fs` | `src/core/vw_fs.{h,c}` | SRV.01 | C | Filesystem utilities, 4MB chunking, content hash, atomic file write |

### Server modules

| Module | File(s) | Owner | Language | Responsibility |
|--------|---------|-------|----------|----------------|
| `vw_server_core` | `src/server/vw_server_core.{h,c}` | SRV.01 | C | Request dispatcher, thread pool, connection management |
| `vw_store` | `src/server/vw_store.{h,c}` | SRV.01 | C | Flat-file storage engine (heap + index + free-list per table) |
| `vw_oplog` | `src/server/vw_oplog.{h,c}` | SRV.01 | C | Append-only operation log for replication and crash recovery |
| `vw_storage_files` | `src/server/vw_storage_files.{h,c}` | SRV.01 | C | Chunk store, dedup ref-counting, version GC |
| `vw_users` | `src/server/vw_users.{h,c}` | SRV.01 | C | User CRUD, sessions, 2FA state, quotas, permissions, subscriptions |
| `vw_auth` | `src/server/vw_auth.{h,c}` | PRT.04 | C | Argon2id hashing, session token lifecycle, 2FA orchestration |
| `vw_auth_provider` | `src/server/vw_auth_provider.{h,c}` | PRT.04 | C | Abstract 2FA provider interface + email OTP implementation |
| `vw_smtp` | `src/server/vw_smtp.{h,c}` | SRV.01 | C | Minimal SMTP relay client (TLS, EHLO, AUTH, MAIL/RCPT/DATA) |
| `vw_acme` | `src/server/vw_acme.{h,c}` | PRT.04 | C | ACME v2 client: DNS-01 (via vw_ddns) primary, HTTP-01 fallback |
| `vw_ddns` | `src/server/vw_ddns.{h,c}` | SRV.01 | C | DDNS provider interface + Cloudflare / No-IP / DuckDNS |
| `vw_gc` | `src/server/vw_gc.{h,c}` | SRV.01 | C | Background GC: session expiry, oplog truncation, file/chunk GC |
| `vw_invite` | `src/server/vw_invite.{h,c}` | SRV.01 | C | Invite token flat-file store; INVITE_CREATE/REDEEM handlers |
| `vw_recovery` | `src/server/vw_recovery.{h,c}` | SRV.01 | C | Password-recovery record store; AUTH_RECOVER_REQUEST/CONFIRM handlers |
| `vw_cluster` | `src/server/vw_cluster.{h,c}` | SRV.01 | C | Primary/replica replication via oplog; health monitoring (**Phase 7**) |
| `vw_admin` | `src/server/vw_admin.{h,c}` | SRV.01 | C | Admin API: user management, quota, audit log, cluster status |
| `vw_server_cli` | `src/server/vw_server_cli.{h,c}` | SRV.01 | C | Server CLI command parser and handler |
| `vw_server_gui` | `src/gui/server/` | GUI.03 | C++ | Dear ImGui server interface (SDL2 + OpenGL) |

### Client modules

| Module | File(s) | Owner | Language | Responsibility |
|--------|---------|-------|----------|----------------|
| `vw_daemon` | `src/client/vw_daemon.{h,c}` | CLI.02 | C | Daemon process: IPC server, session, sync orchestration |
| `vw_ipc` | `src/client/vw_ipc.{h,c}` | CLI.02 | C | IPC protocol (localhost TCP, same framing as wire proto) |
| `vw_client_core` | `src/client/vw_client_core.{h,c}` | CLI.02 | C | Server connection, auth, session, quota tracking |
| `vw_sync` | `src/client/vw_sync.{h,c}` | CLI.02 | C | Sync engine: diff, offline queue, delta-chunk transfer, conflict |
| `vw_cache` | `src/client/vw_cache.{h,c}` | CLI.02 | C | Local metadata cache: file state, selective-sync rules |
| `vw_watch_linux` | `src/client/vw_watch_linux.{h,c}` | CLI.02 | C | inotify-based filesystem watcher |
| `vw_watch_windows` | `src/client/vw_watch_windows.{h,c}` | CLI.02 | C | ReadDirectoryChangesW filesystem watcher |
| `vw_client_cli` | `src/client/vw_client_cli.{h,c}` | CLI.02 | C | Client CLI connecting to daemon via IPC |
| `vw_client_gui` | `src/gui/client/` | GUI.03 | C++ | Dear ImGui client interface (SDL2 + OpenGL) |

### Tools

| Tool | File(s) | Owner | Purpose |
|------|---------|-------|---------|
| `vwdump` | `tools/vwdump/` | SRV.01 | Read and pretty-print all flat-file storage tables (admin diagnostic) |

---

## Inter-Module Dependencies

```
vw_net          ← (mbedTLS)
vw_crypto       ← (mbedTLS, argon2)
vw_proto        ← vw_net
vw_fs           ← (libc only)

vw_store        ← vw_fs, vw_crypto
vw_oplog        ← vw_fs, vw_crypto
vw_storage_files ← vw_store, vw_oplog, vw_fs, vw_crypto
vw_users        ← vw_store, vw_oplog
vw_auth         ← vw_crypto, vw_users, vw_auth_provider
vw_auth_provider ← vw_smtp, vw_crypto
vw_smtp         ← vw_net
vw_ddns         ← vw_net
vw_acme         ← vw_net, vw_crypto, vw_ddns
vw_gc           ← vw_store, vw_oplog
vw_invite       ← vw_fs, vw_crypto
vw_recovery     ← vw_fs, vw_crypto
vw_cluster      ← vw_net, vw_proto, vw_oplog   (Phase 7)
vw_admin        ← vw_users, vw_storage_files, vw_cluster, vw_acme, vw_ddns
vw_server_core  ← vw_net, vw_proto, vw_auth, vw_admin, vw_storage_files, vw_users
vw_server_cli   ← vw_server_core, vw_admin
vw_server_gui   ← vw_server_core, vw_admin  (C++)

vw_ipc          ← vw_proto (shared framing)
vw_cache        ← vw_fs
vw_client_core  ← vw_net, vw_proto, vw_auth (client-side), vw_cache
vw_sync         ← vw_client_core, vw_cache, vw_fs, vw_crypto
vw_watch_linux  ← (libc/Linux only)
vw_watch_windows ← (Win32 only)
vw_daemon       ← vw_sync, vw_ipc, vw_watch_linux|vw_watch_windows, vw_client_core
vw_client_cli   ← vw_ipc
vw_client_gui   ← vw_ipc  (C++)
```

No circular dependencies are permitted. A module may not import from a module that depends on it.

---

## Flat-File Storage Design

The `vw_store` module manages all persistent server metadata. See `docs/PROTOCOL.md` for the wire protocol and `src/server/vw_store.h` for the C struct definitions.

### Principles

- **Crash consistency**: all multi-field record mutations copy-on-write to a new slot; index updates written to `.tmp` then `rename()` (POSIX atomic on same filesystem). Single naturally-aligned 8-byte fields updated in-place via `pwrite()` (POSIX atomic).
- **Concurrency**: per-table `pthread_rwlock_t`. Readers hold shared lock. Writers hold exclusive lock. In-memory index updates happen under write lock before release.
- **In-memory indexes**: built on startup by scanning table files. Disk is source of truth; indexes are rebuilt after crash.
- **Append-only logs** (audit, oplog): each entry has a magic header + CRC32. Startup scans to last valid CRC and truncates the rest.
- **GC**: background thread on configurable interval. Decrements chunk ref counts for expired versions; frees zero-ref chunks; compacts permission and subscription tables; truncates oplog to the minimum replica sync offset.

### On-disk layout under `{data_dir}/`

```
data/
  users/
    users.db            # Fixed-size user records (256 bytes each)
    users.free          # Free-list: reusable record slots
    users.name.idx      # Hash table: username → slot index (rebuilt on load)
    users.email.idx     # Hash table: email → slot index (rebuilt on load)
  sessions/
    sessions.db         # Fixed-size session records (128 bytes each); ring buffer
  files/
    meta.db             # Fixed-size file metadata records
    meta.free           # Free-list
    meta.path.idx       # Hash table: (owner_id, virtual_path) → slot index
    versions.db         # Fixed-size version record headers
    versions.blob       # Variable-length chunk hash arrays (addressed by blob_offset in header)
    versions.free       # Free-list for version headers
    versions.blob.free  # Free-list for blob regions
  chunks/
    {hex[0:2]}/
      {sha256hex}.chunk # Raw 4MB chunk data, named by SHA-256
    refcounts.db        # Hash table: sha256 (32 bytes) → ref_count (u32)
  permissions/
    perms.db            # Append-only log of permission grants/revocations
    perms.idx           # (path_hash, grantee_id) → latest record offset (rebuilt on load)
  subscriptions/
    subs.db             # Fixed-size subscription records
    subs.free           # Free-list
  audit/
    audit-{seq}.log     # Segmented append-only log; each entry has CRC32
    audit.idx           # Timestamp → segment + offset (rebuilt on load)
  cluster/
    oplog-{seq}.db      # Segmented append-only operation log
    oplog.idx           # entry_id → segment + byte offset (rebuilt on load)
    nodes.db            # Fixed-size cluster node records
  ddns/
    state.db            # Single-record file (atomic temp-file rename on update)
  cert/
    cert.pem            # TLS certificate (written by vw_acme or admin)
    key.pem             # Private key
    account.pem         # ACME account key
```

### Key struct sizes

| Struct | Size | Notes |
|--------|------|-------|
| `vw_user_record_t` | 256 bytes | Fixed; `_Static_assert` enforced |
| `vw_session_record_t` | 128 bytes | Fixed; `_Static_assert` enforced |
| `vw_file_record_t` | 128 bytes | Fixed; `_Static_assert` enforced |
| `vw_version_record_t` | 80 bytes | Fixed header; chunk hashes in `.blob` file at `blob_offset` |
| `vw_node_record_t` | 256 bytes | Fixed |
| `vw_oplog_entry_t` | 24-byte header + variable payload | CRC32 over header + payload |

---

## Wire Protocol

See `docs/PROTOCOL.md` (maintained by PRT.04) for the full specification.

### Message framing

```
[ 4 bytes: total message length (LE) ]
[ 2 bytes: message type             ]
[ 2 bytes: protocol version         ]
[ N bytes: payload                  ]
```

### Connection handshake sequence

```
Client                                  Server
  ── TLS handshake (mbedTLS) ─────────────────────────────────
  ── HELLO (max_proto_version) ──────────────────────────────>
                                <─── HELLO_OK (negotiated_ver)
                             or <─── VERSION_REJECT
  ── AUTH_REQUEST (username, stretched_pw_token) ───────────>
                           [if 2FA enabled on account]
                                <─── AUTH_CHALLENGE (otp_type)
  ── AUTH_OTP (code) ───────────────────────────────────────>
                                <─── AUTH_OK (session_token)
                             or <─── AUTH_FAIL (reason)
```

### Key message type groups

| Group | Types |
|-------|-------|
| Auth | `HELLO`, `HELLO_OK`, `VERSION_REJECT`, `AUTH_REQUEST`, `AUTH_CHALLENGE`, `AUTH_OTP`, `AUTH_OK`, `AUTH_FAIL`, `SESSION_RESUME` |
| File ops | `FILE_LIST`, `FILE_STAT`, `CHUNK_QUERY`, `CHUNK_UPLOAD`, `CHUNK_DOWNLOAD`, `FILE_COMMIT`, `FILE_DELETE`, `VERSION_LIST`, `VERSION_RESTORE` |
| Sync | `SYNC_STATE`, `SYNC_DIFF`, `SYNC_ACK` |
| Admin | `USER_CREATE`, `USER_QUOTA`, `USER_SUSPEND`, `INVITE_CREATE`, `AUDIT_QUERY`, `CLUSTER_STATUS` |
| Cluster | `OPLOG_PULL`, `OPLOG_ACK`, `CLUSTER_NODE_HELLO` |

---

## Key Design Decisions

**Content-addressed chunk storage**: Files are split into 4MB chunks keyed by SHA-256. Identical chunks from any user share one on-disk copy (ref-counted). New file versions reference only the chunks that changed — unchanged chunks are already on disk. Delta sync: client sends `CHUNK_QUERY` for each chunk; server replies with which hashes it already has; client uploads only the missing ones.

**Daemon + IPC architecture**: The client daemon owns the sync engine, the server session, and the file watchers. GUI and CLI are thin IPC clients connecting to the daemon over localhost TCP. Sync continues when the GUI is closed; multiple CLI commands share one daemon session.

**DDNS + ACME integration**: The DDNS module has DNS provider API access for IP update. ACME DNS-01 challenges reuse this to add a `_acme-challenge` TXT record — no port 80 needed, works during server restarts, works behind any firewall.

**Extensible 2FA**: `vw_auth_provider` defines two function pointers: `generate_challenge(user_id) → void` (sends OTP or returns TOTP URI) and `verify_response(user_id, code) → bool`. New provider types (TOTP, hardware keys, Proton Pass) add a new `vw_auth_provider_t` implementation without touching `vw_auth`.

**Oplog as recovery journal**: Multi-table writes (e.g., upload that updates file meta + version + chunk refcounts + user quota) are journalled in the oplog before being applied. On crash recovery, the startup pass replays uncommitted oplog entries to completion. This is the highest-complexity part of `vw_store` — every multi-table operation must implement idempotent "complete-or-rollback" logic.

**No automatic failover**: Raft/Paxos in pure C without a battle-tested library introduces split-brain risk. For the target user base (personal cloud admin), manual promotion is safer and simpler. Clients fall back to their offline queue when the primary is unreachable.

---

## Implementation Phases

See `TODO/` for the active task list. Phases in order:

| Phase | Name | Key modules | Agents | Status |
|-------|------|-------------|--------|--------|
| 0 | Foundation | `vw_net`, `vw_proto`, `vw_crypto`, `vw_fs`, CMake | ARCH.00, PRT.04, BLD.05 | **complete** (TASK-001–006 done) |
| 1 | Authentication | `vw_auth`, `vw_auth_provider`, `vw_store` (users/sessions), `vw_smtp` | PRT.04, SRV.01 | **complete** (TASK-007–020 done) |
| 2 | File Transfer | `vw_store` (files/versions), `vw_storage` (chunks/dedup), `vw_file_handlers`, `vw_client_core` file transfer | SRV.01, CLI.02 | **complete** (TASK-021–025 done) |
| 3 | Sync Engine | `vw_cache`, `vw_watch_*`, `vw_sync`, `vw_daemon`, `vw_ipc`, `vw_client_cli`; server quota enforcement | CLI.02, SRV.01 | **complete** (TASK-026–033 done) |
| 4 | Sharing | `vw_store` (permissions/subs), permission checks, shared folder sync | SRV.01, CLI.02 | **complete** (TASK-034–035 done) |
| 5 | DDNS, ACME, Admin | `vw_ddns`, `vw_acme`, thread pool, admin CLI, integration tests | SRV.01, PRT.04 | **complete** (TASK-036–041 done) |
| 6 | GC, Invites, Recovery | `vw_gc`, invite tokens, recovery email | SRV.01, PRT.04 | **complete** (TASK-042–046 done) |
| 7 | GUIs + Cluster | `vw_client_gui`, `vw_server_gui`, `vw_cluster` replication | GUI.03, SRV.01 | **complete** (TASK-047–053 done) |
| 8 | Hardening | Security audit, fuzz testing, integration suite, CI | SEC.07, CQR.08, QA.06 | **in progress** (TASK-054–059) |

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Custom flat-file store correctness bugs | High | Atomic writes via rename(); crash-recovery replay; SEC.07 + QA.06 review |
| ACME client certificate issuance errors | Medium | Implement to RFC 8555; test against Let's Encrypt staging environment |
| Argon2id parameters too slow or too weak | Medium | Benchmark on target hardware in Phase 1; use OWASP-recommended parameters |
| Protocol parser vulnerable to malformed input | High | QA.06 fuzz testing every phase; SEC.07 review |
| Chunk dedup GC races with uploads | Medium | Ref count incremented before chunk committed; GC only frees ref_count == 0 |
| Oplog recovery logic incomplete | High | Every multi-table operation must have idempotent replay; QA.06 crash-injection tests |
