# VaporWault — System Architecture

**Owner**: ARCH.00  
**Last updated**: 2026-08-05 (`TASK-118` — full phase-status/doc-drift audit against `TODO/TASK-001`–`TASK-125`; see the 2026-08-05 audit-note follow-up under Implementation Phases for what was found and fixed. Prior entry, 2026-07-14, covered Phase 10 packaging/e2e-test completion — see `TASK-066`–`TASK-069` for that level of detail; superseded here rather than kept verbatim, since `TODO/` is the trustworthy record of what shipped, not this header.)

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
| mbedTLS | v3.6.7, pinned via CMake `FetchContent` (`third_party/CMakeLists.txt`) — not a submodule, see `TASK-119` | TLS 1.3, SHA-256, AES, ECDSA (for ACME CSR), RNG |
| SDL2 | ≥2.26.0, manually vendored on Windows / system package on Linux+macOS (`VENDOR_SETUP.md`) | Windowing + OpenGL context for Dear ImGui |
| Dear ImGui | vendored (git submodule, `docking` branch) | GUI rendering (C++) |
| Argon2 reference | 20190702, pinned via CMake `FetchContent` (not a submodule, see `TASK-125`) — ~600 lines, public domain | Password hashing (Argon2id) |

**No SQLite. No other external libraries.**

*(2026-08-05, `TASK-118`: corrected — this table previously said mbedTLS/Argon2 were "vendored"/submodules, matching the Repository Structure listing below, but `TASK-119`/`TASK-125` found and removed dead `third_party/mbedtls` and `third_party/argon2` submodules that had drifted from what `FetchContent` actually pulls in; only Dear ImGui is a true submodule today.)*

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
    imgui/          # vendored (git submodule, docking branch)
    SDL2/           # vendored manually on Windows only (VENDOR_SETUP.md); Linux/macOS use the system package
    # mbedTLS and Argon2 are NOT vendored here — CMake FetchContent pulls both
    # at configure time (third_party/CMakeLists.txt); see TASK-119 / TASK-125.
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
| `vw_storage` | `src/server/vw_storage.{h,c}` | SRV.01 | C | Chunk store, dedup ref-counting, version GC |
| `vw_store` (files) | `src/server/vw_store_files.{h,c}` | SRV.01 | C | File/version metadata records, soft-delete + trash retention (split out from `vw_store.c`, which owns users/sessions/quotas) |
| `vw_file_handlers` | `src/server/vw_file_handlers.{h,c}` | SRV.01 | C | Phase 2 file-op dispatch (FILE_LIST/STAT, CHUNK_*, VERSION_*, FILE_MOVE, SHARE_*/LINK_*); permission resolution goes through `vw_share` (grants + scoped sessions), not owner_id-only, since TASK-094 |
| `vw_share` | `src/server/vw_share.{h,c}` | SRV.01 | C | User-to-user grants + public links: CRUD, permission resolution (ancestor walk-up), scoped-session write-count and LINK_ACCESS IP rate limiting (added TASK-094) |
| `vw_conn_registry` | `src/server/vw_conn_registry.{h,c}` | SRV.01 | C | Live-connection tracking for admin CONN_LIST (added TASK-091) |
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
| `vw_cache` | `src/client/vw_cache.{h,c}` | CLI.02 | C | Local metadata cache: per-file sync state (`cache.db`) and tracked sync-folder roots (`sync_folders.db`, including shared-folder `remote_dir_id` addressing, `TASK-106`) |
| `vw_watch_linux` | `src/client/vw_watch_linux.{h,c}` | CLI.02 | C | inotify-based filesystem watcher |
| `vw_watch_windows` | `src/client/vw_watch_windows.{h,c}` | CLI.02 | C | ReadDirectoryChangesW filesystem watcher |
| `vw_client_cli` | `src/client/vw_client_cli.{h,c}` | CLI.02 | C | Client CLI connecting to daemon via IPC |
| `vw_client_gui` | `src/gui/client/` | GUI.03 | C++ | Dear ImGui client interface (SDL2 + OpenGL) |

> **2026-08-05 flag (`TASK-118`):** this document previously claimed
> `vw_cache` owns "selective-sync rules" (letting a user include/exclude
> specific subfolders or file patterns within a synced folder). No such
> logic exists anywhere in `src/client/vw_cache.{h,c}` today, and no closed
> or open task in `TODO/` ever scoped it — it does not appear to be a
> feature that was built and later removed; it reads as aspirational text
> that was never implemented. Corrected the row above to describe what
> `vw_cache` actually does. Not filing a follow-up task to build selective
> sync — that's a product-scope decision (ARCH.00/the project owner's
> call), not something to assume from a stale doc line.

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
  shares/               # Implemented TASK-094 (design: TASK-088).
    shares.db           # Fixed-size vw_share_record_t rows (128 bytes/slot); user grants and
                         # public links share one table (share_type discriminates). No separate
                         # index file — the in-memory link_token hash table and share_id-as-slot
                         # direct index are rebuilt on open, same convention as every other table.
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

**Sharing model (2026-07-29, TASK-088)**: Both files and folders can be
shared via two independent mechanisms — authenticated user-to-user grants
and unguessable public links (read or edit) — full spec in
`docs/PROTOCOL.md` §7.5/§7.10. Public links reuse the existing
`INVITE_REDEEM` pattern: an unauthenticated pre-`AUTH_REQUEST` message
(`LINK_ACCESS`) redeems a token and establishes a *scoped* session bound to
one `share_id`, so all existing file-op dispatch, quota, and oplog machinery
is reused unmodified rather than building a parallel unauthenticated
code path. Storage always counts against the file's actual `owner_id`,
never the acting/grantee session's `user_id` — this is what bounds abuse
from a public edit link to the owner's own existing quota. A revoked share
must invalidate an already-issued scoped session's access on its *next*
request, not just at future `LINK_ACCESS` time — this is checked live
against the share record, not cached at session-creation.

**End-to-end encryption model (2026-07-29, TASK-089)**: Opt-in per
file/folder ("vault"), industry-standard envelope encryption — full spec in
`docs/PROTOCOL.md` §7.11. A random per-vault Vault Key is wrapped by a
Key-Encryption-Key derived (Argon2id) from a user-chosen encryption
passphrase that is **never** transmitted to or derivable by the server —
this is deliberately a separate secret from the account login password,
otherwise the encryption would be server-recoverable and not genuinely E2E.
Only the wrapped-key blob is ever server-side, and it is opaque. Each file
gets its own random Data Encryption Key (AES-256-GCM, matching the TLS
cipher suite already in use), which as a direct consequence makes
ciphertext unique per file — this naturally defeats cross-user/cross-version
dedup for encrypted content without any special-case "skip dedup for
encrypted files" logic. Losing one vault's passphrase only loses that
vault's files, since vault keys are independently random and independently
wrapped; users may reuse one passphrase across vaults or use different ones
per vault as they choose. Only file *content* is encrypted — filenames,
folder structure, and sizes remain visible to the server, and this
boundary must be disclosed plainly in the GUI, not just documented here.

**Implementation complete (2026-07-31, `TASK-098`–`TASK-101`)**: server
storage, client crypto/vault module, GUI (setup wizard, unlock prompts,
encrypted indicators, and all three required disclosures — passphrase-loss,
metadata-scope, delta-sync cost), and the regression suite are all done and
verified (`docs/PROTOCOL.md` §7.11.5, `TODO/TASK-098.md`–`TASK-101.md`).
Two decisions emerged during implementation that the design stage didn't
anticipate: (1) per-chunk content is sized at `VW_CHUNK_SIZE_DEFAULT -
16 bytes` rather than the full chunk size, so a full ciphertext+GCM-tag
chunk lands exactly at the server's existing `CHUNK_UPLOAD` size ceiling
instead of overflowing it; (2) a vault's folder must be a real directory
(`FILE_MKDIR`-created), not merely an owned `file_id` — `VAULT_CREATE`
itself doesn't enforce this, but `FILE_COMMIT`'s "create a new file under
this folder" branch does, which only became apparent once a client
actually tried to create more than one file in a vault (`TASK-100`'s IPC
diagnostic check caught this exact bug on its first run).

**Sync engine awareness of shared folders (2026-07-31, `TASK-106` design)**:
`TASK-095` gave grant-holders file-id-based stat/upload/download/move for a
single shared item, but not folder sync, because paths are owner-namespaced
server-side (`vw_store_file_get_by_path`'s hard filter) — a grantee's own
`FILE_LIST` call can never resolve into someone else's tree by path. The
missing piece: no wire mechanism let an *authenticated* (non-scoped)
session list a shared folder's children by `file_id` at all (only the
anonymous scoped-link case, `LINK_ACCESS`, could navigate a shared subtree,
via its own scope target rather than a caller-supplied id).

Design, implemented across five pieces:
1. **Wire**: `FILE_LIST` gains an optional trailing `dir_file_id` (uint64)
   field. When present and nonzero (and the session isn't already scoped —
   scoped sessions have their own root-resolution path and reject this
   field), the server resolves the listing root via `effective_permission()`
   exactly like `FILE_COMMIT`'s existing directory-target branch does,
   instead of the path-based owner lookup. Purely additive; no version
   bump — mirrors every other trailing-field extension this project uses.
2. **Client cache**: `vw_sync_folder_t` gains `remote_dir_id` (uint64,
   0 = today's owned-path-based folder). A nonzero value means "this sync
   folder is rooted at a shared item, addressed by file_id, not by virtual
   path" — `virtual_root` becomes purely a local bookkeeping/display value
   in that mode, never sent to the server.
3. **Sync engine**: `srv_collect`'s BFS is mirrored (not shared via a
   parameterized abstraction — the two walks differ enough in what they
   carry, and duplication here is cheaper than the abstraction) into a
   `remote_dir_id`-rooted variant using the new `FILE_LIST` extension.
   `compute_actions`/`exec_action` needed `action_t` to carry `file_id` and
   `remote_dir_id` so the executor can pick file-id-addressed primitives
   (`vw_client_file_upload_into_folder`/`_to_id`/`_download_by_id`, plus a
   new `vw_client_file_delete_by_id` — `FILE_DELETE`'s wire format already
   supported file_id addressing, only the client wrapper never exposed it)
   instead of path-based ones for a shared folder, while owned folders keep
   their existing path-based behavior byte-for-byte unchanged.
4. **Live revocation**: a definitive permission error (share revoked)
   walking a shared folder's root auto-pauses that one sync folder
   (reusing the existing `paused` flag/mechanism) rather than being retried
   forever as a generic network error — the folder simply stops advancing
   and stays visible/inspectable, rather than spinning.
5. **Discovered, deliberately not fixed here**: implementing this surfaced
   that `FILE_LIST_RESP` never carries `version_id` per entry, so ongoing
   (non-first-time) remote-change detection driven by `FILE_LIST` alone was
   silently broken for *every* sync folder, not just shared ones — see
   `TODO/TASK-109.md`. Worked around for both owned and shared folders with
   a client-local, wire-safe fix (`compute_actions` also compares
   `mtime_unix`/`size_bytes`, which `FILE_LIST_RESP` already carries
   correctly) rather than the real fix, which means safely extending a
   *repeated* wire structure — a large enough change to deserve its own
   design pass, not a rushed addition here.

---

## Implementation Phases

See `TODO/` for the active task list. Phases in order:

| Phase | Name | Key modules | Agents | Status |
|-------|------|-------------|--------|--------|
| 0 | Foundation | `vw_net`, `vw_proto`, `vw_crypto`, `vw_fs`, CMake | ARCH.00, PRT.04, BLD.05 | **complete** (TASK-001–006 done) |
| 1 | Authentication | `vw_auth`, `vw_auth_provider`, `vw_store` (users/sessions), `vw_smtp` | PRT.04, SRV.01 | **complete** (TASK-007–020 done) |
| 2 | File Transfer | `vw_store` (files/versions), `vw_storage` (chunks/dedup), `vw_file_handlers`, `vw_client_core` file transfer | SRV.01, CLI.02 | **complete** (TASK-021–025 done) |
| 3 | Sync Engine | `vw_cache`, `vw_watch_*`, `vw_sync`, `vw_daemon`, `vw_ipc`, `vw_client_cli`; server quota enforcement | CLI.02, SRV.01 | **complete** (TASK-026–033 done) |
| 4 | Sharing | `vw_share` (new module), permission checks in `vw_file_handlers`, shared-folder sync | SRV.01, CLI.02 | **complete** — design published 2026-07-29 (`docs/PROTOCOL.md` §7.5/§7.10, `TASK-088`); server (`TASK-094`), client library (`TASK-095`), GUI (`TASK-096`), and integration tests (`TASK-097`) all closed `done`. Shared-folder local sync (`vw_sync` awareness of `remote_dir_id`-rooted folders) followed as `TASK-106`, hardened by `TASK-109`/`TASK-111`–`TASK-113`. Verified against `TODO/TASK-094.md`–`TASK-097.md`, `TASK-106.md` 2026-08-05 (`TASK-118`) — this row previously read "design complete, implementation not started" well after implementation had actually finished. |
| 5 | DDNS, ACME, Admin | `vw_ddns`, `vw_acme`, thread pool, admin CLI, integration tests | SRV.01, PRT.04 | **complete** (TASK-036–041 done) |
| 6 | GC, Invites, Recovery | `vw_gc`, invite tokens, recovery email | SRV.01, PRT.04 | **complete** (TASK-042–046 done) |
| 7 | GUIs + Cluster | `vw_client_gui`, `vw_server_gui`, `vw_cluster` replication | GUI.03, SRV.01 | **complete** (TASK-047–053 done) |
| 8 | Hardening | Security audit, fuzz testing, integration suite, CI, and every bug/gap found by exercising previously-untested features for the first time | SEC.07, CQR.08, QA.06, all agents | **in progress, open-ended by design** — this phase has no fixed end, since real-world bugs keep surfacing as previously-untested features get exercised for the first time. Spans `TASK-054`–`TASK-093` and continues through the current task range (`TASK-102`–`TASK-117`, `TASK-119`, `TASK-121`–`TASK-125`), covering GUI wiring (`TASK-107`/`TASK-108`), oplog format hardening (`TASK-121`–`TASK-124`), dependency build hygiene (`TASK-119`/`TASK-125`), and this doc refresh itself (`TASK-118`). `TASK-120` (tutorial doc) is the one item still open as of 2026-08-05. |
| 9 | Vault / End-to-end encryption | `vw_vault` (client + server), envelope encryption, vault UI | PRT.04 (design), SRV.01/CLI.02/GUI.03 (impl), QA.06 | **complete** — design published 2026-07-29 (`docs/PROTOCOL.md` §7.11, `TASK-089`); server storage (`TASK-098`), client vault module (`TASK-099`), GUI (`TASK-100`), and regression tests (`TASK-101`) all closed `done`. |
| 10 | Packaging, deployment docs, end-to-end tests | Linux/Windows service packaging (server + client daemon), `docs/DEPLOYMENT.md`, benchmark suite, e2e sync tests | BLD.05, QA.06 | **complete** (TASK-062–069 done) |

> **2026-07-29 audit note**: this table (and the Module Map / on-disk-layout sections above) was found to contain at least one fabricated completion claim (Phase 4, corrected above) that cited unrelated task IDs and referenced a module (`vw_users`) that was never created. The rest of this document has not been re-audited line-by-line against the current codebase — treat "complete" markers here as unverified until spot-checked against `TODO/` and the actual source tree, the same way Phase 4's was. `TODO/` task files (which get appended-to, never rewritten wholesale) are more trustworthy than this document's prose for "did X actually happen."
>
> **2026-08-05 follow-up (`TASK-118`)**: re-audited every phase-status claim
> in the table above against `TODO/TASK-*.md` status fields (all 125 task
> files checked, not sampled) rather than against memory of past
> conversations. Found Phase 4 (Sharing) was, ironically, *still* wrong —
> the 2026-07-29 fix correctly identified the original fabrication but by
> this date the real implementation had since finished, and the row hadn't
> been updated to say so — plus two whole phases (Vault/E2EE, Packaging)
> that existed in this document's own "Last updated" header prose but were
> never given rows in this table at all. Also found and corrected: the
> Approved External Dependencies table and Repository Structure listing
> both still described `mbedTLS`/`Argon2` as vendored submodules after
> `TASK-119`/`TASK-125` removed them; the `vw_cache` "selective-sync rules"
> claim (§ Module Map) had no corresponding code or task, ever. See
> `TASK-118` for the full diff. This document drifting *again* within ten
> days of its last audit is itself worth noting: prefer trusting `TODO/`
> over this file's prose for anything you're about to act on, and don't
> assume a past "corrected" note means a claim is still accurate today.

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
