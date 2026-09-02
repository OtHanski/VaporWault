# VaporWault — System Architecture

**Owner**: ARCH.00  
**Last updated**: 2026-08-31 (`TASK-224` — added the Android client design: module
map, approved-deps addendum, and Architectural Decisions rows for the wire-protocol
integration, sync model, credential storage, transfer storage/execution, UI toolkit,
and team-ownership choices. Prior entry, 2026-08-26 (`TASK-204`) — re-audited the
Implementation Phases table against every `TODO/` task file's status field (all 218
checked, not sampled) rather than against memory; see the 2026-08-26 audit-note
follow-up under Implementation Phases for what was found and fixed. Prior entry,
2026-08-05 (`TASK-118`), covered `TASK-001`–`TASK-125` at that level of
detail; superseded here rather than kept verbatim, since `TODO/` is the
trustworthy record of what shipped, not this header.)

---

## Overview

VaporWault is a self-hosted cloud file hosting system. It consists of:

- **Server** (Linux only): stores and serves files, manages users, replicates across cluster nodes
- **Client daemon** (Linux + Windows): background process that syncs local folders to the server
- **GUIs** (C++ / Dear ImGui): thin clients that connect to the server GUI process or local client daemon via IPC
- **CLIs** (pure C): also thin clients connecting to the server process or local client daemon via IPC
- **Web gateway + browser client** (Linux; design published 2026-08-10, `TASK-127`): a
  standalone executable that speaks `vw/1` directly to the server as its own authenticated
  client (a sibling of the client daemon, not a bridge over its IPC), translating it to an
  HTTP/JSON API for a static HTML/TypeScript frontend served by nginx. Owned by `WEB.09`.
- **Android client** (design published 2026-08-31, `TASK-224`): a Gradle/NDK app that
  speaks `vw/1` directly to the server as its own authenticated client — another sibling
  of the client daemon and gateway, not a bridge over either's IPC/HTTP surface — by
  cross-compiling `vw_client_core`/`vw_vault` (unmodified C, plus `libvw_core`) for
  Android and driving them from Kotlin over a thin JNI bridge. Does on-demand
  browse/upload/download (Drive-app style), not continuous background folder-mirroring —
  `vw_sync`/`vw_daemon`/`vw_ipc`/`vw_watch_*` are out of scope for it. Owned by `MOB.10`.

All network transport uses TLS 1.3 via mbedTLS. All other implementation is pure C except the Dear ImGui GUIs (C++), the web frontend (TypeScript/HTML/CSS), and the Android client (C via JNI + Kotlin).

---

## Approved External Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| mbedTLS | v3.6.7, pinned via CMake `FetchContent` (`third_party/CMakeLists.txt`) — not a submodule, see `TASK-119` | TLS 1.3, SHA-256, AES, ECDSA (for ACME CSR), RNG |
| SDL2 | ≥2.26.0, manually vendored on Windows / system package on Linux+macOS (`VENDOR_SETUP.md`) | Windowing + OpenGL context for Dear ImGui |
| Dear ImGui | vendored (git submodule, `docking` branch) | GUI rendering (C++) |
| Argon2 reference | 20190702, pinned via CMake `FetchContent` (not a submodule, see `TASK-125`) — ~600 lines, public domain | Password hashing (Argon2id) |

**No SQLite. No other external libraries.**

**Android-only additions** (`TASK-224`, apply only to the `android/` Gradle project;
none of these are linked into the server/client/gateway binaries above):

| Dependency | Version/Vendoring | Purpose |
|---|---|---|
| Android Gradle Plugin + Gradle | Pinned in `android/gradle/wrapper` | The platform's only build path — not optional the way a vendored library is |
| Android NDK + CMake | Pinned `ndkVersion` in `android/app/build.gradle` | Cross-compiles `vw_core`/`vw_client_core.c`/`vw_vault.c`/mbedTLS/Argon2 per ABI; reuses the existing portable CMake, does not fork it |
| `androidx.core`, `androidx.appcompat` | Latest stable at time of `TASK-225` | Minimum viable set for a Views-based app on current API levels; there is no "zero AndroidX" option on modern Android |
| `androidx.documentfile` | Latest stable | Thin wrapper over raw Storage-Access-Framework `ContentResolver` calls, for on-demand file/folder transfers |

No Jetpack Compose, no `androidx.security-crypto` (deprecated 2025; superseded by
raw `AndroidKeyStore` usage, see Architectural Decisions below), no WorkManager/Room
for this milestone (no continuous background sync to schedule).

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
| Primary failover | None *for the server itself* (no automatic promotion, no consensus protocol) — but see "Client-side automatic fallback" and "Replica hot-standby data replication" below, added `TASK-169`–`178` | Correct multi-primary consensus is still too complex for this project's scale and was never attempted. What changed (2026-08-14): clients can now optionally fail over *themselves*, read-only, to an already-paired replica when the primary is unreachable — this never risks split-brain because no server ever accepts a write it can't reconcile: the replica stays read-only from every client's perspective while degraded, and queued writes flush only to the primary once it's reachable again (the existing offline-queue mechanism, unchanged). The consensus problem this row originally avoided was "which server may accept writes," which is still true and still unsolved on purpose — this feature deliberately never has to answer that question |
| Replica hot-standby data replication | Extend the existing replica pull loop (`vw_cluster.c`'s `OPLOG_PULL`/`_DATA`/`_ACK`) to fetch and apply the *actual* record each oplog entry points to (new `CLUSTER_RECORD_FETCH`/`_DATA`, `CLUSTER_CHUNK_QUERY`/`_FETCH`/`_DATA` messages, `0x0708`+), not just copy the notification bytes into its own oplog file as it does today | Discovered while designing `TASK-169`: oplog entries are bare-ID change notifications (`VW_OPLOG_FILE_CREATE`'s payload is literally just `owner_id`, per `vw_store_files.c`/`vw_vault.c`'s append call sites) — a replica that only replicates the oplog stream, as the pre-existing feature did, has an audit trail but no queryable copy of the primary's actual users/files/chunks. `TASK-165`'s multi-account plan already required a fallback target to "be a configured replica" with real data; this makes that literally true rather than aspirational. Reuses the existing per-replica pre-shared `auth_token` handshake (`NODE_HELLO`) for the new messages' authentication rather than inventing a second credential, and reuses the existing batch chunk-existence bitmask (`vw_storage_chunk_query`, already used by the client `CHUNK_QUERY` upload path) for "which chunks is the replica missing" instead of a new primitive (`TASK-170`) |
| GC replica-safety gating | Chunk garbage collection (`vw_gc.c`'s call into `vw_storage_gc_run`) is gated on `vw_cluster_min_sync_watermark()` the same way oplog segment truncation already is — a GC cycle only deletes a zero-refcount chunk once every active replica has acknowledged past the watermark that existed when the cycle started | Found during `TASK-169`'s design research: today only oplog segment truncation checks the replica watermark; chunk deletion (`vw_storage_gc_run`) runs unconditionally on `ref_count == 0`, with no regard for whether a lagging replica has actually pulled/applied the oplog entry that chunk's data is needed for. Without this gate, "hot-standby replication" would have a real, silent data-loss race: a replica that's behind could have a chunk permanently vanish out from under it before it ever syncs the content, no error surfaced anywhere until a client later tries to download that file from the failed-over replica (`TASK-171`) |
| Client-side automatic fallback (read-only) | Opt-in per-account (`vapourwault-daemon`) and per-deployment (`vapourwault-web-gateway`) secondary `host`/`port`/`ca_cert_pem_path`, pointing at an already-paired replica. On a primary connection failure, the daemon connects to the fallback instead (a fresh `AUTH_REQUEST` using a retained `SHA-256(password)` "login token" — never the raw password, never a primary-issued resume token, which is meaningless against a different server — persisted alongside `session.tok` with the same 0600 protection) and serves list/stat/download/share-list/vault-list/version-list normally, but every write (upload, mkdir, delete, move, share grant/revoke, vault create/upload) is rejected client-side (`VW_ERR_READ_ONLY_FALLBACK` for synchronous IPC requests; the automatic sync engine's file actions route into the existing offline queue instead) rather than being sent to the fallback session. The daemon keeps probing the primary every cycle while parked on the fallback and switches back (flushing the queue) the instant it's reachable (`TASK-173`) | User-requested (`TASK-169`, 2026-08-14) explicitly as an *addition* to the existing manual-reconfiguration option, not a replacement. Read-only-while-degraded was the deciding design choice (offered as the recommended option and accepted) specifically so this doesn't reopen the split-brain risk "Primary failover" above was written to avoid — every write still has exactly one possible destination (the primary), whether sent immediately or queued and flushed later. **Gap closed (`TASK-179`, opened `2026-08-14`, closed `2026-08-17`):** this read-only property used to be enforced only client-side — nothing on the replica's own normal client-facing listener rejected a write from a different client connecting to it directly during the outage. `vw_server_dispatch_file_op`'s single dispatch choke point (`vw_file_handlers.c`) now rejects every write-shaped message with a new `VW_ERR_READ_ONLY_REPLICA` (§10.1, `docs/PROTOCOL.md`) whenever `cfg.cluster.is_replica` is true, before the corresponding handler runs — no on-disk state is mutated. What was previously a bounded-but-real sharp edge (a rogue direct write eventually silently discarded by `TASK-172`'s next sync pass, but not rejected at the point of the write) is now rejected outright at the point of the write too, on every server regardless of which client (or hand-rolled script) sent it |
| CA store (vw_net) | Option A: return VW_ERR_INVALID_ARG when verify_required && ca_cert_pem_path==NULL | mbedTLS does not load platform CA stores automatically; Option B (real CA store) deferred to Phase 3 |
| Oplog two-phase commit | confirmed byte (u8, NOT CRC-covered) at offset 16 in each entry header | Allows in-place atomic confirm write without CRC recomputation; seg_scan uses `continue` (not `break`) on confirmed==0 to preserve confirmed entries that follow unconfirmed holes in concurrent transaction patterns |
| vw_net recv timeout | Per-connection `_Atomic uint32_t recv_timeout_ms` in struct vw_conn; custom BIO callbacks read it directly | Allows per-connection deadlines without mutating the shared ssl_config; set via vw_net_conn_set_recv_timeout() post-accept |
| AUTH_FAIL lockout_remaining_secs | u16 (max 65535s) | u8 (max 255s) cannot represent the 600-second OTP lockout window; wire format change introduced in protocol v2 |
| Web UI integration point | New independent `vw/1` client (web gateway), not a bridge over the daemon's loopback IPC | Works from any browser without a local daemon running; the daemon IPC has no TLS and assumes a trusted local OS peer, wrong trust model for a browser-facing service (`TASK-127`) |
| Gateway HTTP/JSON layer | Hand-rolled minimal HTTP/1.1 parser + JSON encoder/decoder (new `vw_http`/`vw_json` modules), no vendored HTTP server library | nginx is the mandatory front door in this deployment model and is the gateway's only upstream, so the gateway never has to handle malformed/non-HTTP1.1/chunked-edge-case traffic — a full general-purpose HTTP server is more than the actual requirement; avoids adding a third-party HTTP server's attack surface to `ARCHITECTURE.md`'s dependency table, consistent with the project's existing hand-rolled-JSON precedent in `vw_acme.c` (`TASK-127`) |
| Vault decryption locus for the web client | In-browser (TypeScript/WASM), never the gateway | Preserves the zero-knowledge property `TASK-089`'s vault design was built around — the gateway only ever sees ciphertext and wrapped keys, never the passphrase or plaintext (`TASK-127`) |
| Gateway session model | One live `vw_client_sess_t` per logged-in browser session, keyed by a gateway-issued session identifier, held in a gateway-managed pool, with a **mandatory hard concurrency cap** | The gateway is a genuine multi-user, multi-session server process (unlike the single-user daemon), so session lifecycle/isolation is new work, not reused from `vw_daemon`'s single-session assumption; the cap is mandatory (not merely recommended) since an unbounded session pool is a trivial resource-exhaustion DoS against a single shared process (`TASK-127`, hardened during SEC.07 review) |
| Gateway↔server TLS verification | `vw_client_cfg_t.cert_verify` MUST be `VW_CERT_VERIFY_REQUIRED` with a real `ca_cert_pem_path`, never `VW_CERT_VERIFY_NONE` | `vw_net_connect`'s API makes disabling verification one flag away, which is fine for the test-only escape hatch it was designed for but unacceptable for a production gateway process authenticating real users — enforced as a build-time/config-time requirement, not left to a developer's default choice (`TASK-127`, hardened during SEC.07 review) |
| Gateway listener bind address | Defaults to loopback (`127.0.0.1`) only, even though nginx is the intended and only supported upstream | Defense-in-depth against a reverse-proxy misconfiguration or a future deployment mistake exposing the gateway directly — `vw_http`'s reduced parser surface (`TASK-129`) assumes a trusted upstream, so an accidental direct exposure would hand its full, less-hardened input space to arbitrary internet traffic (`TASK-127`, hardened during SEC.07 review) |
| Installer packaging mechanism | CMake's built-in CPack, driven by the existing `install()` rules, rather than a hand-rolled packaging step | Reuses the CMake install graph that already exists (`CMakeLists.txt`'s per-target `install()` blocks) instead of maintaining a second, parallel list of "what ships where"; CPack's DEB/RPM/WIX generators are all built into the CMake distribution already in use, so this adds no new external dependency (`TASK-145`) |
| Installer component split | Two CPack components, `server` and `client` (each pulling in its GUI binary when `VW_BUILD_GUI=ON`); `vwdump` ships with `server` | Mirrors the existing install-script split (`packaging/linux/install.sh` vs `client_install.sh`, and the two separate `Install-VaporWault*.ps1` scripts) — server and client are normally installed on different machines, so they stay separate installable units rather than one bundle (`TASK-145`) |
| Linux package formats | `.deb` (CPack DEB) and `.rpm` (CPack RPM), one package per component — four artifacts total (`server`/`client` × `deb`/`rpm`) | Covers both major Linux packaging ecosystems; per-component packages (not one combined package with optional components) match how `apt`/`dnf` users expect to install a specific piece of software (`TASK-145`) |
| Linux maintainer scripts | Shared, portable POSIX-sh logic (`packaging/linux/scripts/`) invoked as both DEB's `postinst`/`prerm`/`postrm` and RPM's `%post`/`%preun`/`%postun` scriptlets | DEB and RPM scriptlet *content* can be identical portable shell; only their invocation argument conventions differ (DEB: `postrm remove` vs `postrm purge`; RPM: `$1` install-count semantics) — kept as one reviewed script per lifecycle stage instead of duplicating install.sh's logic three times (`TASK-145`) |
| Windows package format | One MSI per component (CPack WIX generator, WiX Toolset v3 `candle`/`light`), not one combined MSI with feature selection | Keeps the artifact shape symmetric with the Linux `.deb`/`.rpm` split (one installable unit per component) rather than introducing a different selection model on Windows only (`TASK-145`) |
| Windows service registration (server) | WiX native `<ServiceInstall>`/`<ServiceControl>` elements, replacing `Install-VaporWault.ps1`'s manual `New-Service`/`sc.exe` calls | Native MSI service registration participates correctly in MSI's own install/uninstall/rollback transaction, unlike a script run after the fact; the existing PowerShell installer scripts are kept as a documented manual/advanced-use alternative, not removed (`TASK-145`) |
| Windows client registration | A WiX-invoked deferred custom action running the existing scheduled-task-registration logic from `Install-VaporWaultClient.ps1`, rather than reimplementing Scheduled Task XML authoring in raw WiX | The client daemon is a per-user Scheduled Task (logon trigger), not a Windows Service — deliberately not native MSI territory; reusing the already-shipped, already-reasoned-through PowerShell logic is lower-risk than a from-scratch WiX Scheduled-Task fragment that can't be fully integration-tested in this environment (`TASK-145`) |
| Multi-account daemon model | One `vapourwault-daemon` process holds N concurrently-connected `vw_account_ctx_t` instances (each with its own `vw_client_sess_t`/`vw_cache_t`/vault registry under `{state_dir}/accounts/<account_id>/`), round-robin-scheduled on the existing single-threaded sync loop — not N separate daemon processes | N independent daemon processes already work today with zero daemon-side changes (distinct `--state-dir`/`ipc_port` each), but that means N services to install/monitor and would require the GUI to spawn/track child processes, breaking the existing "sync continues when the GUI is closed" invariant (the GUI has never owned the daemon's process lifecycle). One process/one port keeps the ops story identical to today; round-robin (not real OS-thread concurrency) delivers "every logged-in account keeps syncing regardless of which is displayed" without a multi-threading/locking rewrite of `vw_sync.c`/`vw_cache.c`'s per-account structures, consistent with this project's personal-self-hosted-scale target (`TASK-160`/`TASK-161`) |
| Daemon↔GUI/CLI IPC account scoping | A leading `u32 account_id` field on every existing per-file/vault/share/folder IPC request, assigned once by a new `VW_IPC_ACCOUNT_ADD_RESP` and reused thereafter — not a "select active account" stateful connection, and not a separate IPC port per account | `VwGuiIpc`'s one-shot-connection-per-call design (`TASK-108`) means there is no persistent connection to hold "current account" state on; a leading id field is the same pattern already used for `file_id` instead of repeating paths, and needs no protocol version negotiation since both IPC ends always ship from the same build (`TASK-161`) |
| Accounts are per-server, not just per-user | Each `vw_account_ctx_t` independently carries its own `server_host`/`server_port`/`ca_cert_pem_path`/`username` (`account.conf`, set via `VW_IPC_ACCOUNT_ADD_REQ`'s own fields) — there is no daemon-global "the server" anywhere; two accounts on one daemon may point at two entirely unrelated VaporWault deployments (e.g. a family server and a separate friends server), each with its own CA trust root | Settled requirement (2026-08-13 revision): a user belonging to two independent self-hosted networks must be able to add both on the same client. This fell out of the account-isolation design almost for free — `accounts/<id>/` was already fully self-contained (own cache, own session, own sync loop) with no shared connection state to begin with — but is recorded here explicitly so `TASK-162`'s CLI `account add` and `TASK-163`'s GUI "add account" dialog both surface host/port/CA-cert per account (not just username/password) rather than accidentally re-introducing a single implied server (`TASK-161`) |
| Gateway stays one-process-one-server | The web gateway is *not* extended to multi-server the way the daemon is — one gateway+nginx deployment is still configured for exactly one upstream VaporWault server (its own `--server-host`/`--server-port` CLI flags, unchanged). Accessing a second, unrelated server from a browser means visiting that server's own separate gateway deployment/URL, not adding it as another slot on the first one | Explicit scope decision (2026-08-13), made when the daemon side turned out to already be multi-server: multi-server-per-gateway would mean each session slot needing its own upstream TLS connection/CA trust root, a materially bigger rework of the session pool (`TASK-164`) and remember-me store (`TASK-165`) than either was designed for. `TASK-164`–`166`'s "multi-account" therefore means multiple accounts *on the one server this gateway is deployed for*, not cross-server — consistent with one-gateway-per-self-hosted-deployment being the existing norm (`docs/DEPLOYMENT.md`) |
| Gateway multi-account browser sessions | Per-slot cookie names (`vw_session_0`..`vw_session_<N-1>`, small hard cap) instead of one fixed cookie name, with a `X-Vw-Slot` request header selecting which slot backs a given request | A browser automatically attaches every matching-path cookie on every request regardless of name, so multiple concurrently-live HttpOnly session cookies already coexist without any new browser-side storage; the gateway just needed a way to know which of the several presented cookies a given request means, and a header keeps that out of every endpoint's JSON body schema (`TASK-164`) |
| Gateway remember-me persistence | New gateway `--state-dir` holding a small on-disk store mapping remembered cookie value → resumable `vw_client_get_token()` value, consulted only on a live-pool cookie-miss (gateway restart or eviction), reusing `vw_client_resume()` — not a separate long-lived credential/refresh-token scheme | Reuses the exact primitive the daemon's own single-account "remember me" already relies on (`vw_client_resume`/`tok_load`/`tok_save`, `vw_daemon.c`) instead of inventing a second credential-longevity mechanism; resumption is already single-use/rotating per `docs/PROTOCOL.md` §7.1, so the security properties are already reviewed and understood (`TASK-165`) |
| Public link password protection | `LINK_CREATE` gains an optional password (additive field, no protocol version bump); server stores only an Argon2id hash (reusing the account-password hashing path), never plaintext. `LINK_ACCESS` gains an optional password field and rejects with distinct new error codes for missing/wrong password. Brute-force mitigation reuses the *existing* `LINK_ACCESS` per-IP rate limiter (`vw_share.c`'s `LINK_ACCESS_MAX_FAILURES`/`_WINDOW_SECS`, 5/60s) rather than adding a second, redundant per-token lockout mechanism — it already gates every `LINK_ACCESS` call, including password guesses against a known token, since a wrong password is just another rejected `LINK_ACCESS` attempt | Feature-gap review (2026-08-25) found public links have no password gating — once minted, anyone with the token has access forever until manually revoked. **Correction (2026-08-26, found while implementing `TASK-186`):** the same review incorrectly also claimed links have no *expiration* — `expires_at` on `LINK_CREATE`/enforcement in `vw_share_get_by_token` (`vw_share.c:505`) already existed end-to-end (protocol, server, CLI, GUI) before this session; only the web frontend's create-link form never surfaced a picker for it (`TASK-190`), and password protection was the only real gap. `TASK-185`'s design task and `TASK-186`-`191` were corrected in place rather than silently left describing a feature that doesn't need building. Existing links (no password) are byte-for-byte unaffected (`TASK-185`–`191`) |
| Selective-sync rules | Per-sync-folder glob-style exclude patterns, stored on `vw_sync_folder_t`/`account.conf`, enforced entirely client-side in `vw_sync.c`'s BFS collect step — no server/protocol change. Excluding an already-locally-synced path never deletes the local copy; it only stops pulling further remote changes into it. Not available on vault-rooted sync folders | Corrects a fictional claim: this document previously attributed "selective-sync rules" to `vw_cache`, but no such code, in `vw_cache` or anywhere else, ever existed (flagged by the 2026-08-05 audit note, designed for real 2026-08-25, `TASK-192`–`195`) |
| Filename search | New `SEARCH`/`SEARCH_RESP` messages: server-side, case-insensitive substring match on filename, scoped to exactly what `effective_permission()`/`FILE_LIST` already let the caller see (owned + shared-with-me). A single linear scan of the whole file table (no owner-indexed enumeration exists to walk instead), hard-capped at 200 entries with a `truncated` flag — **not paginated**: `docs/PROTOCOL.md` was checked for a cursor convention to reuse and none exists anywhere in it (this row originally, incorrectly, said "paginated" — corrected here, `TASK-196`/`197`). Content search is out of scope — vault contents are opaque ciphertext by design, and non-vault content search would need an index the flat-file store doesn't have. No scoped (`LINK_ACCESS`-redeemed) session support — such a session already sees only its one directly-browsable subtree. GUI/web results with no locally-known path (SEARCH never returns one, by design) are read-only/action-limited rather than reusing the normal browser's path- or version_id-addressed actions | Feature-gap review (2026-08-25) found no search anywhere in the product (GUI, CLI, or web frontend) past the server admin GUI's audit-log view. Server-side (not client-side full-tree-pull-then-filter) to reuse `FILE_LIST`'s existing permission-scoping logic rather than duplicating it (`TASK-196`–`202`, closed 2026-08-26). Follow-ups filed during implementation, not fixed inline: `TASK-217` (several integration test wrappers' binary-search lists predate and don't include `build-gw-e2e/bin`) and `TASK-218` (a locally-created new subdirectory never syncs up through the ordinary background watcher at all — unrelated pre-existing gap in `vw_sync.c`, found while writing `TASK-199`'s CLI test) |
| Opt-in email alerts (admin + user) | Two separate preference surfaces reusing the existing `vw_smtp.c` relay: user categories (`share_received`, `quota_warning`, `new_login`, `account_security_change`) are per-user, opt-in, settable live via a new additive `NOTIFY_PREFS_GET`/`_SET` wire message pair — same shape as the existing "2FA optional per-user" precedent. Admin categories (`replica_lag`, `acme_renewal_failure`, `disk_capacity`, `lockout_spike`, `crash_recovery`) are `vapourwaultd.conf`-only, no protocol change — operational knobs an operator sets once, not per-session user state. Default off everywhere; threshold-style categories are edge-triggered with re-arm, not repeated, to avoid mail floods | Identified as a real gap while discussing `TASK-169`'s fallback feature: it has no alerting layer, so a degraded/lagging replica or a stuck primary outage can go unnoticed. `replica_lag` is the closest server-observable proxy for that specific concern but is explicitly not the same signal as "clients are on fallback" — the primary has no visibility into a client connecting directly to a replica — recorded here so a future "true fallback-usage" alert isn't assumed already covered (`TASK-205`–`213`) |
| Android wire-protocol integration | Native JNI reuse of `vw_client_core.c`/`vw_vault.c` (unmodified) + `vw_core`, cross-compiled per-ABI via NDK/CMake — not a Kotlin reimplementation of `vw/1`, not routing through the web gateway's HTTP/JSON API | Matches the established "every native client compiles the same C source" pattern (CLI, daemon, gateway); unlike a browser, Android *can* link C code, so the constraint that justified the gateway's existence doesn't apply here. A Kotlin reimplementation would duplicate protocol/crypto logic in a second language with no precedent elsewhere in the project; routing through the gateway would require a gateway instance reachable from mobile devices as new infrastructure, for no benefit an Android client can't get natively (`TASK-224`) |
| Android sync model | On-demand browse/upload/download only (Drive/Proton-Drive-app style) — no continuous background folder-mirroring | Android has no equivalent of a persistent POSIX daemon; `WorkManager`/`JobScheduler`/foreground services are the only mechanisms, each with real time/battery limits the desktop daemon doesn't face. The user's own framing ("in likeness to Google Drive/Proton Drive") already describes an on-demand model, not continuous mirroring, so `vw_sync`/`vw_daemon`/`vw_ipc`/`vw_watch_*` are out of scope — there is no separate daemon process for the app to be, or to talk IPC to (`TASK-224`) |
| Android credential/session storage | Raw `AndroidKeyStore` (`KeyGenParameterSpec`, hardware-backed where available), no wrapper library | Genuinely new capability, not a port — the desktop/native client has no OS-keychain integration anywhere (session/login tokens are plain mode-0600 files). `androidx.security-crypto`'s `EncryptedSharedPreferences` convenience wrapper was deprecated in 2025 in favor of a heavier Tink+DataStore combo; raw `AndroidKeyStore` is the actual minimal-dependency choice, not the deprecated wrapper (`TASK-224`) |
| Android on-demand transfer storage | Storage Access Framework (`ACTION_OPEN_DOCUMENT`/`_TREE`/`ACTION_CREATE_DOCUMENT`) for user-visible source/destination files, staged through the app's private cache dir for chunking; `vw_fs.c` unmodified | Scoped storage gives no path-based access to arbitrary user-chosen locations outside the app sandbox — the native layer gets a raw fd for the user-visible file, never a resolved path, so `vw_fs.c`'s path-based API only ever touches the app's own private (real POSIX path) staging area, which needs no change (`TASK-224`) |
| Android transfer execution | User-Initiated Data Transfer job (`JobScheduler.setUserInitiated()`, API 34+) with a `dataSync`-typed foreground-service fallback pre-API-34; no periodic `WorkManager` job | UIDT is Google's purpose-built mechanism for exactly this case (explicit user-triggered upload/download), exempt from standard job-quota throttling and supporting long/resumable transfers. No periodic background job is needed since this milestone does on-demand transfers only, which also avoids pulling in `WorkManager`'s transitive `Room` dependency (`TASK-224`) |
| Android UI toolkit | Classic Views (RecyclerView-based), not Jetpack Compose | Closest philosophical match to "Dear ImGui, not Qt" — smallest first-commit dependency graph, most direct control — at the deliberate cost of being Google's less actively-pushed option going forward; both still require some AndroidX, there is no "zero framework" option on Android the way Dear ImGui provides on desktop (`TASK-224`) |
| Android team ownership | One role, `MOB.10`, owns both the native JNI layer and the Kotlin/UI layer | Unlike desktop's CLI.02/GUI.03 split (a genuinely separate GUI process talking IPC to a daemon), the Android app is one Gradle project with no separate GUI process — forcing an artificial two-agent split doesn't map the way "no protocol code in the GUI" does for a real second process (`TASK-224`) |
| Web frontend: public-link redemption page | A query parameter (`?link=<64-hex-char token>`), not a path segment — nginx serves this frontend as a static, SPA-less page with no server-side routing (`WEB.09`'s own charter), so a query param needs no nginx change while a path segment would (a fallback rewrite to `index.html` that doesn't exist today). The token is stripped from the URL via `history.replaceState` before any redemption attempt, purely as hygiene. A password (when the link needs one) is only ever collected via the redemption view's own password field, sent as a POST body — never the URL, browser history, or a referrer header. **Scope decision**: once redemption succeeds, the existing logged-in browser view is reused completely unmodified for both VIEW- and EDIT-permission links — no client-side hiding/graying of actions by permission level, since no such pattern exists anywhere else in this frontend either (an ordinary VIEW-only share grant already relies entirely on server-side `effective_permission()` enforcement plus a clean error message on a disallowed action, e.g. `handleDelete`'s `showError` path) | `TASK-190` (password support for public links) discovered the redemption page itself didn't exist at all — checked `main.ts`/`index.html` in full: no route ever called `POST /api/links/access`, despite the server side (`TASK-134`/`140`, gateway session-cookie issuance for a redeemed anonymous scoped session) having supported it all along, already end-to-end tested (`test_gateway.py::test_public_link_create_redeem_revoke`/`test_public_link_password_via_gateway`). Filed as `TASK-216`, closed 2026-08-26 — building the page needed no backend change at all, only wiring the frontend to an already-complete, already-tested API |

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
    gateway/        # vapourwault-web-gateway (C) — new independent vw/1 client + HTTP/JSON API (TASK-127)
  web/              # Static TypeScript/HTML/CSS frontend, built to plain JS, served by nginx (TASK-127)
    dist/           # npm run build output (gitignored; not checked in)
  android/          # Android client: Gradle project + JNI bridge, another independent
                    # vw/1 client (TASK-224)
    app/
      src/main/
        cpp/        # vw_jni_bridge.c + CMakeLists.txt reusing vw_core/vw_client_core.c/
                    # vw_vault.c from src/ unmodified, builds libvaporwault_jni.so
        java/       # Kotlin: VwClient JNI wrapper, UI (Views), account/credential storage
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
  cmake/            # Packaging.cmake (CPack DEB/RPM/WIX, TASK-145/146);
                    # vw_version.h.in (embedded --version string, TASK-203)
  packaging/        # linux/ (systemd units, install.sh, maintainer scripts),
                    # windows/ (WiX fragments, Install-VaporWault*.ps1)
  docs/
    PROTOCOL.md     # Wire protocol specification (owned by PRT.04)
    STYLE.md        # C/C++ style decisions (owned by CQR.08)
    RELEASE.md      # Release workflow, versioning (owned by BLD.05)
    DEPLOYMENT.md   # Admin deployment/operations guide
    TUTORIAL.md     # Non-technical end-user client setup tutorial
    CLIENT_GETTING_STARTED.md  # Plain-language end-user feature walkthroughs
  TODO/             # One TASK-NNN.md file per task
  VERSION           # MAJOR.MINOR.PATCH, no leading "v" (TASK-203) — see
                    # docs/RELEASE.md for how this relates to a release tag
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

### Web gateway + browser client modules (design, `TASK-127` — not yet implemented)

| Module | File(s) | Owner | Language | Responsibility |
|--------|---------|-------|----------|----------------|
| `vw_gateway_core` | `src/gateway/vw_gateway_core.{h,c}` | WEB.09 | C | Executable entry point; owns the gateway session pool |
| `vw_gateway_session` | `src/gateway/vw_gateway_session.{h,c}` | WEB.09 | C | Per-browser-session `vw_client_sess_t` lifecycle, timeout, concurrency |
| `vw_http` | `src/gateway/vw_http.{h,c}` | WEB.09 | C | Minimal HTTP/1.1 request/response parsing, trusts nginx as sole upstream |
| `vw_json` | `src/gateway/vw_json.{h,c}` | WEB.09 | C | Minimal JSON encode/decode for the gateway's REST endpoints |
| `vw_gateway_api` | `src/gateway/vw_gateway_api.{h,c}` | WEB.09 | C | Endpoint dispatch: maps HTTP/JSON requests onto `vw_client_core` calls |
| `web/` frontend | `web/src/*.ts` | WEB.09 | TypeScript | File browser, upload/download progress, login/2FA, sharing, vault UI |
| `web/vault-crypto` | `web/src/vault/*.ts` + WASM Argon2 build | WEB.09 | TypeScript/WASM | In-browser Argon2id (WASM) + AES-256-GCM (`SubtleCrypto`); passphrase/plaintext never leave the browser |

> Reuses `vw_core` and `src/client/vw_client_core.c` directly (compiled into the gateway
> executable's source list), the same "no shared lib, reuse the source file" pattern
> `vapourwault-cli`/`vapourwault-gui` already use for `vw_ipc.c`. Does **not** link
> `vw_sync`/`vw_cache`/`vw_daemon` — the gateway is request/response per browser action,
> not a persistent local-folder sync engine.

### Android client modules (`TASK-224` design; `vw_jni_bridge`/`VwClient` implemented `TASK-225`/`226` — vault support still TASK-230, everything below that still pending)

| Module | File(s) | Owner | Language | Responsibility |
|--------|---------|-------|----------|----------------|
| `vw_jni_bridge` | `android/app/src/main/cpp/vw_jni_bridge.{h,c}` | MOB.10 | C | JNI shim over `vw_client_core` (session lifecycle, file ops/chunking, sharing, version history, account self-service — `TASK-225`/`226`, done); vault RPCs are `TASK-230` |
| `VwClient`/`VwNative` | `android/app/src/main/java/.../{VwClient,VwNative}.kt` | MOB.10 | Kotlin | `VwNative`: raw 1:1 JNI mirror. `VwClient`: the ergonomic wrapper — mobile analogue of desktop's `VwGuiIpc`, minus the socket (calls straight into linked-in native code). Both done (`TASK-226`) for everything but vault. |
| Credential/account store | `android/app/src/main/java/.../accounts/` | MOB.10 | Kotlin | `AndroidKeyStore`-backed credential storage (`VwSecureStore`); multi-profile account registry (`ProfileStore`/`VwAccountRegistry`) — done, `TASK-227` |
| Transfer service | `android/app/src/main/java/.../transfer/` | MOB.10 | Kotlin | SAF-based on-demand upload/download staged through private cache; runs as a User-Initiated Data Transfer job / foreground-service fallback |
| UI (Views) | `android/app/src/main/java/.../ui/` | MOB.10 | Kotlin | File browser, login/2FA, transfer queue, account/profile, sharing/links, vault create/unlock/browse |

> Reuses `vw_core` and `src/client/vw_client_core.c`/`vw_vault.c` directly (compiled into
> `libvaporwault_jni.so`'s source list), the same "no shared lib, reuse the source file"
> pattern the gateway and CLI/GUI already use. Does **not** link `vw_sync`/`vw_cache`/
> `vw_daemon`/`vw_ipc`/`vw_watch_*` — this client is on-demand transfers per user action,
> not a persistent local-folder sync engine, and there is no separate daemon process on
> Android for it to be, or to talk IPC to.

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

vw_json           ← (libc only)
vw_http            ← vw_json
vw_gateway_session ← vw_net, vw_proto, vw_client_core   (one vw_client_sess_t per browser session)
vw_gateway_api     ← vw_http, vw_json, vw_gateway_session, vw_client_core
vw_gateway_core    ← vw_gateway_api, vw_gateway_session   (executable entry point)
web/ frontend      ← (no C dependency; talks HTTP/JSON to vw_gateway_api over the network)

vw_jni_bridge      ← vw_core, vw_client_core, vw_vault   (compiled directly into libvaporwault_jni.so)
VwClient (Kotlin)  ← vw_jni_bridge   (JNI call, in-process — no socket/IPC)
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
verified (`docs/PROTOCOL.md` §7.11.5, `TASK-098`–`TASK-101`).
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
   `TASK-109`. Worked around for both owned and shared folders with
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
| 4 | Sharing | `vw_share` (new module), permission checks in `vw_file_handlers`, shared-folder sync | SRV.01, CLI.02 | **complete** — design published 2026-07-29 (`docs/PROTOCOL.md` §7.5/§7.10, `TASK-088`); server (`TASK-094`), client library (`TASK-095`), GUI (`TASK-096`), and integration tests (`TASK-097`) all closed `done`. Shared-folder local sync (`vw_sync` awareness of `remote_dir_id`-rooted folders) followed as `TASK-106`, hardened by `TASK-109`/`TASK-111`–`TASK-113`. Verified against `TASK-094`–`TASK-097`, `TASK-106` 2026-08-05 (`TASK-118`) — this row previously read "design complete, implementation not started" well after implementation had actually finished. |
| 5 | DDNS, ACME, Admin | `vw_ddns`, `vw_acme`, thread pool, admin CLI, integration tests | SRV.01, PRT.04 | **complete** (TASK-036–041 done) |
| 6 | GC, Invites, Recovery | `vw_gc`, invite tokens, recovery email | SRV.01, PRT.04 | **complete** (TASK-042–046 done) |
| 7 | GUIs + Cluster | `vw_client_gui`, `vw_server_gui`, `vw_cluster` replication | GUI.03, SRV.01 | **complete** (TASK-047–053 done) |
| 8 | Hardening | Security audit, fuzz testing, integration suite, CI, and every bug/gap found by exercising previously-untested features for the first time | SEC.07, CQR.08, QA.06, all agents | **in progress, open-ended by design** — this phase has no fixed end, since real-world bugs keep surfacing as previously-untested features get exercised for the first time. Spans `TASK-054`–`TASK-093`, `TASK-102`–`TASK-117`, `TASK-119`–`TASK-125` (2026-08-05 range), and — found since then, each while implementing or verifying a later feature phase rather than through a dedicated audit pass — `TASK-155` (a protocol-parser desync on `VW_ERR_PROTO_TOO_LARGE` that left unread bytes on the wire), `TASK-156`/`159` (`FILE_LIST_RESP` per-entry `vault_id`), `TASK-157` (`FILE_MOVE` not updating the path index), `TASK-217` (integration test wrappers' build-dir search lists missing `build-gw-e2e`), and `TASK-218` (a new local subdirectory never syncing up through the background watcher). No item in this phase is currently open — the next one is, by design, whatever the next feature phase happens to surface. |
| 9 | Vault / End-to-end encryption | `vw_vault` (client + server), envelope encryption, vault UI | PRT.04 (design), SRV.01/CLI.02/GUI.03 (impl), QA.06 | **complete** — design published 2026-07-29 (`docs/PROTOCOL.md` §7.11, `TASK-089`); server storage (`TASK-098`), client vault module (`TASK-099`), GUI (`TASK-100`), and regression tests (`TASK-101`) all closed `done`. |
| 10 | Packaging, deployment docs, end-to-end tests | Linux/Windows service packaging (server + client daemon), `docs/DEPLOYMENT.md`, benchmark suite, e2e sync tests | BLD.05, QA.06 | **complete** (TASK-062–069 done) |
| 11 | Web gateway + browser client | `vw_gateway_session`, `vw_http`, `vw_json`, `vw_gateway_api`, `web/` TypeScript frontend, in-browser vault crypto (WASM Argon2id + `SubtleCrypto` AES-256-GCM) | WEB.09 (design + impl), BLD.05 (build/packaging), SEC.07 (review), QA.06 (tests) | **complete** — corrected 2026-08-26; this row previously read "design published, implementation not started" well after `TASK-128`–`144` (HTTP/JSON layer, session manager, auth/file/sharing/vault endpoints, frontend views, packaging docs, integration tests, SEC.07 security review) had all closed `done`. One gap surfaced afterward and closed separately: the frontend never actually had a public-link redemption view (`TASK-216`, closed 2026-08-26 — see the Architectural Decisions table entry). |
| 12 | Multi-account support | `vw_daemon` (multi-account core), `vw_ipc` (`ACCOUNT_*` + account-scoped requests), GUI account switcher, `vapourwault-cli` `account` subcommands, gateway multi-slot sessions + persistent remember-me, `web/` frontend switcher | ARCH.00 (design), CLI.02/GUI.03/WEB.09 (impl), SEC.07 (review), QA.06 (tests) | **complete** — corrected 2026-08-26; this row previously read "design published, implementation not started" well after `TASK-161`–`168` (daemon core, CLI, GUI switcher, gateway multi-slot sessions, persistent remember-me, frontend switcher, docs, integration tests) had all closed `done`, including the two `security-sensitive` tasks' (`TASK-161`, `TASK-165`) SEC.07 sign-off. |
| 13 | Installer packages (DEB/RPM/MSI) | CPack component packaging (`cmake/Packaging.cmake`), Linux maintainer scripts, Windows WiX fragments/custom actions, `release.yml` integration | BLD.05 (impl), SEC.07 (review), QA.06 (tests) | **in progress** — design (`TASK-145`), CMake/CPack scaffolding (`TASK-146`), Windows server/client MSIs (`TASK-147`/`148`), Linux `.deb`/`.rpm` (`TASK-149`/`150`), CI wiring (`TASK-151`), security review (`TASK-153`), and docs (`TASK-154`) are all `done`. `TASK-152` (verify install/uninstall/upgrade end-to-end in disposable environments, plus real Windows MSI installs on a real machine) is the one item still open — see `docs/RELEASE.md` §8's disclosed testing limits for exactly what has and hasn't been exercised for real. |
| 14 | Replica hot-standby + automatic client fallback | `vw_cluster` (`CLUSTER_RECORD_*`/`CLUSTER_CHUNK_*` replication), GC replica-safety gating, per-account daemon/gateway read-only fallback | ARCH.00 (design), PRT.04, SRV.01, CLI.02, GUI.03, WEB.09, QA.06 | **complete** (`TASK-169`–`181` done, including two chunk-refcount bugs — `TASK-180`/`181` — found and fixed during this phase's own integration testing, not discovered later). |
| 15 | Client-side version history | Daemon IPC + CLI `version list`/`restore`, desktop GUI view, integration tests | CLI.02, GUI.03, QA.06 | **complete for owned files** (`TASK-182`–`184` done, including `TASK-215`'s root-caused-and-fixed spurious-duplicate-version bug found while writing `TASK-184`'s own test). **Known gap, filed and still open**: `TASK-214` (a grantee has no version history for a shared file at all — `vw_client_version_list`/`_restore` are 100% path-based, and path resolution never crosses into another user's tree, unlike `FILE_LIST`/`_STAT`/`_UPLOAD`/`_DOWNLOAD`/`_DELETE`, which all got a `file_id`-addressed variant for exactly this reason). |
| 16 | Public link password protection | `LINK_CREATE`/`LINK_ACCESS` password field, client/GUI/web surfacing, integration tests | PRT.04, SRV.01, CLI.02, GUI.03, WEB.09, QA.06 | **complete** (`TASK-185`–`191` done). See the Architectural Decisions table entry for the design task's own self-correction (expiration already existed; only password protection was the real gap) and `TASK-216` (the web frontend's redemption page itself, discovered missing while implementing this phase, filed and closed separately since it's a Phase 11 gap, not this phase's). |
| 17 | Selective sync (include/exclude rules) | Per-folder glob exclude patterns in `vw_sync.c`, GUI rule editor | ARCH.00 (design), CLI.02, GUI.03, QA.06 | **complete** (`TASK-192`–`195` done). |
| 18 | Filename search | `SEARCH`/`SEARCH_RESP`, permission-scoped server-side substring match, CLI/GUI/web surfacing | ARCH.00 (design), PRT.04, SRV.01, CLI.02, GUI.03, WEB.09, QA.06 | **complete** (`TASK-196`–`202` done). Two out-of-domain gaps discovered while verifying this phase were filed under Phase 8 rather than fixed inline here — `TASK-217`/`218`, see that row. |
| 19 | Build/version embedding + doc drift audit | Checked-in `VERSION` file, `--version` on every binary, this document's own accuracy | BLD.05, ARCH.00 | **complete** (`TASK-203` — embedded version strings — and `TASK-204` — this audit pass — both done). |
| 20 | Opt-in email alerts (admin + user) | `NOTIFY_PREFS_GET`/`_SET`, `vw_notify` server dispatch/debounce helper, `vapourwaultd.conf` admin-category config, CLI/GUI/web preference UI, integration tests | PRT.04, SRV.01, CLI.02, GUI.03, WEB.09, QA.06 | **complete** — design in `TASK-205`; `TASK-206`–`213` (protocol, server user/admin-category triggers, client IPC/CLI, GUI panel, web gateway/frontend, docs, integration tests) all `done`, including SEC.07 sign-off on the three `security-sensitive` tasks (`TASK-207`, `208`, `211`). Two follow-up gaps surfaced during implementation and filed separately rather than blocking this milestone: `TASK-219` (no self-service 2FA toggle exists, so `account_security_change` only fires for password changes — still open) and `TASK-222` (no wire path set a user's email at all — closed 2026-08-27, `ACCOUNT_EMAIL_GET`/`SET`, §7.14 — this is what finally makes the notify categories above, and the pre-existing `TASK-046` password recovery, reachable for a real account). |
| 21 | Android client | `vw_jni_bridge` (new), Gradle/NDK build, Kotlin `VwClient`/UI/account-store/transfer-service, on-demand upload/download via SAF, vault support | ARCH.00 (design), MOB.10 (impl), BLD.05 (CI), SEC.07 (review), QA.06 (tests) | **in progress** — design published 2026-08-31 (`TASK-224`, this row added at design-close time per the note below rather than left undocumented until the phase finishes). `TASK-225` (Gradle/NDK scaffolding + toolchain proof-of-life) and `TASK-226` (full JNI bridge surface — session lifecycle, file ops/chunking, version history, sharing, account self-service — plus the `VwClient` Kotlin wrapper) both `done`, verified end-to-end against a real `vapourwaultd` (not just a successful build). Found one out-of-domain gap while verifying `TASK-226` and folded it into the existing `TASK-237` rather than filing a near-duplicate: an old/differently-configured server not dispatching a given message type appears to hang the client forever rather than erroring. `TASK-227` (`AndroidKeyStore` credential storage + multi-profile registry, plus a new `nativeConnectWithHash`/`VwClient.connectWithHash` JNI export needed to actually use the stored login-token fallback) also `done`, verified end-to-end including a real `adb` process restart (not just same-process reuse) and a forced fresh `AndroidKeyStore` key generation. Remaining: `TASK-228`-`235` (on-demand transfers, UI, vault support, CI, security review, integration tests); `TASK-236` closes the milestone. |

> **2026-07-29 audit note**: this table (and the Module Map / on-disk-layout sections above) was found to contain at least one fabricated completion claim (Phase 4, corrected above) that cited unrelated task IDs and referenced a module (`vw_users`) that was never created. The rest of this document has not been re-audited line-by-line against the current codebase — treat "complete" markers here as unverified until spot-checked against `TODO/` and the actual source tree, the same way Phase 4's was. `TODO/` task files (which get appended-to, never rewritten wholesale) are more trustworthy than this document's prose for "did X actually happen."
>
> **2026-08-05 follow-up (`TASK-118`)**: re-audited every phase-status claim
> in the table above against every `TODO/` task file's status field (all 125
> task files checked, not sampled) rather than against memory of past
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
>
> **2026-08-26 follow-up (`TASK-204`)**: re-audited every phase-status claim
> above against all 218 `TODO/` task files' actual `status:` fields (all of
> them, not sampled) rather than against memory. Found Phases 11 (Web
> gateway) and 12 (Multi-account) both still read "design published,
> implementation not started" — the same class of staleness the
> 2026-08-05 note flagged for Phase 4 — despite every task in both waves
> (`TASK-128`-`144`, `TASK-161`-`168`) having closed `done` weeks earlier;
> corrected both rows. More significantly, **eight entire feature phases
> shipped since the last audit with no row in this table at all**:
> installer packages (`TASK-145`-`154`, still has one open item —
> `TASK-152`), replica hot-standby + client fallback (`TASK-169`-`181`),
> client version history (`TASK-182`-`184`, plus the shared-file gap
> `TASK-214` — closed 2026-08-27 with a corrected finding: the server
> side needed only a one-line permissive relaxation, not the wire change
> originally proposed; remaining client-surfacing work continues as
> `TASK-223`, also closed 2026-08-27), public link password protection
> (`TASK-185`-`191`), selective sync (`TASK-192`-`195`), filename search
> (`TASK-196`-`202`), version-string embedding (`TASK-203`), and this audit
> itself (`TASK-204`) — added as Phases 13-19. The opt-in email alert
> system (`TASK-205`-`213`, in progress) is added as Phase 20 rather than
> left undocumented until it finishes, unlike every phase above that only
> got a row after the fact. Also corrected: the Repository Structure
> listing was missing `cmake/`, `packaging/`, the new root `VERSION` file,
> and three real `docs/` files (`DEPLOYMENT.md`, `TUTORIAL.md`,
> `CLIENT_GETTING_STARTED.md`) that existed but were never listed. The
> Approved External Dependencies and Architectural Decisions tables were
> spot-checked against the current source tree and found current — no
> changes needed there this pass. Once again: this table drifting for
> *entire shipped phases*, not just a stale status word, suggests updating
> it only during dedicated audit passes isn't sufficient — ARCH.00 should
> consider adding a phase row as part of closing each design task
> (analogous to `TASK-127`/`160`/`169`/`185`/`192`/`196`/`205`) rather than
> backfilling it later, though that process change is noted here rather
> than unilaterally adopted.

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
| Web gateway is new externally-reachable attack surface (sessions, HTTP parsing, XSS from rendered filenames, CSRF) | High | Hand-rolled HTTP/JSON layer scoped to trust nginx as sole upstream (smaller parser surface than a general HTTP server); mandatory SEC.07 review before `TASK-127` closes and before any implementation task reaches `done`; `TASK-144` dedicated review pass |
| Gateway becomes a bridge that silently weakens vault E2EE if a future change routes decryption server-side | Medium | Design decision recorded (`TASK-127`, in-browser decryption only); `TASK-143` integration tests must assert the gateway process never deserializes a passphrase field, not just that decryption "works" |
| Session-token file storage precedent (no real Windows ACL, no OS keychain) carried into a richer multi-session gateway target | Medium | Flagged in `TASK-131`/`TASK-144`; gateway session identifiers should not reuse the daemon's `session.tok` file scheme without fixing the Windows ACL gap for real this time. Now concrete, not hypothetical: `TASK-165`'s gateway remember-me store and `TASK-161`'s per-account daemon tokens (1 → N `session.tok`-equivalent files) both must apply real file permission hardening (POSIX `0600`; a real Windows ACL restricting to the service account), not repeat the known gap — `security-sensitive`, SEC.07 sign-off required before either closes |
