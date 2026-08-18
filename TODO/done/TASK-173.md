---
id:          TASK-173
title:       Daemon: per-account read-only fallback to a replica
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-08-14
priority:    high
depends_on:  [TASK-172]
blocks:      [TASK-174, TASK-175, TASK-178]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, client]
---

Depends on `TASK-172`'s replica hot-standby (a fallback target must have
real, live data now). Each `vw_account_ctx_t`/`account.conf`
(`TASK-161`'s per-account, per-server model) gains an OPTIONAL fallback
server: `fallback_host`/`fallback_port`/`fallback_ca_cert_pem_path`. Unset
= today's behavior unchanged (this feature is opt-in, per the user's own
framing — additive to the existing manual-reconfiguration option, not a
replacement for it).

## Work

- `vw_account_cfg_t`/`account.conf` (`vw_daemon.c`): three new optional
  fields, same per-account/per-server model as the primary
  `server_host`/`server_port`/`ca_cert_pem_path` (`ARCHITECTURE.md`'s
  "Accounts are per-server, not just per-user" — the fallback is
  independently configured too, never implicitly derived).
- `try_connect()`: on primary connection failure (today: falls straight
  to "offline mode," `vw_daemon.c:1445-1471`), if a fallback is
  configured, attempt it before giving up. Track a new per-account state:
  connected-to-primary / connected-to-fallback (read-only) / offline —
  exposed via `STATUS_RESP`/`ACCOUNT_LIST_RESP` (new field(s); GUI/CLI
  need to actually show this, not just internally track it — see
  `TASK-174`/`175`).
- Read-only enforcement while on fallback: every write-shaped IPC request
  (`FOLDER_ADD_REQ` behavior is unaffected — folder *config* is local;
  what matters is actual file mutations: uploads, `FILE_MKDIR_REQ`,
  deletes/moves, `SHARE_GRANT`/`REVOKE_REQ`, `VAULT_CREATE_REQ`, etc.)
  gets queued into the EXISTING offline-queue mechanism instead of being
  sent to the fallback connection — reuse that mechanism exactly, do not
  build a second one. Reads (file list, stat, download, share list, vault
  list/key_fetch, version list) go through to the fallback normally.
- Reconnection: the daemon's existing retry/backoff loop must keep
  probing the PRIMARY (not just stay parked on the fallback indefinitely)
  so it can transparently switch back and flush the queue the moment the
  primary is reachable again.

## Security note (`security-sensitive`)

The fallback is a second, independent TLS trust anchor
(`ca_cert_pem_path`) per account — same `VW_CERT_VERIFY_REQUIRED`
requirement as the primary (`ARCHITECTURE.md`'s CA store decision), never
optional/defaulted. Same credentials (username/password or resumable
token) are presented to the fallback as to the primary — confirm this is
safe given `TASK-172`'s replication actually keeps the replica's own user
record (password hash) in sync, and that a resume token issued by the
PRIMARY is never sent to the fallback (it's meaningless there — a fresh
`vw_client_connect` against the fallback is required, not
`vw_client_resume`).

## Acceptance criteria

- With no fallback configured: zero behavior change (regression tests for
  every existing daemon/account test must still pass unmodified).
- With a fallback configured and the primary reachable: fallback is never
  used (verified, not just assumed — e.g. by pointing the "fallback" at a
  deliberately broken address and confirming nothing breaks while the
  primary is healthy).
- With a fallback configured and the primary made unreachable
  (integration test kills/blocks it): file list/download continue working
  against the fallback; an attempted upload/mkdir/delete is queued, not
  sent to the fallback, and not silently dropped.
- Once the primary is reachable again: the daemon reconnects to it
  (not the fallback) and flushes the queued writes to it.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**CLI.02, 2026-08-14 — implementation complete.**

- `vw_account_cfg_t`/`account.conf` (`vw_daemon.c`): added `fallback_host`/
  `fallback_port`/`fallback_ca_cert_pem_path`, persisted via
  `account_cfg_apply_kv`/`account_cfg_save`. Set via new optional trailing
  fields on `VW_IPC_ACCOUNT_ADD_REQ` (absent = leave as-is on re-auth, or
  "no fallback" on a new account; empty string explicitly clears one) — no
  new IPC message pair, reusing the existing account add/re-auth flow
  rather than inventing a second one (TASK-174 can revisit this if a
  password-free "just update the fallback" flow turns out to be needed).
- `vw_client_core.c`/`.h`: added `vw_client_connect_with_hash()` — refactored
  `vw_client_connect`'s AUTH_REQUEST/2FA/response handling into a shared
  `do_auth_with_token()` static helper both now call, so the fallback path
  reuses 100% of the existing auth-flow logic rather than a parallel copy.
- `login_token.bin` (new per-account file, mode 0600, same "wrong
  permissions → ignore" load-time check as `session.tok`): retains
  SHA-256(password) — never the raw password — specifically so an
  unattended fallback connect can authenticate fresh (a primary-issued
  `SESSION_RESUME` token is meaningless against a different server).
  Written whenever `ACCOUNT_ADD_REQ` supplies a password; also kept in
  memory on the `vw_account_ctx_t` for the same reason `session.tok`'s
  in-memory `sess` already is.
- `vw_account_conn_mode_t` (offline/primary/fallback) + `account_set_conn()`
  (the single place that ever assigns `a->sess`/`a->conn_mode`, keeping
  them and the sync context's mirrored session/read_only flags moving
  together) — added after finding that the naive version of this (setting
  `a->sess` in three separate places without a shared helper) was already
  drifting inconsistent by the second call site.
- `try_connect` split into `try_connect_primary` (unchanged logic, renamed)
  and `try_connect_fallback` (new — `vw_client_connect_with_hash`, no OTP
  callback: a 2FA-enabled account simply can't fail over unattended, by
  design, not by oversight). `account_reconnect()` tries primary then
  fallback. The round-robin loop now: reconnects offline accounts via
  `account_reconnect`; while parked on fallback, probes primary every
  cycle and switches back (closing the fallback session) the moment it
  succeeds, without disturbing the working fallback connection on a failed
  probe (the acceptance criterion this task states explicitly).
- `vw_sync.c`/`.h`: new `ctx->read_only` flag + `vw_sync_set_read_only()`.
  Gates `oq_drain` (never drain against a read-only session — that would
  attempt real writes) and every write branch of `exec_action`
  (ACT_UPLOAD, ACT_DEL_REMOTE, ACT_CONFLICT) and `resolve_or_create_dir`'s
  FILE_MKDIR attempt: non-shared actions queue into the existing offline
  queue exactly as their own is_net_err() path already does; shared-folder
  actions defer silently to next cycle, matching that path's own existing
  (queue-less, by design) net-error handling. `resolve_or_create_dir`
  specifically memoizes "unresolvable this cycle" rather than propagating
  a net-error-shaped return, since that would abort sync for every OTHER
  folder too, not just the one shared folder needing a directory.
- Six synchronous, user-initiated write-shaped IPC handlers with no
  offline-queue equivalent (`SHARE_GRANT_REQ`, `SHARE_REVOKE_REQ`/
  `LINK_REVOKE_REQ`, `LINK_CREATE_REQ`, `FILE_MKDIR_REQ`, `VAULT_CREATE_REQ`,
  `VAULT_UPLOAD_REQ`) now reject with a new `VW_ERR_READ_ONLY_FALLBACK`
  (`vw_proto.h`, IPC-only, never sent over the wire — same precedent as
  `VW_ERR_SYNC_TREE_TOO_LARGE`) via a small `account_is_read_only()` check,
  rather than actually attempting them against the fallback session.
- `STATUS_RESP` gained a trailing `any_on_fallback` byte;
  `ACCOUNT_LIST_RESP` gained a trailing per-account `conn_mode` byte — both
  documented in `vw_ipc.h`. Real UI surfacing of these is `TASK-174`/`175`'s
  job; this task only had to make the daemon *track and expose* the state.
- **Found and fixed a real wire-format desync bug from the
  `ACCOUNT_LIST_RESP` trailing-byte change**, caught by re-running the
  actual test suite (see below) rather than by inspection: both
  `vw_client_cli.c`'s and `vw_gui_ipc.cpp`'s independent decoders of that
  message hardcoded the pre-existing per-entry byte count, so the new
  trailing `conn_mode` byte desynced every entry after the first (a
  2-account list would misparse account 2 entirely). Fixed both decoders
  to consume-and-currently-ignore the new byte; `tests/integration/
  test_daemon_ipc_accounts.py`'s own raw-wire decoder had the identical
  bug and is fixed the same way.
- **Process note for future work in this repo:** `build-gw-e2e`'s
  `CMakeCache.txt` has `VW_BUILD_TESTS=OFF` — `ctest` against it silently
  runs whatever pre-existing test binaries happen to already be on disk
  from before that was set, NOT rebuilt copies reflecting current source.
  Discovered mid-task when `cmake --build build-gw-e2e --target
  test_vw_sync` came back "unknown target." A previous "19/19 ctest
  passed" claim earlier in this same session (during TASK-171/172) was
  against those stale binaries — the only trustworthy verification from
  that period is the real end-to-end Python integration tests, which
  exercise the actually-rebuilt `vapourwaultd` binary directly. Built a
  fresh `build-gw-tests` tree (`-DVW_BUILD_TESTS=ON -DVW_BUILD_GUI=OFF`,
  the latter only because this fresh tree has no vendored Dear ImGui yet)
  for this task's own real unit-test verification.
- Verified for real this time: `build-gw-tests` (WSL/GCC) 19/19 `ctest`;
  `build-msvc-105` (MSVC) 18/18 `ctest`; the full non-cluster Python
  integration suite (95 passed, 0 failed) against freshly rebuilt
  `build-gw-e2e` binaries; the cluster suite (5/5, unaffected by this
  task's changes, re-run for confidence given the shared `vw_daemon.c`/
  `vw_sync.c` edit surface).
- Out-of-domain discovery opened as `TASK-179` (SRV.01): the server's own
  normal client-facing listener does not yet reject writes on a replica —
  read-only is currently a client-side-only behavior. See that task and
  `ARCHITECTURE.md`'s amended decision-log row for the full reasoning on
  why this is bounded (not a correctness hazard) but real.
- Not done here, left to later tasks in this milestone: CLI surfacing of
  fallback config/status (`TASK-174`), GUI surfacing (`TASK-175`), the
  idempotent-mid-sync-crash-replay and lagging-GC-replica end-to-end
  criteria this milestone's acceptance list mentions (better proven once
  the full stack exists — `TASK-178`).

**QA.06, 2026-08-17 — TASK-178 sign-off.** `tests/integration/
test_cli_fallback.py::test_cli_account_add_fallback_and_real_failover`
now additionally verifies (beyond what `TASK-174` already covered): a
sync-engine upload made while on the fallback shows as a queued local
change (not `synced`, not silently dropped) and is confirmed absent from
the replica's own listing at that point; once the primary returns, the
same write is confirmed to land on the primary specifically (not the
replica). Also added `test_cli_fallback_rejects_mismatched_ca_cert`,
regression-testing this task's own security note ("same
`VW_CERT_VERIFY_REQUIRED` requirement as the primary ... never optional/
defaulted") — a `--fallback-ca-cert` that doesn't match the replica's
real certificate must fail closed (account stays `offline`, never
`fallback (read-only)`), proving verification is genuinely enforced
against a real mismatch, not just an argument-presence check.
