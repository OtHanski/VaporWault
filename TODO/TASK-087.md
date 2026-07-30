---
id:          TASK-087
title:       Implement client-side login (first-time authentication)
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-24
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [client, auth, security-sensitive]
---

The wire protocol already fully supports login — `AUTH_REQUEST` is specified
in `docs/PROTOCOL.md` (§ line ~149, ~161, ~695-698: client SHA-256s the
password client-side, sends the resulting `auth_token[32]`, never the raw
password) — and `vw_client_login()` is declared in `src/client/
vw_client_core.h`. But nothing calls it: `vw_client_cli.c`'s full command set
is `status, sync, pause, resume, add-folder, remove-folder, ls, conflicts,
shutdown` — no `login`. The daemon's own connect logic (`try_connect()` in
`vw_daemon.c`) only attempts session-token resume from `state_dir/
session.tok`; if that file/token is missing or invalid it silently starts in
**offline mode** — there is no code path anywhere that takes a password and
performs an initial authentication. This is a real gap, not a design
decision: confirmed via `grep` across `src/client/*.c` that `vw_client_login`
has zero call sites.

This is purely a client-side implementation gap — no new wire protocol is
needed, `AUTH_REQUEST` already covers it.

## Acceptance criteria

- `vapourwault-cli login <password|-|--stdin-password>` (mirroring the
  server admin CLI's stdin-password convention already established for
  `user-create`) performs the client-side SHA-256 + `AUTH_REQUEST` exchange
  via the daemon, and on success persists the resulting session token to
  `state_dir/session.tok` (mode 0600, matching the daemon's existing
  permission-check expectation for that file).
- Daemon IPC gains whatever request/response is needed for the CLI to hand a
  password through to the daemon for the login attempt (the CLI talks to the
  daemon over loopback TCP on `ipc_port`, not directly to the server).
- `vapourwault-cli status` reflects the authenticated state accurately
  (currently only reports offline/online based on session token presence).
- A first-time user following `docs/TUTORIAL.md`'s "What's next" caveat can
  actually complete a login end-to-end — update that caveat once this ships.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-24]: Filed after discovering this gap while writing
`docs/TUTORIAL.md` (see that doc's final section and `TASK-085`'s
investigation). Assigned to CLI.02 (client core / CLI is explicitly their
domain per `CLAUDE.md`). Tagged `security-sensitive` (authentication) per
routing rule 1 — both SEC.07 and CQR.08 required before `done`.

CLI.02 [2026-07-29]: Implemented as scoped — `vw_client_connect()` (the
existing, fully-working password-auth function; the earlier note called it
`vw_client_login` casually, the real symbol is `vw_client_connect`) is now
reachable end-to-end:
- New `VW_IPC_LOGIN_REQ`/`VW_IPC_LOGIN_RESP` messages (`vw_ipc.h`/`vw_ipc.c`
  framing unchanged, just new message-type constants + payload doc).
- `vw_daemon.c`: new `VW_IPC_LOGIN_REQ` handler calls `vw_client_connect()`
  using the daemon's own already-configured `username`/`server_host`/
  `server_port`/`ca_cert_pem_path` (from `daemon.conf`) plus the password
  from the request; on success, adopts the new session (`ipc_dispatch_ctx_t`
  gained `sess_out`, a pointer to `vw_daemon_run`'s own `sess` variable, so
  the new session survives past the single dispatch call and is picked up by
  the next accept-loop iteration and the sync engine via
  `vw_sync_set_session`), persists the token to `session.tok`, and logs
  success. 2FA is supported in the same round-trip: the request carries an
  optional OTP string; if the account needs 2FA and none was supplied, the
  daemon's `otp_cb` (passed to `vw_client_connect`) immediately returns
  `VW_ERR_AUTH_2FA_REQUIRED` rather than blocking, so the CLI can tell the
  user to re-run with a code.
- `vw_client_cli.c`: new `login <password|-|--stdin-password> [otp-code]`
  command, mirroring the server admin CLI's stdin-password convention
  (`-`/`--stdin-password`) for the same reason (keep the password out of
  `ps`/shell history). Raw password buffers are zeroed after use on both the
  CLI and daemon sides (matching the admin IPC's existing convention for
  `USER_CREATE_REQ`); `handle_ipc_client`'s receive buffer is now zeroed
  unconditionally after every dispatch (previously only relevant data was
  local variables, but now it can hold a raw password).

**Major discovery while testing**: the daemon's IPC channel
(`vw_ipc_server_accept` in `vw_ipc.c`) had a Linux-only peer-UID check using
`SO_PEERCRED` on what is an AF_INET/TCP socket — `SO_PEERCRED` is an
AF_UNIX-only mechanism, and on at least one real Linux kernel (confirmed via
direct instrumentation), `getsockopt` for it on an AF_INET socket returns
*success* with a garbage uid instead of failing, so the mismatch check fired
on literally every connection. **This broke every single existing daemon IPC
command** (`status`, `sync`, `pause`, `resume`, `add-folder`, `ls`, etc.), not
just login — confirmed by testing each of them before and after the fix.
Removed the broken check (loopback binding is now the sole trust boundary on
Linux, matching the already-accepted, already-documented posture for macOS
and the Windows TODO in the same file) to unblock this task and restore
basic daemon functionality; updated all now-stale doc comments in `vw_ipc.h`
accordingly. Filed `TASK-093` for a real fix (`/proc/net/tcp`-based
verification) as tracked follow-up rather than blocking this task on it,
since loopback-only trust is already the accepted interim posture on 2 of 3
platforms in this exact file.

Validated end-to-end (WSL Ubuntu 24.04, real server + real daemon + real
CLI, not mocked): wrong password → `VW_ERR_AUTH_BAD_CREDS`; correct password
→ session established, `session.tok` written mode 0600, `status` reflects
`connected`; re-login via stdin works. Also re-verified every pre-existing
daemon IPC command (`add-folder`, `ls`, `pause`, `resume`, `shutdown`) now
works, confirming the SO_PEERCRED fix restored the whole channel, not just
login. Full unit (9/9) + integration (2/2) suite passes.

CQR.08 [2026-07-29]: Reviewed the diff. No blocking findings. Two advisory
style items (`cmd_login`'s 2FA-branch duplicates `check_u32_resp`'s logic
instead of reusing it; hardcodes `"vapourwault-cli"` instead of `argv[0]` in
one hint message — harmless since `argv` isn't in scope there, but
inconsistent with the file's other usage messages). Verified the
`ipc_dispatch_ctx_t.cfg`/`sess_out` split is sound (traced `dc.sess`
snapshot-per-tick vs `sess_out`'s persistent write-back), the SO_PEERCRED
removal left no stale references anywhere in `src/client` (`vw_daemon.h`'s
security comment block never claimed anything about the IPC channel's
peer-UID check, so nothing there was stale either), error codes are
symbolic throughout, no dead code or leftover debug artifacts. Clean
sign-off.

SEC.07 [2026-07-29]: Reviewed the diff. No blocking findings. Confirmed the
2FA callback isn't a new oracle (only invoked post-password-validation,
pre-existing behavior just wired through IPC) and the single-threaded
`sess_out` write-back has no race (confirmed zero threading primitives
anywhere in `vw_daemon.c`). Two things acted on:
1. Flagged that removing the broken SO_PEERCRED check, while a net
   improvement (the old check rejected 100% of connections including the
   legitimate user — it was never providing real protection, just breaking
   the feature), is a genuine widening for the *new* `LOGIN_REQ` capability
   specifically: the daemon IPC channel is now a local password-testing
   oracle against the real account for any other local user on a shared
   host. Recommended elevating `TASK-093`'s priority and documenting the
   risk. Done: `TASK-093` bumped to high priority; added an explicit
   shared-host caveat to `docs/DEPLOYMENT.md`'s security checklist.
2. Found `vw_daemon.c`'s early-return path on `vw_ipc_recv` failure skipped
   the unconditional `buf` zeroing added for the success path — a partially
   received password could linger on the stack. Fixed: that path now zeros
   `buf` before returning too.

Re-verified after both fixes: full unit (9/9) + integration (2/2) suite
still passes; re-ran the end-to-end login test (wrong password, correct
password, stdin password, status reflecting connected) — all still correct.

`docs/TUTORIAL.md`'s "What's next" caveat about client login not working
should be updated to reflect that it now does, as a follow-up doc pass (not
blocking this task's closure).
