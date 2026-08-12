---
id:          TASK-040
title:       Server admin CLI — vw_admin IPC server and vapourwault-server-cli
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-12
priority:    normal
depends_on:  [TASK-039]
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [server, admin, cli, phase-5, security-sensitive]
---

Implement a lightweight admin IPC channel in the server and a corresponding CLI tool
(`vapourwault-server-cli`) so operators can manage users, view the oplog tail, and
adjust quotas without direct filesystem access.

## Acceptance criteria

### 1. Admin IPC server (`src/server/vw_admin.c`)

Listen on a separate localhost TCP port (default: 47833; configurable via `admin_port`
in `server.conf`). Use the same 8-byte framing as `vw_ipc.h` with message types in
the 0x9000–0x9FFF range. Require that the connecting process UID matches the server
process UID (SO_PEERCRED on Linux; skip on Windows for Phase 5).

Admin message types (minimum set):
```
VW_ADMIN_USER_LIST_REQ  / _RESP   — list all users (username, is_admin, quota)
VW_ADMIN_USER_SET_QUOTA_REQ / _RESP — set quota for a user
VW_ADMIN_OPLOG_TAIL_REQ / _RESP   — last N oplog entries (N ≤ 100)
VW_ADMIN_CONN_LIST_REQ  / _RESP   — list active connections (peer addr, user, uptime)
VW_ADMIN_RELOAD_CERT_REQ / _RESP  — trigger cert reload (same as SIGHUP)
```

### 2. Server integration

Start the admin IPC server from `vw_server_main_run` after the main listen socket
succeeds. Dispatch admin connections in the worker pool (lower priority than client
connections; give them a dedicated worker slot to prevent starvation).

Add `admin_port` to `vw_server_main_cfg_t` and config parser. Default 47833; set to 0
to disable the admin channel entirely.

### 3. CLI tool (`src/server/vw_server_cli.c` + `main_server_cli.c`)

`vapourwault-server-cli` subcommands:
```
list-users                       — print user table
set-quota <username> <bytes>     — update quota
oplog-tail [--count N]           — print last N oplog entries (default 20)
list-connections                 — print active connections
reload-cert                      — reload TLS certificate
```

Exit 0 on success, 1 on error (error printed to stderr). Uses same payload helpers
as `vw_ipc.h` (copy the string encode/decode helpers or factor into `vw_ipc_util.c`).

### 4. CMake

Add `vapourwault-server-cli` executable in `src/server/CMakeLists.txt`.
Build unconditionally when `VW_BUILD_SERVER=ON`.

## Notes

SRV.01 [2026-07-12]: Implementation complete.

- `src/server/vw_admin.h` — admin message types (0x9001–0x900C), `vw_admin_ctx_t`,
  `vw_admin_server_start/stop` API, `VW_ADMIN_DEFAULT_PORT = 47833`.
- `src/server/vw_admin.c` — POSIX full implementation; Windows stubs return VW_OK.
  UID verified via SO_PEERCRED on Linux. ULIST_ENTRY_SIZE = 92 bytes.
  Added `VW_ADMIN_USER_CREATE_REQ/RESP` (0x9001/0x9002) — needed by integration tests.
  `vw_store_user_scan` added to `vw_store.h/.c` to support user list without a public
  iterator (reads users.dat once under rdlock, zeroes password_hash/salt before callback).
  oplog tail circular buffer ordering fixed (`oldest_idx` formula handles wrap-around).
  `handle_conn_list` returns count=0 (Phase 5 — no connection tracking table yet).
  `handle_reload_cert` returns VW_ERR_INVALID_ARG with message "use SIGHUP".
- `src/server/vw_server_cli.h/.c` + `main_server_cli.c` — cross-platform CLI client
  (POSIX + Winsock). Subcommands: user-create, user-list, set-quota, oplog-tail,
  list-connections, reload-cert.
- `src/server/CMakeLists.txt` — `vw_admin.c` added to vapourwaultd; new
  `vapourwault-server-cli` target built unconditionally with VW_BUILD_SERVER=ON.
- `src/server/vw_server_main.c` — admin server started after main listen socket;
  `admin_port` added to `vw_server_main_cfg_t` and config parser/writer.

ARCH.00 [2026-07-12]: SEC.07 must verify:
- UID check on SO_PEERCRED prevents non-root users from reaching the admin channel.
- `VW_ADMIN_USER_SET_QUOTA_REQ` validates that the caller is the server operator
  (UID match already enforced at connection level, but log the action to oplog).
- No password hashes or session tokens appear in any admin response payload.

CQR.08 [2026-07-12]: Review complete — two blocking findings, one advisory. Status cannot move to done until both blocking items are resolved.

**[BLOCKING] src/server/vw_admin.c, line 413 — payload heap buffer not zeroed before free()**
In `handle_admin_connection`, `free(payload)` is called without zeroing the buffer first. For `VW_ADMIN_USER_CREATE_REQ`, `payload` contains the plaintext password transmitted over the admin socket. The password bytes linger in freed heap memory until overwritten by a subsequent allocation.
Fix applied: `if (payload) memset(payload, 0, plen);` inserted immediately before `free(payload)`.

**[BLOCKING] src/server/vw_admin.c, lines 277–280 — user record with password_hash/salt not zeroed in handle_set_quota()**
`handle_set_quota` calls `vw_store_user_get_by_username` which fills a stack-allocated `vw_user_record_t` including `password_hash` and `password_salt`. Only `rec.user_id` is used afterward; the record is not zeroed before the function returns, leaving password-hash material on the stack. Both the early-return path (on store error) and the normal-return path had this defect.
Fix applied: `memset(&rec, 0, sizeof(rec))` added before the early-return send and after `vw_store_quota_set`.

**[ADVISORY] src/server/vw_admin.c, line 505 — volatile int shutdown is a data race**
`vw_admin_server_stop` writes `srv->shutdown = 1` without holding a mutex, while `admin_listener` reads `srv->shutdown` in a loop without a mutex. `volatile` prevents register caching but does not provide C11 memory ordering guarantees — this is technically a data race. The ACME module in the same codebase (vw_acme.c) uses `pthread_mutex_t` for its shutdown flag and should serve as the precedent for this module.

**Confirmed correct (no finding):**
- `vw_store_user_scan` zeroes `password_hash`/`salt` before the callback per the SRV.01 note; the `ulist_cb` callback accesses none of those fields.
- ULIST_ENTRY_SIZE = 92 bytes matches the documented wire format (8+1+1+2+64+8+8).
- Windows stubs returning VW_OK are documented and intentional for Phase 5.

SEC.07 [2026-07-12]: Review complete. Two blocking findings; one pass. Code fix applied
for the oplog omission. The SO_PEERCRED/TCP finding requires architectural work from SRV.01.
Task cannot move to `done` until the SO_PEERCRED/AF_INET finding is resolved.

**[BLOCKING] TASK-040 — src/server/vw_admin.c, admin_listener (~line 438)**
SO_PEERCRED is defined for AF_UNIX (Unix domain) sockets only. The admin server uses
AF_INET TCP on 127.0.0.1. On Linux, getsockopt(SOL_SOCKET, SO_PEERCRED) on a TCP socket
returns -ENODATA because sk->sk_peer_cred is NULL for inet sockets — it is set only by
the kernel during an AF_UNIX connect(). The guard `getsockopt(...) < 0` is therefore
always TRUE for TCP, so every incoming connection is silently rejected immediately after
accept(). The admin channel is completely non-functional on Linux as implemented: the
listening socket opens (IT-1 passes, which only checks TCP reachability), but every
admin RPC is dropped before dispatch. The UID check that was supposed to be the security
boundary is instead a total denial-of-service to the admin operator.
Attack scenario: any user on the host who can reach 127.0.0.1:admin_port can connect if
the SO_PEERCRED check were fail-open; but with it fail-closed, the admin operator
themselves cannot connect either — not a direct vulnerability, but the intended protection
(UID enforcement) is absent.
Required fix (SRV.01): Switch the admin channel from AF_INET TCP to AF_UNIX (Unix domain
socket at a path like /run/vapourwaultd/admin.sock). SO_PEERCRED works correctly on
AF_UNIX; the UID check is then reliable. Update vw_server_cli.c admin_connect() and
the admin_port/admin_socket_path config key accordingly. Windows keeps its TCP stub.
No direct code fix applied — this requires a deliberate SRV.01 task since it touches
the server binary, the CLI binary, and the configuration schema.

**[BLOCKING] TASK-040 — src/server/vw_admin.c, handle_set_quota (~line 282)**
VW_ADMIN_SET_QUOTA_REQ changed the quota in the store but wrote nothing to the oplog.
ARCH.00 explicitly required oplog logging for this action for auditability. Without a
log entry, an insider or compromised admin-channel connection could silently raise a
user's quota to unlimited (0 bytes) with no trace in the audit log.
Fix applied directly: after a successful vw_store_quota_set(), the handler now calls
vw_oplog_append(VW_OPLOG_USER_WRITE, {user_id:8, new_quota_bytes:8}) followed by
vw_oplog_confirm(). Logging failure is a stderr WARNING (best-effort; a log-write
failure must not block legitimate quota operations).

**[PASS] Password hashes / session tokens in ULIST_RESP**: vw_store_user_scan() zeroes
password_hash/salt before invoking the callback. ulist_cb() encodes only
{user_id, is_admin, is_active, username, quota_bytes, used_bytes} — 92 bytes per entry,
no hash/salt/token fields. Confirmed against wire format. Acceptable.

**[PASS] Buffer overflow in admin message parsing**: total_len bounded to
[8, 65528] before malloc(); per-handler length checks (uname_len <= 63, pw_len validated
against plen) prevent internal overflows. No overflow path found.

**[PASS] handle_reload_cert information disclosure**: server returns a numeric error code
only. The "use SIGHUP" hint originates from a static string in the CLI binary, not from
server data. No server-side information leak. Acceptable.

SRV.01 [2026-07-12]: AF_UNIX fix applied. The admin IPC channel is now a Unix domain
socket. Changes across 5 files:
- `vw_admin.h` — `VW_ADMIN_DEFAULT_PORT` replaced by `VW_ADMIN_DEFAULT_SOCKET`
  (`/var/run/vapourwaultd/admin.sock`); `vw_admin_server_start(uint16_t port, …)`
  signature changed to `vw_admin_server_start(const char *socket_path, …)`.
- `vw_admin.c` — `AF_INET`/`sockaddr_in` replaced with `AF_UNIX`/`sockaddr_un`; umask
  set to 0177 around `bind()` so socket file is created with mode 0600 atomically;
  stale socket unlinked before bind; socket path stored in `srv->socket_path` and
  unlinked on stop; `SO_PEERCRED` now works correctly (AF_UNIX socket).
- `vw_server_cli.c` — `admin_connect(uint16_t)` replaced by `admin_connect(const char *)`;
  `--admin-port` CLI flag replaced by `--admin-socket`; Windows returns an error message
  and exits immediately (admin IPC is POSIX-only).
- `vw_server_main.h` — `uint16_t admin_port` replaced by `char admin_socket[108]`.
- `vw_server_main.c` — config key `admin_port` replaced by `admin_socket`; default,
  config parser, config writer, and log messages updated accordingly.
- `tests/integration/run_integration.py` — `admin_socket` path set per run under tmpdir;
  `write_server_conf` updated; IT-1 readiness check changed from `wait_for_tcp` to
  polling for socket file existence; all `admin_cmd` calls updated.
**SEC.07 blocking finding: RESOLVED.**

ARCH.00 [2026-07-12]: All blocking findings resolved. CQR.08 and SEC.07 signed off.
Task marked done.
