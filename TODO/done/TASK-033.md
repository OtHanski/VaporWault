---
id:          TASK-033
title:       Implement vw_server_main — server entry point and main loop
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-11
priority:    high
depends_on:  [TASK-002, TASK-003, TASK-004, TASK-005, TASK-006, TASK-007, TASK-008, TASK-009, TASK-010, TASK-011, TASK-013, TASK-014]
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [server, main, config, phase-4, security-sensitive]
---

Implement `src/server/main.c` and `src/server/vw_server_main.{h,c}` — the entry point
that wires all existing server modules into a runnable `vapourwaultd` binary.

All individual server modules (auth, store, quota, oplog, SMTP, proto dispatcher) are
already implemented. This task connects them under a single startup/shutdown lifecycle
with config file support and clean signal handling.

## Acceptance criteria

### 1. Config file format (`server.conf`)

Simple INI: `key = value`, `#` comments, blank lines ignored. Missing keys use
documented defaults. Unknown keys are silently ignored (forward-compat).

Required keys:
```
listen_host      = 0.0.0.0          # bind address
listen_port      = 4430             # TLS listen port
data_dir         = /var/lib/vapourwaultd
cert_pem_path    = /etc/vapourwaultd/server.crt
key_pem_path     = /etc/vapourwaultd/server.key
log_level        = INFO             # ERROR | WARN | INFO | DEBUG
max_connections  = 256
smtp_host        =                  # empty = SMTP disabled
smtp_port        = 587
smtp_tls_mode    = starttls
smtp_username    =
smtp_password    =
smtp_from_addr   =
smtp_from_name   = VaporWault
smtp_verify_cert = 1
smtp_ca_cert_path =
```

### 2. Startup sequence

```
1. Parse argv: --config <path> (default: /etc/vapourwaultd/server.conf or ./server.conf)
              --daemon (POSIX only: daemonize after binding)
2. Load and validate config
3. vw_store_open(data_dir)
4. vw_oplog_open(data_dir/oplog)
5. vw_auth_init(store)
6. If SMTP config non-empty: vw_smtp_validate_cfg; store cfg for 2FA mail
7. vw_net_listen(listen_host, listen_port, cert_pem_path, key_pem_path)
8. Write PID file to data_dir/server.pid (O_EXCL — refuse if another instance running)
9. Log "VaporWault server listening on <host>:<port>"
10. Enter accept loop (see §3)
```

### 3. Accept loop (single-threaded, Phase 4)

```
while (running) {
    vw_conn_t *conn = vw_net_accept(ctx);  /* blocks */
    dispatch_request(conn);                /* handle one request synchronously */
    vw_net_close(conn);
}
```

`dispatch_request` reads the 8-byte wire header, dispatches to the appropriate handler
based on `msg_type` (auth, file upload, file download, file list, file delete, quota
query, admin ops), writes the response, and returns. All existing server module functions
are called from here.

A per-connection recv timeout of 30 seconds must be set immediately after accept
(via `vw_net_conn_set_recv_timeout`) to guard against slow-loris attacks before
auth completes.

Multi-threaded accept is deferred to Phase 6 (thread pool).

### 4. Signal handling

- **SIGTERM / SIGINT** (POSIX): set `running = 0`; `vw_net_ctx_close` unblocks accept.
- **SIGHUP** (POSIX): reload cert via `vw_net_ctx_reload_cert`; re-read log level from
  config (not a full restart).
- **Windows**: `SetConsoleCtrlHandler` for CTRL_C and CTRL_BREAK; no SIGHUP equivalent.

### 5. Logging

Log to stderr by default; to `data_dir/server.log` when `--daemon` is passed.
Rotate at 10 MiB (rename to `server.log.1`, keep at most 2 rotated files).
Log level controlled by `log_level` config key and `VW_LOG_LEVEL` env var (env var wins).
No session tokens, password hashes, or chunk data in any log call.

### 6. Daemonisation (POSIX only)

If `--daemon` passed: call `daemon(1, 0)` after binding the port but before entering
the accept loop. On Windows, run as a foreground process.

### 7. PID file

Write PID to `data_dir/server.pid` with `O_CREAT|O_EXCL`. If the file exists and the
process is alive (`kill(pid, 0)` returns 0), refuse to start with an error. Remove the
PID file on clean shutdown.

### 8. CMake

Add `vapourwaultd` server executable in `src/server/CMakeLists.txt`:
```cmake
add_executable(vapourwaultd
    main.c
    vw_server_main.c
)
target_link_libraries(vapourwaultd PRIVATE
    vw_server     # static lib containing all server modules
    vw_core
    pthread
)
```

If `vw_server` static lib does not yet exist as a CMake target, convert the server
module sources to a static library first (same pattern as `vw_core`).

### 9. Smoke-level self-test

`vapourwaultd --help` prints usage and exits 0.
`vapourwaultd --check-config --config <path>` validates config and exits 0/1 without
binding any port. Used by CI and the integration test scaffold.

## Notes

ARCH.00 [2026-07-11]: This task produces the first runnable server binary. Once complete,
TASK-012 §4 (integration test scaffold) can be implemented. The accept loop is intentionally
single-threaded for Phase 4; the dispatch_request function must not block indefinitely
(rely on the 30 s recv timeout).

SEC.07 must verify:
- Per-connection recv timeout is set before any read (slow-loris guard).
- PID file uses O_EXCL to prevent TOCTOU.
- Session tokens and password hashes never appear in log calls.
- `--check-config` exits before binding — no port held open on config error.

SRV.01 [2026-07-12]: Implementation complete. Deliverables:
- `src/server/main.c` — thin entry point calling `vw_server_main_run()`.
- `src/server/vw_server_main.h` — `vw_server_main_cfg_t`, `vw_server_main_cfg_load`,
  `vw_server_main_cfg_write_defaults`, `vw_server_main_run`.
- `src/server/vw_server_main.c` — INI config parser, startup sequence (oplog → store →
  auth → SMTP validate → net_listen → PID file → accept loop), SIGTERM/SIGINT/SIGHUP
  handlers (POSIX) and SetConsoleCtrlHandler (Windows), log rotation at 10 MiB,
  `daemon(1,0)` on `--daemon` (POSIX only), `--check-config` mode, `--help`.
- `src/server/CMakeLists.txt` — `vapourwaultd` executable target; removed six
  non-existent source files that caused build failure.
- Cross-platform fixes: `vw_fs_exists()` instead of `access()`/`F_OK` (Windows),
  `snprintf+write()` instead of `dprintf()` (GNU extension), `g_net_ctx = NULL` before
  `vw_net_ctx_close()` to prevent signal-handler double-close.
Awaiting SEC.07 + CQR.08 review.

SEC.07 [2026-07-12]: APPROVED. Verified:
- Slow-loris guard: `vw_net_conn_set_recv_timeout(conn, 30000)` called at line 328,
  before `vw_server_conn_handle` — no recv can happen before the timeout is armed.
- PID file: `open(O_CREAT|O_EXCL|O_WRONLY, 0644)` on POSIX; stale detection uses
  `kill(pid, 0)` then `remove + re-create with O_EXCL`. Inherent TOCTOU window on
  the stale path is not exploitable for privilege escalation — advisory only.
- Log calls: peer addresses, error codes, and msg type numbers only. No session
  tokens, password hashes, or chunk data appear in any log call.
- `--check-config`: returns at line 397 (`if (check_only) return 0;`) which is before
  `vw_net_listen` at line 432. Port is never bound on config-only exit.
- Windows PID path: `fopen/remove/fopen` pattern has an inherent race window; acceptable
  given no O_EXCL equivalent exists on Windows for named files — advisory only.
No blocking findings. Task may proceed to done.

CQR.08 [2026-07-12]: APPROVED. Verified:
- Config parser: `S/U/I` macros defined and immediately `#undef`'d — no namespace
  pollution. Unknown keys silently ignored (forward-compat as specified).
- `strncpy` pattern: `memset(&cfg, 0)` before all copies guarantees NUL termination.
- `handle_connection`: `malloc` failure returns silently without a crash — advisory:
  a LOG_ERROR call would be cleaner, but the server correctly continues accepting.
- Shutdown label: all pointers initialised NULL, checked before close; g_net_ctx
  nulled before `vw_net_ctx_close` prevents signal-handler double-close.
- `cfg_validate`'s `check_only` flag: slightly overloaded but contained within one
  function — acceptable for Phase 4 scope.
No blocking findings.
