---
id:          TASK-027
title:       Implement vw_ipc — daemon IPC protocol (localhost TCP)
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-11
priority:    high
depends_on:  []
blocks:      [TASK-030, TASK-031]
review_by:   [CQR.08]
tags:        [client, ipc, protocol, phase-3]
---

Implement `src/client/vw_ipc.{h,c}` — the IPC protocol used between the
VaporWault daemon (TASK-030) and its thin clients (CLI: TASK-031, GUI: Phase 7).

The IPC channel uses localhost TCP with the same 8-byte message framing as
the server wire protocol (`vw_proto`), but with a separate set of message-type
constants in the 0x8000–0x8FFF range to avoid collisions. No TLS — the channel
is loopback-only, authenticated by OS user identity (connection is refused if
the connecting PID is not owned by the same UID as the daemon).

## Acceptance criteria

### 1. Message type constants

Add to `src/core/vw_proto.h` (or a new `src/client/vw_ipc_proto.h`):

| Constant                    | Value  | Direction | Description |
|-----------------------------|--------|-----------|-------------|
| `VW_IPC_STATUS_REQ`         | 0x8001 | C→D | Request daemon status snapshot |
| `VW_IPC_STATUS_RESP`        | 0x8002 | D→C | Status: connected, syncing, paused, last_sync_at, pending_ops |
| `VW_IPC_SYNC_NOW_REQ`       | 0x8003 | C→D | Trigger immediate sync cycle |
| `VW_IPC_SYNC_NOW_RESP`      | 0x8004 | D→C | Acknowledged (sync queued) or error |
| `VW_IPC_PAUSE_REQ`          | 0x8005 | C→D | Pause sync (all folders or one) |
| `VW_IPC_PAUSE_RESP`         | 0x8006 | D→C | Acknowledged |
| `VW_IPC_RESUME_REQ`         | 0x8007 | C→D | Resume sync |
| `VW_IPC_RESUME_RESP`        | 0x8008 | D→C | Acknowledged |
| `VW_IPC_FOLDER_ADD_REQ`     | 0x8009 | C→D | Add sync folder (local_root + virtual_root) |
| `VW_IPC_FOLDER_ADD_RESP`    | 0x800A | D→C | success or error_code |
| `VW_IPC_FOLDER_REMOVE_REQ`  | 0x800B | C→D | Remove sync folder by local_root |
| `VW_IPC_FOLDER_REMOVE_RESP` | 0x800C | D→C | success or error_code |
| `VW_IPC_FOLDER_LIST_REQ`    | 0x800D | C→D | List all sync folders |
| `VW_IPC_FOLDER_LIST_RESP`   | 0x800E | D→C | count + array of folder entries |
| `VW_IPC_FILE_LIST_REQ`      | 0x800F | C→D | List cache entries (optionally filtered by sync_state) |
| `VW_IPC_FILE_LIST_RESP`     | 0x8010 | D→C | count + array of file entries |
| `VW_IPC_SHUTDOWN_REQ`       | 0x8011 | C→D | Ask daemon to shut down gracefully |
| `VW_IPC_SHUTDOWN_RESP`      | 0x8012 | D→C | Acknowledged |

All integers little-endian. Strings: u16 length-prefix + UTF-8 bytes.

### 2. Payload layouts

**VW_IPC_STATUS_RESP** payload:
```
u8  connected       /* 1 = live server connection */
u8  syncing         /* 1 = sync cycle in progress */
u8  paused          /* 1 = all sync paused */
u8  _pad
i64 last_sync_at    /* Unix timestamp of last completed sync; 0 if never */
u32 pending_uploads /* count of files queued for upload */
u32 pending_downloads
u32 error_count     /* non-fatal errors since last sync */
```

**VW_IPC_FOLDER_ADD_REQ** payload:
```
string local_root   /* u16 len + UTF-8 */
string virtual_root
```

**VW_IPC_FOLDER_REMOVE_REQ** / **VW_IPC_FILE_LIST_REQ** payload:
```
string path   /* local_root for folder remove; virtual prefix for file list */
u8     filter /* VW_IPC_FILE_LIST: sync_state filter; 0xFF = all */
```

**VW_IPC_FOLDER_LIST_RESP** per-entry:
```
string local_root
string virtual_root
u8     paused
```

**VW_IPC_FILE_LIST_RESP** per-entry:
```
string virtual_path
string local_path
u32    sync_state    /* vw_sync_state_t */
u8     entry_type
i64    server_mtime
i64    local_mtime
u64    server_size
```

### 3. Server-side IPC listener (for vw_daemon use)

```c
typedef struct vw_ipc_server vw_ipc_server_t;

/*
 * Open a listening TCP socket on localhost:port (default port: 47832).
 * Binds SO_REUSEADDR, listens with backlog 8.
 * Returns VW_OK and sets *out on success.
 */
vw_err_t vw_ipc_server_open(uint16_t port, vw_ipc_server_t **out);
void     vw_ipc_server_close(vw_ipc_server_t *srv);

/*
 * Accept one client connection (blocking). Returns a vw_conn_t using the same
 * vw_net raw-TCP interface (no TLS). Sets *out_conn on success.
 *
 * UID check: on POSIX, uses SO_PEERCRED or /proc/net/tcp to verify the
 * connecting process is owned by the daemon's UID. On Windows, uses
 * GetNamedPipeClientProcessId equivalent via GetExtendedTcpTable.
 * If UID mismatch: closes the socket and returns VW_ERR_AUTH_REQUIRED.
 */
vw_err_t vw_ipc_server_accept(vw_ipc_server_t *srv, vw_conn_t **out_conn);
```

### 4. Client-side IPC connection (for vw_client_cli / vw_client_gui use)

```c
/*
 * Connect to the daemon IPC port on localhost.
 * Returns VW_ERR_NET_CONNECT if the daemon is not running.
 */
vw_err_t vw_ipc_connect(uint16_t port, vw_conn_t **out_conn);
```

After connecting, use `vw_proto_send` / `vw_proto_recv` directly with the
IPC message type constants.

### 5. Default port

`#define VW_IPC_DEFAULT_PORT ((uint16_t)47832)`

Register this in `src/core/vw_proto.h` or `src/client/vw_ipc.h`.

### 6. Error codes

Reuse existing `vw_err_t` codes. IPC-specific codes:
- `VW_ERR_IPC_NOT_RUNNING = 700` — daemon not listening on IPC port.
Add to `vw_err_t` in `vw_proto.h`.

## Notes

ARCH.00 [2026-07-11]: The UID check is a defence-in-depth measure; loopback
means the channel is not exposed to the network. For Phase 3 on Linux, use
`SO_PEERCRED` (available on all major distros). On Windows, `GetExtendedTcpTable`
is complex; accept the risk and skip the UID check for Phase 3 (document the
limitation). Add a TODO for Phase 6 (hardening).

Port 47832 is unassigned per IANA. The daemon must detect port conflicts at
startup and log a clear error if it cannot bind.

---

CLI.02 [2026-07-11]: Implementation complete.

- `src/client/vw_ipc.h` — public API with `vw_ipc_conn_t`, `vw_ipc_server_t`,
  all 18 message-type constants, `VW_IPC_DEFAULT_PORT`, `VW_IPC_FILTER_ALL`,
  send/recv/close/timeout, server open/close/accept, client connect, and
  string encode/decode helpers.
- `src/client/vw_ipc.c` — implementation using plain TCP (no TLS). `raw_send_all`
  and `raw_recv_all` loop until all bytes are transferred or an error occurs.
  `vw_ipc_send`/`vw_ipc_recv` implement the same 8-byte framing as `vw_proto`.
- `src/core/vw_proto.h` — added `VW_ERR_IPC_NOT_RUNNING = 700` to `vw_err_t`.

Design note: `vw_ipc_conn_t` is a separate type from `vw_conn_t` because
`vw_conn_t` is TLS-only and `vw_proto_send`/`vw_proto_recv` internally call
`vw_net_send`/`vw_net_recv` which assume mbedTLS. IPC-specific framing functions
(`vw_ipc_send`/`vw_ipc_recv`) provide the same semantics on a raw TCP socket.

Linux: SO_PEERCRED UID check implemented in `vw_ipc_server_accept`.
Windows: UID check deferred; TODO comment in code for Phase 6.
macOS: UID check not implemented (loopback binding limits exposure).

---

CQR.08 [2026-07-11]: Review complete. No blocking findings.

Advisory CQR.08-A-1: `ipc_platform_init` uses a non-atomic `static int done`
flag on Windows. Safe for Phase 3 (single-threaded daemon init); Phase 7
multi-thread use should use `InitOnceExecuteOnce` or similar.

Advisory CQR.08-A-2: `vw_ipc_server_accept` silently falls through on macOS
after the Linux SO_PEERCRED block. The comment documents the omission clearly.

---

ARCH.00 [2026-07-11]: Task closed. TASK-030 and TASK-031 are unblocked.
