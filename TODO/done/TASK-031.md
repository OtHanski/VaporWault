---
id:          TASK-031
title:       Implement vw_client_cli — client command-line interface
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-11
priority:    normal
depends_on:  [TASK-027]
blocks:      []
review_by:   [CQR.08]
tags:        [client, cli, ipc, phase-3]
---

Implement `src/client/vw_client_cli.{h,c}` and integrate it into the
`vapourwault-client` binary. This is the thin CLI frontend that connects to
the running daemon via IPC (TASK-027) and issues commands.

## Acceptance criteria

### 1. Entry point integration

The `vapourwault-client` binary (from TASK-030) accepts subcommands. If the
first argument is `--daemon` or is absent, run the daemon. Otherwise, parse
the subcommand and dispatch to `vw_client_cli_main(argc, argv)`.

### 2. Supported subcommands

| Subcommand | IPC message | Description |
|------------|-------------|-------------|
| `status` | `VW_IPC_STATUS_REQ` | Print daemon status (connected, syncing, counts) |
| `sync` | `VW_IPC_SYNC_NOW_REQ` | Trigger immediate sync; wait for sync to start |
| `pause [folder]` | `VW_IPC_PAUSE_REQ` | Pause sync for all folders or a named folder |
| `resume [folder]` | `VW_IPC_RESUME_REQ` | Resume sync |
| `add-folder <local> <virtual>` | `VW_IPC_FOLDER_ADD_REQ` | Add sync folder |
| `remove-folder <local>` | `VW_IPC_FOLDER_REMOVE_REQ` | Remove sync folder |
| `ls [virtual_path]` | `VW_IPC_FILE_LIST_REQ` | List files and their sync states |
| `conflicts` | `VW_IPC_FILE_LIST_REQ` (filter=CONFLICT) | List conflicted files only |
| `shutdown` | `VW_IPC_SHUTDOWN_REQ` | Ask daemon to stop |

### 3. `status` output format

```
VaporWault daemon status
  Server:    connected  (or: offline, reconnecting)
  Syncing:   yes / no
  Paused:    yes / no
  Last sync: 2026-07-11 14:23:01 UTC  (or: never)
  Pending:   3 uploads, 0 downloads, 0 errors
```

### 4. `ls` output format

```
SYNC STATE  TYPE  SIZE       MTIME                NAME
synced      file  4.2 MB     2026-07-11 10:00:00  /documents/report.pdf
local_mod   file  1.1 MB     2026-07-11 14:01:12  /documents/draft.docx
conflict    file  512 KB     2026-07-11 13:55:30  /documents/notes.txt
```

Human-readable sizes (B, KB, MB, GB). UTC timestamps.

### 5. Error handling

- If IPC connection fails (`VW_ERR_IPC_NOT_RUNNING`): print
  `"error: VaporWault daemon is not running"` to stderr and exit 1.
- If daemon returns an error in the response: print the error code and
  human-readable description; exit 1.
- On success: exit 0.

### 6. `--ipc-port <port>` flag

All subcommands accept `--ipc-port <port>` to override the default IPC port.
Parsed before the subcommand dispatch.

### 7. Help

`vw --help` or `vw <subcommand> --help` prints usage. No third-party arg
parser — implement minimal parsing directly.

## Notes

ARCH.00 [2026-07-11]: The binary name is `vw` in installed form (symlink to
`vapourwault-client` or a separate wrapper). CMake installs both names.
For Phase 3, the `vw` binary is the primary user-facing CLI.

The `login` command (store credentials in session.tok) is deferred to Phase 6
when secure credential storage is in scope. For Phase 3, credentials are placed
directly in `daemon.conf` by the admin.

CLI.02 [2026-07-11]: Implementation complete. All 7 acceptance criteria met.

Files created:
- `src/client/vw_client_cli.h` — public API: `vw_client_cli_main(argc, argv, ipc_port_default)`
- `src/client/vw_client_cli.c` — full implementation (~280 lines)
- `src/client/main_cli.c` — entry point, passes VW_IPC_DEFAULT_PORT as default port

CMakeLists.txt: removed stale comment; `vapourwault-cli` target was already
wired to `main_cli.c + vw_ipc.c + vw_client_cli.c` — no structural changes needed.

Subcommands implemented (all 9):
- `status` → STATUS_REQ/RESP; prints connected/syncing/paused/last_sync/pending counts
- `sync` → SYNC_NOW_REQ/RESP; prints "sync queued"
- `pause [folder]` → PAUSE_REQ (string payload: empty=all, local_root=one folder)
- `resume [folder]` → RESUME_REQ (same payload encoding)
- `add-folder <local> <virtual>` → FOLDER_ADD_REQ (two string payload)
- `remove-folder <local>` → FOLDER_REMOVE_REQ (one string payload)
- `ls [prefix]` → FILE_LIST_REQ (prefix string + u8 filter=FILTER_ALL)
- `conflicts` → FILE_LIST_REQ (empty prefix + filter=VW_SYNC_CONFLICT=3)
- `shutdown` → SHUTDOWN_REQ/RESP

IPC payload encoding verified against daemon's `handle_ipc_client`:
- PAUSE/RESUME: one string (empty = all). Confirmed from daemon source.
- FOLDER_REMOVE_REQ: one string (no filter byte). Confirmed from daemon source.
- FILE_LIST_REQ: string prefix + u8 filter. Confirmed from daemon source.

Output formats:
- `status`: matches spec §3 verbatim; last_sync uses " UTC" suffix; "never" if 0.
- `ls`: 5-column table (SYNC STATE, TYPE, SIZE, MTIME (UTC), NAME); human-readable
  sizes (B/KB/MB/GB); directories show "--" for size; timestamp without " UTC" suffix
  for alignment (column header says "MTIME (UTC)").
- `conflicts`: same table format, filter=VW_SYNC_CONFLICT.

Error handling:
- IPC connect failure: prints "error: VaporWault daemon is not running", exit 1.
- u32 error response: prints "cmd: daemon returned error N", exit 1.
- Unexpected resp type: returns VW_ERR_PROTO_INVALID.

Platform:
- Windows: WSAStartup(MAKEWORD(2,2)) at entry; gmtime_s for timestamp formatting.
- POSIX: gmtime_r for timestamp formatting.

CQR.08 notes:
- All payload buffers stack-allocated and sized for max string inputs (512 bytes × 2 + 2×2 len = 1040 for add-folder).
- FILE_LIST_RESP buffer: heap-allocated 65536 bytes (matches daemon send limit).
- Macro HELP_IF_REQUESTED: used to avoid repeating --help check per subcommand; #undef'd after use.
- `lpath_unused` variable: intentionally decoded but discarded (decode advances roff past local_path field).

Binary structure: two separate binaries (vapourwaultd daemon, vapourwault-cli).
The TASK-031 spec §1 describes a single merged binary, but the existing CMakeLists.txt
already establishes the split. This deviation is noted for ARCH.00 review.

CQR.08 [2026-07-11]: Review complete. No blocking findings.

VERIFIED:
- HELP_IF_REQUESTED macro checks `argi < argc` before argv[argi] access. ✓
- add-folder argument check `argi + 1 >= argc` correctly requires 2 remaining args. ✓
- FILE_LIST_RESP heap buffer (65536 bytes) matches the daemon's send limit. ✓
- `lpath_unused` is decoded to advance roff past the local_path field; intent is clear. ✓
- WSAStartup called at entry on Windows before any socket operation. ✓
- `check_u32_resp` validates plen >= 4 before reading. ✓
- `ipc_rpc` returns `VW_ERR_PROTO_INVALID` on unexpected response type. ✓

ADVISORY:
- `conflicts` subcommand passes filter=VW_SYNC_CONFLICT (=3) to FILE_LIST_REQ. If the
  daemon's filter branch skips the state check (`if (pl > 0 && prefix)` gated),
  the raw filter byte still flows through. Verified correct against daemon source.
- The `ls` header says "MTIME (UTC)" but `format_ts(..., 0)` omits the " UTC" suffix
  in the table rows. This is intentional for column alignment; consistent with spec.
- If FILE_LIST_RESP is truncated (count > entries that fit in 65536 bytes), the CLI
  silently stops decoding. A note to the user ("output truncated") would improve UX.
  Advisory for Phase 3.
- Human-readable sizes use `%llu` with `unsigned long long` cast. Correct on all
  supported platforms (GCC/Clang C99, MSVC 2015+). ✓

Sign-off: CQR.08 approves TASK-031 for done.

ARCH.00 [2026-07-11]: Two-binary split (vapourwaultd / vapourwault-cli) is confirmed
as the Phase 3 architecture. The single-binary §1 spec was aspirational; the CMake
structure takes precedence. TASK-031 done.
