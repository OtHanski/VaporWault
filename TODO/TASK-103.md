---
id:          TASK-103
title:       Real peer-UID verification for the daemon IPC channel on Windows
status:      todo
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-30
priority:    normal
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [client, security-sensitive]
---

Split out of `TASK-093` (real peer-UID verification for the daemon IPC
channel), which implemented the Linux side via `/proc/net/tcp` parsing.
`TASK-093`'s acceptance criteria explicitly allowed the Windows equivalent to
be split into its own task — doing so here to keep each task's diff and
review scoped to one platform's networking API.

`src/client/vw_ipc.c`'s `vw_ipc_server_accept()` has a long-standing
`TODO Phase 6` comment noting that `GetExtendedTcpTable` (from `iphlpapi.h`)
is the Windows equivalent of what `/proc/net/tcp` provides on Linux: a
system-wide table of TCP connections including the owning PID, from which
the owning user SID can be resolved (`OpenProcess` +
`OpenProcessToken`/`GetTokenInformation` on the PID, or
`WTSQueryUserToken`-style approaches) and compared against the daemon
process's own SID.

Until this lands, Windows (and macOS, deferred project-wide per
[[project_macos_deferred]]) daemon hosts rely on loopback binding alone as
the IPC trust boundary — see the `docs/DEPLOYMENT.md` caveat added
alongside `TASK-093`.

## Acceptance criteria

- `vw_ipc_server_accept()` on Windows resolves the connecting process's
  owning user SID (via `GetExtendedTcpTable` + the PID-to-SID lookup) and
  rejects the connection (`VW_ERR_AUTH_REQUIRED`) if it doesn't match the
  daemon's own SID, mirroring the Linux behavior added in `TASK-093`.
- Failure to determine the peer SID (API unavailable, insufficient
  privilege to open the peer process, race between accept() and the table
  snapshot) falls back to trusting loopback binding alone, matching
  `TASK-093`'s Linux fallback posture — do not regress to rejecting every
  connection.
- A regression test exercising the parsing/decision logic with fabricated
  `GetExtendedTcpTable` output, following the same pattern `TASK-093`'s
  `tests/unit/test_vw_ipc.c` uses for `/proc/net/tcp` (a real cross-user
  connection isn't practical to simulate in CI on Windows either).
- `docs/DEPLOYMENT.md`'s IPC caveat updated to drop the Windows carve-out
  once this lands.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-30]: Split out of `TASK-093` per its own acceptance
criteria, which left this split-vs-combine call to whoever implemented the
Linux side. Normal priority — Windows daemon hosts keep today's
loopback-only posture (no regression) until this lands; the `DEPLOYMENT.md`
caveat makes the gap explicit in the meantime.
