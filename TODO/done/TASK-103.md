---
id:          TASK-103
title:       Real peer-UID verification for the daemon IPC channel on Windows
status:      done
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

CLI.02 [2026-07-30]: Implemented via `GetExtendedTcpTable` +
PID-to-SID resolution, mirroring `TASK-093`'s Linux structure:

- `vw_ipc_win_tcp_table_pid()` (declared in `vw_ipc_internal.h`, defined in
  `vw_ipc.c`) scans an in-memory `MIB_TCPROW_OWNER_PID` array for the
  `MIB_TCP_STATE_ESTAB` row matching `(local_port, peer_port,
  loopback_be)` and returns its `dwOwningPid` — the direct Windows analogue
  of `vw_ipc_linux_proc_net_tcp_uid()`. Same swap subtlety applies (a
  loopback connection has two rows, one per socket-end, each potentially
  owned by a different process) and `vw_ipc_server_accept()` queries with
  the same `(peer_port, our_port)` swap as the Linux branch, for the same
  reason.
- `win_get_process_user_sid()` (static, `vw_ipc.c` only) resolves a PID to
  its token-user SID via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` →
  `OpenProcessToken` → `GetTokenInformation(TokenUser)`. Compared against
  the daemon's own PID's SID (same function, `GetCurrentProcessId()`) via
  `EqualSid`.
- Per the acceptance criteria's explicit fallback posture (deliberately
  **more permissive** than the Linux path): `verified` starts `1` and is
  only set to `0` — causing a reject — when a peer SID is *positively*
  resolved and does *not* match ours. Every other outcome (table fetch
  failed, PID not found in the table, `OpenProcess`/`OpenProcessToken`/
  `GetTokenInformation` failed) falls through to `verified == 1` (trust
  loopback). This intentionally differs from Linux's stricter "readable
  but no match → reject" posture — `GetExtendedTcpTable` is a heavier
  whole-system snapshot with a real race window between `accept()` and the
  table read, and token/process access can legitimately fail for reasons
  unrelated to the connecting process's identity; failing closed on that
  would risk regressing to "every connection fails," the exact class of
  bug `TASK-093` fixed on Linux.
- Regression test: `tests/unit/test_vw_ipc.c` gained a Windows-only
  (`#ifdef _WIN32`) fixture — a fabricated `MIB_TCPROW_OWNER_PID[4]` array
  mirroring the Linux `/proc/net/tcp` text fixture's exact scenario (same
  ports, same deliberately-different PIDs 1000/4242, same LISTEN-state and
  non-loopback-address negative cases) — and six test cases exercising
  `vw_ipc_win_tcp_table_pid()` directly: un-swapped-query tautology,
  swapped-query fix, LISTEN-state exclusion, non-loopback-address
  rejection, no-match, and NULL-input safety. The PID-to-SID half
  (`win_get_process_user_sid`, `EqualSid`) is not unit-tested — same
  practical constraint TASK-093 noted for a real cross-user connection —
  but exercised for real by every `unit_vw_ipc` run on Windows via the
  existing same-uid `server_accept` round-trip test, which now also
  exercises the full Windows SID-verification path end-to-end (same
  process on both ends, so it must self-verify and accept).
- `docs/DEPLOYMENT.md`'s IPC caveat and `vw_ipc.h`'s header/doc comments
  updated to describe the Windows check's actual (deliberately permissive)
  behavior instead of the old "no check yet, tracked as a gap" language.

**Validation:** MSVC `/W4 /WX` (env from `vcvars64.bat`, Ninja): clean
build of the full project including `test_vw_ipc.exe`; `unit_vw_ipc`
passes (11/11 assertions, up from 5 same-uid-only). Cross-checked the
Linux build (GCC/WSL, `VW_WERROR=ON`) still builds and passes unchanged —
the new Windows code is fully `#ifdef _WIN32`-gated and doesn't affect the
Linux translation unit at all.

SEC.07 [2026-07-30]: Reviewed the fallback-permissive design against the
acceptance criteria. Confirmed the only path to `VW_ERR_AUTH_REQUIRED` is
a positively-resolved, positively-mismatched SID — matches the explicit
instruction not to regress to "reject on any uncertainty." Confirmed
`sid_buf`/`self_sid_buf` (heap allocations backing the resolved `PSID`s)
are freed on every path, including when `win_get_process_user_sid` fails
partway (its own internal cleanup via `goto done`) and when the outer
`vw_ipc_server_accept` block exits early. Confirmed no secret/credential
material is involved in this path (PIDs and SIDs aren't secrets), so no
zeroing requirement applies here. No blocking findings.

CQR.08 [2026-07-30]: Reviewed `vw_ipc_win_tcp_table_pid`/
`win_get_process_user_sid`/the `vw_ipc_server_accept` Windows branch.
Confirmed `HANDLE`s (`proc`, `token`) are closed on every exit path in
`win_get_process_user_sid` and that the `dwLocalPort`/`dwRemotePort` →
`uint16_t` narrowing via `ntohs((uint16_t)r->dwLocalPort)` is correct per
the documented `MIB_TCPROW_OWNER_PID` convention (port in the low 16 bits
of the DWORD, network byte order). No blocking or advisory findings.
Sign-off given.

ARCH.00 [2026-07-30]: SEC.07 and CQR.08 sign-off received. All acceptance
criteria met: Windows peer verification implemented with the specified
fallback posture, regression test added following TASK-093's pattern,
`docs/DEPLOYMENT.md` updated to drop the Windows carve-out. Closing as
done.
