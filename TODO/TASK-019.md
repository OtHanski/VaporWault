---
id:          TASK-019
title:       vw_oplog — fix fd_size on FILE_APPEND_DATA handle silently failing on Windows
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-06
priority:    normal
depends_on:  [TASK-007]
blocks:      []
review_by:   [CQR.08]
tags:        [oplog, windows, phase-1]
---

During TASK-007 closure review, a platform-specific gap in the BLOCKING-E fix was
identified: on Windows, `fd_size(ctx->seg_fd)` silently returns -1 when called on a
handle opened with `FILE_APPEND_DATA` access, because `GetFileSizeEx` requires
`FILE_READ_ATTRIBUTES` (which `FILE_APPEND_DATA` does not include). As a result, the
BLOCKING-E fix — which re-queries the segment file size after a `fd_write` failure to
keep `ctx->seg_bytes` accurate — is a no-op on Windows for the `fd_write` failure path.

On the `fd_sync` failure path, `ctx->seg_bytes += total` is executed before the return,
and this path is platform-independent and correct.

**Impact**: Low in practice. `WriteFile` with `FILE_APPEND_DATA` on Windows is typically
atomic for small writes, so partial writes triggering this code path are rare. The
consequence when it does occur is the same as the pre-TASK-007-fix state: the next
`vw_oplog_confirm` call writes to the wrong offset, silently corrupting the confirmed byte
of the new entry, which is then dropped on replay. Recovery via restart is still possible
(the corrupt tail is truncated). No data beyond the oplog entry in flight is affected.

## Acceptance criteria

### 1. Fix fd_size on FILE_APPEND_DATA handles (Windows)

The fd_write failure path in `vw_oplog_append` needs a reliable way to query the actual
segment file EOF on Windows even when `ctx->seg_fd` was opened with `FILE_APPEND_DATA`.

Choose one of:
- **Option A** (separate query handle): Open a second, temporary read-only handle on the
  same segment path (`CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, ...)`),
  call `GetFileSizeEx` on it, close it, then update `ctx->seg_bytes`. This is safe because
  the Windows filesystem guarantees that `WriteFile` with `FILE_APPEND_DATA` commits
  atomically before `GetFileSizeEx` on a different handle sees the new size.
- **Option B** (open for GENERIC_READ|FILE_APPEND_DATA): Change `fd_open_append` on
  Windows to include `GENERIC_READ` alongside `FILE_APPEND_DATA`. This allows
  `GetFileSizeEx` to succeed on the existing handle. Check that no other code path is
  broken by the wider access flag.

CQR.08 preference: Option B is simpler (one fewer handle to open/close) and should be
safe on current Windows versions. Option A is more defensively correct if there are any
concerns about widening the access rights.

### 2. Add a non-regression comment

After the fix, add a brief comment above `fd_size(ctx->seg_fd)` in the `fd_write` failure
path explaining why `GENERIC_READ` is needed: "GetFileSizeEx requires FILE_READ_ATTRIBUTES;
FILE_APPEND_DATA alone is insufficient on Windows."

## Notes

ARCH.00 [2026-07-06]: Created from advisory finding raised during independent re-review
of TASK-007 BLOCKING-C/D/E fixes. TASK-007 is closed; this is a follow-up advisory fix.
Priority is normal because the failure mode requires a partial write failure on Windows
(rare), and the consequence is limited to the in-flight oplog entry. Not a blocking gate
for TASK-008 — vw_store can start while this task is in progress.

---

SRV.01 [2026-07-10]: Option B implemented. Two edits in `src/server/vw_oplog.c`:

1. `fd_open_append` (Windows path): `FILE_APPEND_DATA` → `GENERIC_READ | FILE_APPEND_DATA`.
   A four-line comment explains why `GENERIC_READ` is needed (GetFileSizeEx requires
   FILE_READ_ATTRIBUTES; FILE_APPEND_DATA alone triggers ERROR_ACCESS_DENIED on that call).

2. `fd_write` failure path (~line 724): comment expanded to reference the GENERIC_READ
   fix and note that TASK-019 resolved the fd_size silently returning -1 on Windows.

No other callers of `fd_open_append` exist in the file — verified by grep. No logic
changes; the wider access right is safe on current Windows versions (NT-kernel behaviour
is stable for this access combination). Appends remain atomic via FILE_APPEND_DATA;
GENERIC_READ adds read capability only.

---

CQR.08 [2026-07-10]: Reviewed. No blocking findings.

**Advisory CQR.08-A-1**: The four-line comment in `fd_open_append` is accurate and
sufficient. Would be marginally cleaner to extract the intent to a single-line comment
("GENERIC_READ required for GetFileSizeEx; FILE_APPEND_DATA alone lacks
FILE_READ_ATTRIBUTES"), but the current form is not wrong. Advisory only — no action
required.

**Sign-off**: Option B is correct and safe. GENERIC_READ | FILE_APPEND_DATA is the
documented access combination for handles that both append and allow metadata queries on
Windows NT. No other code paths are affected. The `fd_size` failure in the `fd_write`
path is now resolved on Windows. Task may move to `done`.

---

ARCH.00 [2026-07-10]: Milestone closed. CQR.08 signed off; no blocking findings.
Advisory CQR.08-A-1 noted for style only — no action required. TASK-019 is done.
