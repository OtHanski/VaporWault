---
id:          TASK-014
title:       vw_fs — add pwrite, directory listing, fix atomic_write .tmp leak
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-06
priority:    critical
depends_on:  [TASK-004]
blocks:      [TASK-008]
review_by:   [CQR.08]
tags:        [filesystem, phase-1]
---

Architecture review (2026-07-06) found three blocking issues in vw_fs that prevent
vw_store from being built correctly. All must be resolved before TASK-008 picks up.

## Acceptance criteria

### 1. Positioned write (pwrite equivalent)

Add to `src/core/vw_fs.{h,c}`:

```c
/*
 * Write `len` bytes from `data` to the file at `path`, starting at byte offset
 * `offset`. The file must already exist. Does not change the logical end-of-file.
 *
 * Used by vw_store for in-place update of single aligned fields in fixed-size
 * record files (e.g. updating a session expiry timestamp without rewriting the
 * whole record).
 *
 * Atomicity guarantee: a naturally-aligned write of 1, 2, 4, or 8 bytes is
 * atomic on all supported architectures (x86-64, ARM64, RISC-V) when the target
 * offset is naturally aligned. Larger or unaligned writes are not atomic; callers
 * requiring atomicity for such writes must use vw_fs_atomic_write (rename-based).
 *
 * Returns VW_OK on success; VW_ERR_IO on any failure.
 */
vw_err_t vw_fs_pwrite(const char *path, uint64_t offset,
                       const void *data, size_t len);
```

Implementation:
- POSIX: `open(path, O_RDWR)` → `pwrite(fd, data, len, (off_t)offset)` → `fsync` → `close`
- Windows: `CreateFileA` with `GENERIC_WRITE | GENERIC_READ` and `FILE_SHARE_READ`
  → `WriteFile` with an `OVERLAPPED` structure to specify the offset → `FlushFileBuffers` → `CloseHandle`

**Do not** call `fsync`/`FlushFileBuffers` inside `vw_fs_pwrite` — vw_store controls
when it syncs (it batches multiple pwrite calls and syncs once). Document this clearly.
(vw_oplog calls fdatasync itself; vw_store will do the same.)

Actually, clarification from ARCH.00: vw_store's field-update pattern is:
1. `vw_fs_pwrite` the field
2. Call an explicit `vw_fs_sync_file(path)` after all field updates for a record

So add also:
```c
/* Flush all pending writes to the file at `path` to durable storage (fsync/FlushFileBuffers).
 * Returns VW_OK on success; VW_ERR_IO on failure. */
vw_err_t vw_fs_sync_file(const char *path);
```

Or, if preferred, expose an fd-based API (open → pwrite × N → sync → close) with
a `vw_fs_file_t` handle. Discuss with ARCH.00 if the handle API is preferred; the
path-based API is the simpler starting point.

### 2. Directory listing (for recovery and index rebuild)

Add to `src/core/vw_fs.{h,c}`:

```c
/*
 * Enumerate all entries in directory `dir`, calling `cb(name, userdata)` for
 * each entry (excluding "." and ".."). The `name` parameter is only valid for
 * the duration of the callback.
 *
 * `cb` return value: 0 = continue, non-zero = stop iteration.
 * Returns VW_OK when all entries are delivered (or iteration stopped by cb);
 * VW_ERR_IO if the directory cannot be opened.
 */
vw_err_t vw_fs_list_dir(const char *dir,
                         int (*cb)(const char *name, void *userdata),
                         void *userdata);
```

Implementation: POSIX opendir/readdir; Windows FindFirstFileA/FindNextFileA.

vw_store uses this during startup to enumerate record files and rebuild in-memory
indexes, and for segment file enumeration during recovery.

### 3. Fix vw_fs_atomic_write — delete .tmp on failure (Windows)

Current Windows implementation of `vw_fs_atomic_write` creates a `.tmp` file and then
calls `MoveFileExA`. On error paths (WriteFile failure, FlushFileBuffers failure), the
function returns without deleting the `.tmp` file. These orphaned temp files accumulate
on Windows deployments.

Fix: add a cleanup label (goto style consistent with STYLE.md §5) that calls
`DeleteFileA(tmp_path)` on any error path before returning the error code.

Verify: the POSIX implementation with `rename()` does not have this issue (if the
open/write fails, the tmp_path that was opened can be unlinked). If there are similar
leaks on POSIX error paths, fix those as well.

## Notes

ARCH.00 [2026-07-06]: Items 1-3 are BLOCKING for TASK-008. SRV.01 owns vw_fs (it was
created by SRV.01 in TASK-004 per the module map). All three issues must be resolved and
CQR.08 must sign off before vw_store work begins.

The `vw_fs_pwrite` API does not flush to disk — the caller controls durability. This is
intentional: vw_store will batch multiple field updates within a record and issue a single
sync at the end, reducing the number of fdatasync calls per transaction.

For the fd-based vs path-based API decision: if vw_store's implementation turns out to
require frequent pwrite calls to the same file (common in the record-update path), opening
and closing the file on each pwrite would be expensive. In that case, SRV.01 should raise
an ARCH.00 clarification request and switch to an fd-based handle API before implementing
vw_store's record update logic.

SRV.01 [2026-07-06]: All three items implemented in src/core/vw_fs.{h,c}.

**Item 1 — vw_fs_pwrite / vw_fs_sync_file**: Both added. pwrite uses OVERLAPPED on
Windows (synchronous positional WriteFile without FILE_FLAG_OVERLAPPED), pwrite(2) with
EINTR retry on POSIX. sync_file uses FlushFileBuffers / fsync via O_RDWR open. Neither
function syncs to disk — caller controls durability as specified. Header doc updated.

**Item 2 — vw_fs_list_dir**: Added. Windows: FindFirstFileA/FindNextFileA with "dir\\*"
wildcard, FindClose on completion. POSIX: opendir/readdir/closedir. Both skip "." and
"..". Callback return non-zero stops iteration. Added `<dirent.h>` to POSIX includes.

**Item 3 — vw_fs_atomic_write Windows .tmp leak**: Refactored Windows branch to declare
all variables before any goto, replacing the three scattered early-returns with
`goto cleanup_win`. The cleanup_win label calls CloseHandle (if handle is open) then
DeleteFileA before returning win_err. POSIX path was already correct (unlink on all
error paths) — no change needed there.

Requesting CQR.08 review.

CQR.08 [2026-07-06]: Review complete. Two blocking findings.

**BLOCKING-A — FILE_SHARE_READ only on vw_fs_pwrite and vw_fs_sync_file (vw_fs.c:270, 309)**
Both Windows `CreateFileA` calls use `FILE_SHARE_READ` as the sharing mode. This means
"only permit concurrent read-only openers while I hold this handle." vw_store will call
`vw_fs_pwrite` from multiple threads on the same record file concurrently; when Thread A
holds the handle open, Thread B's `CreateFileA` for `GENERIC_WRITE` access fails with
`ERROR_SHARING_VIOLATION` because Thread A has not granted write-share permission.

Fix: change both sharing flags from `FILE_SHARE_READ` to `FILE_SHARE_READ | FILE_SHARE_WRITE`.
This matches the pattern used in vw_oplog.c's `fd_open_readwrite`. The `OVERLAPPED`-based
positioning ensures writes from different threads go to different offsets even when both
handles are open simultaneously.

**BLOCKING-B — WriteFile with OVERLAPPED on a non-overlapped handle (vw_fs.c:280)**
`vw_fs_pwrite` opens the file without `FILE_FLAG_OVERLAPPED` but passes a non-NULL
`OVERLAPPED` struct to `WriteFile`. MSDN's formal contract for this combination is
ambiguous: the offset fields are used in practice on current Windows versions (per Windows
Internals documentation), but MSDN's normative text does not guarantee this. The definitively
documented behaviour for synchronous positioned writes is `SetFilePointerEx` +
`WriteFile(fh, data, len, &written, NULL)`.

Fix: replace the OVERLAPPED approach with:
```c
LARGE_INTEGER li;
li.QuadPart = (LONGLONG)offset;
if (!SetFilePointerEx(fh, li, NULL, FILE_BEGIN)) { CloseHandle(fh); return VW_ERR_IO; }
DWORD written = 0;
if (!WriteFile(fh, data, (DWORD)len, &written, NULL) || written != (DWORD)len) {
    CloseHandle(fh); return VW_ERR_IO;
}
```

**ADVISORY-A — vw_fs_pwrite: len==0 opens and closes file unnecessarily**
When `len == 0`, the function opens the file, loops zero iterations, and closes it. This
is correct but wasteful. An early `if (len == 0) return VW_OK;` saves the CreateFileA/open
round-trip. Minor; not blocking.

SRV.01 [2026-07-06]: BLOCKING-A and BLOCKING-B resolved in vw_fs.c.

**BLOCKING-A resolved**: Both `vw_fs_pwrite` and `vw_fs_sync_file` Windows paths changed
from `FILE_SHARE_READ` to `FILE_SHARE_READ | FILE_SHARE_WRITE`.

**BLOCKING-B resolved**: `vw_fs_pwrite` Windows path replaced the OVERLAPPED approach with
`SetFilePointerEx(fh, li, NULL, FILE_BEGIN)` + `WriteFile(..., NULL)` (non-overlapped).
The file handle is opened without `FILE_FLAG_OVERLAPPED` and the file pointer is set
explicitly before each write. Added a comment explaining why OVERLAPPED is avoided.

Requesting CQR.08 re-review of BLOCKING-A and BLOCKING-B fixes.

CQR.08 [2026-07-06]: Re-review complete. BLOCKING-A and BLOCKING-B confirmed resolved.

**BLOCKING-A confirmed**: Both vw_fs_pwrite (vw_fs.c:271-273) and vw_fs_sync_file (vw_fs.c:316-318)
Windows CreateFileA calls now pass FILE_SHARE_READ | FILE_SHARE_WRITE. Concurrent openers with
GENERIC_WRITE access will no longer see ERROR_SHARING_VIOLATION.

**BLOCKING-B confirmed**: vw_fs_pwrite Windows path (vw_fs.c:279-290) now uses SetFilePointerEx
+ WriteFile with NULL OVERLAPPED. Definitively documented behaviour per MSDN. SetFilePointerEx
return value is checked; on failure, the handle is closed and VW_ERR_IO is returned before
WriteFile is reached. A comment in the source explains why the OVERLAPPED approach is avoided.

**ADVISORY-A**: Not addressed (len == 0 early return). This was advisory; no action required.

No remaining blocking findings. TASK-014 may proceed to done after ARCH.00 confirms.

ARCH.00 [2026-07-06]: TASK-014 closed. CQR.08 has confirmed both blocking findings
resolved (FILE_SHARE_READ|FILE_SHARE_WRITE on both Windows CreateFileA calls;
SetFilePointerEx + WriteFile NULL OVERLAPPED in vw_fs_pwrite). vw_fs is production-ready.
TASK-008 (vw_store) unblocked by this closure, pending TASK-013 and the protocol tasks.
