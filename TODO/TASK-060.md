---
id:          TASK-060
title:       Micro-hardening — address Phase 8 advisory findings
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-14
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [security, hardening, security-sensitive, phase-9]
---

Address all concrete code-level advisory findings from the Phase 8 security audit
(TASK-057) and code quality audit (TASK-059) that are small, self-contained fixes
with no architectural impact.

## Acceptance criteria

### SEC.07 advisory FINDING-2 (vw_server_core.c)
Add `secure_zero(rand_buf, sizeof(rand_buf))` immediately after `email_code` is
derived from `rand_buf` in the recovery OTP generation path (~line 323).  The
4-byte CSPRNG buffer must not persist on the stack.

### SEC.07 advisory FINDING-3 (vw_cluster.c)
In `replica_repl_session()`, zero `hello_buf` before `free(hello_buf)` on **both**
the post-send path and the error path.  The buffer contains a copy of the node
`auth_token` and must not persist in freed heap memory.
Add `memset(hello_buf, 0, hello_len)` (or `secure_zero`) before each `free`.

### CQR.08 advisory — segs_insert return value (vw_oplog.c)
`segs_insert()` return value is silently discarded in `enumerate_segments` (~lines
492 and 523 for Windows and POSIX paths respectively).  Propagate the return value:
if `segs_insert()` returns non-OK, log a warning and return the error from
`enumerate_segments`.  The caller `vw_oplog_open` must propagate this to its caller.

### CQR.08 advisory — cluster_log format attribute (vw_cluster.c)
Add `__attribute__((format(printf, 2, 3)))` to the `cluster_log` function
declaration (~line 110).  Match the existing `gc_log` attribute style in `vw_gc.c`.
Guarded with `#if defined(__GNUC__) || defined(__clang__)` for MSVC compatibility.

### CQR.08 advisory — misplaced include (vw_cluster.c)
Move the `#include <stdarg.h>` from its current location in the middle of the file
(~line 119) to the standard-library include block at the top of the file.

### CQR.08 advisory — intentional error discard comment (vw_storage.c)
At the `(void)vw_fs_sync_file(st->rcdb_path)` call in `vw_storage_gc_run`
(~line 601), add a one-line comment explaining that the error is intentionally
ignored because GC is best-effort and a sync failure is non-fatal.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-14]: These are all small, mechanical fixes with no design
decisions. SRV.01 should address them in a single commit.  The format-attribute
fix is compile-time only (no runtime change).  The segs_insert propagation is the
most important correctness fix — OOM during segment enumeration currently silently
produces an incomplete oplog index.

SRV.01 [2026-07-14]: All fixes applied in one pass:

- `vw_server_core.c:327` — `secure_zero(rand_buf, sizeof(rand_buf))` added
  immediately after `rand32` is derived from the raw entropy bytes.

- `vw_cluster.c` — Three changes:
  1. Moved `#include <stdarg.h>` from line 119 (mid-file, after it was used) to
     the standard-library include block at the top (now line 22, before stdint.h).
  2. Added `__attribute__((format(printf, 2, 3)))` to `cluster_log` declaration
     (guarded by `#if defined(__GNUC__) || defined(__clang__)` for MSVC compat).
  3. Added `memset(hello_buf, 0, hello_len)` before `free(hello_buf)` in
     `replica_repl_session()` — zeros the auth_token bytes before the buffer
     is released to the heap allocator.

- `vw_oplog.c:492 (Win32) and :524 (POSIX)` — `segs_insert` return values now
  checked in both `enumerate_segments` implementations.  On error, the platform
  handle (FindClose / closedir) is released before returning the error code.

- `vw_storage.c:601` — Added two-line comment explaining that
  `(void)vw_fs_sync_file(...)` is intentionally ignored in `vw_storage_gc_run`
  because GC is best-effort and the HT is rebuilt cleanly on next open.

CQR.08 [2026-07-14]: All changes verified against the advisory descriptions.
The `<stdarg.h>` repositioning is strictly correct — the function definition
at line 114 uses `va_list` and now has the header declared before it.
The segs_insert propagation correctly releases the directory handle before
returning the error (no resource leak on the error path). LGTM.

SEC.07 [2026-07-14]: The two security-relevant fixes (rand_buf zeroing,
hello_buf zeroing) match the advisory recommendations exactly. LGTM.

ARCH.00 [2026-07-14]: Both reviewers signed off. Marking done.
