---
id:          TASK-042
title:       Background GC thread — session expiry and oplog truncation
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-12
priority:    high
depends_on:  [TASK-037]
blocks:      [TASK-043]
review_by:   [CQR.08, SEC.07]
tags:        [server, gc, phase-6, security-sensitive]
---

Implement a background garbage-collection thread that runs every 30 minutes
(configurable) to expire stale sessions and truncate old oplog segments.

## Acceptance criteria

### 1. Source files

- `src/server/vw_gc.h` — `vw_gc_cfg_t`, opaque `vw_gc_ctx_t`, API.
- `src/server/vw_gc.c` — POSIX + Windows background thread; no-op when
  `interval_secs == 0`.

### 2. New store API

Add to `vw_store.h`/`vw_store.c`:

```c
vw_err_t vw_store_session_gc(vw_store_t *ctx, uint64_t now_unix,
                              uint32_t *out_count);
```

Scans all session slots; for each where `is_active == 1 && expires_at != 0 &&
expires_at <= now_unix`: writes `is_active = 0` to disk (one `pwrite` per
slot), removes the token from the in-memory index, pushes the slot onto the
free list. Performs a single `fsync` after all in-place writes. Does NOT write
an oplog entry per expired session to avoid flooding the log; logs the count
instead. Holds the sessions write lock for the entire scan (GC runs
infrequently; this is acceptable).

### 3. GC passes

**Session expiry** (every cycle):  
Call `vw_store_session_gc` with `now = time(NULL)`. Log count at INFO level.

**Oplog truncation** (every cycle):  
In single-node mode (no cluster), call
`vw_oplog_truncate_before(oplog, vw_oplog_last_entry_id(oplog))` to delete all
completed segments except the active one. When cluster replication is
implemented (Phase 7), this must be replaced with the minimum replica
sync offset.

### 4. Configuration

Two new keys in `server.conf`:

```
gc_interval_secs = 1800   # 0 = disable GC thread
```

`vw_gc_cfg_t.interval_secs == 0` → `vw_gc_start` returns `VW_OK` immediately
without spawning a thread.

Add `vw_gc_cfg_t gc` to `vw_server_main_cfg_t`.

### 5. Build

Add `vw_gc.c` to `src/server/CMakeLists.txt` (vapourwaultd target).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-07-12]: Implementation complete.

- `src/server/vw_store.h/.c` — added `vw_store_session_gc(ctx, now_unix, *count)`.
  Holds sessions write lock for the full scan. Single `vw_fs_sync_file` after
  all per-slot `pwrite` calls. Buffer zeroed with `secure_zero` before free.
  pwrite failures per slot are non-fatal; the slot is skipped and retried next cycle.

- `src/server/vw_gc.h` — `vw_gc_cfg_t` (interval_secs), opaque `vw_gc_ctx_t`,
  API: `vw_gc_create`, `vw_gc_destroy`, `vw_gc_start`, `vw_gc_stop`,
  `vw_gc_run_once`.

- `src/server/vw_gc.c` — 1-second sleep-loop thread (POSIX pthread /
  Windows CreateThread). Shutdown latency: ≤1 second. Two GC passes per cycle:
  (1) `vw_store_session_gc` for session expiry; (2) `vw_oplog_truncate_before`
  with `vw_oplog_last_entry_id(oplog)` to prune all completed segments in
  single-node mode. Logging via `fprintf(stderr, ...)` with [GC] tag, matching
  the vw_acme logging pattern.

- `src/server/vw_server_main.h` — added `#include "vw_gc.h"` and
  `vw_gc_cfg_t gc` field to `vw_server_main_cfg_t`.

- `src/server/vw_server_main.c` — `cfg_defaults` sets
  `gc.interval_secs = VW_GC_DEFAULT_INTERVAL_SECS` (1800); config key
  `gc_interval_secs` parsed; default config writer includes GC section;
  `vw_gc_create`+`vw_gc_start` after ACME; `vw_gc_stop`+`vw_gc_destroy`
  first in shutdown block (before ACME, before admin server).

- `src/server/CMakeLists.txt` — `vw_gc.c` added to vapourwaultd target.

SEC.07 should review: session expiry writes `is_active=0` by pwrite (not zeroing
the entire slot — token bytes remain on disk but the slot is unreachable via the
token HT; acceptable since the sessions file is not world-readable).

ARCH.00 note: oplog truncation in single-node mode is correct. When vw_cluster
is added (Phase 7), the GC must receive the minimum replica sync offset and pass
it to `vw_oplog_truncate_before` instead of `vw_oplog_last_entry_id`.

CQR.08 / SEC.07: ready for review.

SEC.07 [2026-07-12]: ADVISORY — Expired session records retain their token
bytes on disk (only `is_active` is overwritten). The slot becomes unreachable
via the in-memory token HT, so the token cannot be replayed. The sessions
file is not world-readable (mode 0600 per POSIX requirements enforced at open
time). Advisory: if defence-in-depth requires on-disk zeroing of expired
tokens, a future cleanup pass can `pwrite` the 32-byte token field to zeros.
Not a blocking issue for Phase 6. **SEC.07 sign-off granted.**

CQR.08 [2026-07-12]: ADVISORY — `volatile int shutdown` in `vw_gc.c` is used
as a cross-thread signal. `volatile` prevents the compiler from caching the
read in a register but does not provide a memory barrier on all architectures.
`_Atomic int` (C11 `stdatomic.h`) or a mutex-guarded flag is the correct
tool. Under GCC/Clang with x86 hardware the current code works in practice
but is undefined behaviour per the C standard. Recommend replacing with
`_Atomic int shutdown` and `atomic_load_explicit(&shutdown,
memory_order_acquire)` in the loop check. Not blocking for Phase 6 given the
x86 target but should be fixed before any ARM port.

CQR.08 [2026-07-12]: No blocking findings. Per-slot pwrite failure is
non-fatal (retry next cycle), single fsync after all writes, buffer zeroed
before free, correct lock discipline throughout. **CQR.08 sign-off granted.**

ARCH.00 [2026-07-12]: All reviewers signed off. No blocking findings remain.
Task marked done. TASK-043 (version/chunk GC) is now unblocked.

CQR.08 [2026-07-12]: BLOCKING — `vw_gc.c` uses a bare
`__attribute__((format(printf, 2, 3)))` declaration on `gc_log` without a
`#if defined(__GNUC__) || defined(__clang__)` guard. MSVC does not support
this attribute syntax and will fail to compile the file. This is a cross-platform
build breakage on Windows.

**Fix applied by SRV.01 (2026-07-12):** Wrapped the attribute declaration in
`#if defined(__GNUC__) || defined(__clang__) … #endif` in `vw_gc.c` (lines 29–31).
MSVC builds fall through to the unattributed declaration; GCC/Clang receive the
format check. **Blocking finding: RESOLVED.**

CQR.08 [2026-07-12]: Post-fix re-review complete. No remaining blocking items.
**CQR.08 sign-off re-granted.**

ARCH.00 [2026-07-12]: Blocking finding resolved by code fix. Re-marking done.
