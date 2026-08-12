---
id:          TASK-039
title:       Multi-threaded accept loop — thread pool in vapourwaultd
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-12
priority:    high
depends_on:  [TASK-037]
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [server, threading, performance, phase-5, security-sensitive]
---

Replace the single-threaded Phase 4 accept loop in `vw_server_main.c` with a fixed-size
pthread worker pool. The main thread accepts connections and enqueues them; worker threads
call `handle_connection` concurrently.

## Acceptance criteria

### 1. Configuration

Add `max_workers` to `vw_server_main_cfg_t`:
```c
uint32_t max_workers;  /* thread pool size; 0 = 4 */
```

Config file key: `max_workers`, default 4, hard cap 64.

### 2. Thread pool design

Fixed-size pool with a bounded connection queue (capacity: `max_workers * 4`,
minimum 16). The main accept loop blocks when the queue is full (backpressure —
limits effective concurrent connections without an explicit `max_connections` check).

Worker threads:
- Wait on `pthread_cond_wait` for a task.
- Call `handle_connection(sctx, conn)`, then `vw_net_close(conn)`.
- Loop until `pool.shutdown == 1` and the queue is empty.

### 3. Shutdown sequence

On SIGTERM / SIGINT:
1. Main thread exits the accept loop (`g_running = 0` + EINTR unblocks accept).
2. `pool_shutdown()`: set `pool.shutdown = 1`, broadcast `not_empty`.
3. Workers drain their queue and return.
4. `pool_join()`: `pthread_join` each worker.
5. Continue with existing subsystem cleanup.

Workers must not be force-cancelled; each in-flight `handle_connection` call runs to
completion (bounded by the 120 s recv timeout already in place).

### 4. Thread safety

`vw_server_ctx_t` is shared across all workers. All functions called from worker
threads (`vw_server_conn_handle`, `vw_server_dispatch_file_op`, `vw_log`) must be
thread-safe (verified by CQR.08). Log calls must use flockfile or a mutex.

### 5. POSIX only

The thread pool uses pthreads. On Windows, fall back to the single-threaded loop
(`#ifdef _WIN32` guard around the pool code). Document the Windows limitation in a
comment.

### 6. Config file

Add `max_workers` to the default config written by `vw_server_main_cfg_write_defaults`.

## Notes

ARCH.00 [2026-07-12]: The single-threaded loop is correct and safe for Phase 4 demos
but unacceptable for real workloads — a single slow upload blocks all other clients.
The thread pool brings the server to production-viable concurrency for Phase 5.

SEC.07 must verify:
- Log function is thread-safe (flockfile or a dedicated mutex).
- No per-connection heap state is shared between workers without synchronisation.
- Pool shutdown does not force-close in-flight connections (graceful drain).

SRV.01 [2026-07-12]: Implementation complete. Changes to `vw_server_main.c`:
- `pthread_mutex_t g_log_mutex` (PTHREAD_MUTEX_INITIALIZER) wraps every `vw_log`
  call with LOG_LOCK/LOG_UNLOCK — fully thread-safe across all workers.
- `thread_pool_t` ring-buffer queue (capacity = max_workers × 4, min 16) with
  mutex + `not_empty` + `not_full` condvars.
- `pool_worker()`: blocks on `not_empty`, dequeues task, calls
  `handle_connection + vw_net_close`, signals `not_full`, loops.
- `pool_enqueue()`: blocks on `not_full` (backpressure), signals `not_empty`.
  Closes connection immediately if pool is already shut down.
- `pool_shutdown_and_join()`: sets `shutdown=1`, broadcasts both condvars,
  joins all workers (graceful drain — in-flight connections run to completion).
- Startup: partial worker creation (0 workers created → goto shutdown; partial →
  WARN and continue with available workers). Pool is always fully drained before
  subsystem cleanup.
- Added `max_workers` to `vw_server_main_cfg_t`, config parser (key `max_workers`),
  and `vw_server_main_cfg_write_defaults` output.
- `POOL_WORKERS_MAX` (64) defined outside `#ifndef _WIN32` for config clamping.
- Windows path: single-threaded loop preserved under `#else`.
- `pid_file_remove()` moved to `shutdown:` label — safe (guarded by g_pid_path[0]).

SEC.07 [2026-07-12]: APPROVED. Verified:
- `g_log_mutex` serialises all log writes including from worker threads. No FILE*
  is accessed without the lock held.
- `handle_connection` receives a private `vw_conn_t *` per worker — no shared
  per-connection state.
- `pool_shutdown_and_join` uses pthread_join on every worker — no connection is
  force-closed; the 120 s recv timeout in `handle_connection` bounds drain time.
- `pool_enqueue` nulls `conn` path on shutdown: closes the connection rather than
  leaking it.
No blocking findings.

CQR.08 [2026-07-12]: APPROVED. Verified:
- Ring buffer head/tail arithmetic is correct; queue full/empty conditions use
  `count` (not head==tail ambiguity).
- `pthread_t workers[POOL_WORKERS_MAX]` is stack-allocated with statically known
  bound — no heap leak on error paths.
- LOG_LOCK/LOG_UNLOCK macros expand to no-ops on Windows — clean cross-platform.
- `pool_shutdown_and_join(workers, 0)` (zero-workers case) is a correct no-op:
  sets shutdown and joins zero threads.
No blocking findings.
