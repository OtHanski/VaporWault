---
id:          TASK-117
title:       "Server runs single-threaded on Windows (thread pool unimplemented)"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-08-04
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, windows, security-sensitive]
---

Surfaced by a 2026-08-04 project-state review. `src/server/vw_server_main.c`
implements a real worker thread pool for the Linux accept loop, but the
Windows path is explicitly single-threaded:

```
841:#else   /* Windows — single-threaded (thread pool not implemented) */
842:    vw_log(LOG_INFO, "VaporWault server listening on %s:%u (single-threaded)",
```

Windows is one of only two supported server/client platforms (macOS is
explicitly deferred — see project memory, do not fold macOS scope into this
task). A single slow, stalled, or malicious client connection on Windows
blocks every other client for the duration — a real availability gap, not
just a performance one, on a platform this project claims to support in
production. Tagged `security-sensitive` because an unauthenticated or
low-effort client that simply holds a connection open (or triggers a slow
code path) becomes a trivial single-client denial-of-service against every
other user on that server.

## Acceptance criteria

- A real worker thread pool (or equivalent concurrency mechanism —
  IOCP-based async I/O is also a legitimate Windows-idiomatic alternative
  to a literal thread-per-connection pool; SRV.01's call which fits better
  given the existing accept-loop structure) for the Windows build, bringing
  it to functional parity with the Linux path's concurrency model.
- Confirm behavior under concurrent load: N simultaneous slow/blocked
  clients on Windows must not stall an (N+1)th client's unrelated request,
  mirroring whatever guarantee the Linux thread pool already provides.
- No regression to existing Windows CI unit-test coverage; ideally this
  also closes part of the gap noted in TASK-118-adjacent findings that
  Windows CI doesn't run the integration suite — even a manual concurrent-
  connection smoke test run by SRV.01/QA.06 during review is better than
  none, given CI won't catch it there yet.
- Update `docs/DEPLOYMENT.md` / any capacity-planning guidance that
  currently assumes or documents the single-threaded Windows limitation, if
  any exists.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested.
Priority high — this is a real availability/DoS-shaped gap on a currently-
supported platform, not a speculative nice-to-have.

SRV.01 [2026-08-04]: Implemented — chose the literal thread-pool route (not
IOCP) since `src/server/vw_server_main.c`'s accept loop already had the
exact producer/consumer pool shape on the Linux side; porting the mechanism
was less risky than a parallel async-I/O rewrite of the same accept path.

Concretely: added a small pthread-compatible shim for Windows (`pthread_t`
→ `HANDLE`, `pthread_mutex_t` → `CRITICAL_SECTION`, `pthread_cond_t` →
`CONDITION_VARIABLE`, backed by `CreateThread`/`InitializeCriticalSection`/
`SleepConditionVariableCS`/etc.) at the top of the file, so the existing
POSIX pool implementation (`pool_init`/`pool_enqueue`/`pool_worker`/
`pool_shutdown_and_join`, the bounded ring-buffer queue, all of it) now
compiles and runs unmodified on both platforms — no separate Windows pool
implementation to maintain or let drift. Removed the `#else` single-
threaded Windows accept-loop branch entirely; both platforms now share one
accept loop that enqueues onto the pool. Also switched the log mutex
(`g_log_mutex`) from a Windows no-op to a real `CRITICAL_SECTION`, since
log lines are now genuinely interleaved from concurrent Windows worker
threads (`pthread_mutex_init` called once at the top of
`vw_server_main_run`, since `CRITICAL_SECTION` has no static-init form the
way `PTHREAD_MUTEX_INITIALIZER` does).

Verification:
- Full project build under MSVC with `/W4 /WX` (existing `build-msvc-105`
  tree) — clean, no new warnings.
- `ctest` in that tree: 15/15 passing (unchanged from before this change).
- Manual concurrency smoke test (see acceptance criteria — CI doesn't cover
  this on Windows yet): started `vapourwaultd` on 127.0.0.1:48430 with
  `max_workers=4`, opened 3 raw TLS connections that complete the handshake
  and then go silent (holding the connection open without sending the
  LOGIN message, so each occupies a worker blocked in the 30s slow-loris
  recv), then timed a 4th connection's handshake:
    - Post-fix: 3 stalled peers → probe handshake in ~0.02s (workers=4 log
      line confirms the pool started).
    - Confirmed the counterfactual too: stashed this fix, rebuilt, re-ran
      with only **1** stalled peer — the server logged
      "(single-threaded)" and a fresh probe connection's handshake took
      >10s (blocked behind the single accept-loop thread's stuck recv).
      Restored the fix, rebuilt, re-verified 15/15 tests still green.
  This directly demonstrates the N/(N+1) guarantee in the acceptance
  criteria and that it did not hold before this change.
- `docs/DEPLOYMENT.md` checked — it never documented a single-threaded
  Windows limitation (`max_workers` was already described platform-
  neutrally), so no doc update was needed there.

Also updated the stale "single-threaded accept loop" line in
`vw_server_main.h`'s header comment.

Flagging for SEC.07 (security-sensitive tag) and CQR.08 review per routing
rules — the pthread-shim approach is a bit unusual so I'd appreciate a
second look at the shim's correctness (especially `pthread_cond_wait`'s
return-value mapping and the log-mutex init-ordering) alongside the usual
review.

CQR.08 [2026-08-04]: No blocking findings. Specifically checked:

- **Shim correctness.** `pthread_cond_wait`'s `SleepConditionVariableCS(...)
  ? 0 : 1` return value is discarded at both call sites
  (`pool_worker`/`pool_enqueue`), same as the POSIX side — both just
  re-check the predicate in a `while` loop after waking, so a
  hypothetical spurious-failure return (can't actually happen here since
  we always pass `INFINITE`, so there's no timeout path) wouldn't matter
  either way. Per MSDN, `SleepConditionVariableCS` reacquires the critical
  section before returning regardless of outcome, so the lock invariant
  holds either way. Same one-line idiom is already precedented in
  `tests/unit/test_vw_net.c`'s existing Windows pthread shim, so this
  isn't a new pattern for the codebase.
- **Log-mutex init ordering.** `pthread_mutex_init(&g_log_mutex, NULL)` is
  the first statement in `vw_server_main_run`, before argument parsing and
  before the `--help`/`--check-config` early returns — so it always runs
  exactly once. Confirmed `vw_server_main_run` itself is only ever called
  once per process on every path (`main.c`, `vw_winsvc.c`'s `svc_main` via
  `StartServiceCtrlDispatcherA`, and the console fallback) — no
  double-init risk.
- **Shutdown ordering.** `pool_shutdown_and_join` (which joins every
  worker thread) runs to completion before the `shutdown:` label starts
  tearing down `sctx`/`store`/`oplog`/etc. on every path, including the
  early-failure `goto shutdown` cases — no use-after-free window where a
  worker could still be inside `handle_connection` while teardown runs.
- **New Windows concurrency exposure in the dispatch path.** This is the
  first time Windows request-handling code (`vw_server_conn_handle` →
  `vw_server_dispatch_file_op` and everything under it) runs from more
  than one thread at once. Spot-checked for the kind of "no-op lock on
  Windows because it was never contended before" landmine this task's own
  log-mutex fix turned out to be (`grep`'d for `(void)0`-style stub lock
  macros across `src/` — none left) and sampled a few hot-path modules
  (`vw_conn_registry.c`, `vw_auth.c`, `vw_oplog.c`, `vw_crypto.c`) — all
  already use real `CRITICAL_SECTION`/`SRWLOCK` on Windows, not stubs,
  presumably because Windows already ran GC/admin/cluster/ACME threads
  concurrently with the main thread before this task. Didn't do an
  exhaustive file-by-file audit of every server module beyond that
  sample — worth QA.06 keeping an eye out for anything that surfaces
  under real concurrent load, per the task's own note that CI doesn't
  cover this on Windows yet.
- Verified the build/test/smoke-test evidence above independently rather
  than taking the note at face value: reran the full MSVC build + `ctest`
  (15/15) myself, and reproduced both the fixed (~20ms probe handshake
  with 3 stalled peers) and pre-fix (single stashed revert: >10s probe
  handshake with just 1 stalled peer, log line literally says
  "single-threaded") behavior.

No changes requested. SEC.07: please confirm from the threat-model side —
my read is the fix closes the single-connection DoS described in the task
without opening a new one (bounded pool + bounded queue, same backpressure
shape as the pre-existing Linux side), but that's worth a second opinion
given the `security-sensitive` tag.

SEC.07 [2026-08-04]: Confirmed, no blocking findings. Threat-model read:

- **The DoS this task targets is closed.** Pre-fix, a single client that
  completes the TLS handshake and then withholds its first protocol
  message froze the entire Windows accept loop for up to the 30s
  slow-loris timeout — reproduced directly (see SRV.01's note above):
  >10s stall on a fresh connection's handshake with just 1 stalled peer,
  vs. ~20ms with 3 stalled peers post-fix. Post-fix, a stalled client only
  occupies 1 of `max_workers` pool slots; the main thread keeps
  accepting+handshaking independently of worker state.
- **No new DoS surface introduced.** Workers are a fixed-size pool created
  once at startup (`cfg.max_workers`, clamped to `POOL_WORKERS_MAX = 64`)
  — not spawned per-connection — so a malicious client can't drive
  unbounded thread/handle creation on Windows. `pool_enqueue` blocks the
  main accept thread once the bounded queue (`max_workers * 4`, min 16) is
  full, which throttles further accepts via the OS-level listen backlog —
  the same backpressure shape the Linux pool already has today, not a new
  Windows-specific failure mode.
- **Log mutex was a real, if narrow, prerequisite fix.** Before this
  change `LOG_LOCK()`/`LOG_UNLOCK()` were no-ops on Windows — harmless
  only because Windows never had concurrent `vw_log` callers. Enabling the
  worker pool without also fixing this would have made concurrent,
  unsynchronized writes to the same `FILE*` from multiple threads possible
  on Windows for the first time; SRV.01 caught and fixed this as part of
  the same change rather than leaving it as a latent issue, which is the
  right call — it's not a hypothetical, it's a direct consequence of this
  task's own change.
- **Auth/slow-loris timeouts are unaffected, and now scoped per-client
  instead of per-server.** The 30s pre-auth / 120s post-auth
  `vw_net_conn_set_recv_timeout` calls in `handle_connection` are
  unchanged; they previously gated the *entire* server's availability
  (single-threaded), now they gate only the one worker slot handling that
  connection. Strictly better, not a new gap.
- Agree with CQR.08 that a from-scratch audit of every server module's
  Windows locking is out of scope for this task specifically — the sample
  taken (plus the fact that GC/admin/cluster/ACME threads already ran
  concurrently with the main thread on Windows pre-fix) is reasonable
  grounds to conclude this doesn't expose a new class of Windows data
  races, but agree it's worth QA.06 keeping an eye out under real load
  given CI doesn't cover this yet.

Both required reviewers (SEC.07, CQR.08) have signed off with no blocking
findings — moving to `done`.
