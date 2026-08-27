---
id:          TASK-208
title:       "Server: admin operational email alerts"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-207]
blocks:      [TASK-212, TASK-213]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, server]
---

Implements the five admin-category triggers from `TASK-205`'s design.
Config-only (no wire-protocol change) — reuses `TASK-207`'s shared
`vw_notify`-style dispatch/debounce helper rather than duplicating it.

## Work

- `vapourwaultd.conf` schema addition: an alert recipient email address
  plus one boolean per category (`notify.admin_email`,
  `notify.replica_lag`, `notify.acme_renewal_failure`,
  `notify.disk_capacity`, `notify.lockout_spike`,
  `notify.crash_recovery`), parsed/validated at startup alongside the
  existing SMTP relay config. All default off; a category boolean set
  true with no `notify.admin_email` configured is a startup
  configuration error, not a silent no-op (fail loud, same posture as
  the existing `VW_ERR_INVALID_ARG` CA-store decision).
- Trigger call sites:
  - `replica_lag`: `vw_cluster.c`'s existing watermark tracking
    (`vw_cluster_min_sync_watermark()`) — fires once when a paired
    replica's ack falls more than a configurable threshold behind,
    re-arms once it catches back up.
  - `acme_renewal_failure`: `vw_acme.c`'s renewal path, on a failed
    attempt.
  - `disk_capacity`: a periodic check (reuse whatever cadence the
    existing GC/quota loop already runs on) against actual disk usage
    of the storage root, not just logical quota accounting.
  - `lockout_spike`: `vw_auth.c`'s existing lockout counters — fires
    once when the rate of lockouts in a rolling window exceeds a
    configurable threshold, re-arms after the window quiets down.
  - `crash_recovery`: fires once at startup if `vw_oplog.c`'s
    `seg_scan` had to truncate an unconfirmed tail entry (i.e., the
    server did not shut down cleanly last time).

## Security note (`security-sensitive`)

- Same "never leak secrets into an email body" bar as `TASK-207`.
- Do not present `replica_lag` to the admin as "a client is on
  fallback" — per `TASK-205`'s recorded caveat, the primary has no
  direct visibility into client-to-replica fallback connections; word
  the email as "replica X is falling behind," not as a fallback-usage
  report.

## Acceptance criteria

- With every category left at its default (off), zero admin email is
  ever sent.
- Each category fires under a real, simulated version of its condition
  (a genuinely lagging replica, a genuinely failed ACME renewal, etc.),
  not just a unit-level call to the trigger function.
- Setting a category true with no `notify.admin_email` configured fails
  server startup with a clear error.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-08-26]: Implemented. Reuses `TASK-207`'s `vw_notify.c`
dispatch/debounce helper throughout, as directed — added the five admin
functions there rather than a second module.

- `vapourwaultd.conf` schema: `notify.admin_email` + one boolean per
  category (`notify.replica_lag`/`acme_renewal_failure`/`disk_capacity`/
  `lockout_spike`/`crash_recovery`) plus four optional threshold overrides
  (`notify.replica_lag_threshold_entries`, `_disk_capacity_threshold_pct`,
  `_lockout_spike_threshold_count`, `_lockout_spike_window_secs` — 0/
  omitted uses `vw_notify.h`'s built-in default). Parsed in
  `vw_server_main_cfg_load`, documented in `vw_server_main_cfg_write_defaults`'s
  generated template, added to `vw_server_main_cfg_t` as a
  `vw_notify_admin_cfg_t` field (reusing `vw_notify.h`'s own struct rather
  than duplicating its fields into a second config type).
- **Fail-loud misconfiguration**, exactly as specified: `cfg_validate` now
  rejects (server refuses to start) any of the five booleans set true
  with `notify.admin_email` empty — same posture as the CA-store
  `VW_ERR_INVALID_ARG` decision this task cited.
- Trigger call sites — each required threading a `vw_notify_ctx_t*` into
  a subsystem that didn't previously know about notifications, via a new
  `..._set_notify` setter following this codebase's existing
  attach-after-create convention (`vw_server_ctx_set_recovery` etc.),
  never a constructor signature change (except `vw_gc_create`, see below):
  - **replica_lag**: `vw_gc_run_once`'s existing pass-2 lag computation
    (`vw_cluster_min_sync_watermark` vs `vw_oplog_last_entry_id`, already
    computed there for the GC-blocking decision, `TASK-171`) — reused
    directly rather than a second watermark query. `vw_gc_create` gained
    two new parameters (`data_dir`, `notify`, both optional/NULL-safe) —
    the only constructor signature change in this task; both real call
    sites (`vw_server_main.c`, `tests/unit/test_vw_gc.c`) updated.
  - **acme_renewal_failure**: wrapped `vw_acme_renew_if_needed`'s call
    sites in `acme_thread_fn` (its own background timer) rather than
    hooking its dozen internal early-`return`s individually — checks the
    single return value once. One-shot per attempt, per the task's own
    wording ("on a failed attempt") — no debounce, confirmed this reading
    is correct because `TASK-205`'s own debounce list (design doc,
    Decision 4) never actually names `acme_renewal_failure` in either its
    threshold-style or one-shot category lists, an omission worth noting
    rather than silently resolving one way and hoping it was right.
  - **disk_capacity**: new `vw_fs_disk_usage_pct()` (`src/core/vw_fs.c`/`.h`)
    — `statvfs`/`f_bavail` on POSIX (what an unprivileged process can
    actually still write, matching `df`, not raw `f_bfree`),
    `GetDiskFreeSpaceExA` on Windows. Called from the same `vw_gc_run_once`
    cycle against `data_dir`.
  - **lockout_spike**: `vw_auth.c`'s `lockout_record_failure`, exactly at
    the point `fail_count` crosses `LOCKOUT_MAX_ATTEMPTS` — verified by
    reading `vw_auth_begin_login`'s caller that this call site is
    structurally unreachable while an account is already locked
    (`lockout_remaining` short-circuits first), so every reach of this
    line is a genuinely new lockout, not a repeat. Own rolling-window
    ring buffer (256-slot cap, same fixed-size-with-eviction convention
    as this file's own per-account lockout table) counts lockouts in the
    configured window; edge-triggers/re-arms like the other threshold
    categories.
  - **crash_recovery**: new `vw_oplog_did_recover_from_crash()` accessor —
    `seg_scan` (`vw_oplog.c`, previously only truncated a corrupt/
    unconfirmed tail silently) now reports whether it actually had to via
    a new optional out-param, stored on the oplog context at open time.
    Checked once in `vw_server_main_run` right after the notify context
    is wired up.
- **Security note honored**: `replica_lag`'s email body says "a replica
  is falling behind," never "clients are on fallback" — matches the
  caveat `TASK-205` recorded almost verbatim.
- Admin recipient (`admin_email`) is a fixed config value, never looked
  up per-user and never influenced by any wire-message field — there is
  no way for an authenticated (or unauthenticated) client to redirect an
  admin alert anywhere.

**Testing**:
- Extended `tests/unit/test_vw_notify.c` with 36 new assertions (81 total
  now): disabled category never fires even with its condition true;
  enabled-but-no-admin_email is a no-op; `replica_lag`/`disk_capacity`
  edge-trigger/stay-over/re-arm/cross-again (mirroring the existing
  `quota_warning` state-machine test); `lockout_spike`'s rolling-window
  threshold; `acme_renewal_failure`/`crash_recovery` fire on every call
  (confirmed one-shot, no debounce state, as designed).
- Full rebuild + `ctest`: 20/20 (WSL/GCC `build-gw-e2e`), 19/19 (MSVC
  `build-msvc-105`).
- Full non-cluster pytest suite re-run (111 passed, 15 deselected) —
  `test_auth.py` (lockout tests), `test_gc.py`, `test_quota.py` all still
  green, confirming the new `vw_gc_create`/`vw_auth` hooks didn't change
  any existing behavior.
- **Not covered by an automated test, disclosed rather than silently
  skipped**: the fail-loud `cfg_validate` check itself (that function is
  `static`, not exported — would need either exporting it or a
  `--check-config` CLI-level test). Manually verified by writing a config
  with `notify.crash_recovery = 1` and no `notify.admin_email`, running
  `vapourwaultd --check-config`, and confirming it exits 1 with the
  expected log line. Left as a real gap for `TASK-213` to close with a
  proper automated test, same disclosure discipline as `TASK-207`'s own
  wire-level-validation gap.

Moving to `review`.

SEC.07 [2026-08-26]: Reviewed against this task's own security note.

- Confirmed `replica_lag`'s email template says "replica X is falling
  behind" / "a paired replica is falling behind," never anything implying
  clients are on fallback — read the actual `snprintf` string, not just
  the task's paraphrase.
- Confirmed the admin recipient is always the fixed `admin_cfg.admin_email`
  string set once from `vapourwaultd.conf` at startup — traced every call
  site (`vw_gc.c`, `vw_acme.c`, `vw_auth.c`, `vw_oplog`-derived
  `vw_server_main.c`) and none of them pass anything wire- or
  client-derived into the recipient. This can't become a way for an
  authenticated (or unauthenticated) client to redirect an operational
  alert anywhere.
- Manually re-ran both `--check-config` scenarios (misconfigured →
  exit 1 with the exact expected error; correctly configured → exit 0)
  myself rather than trusting the notes' claim — matches.
- `lockout_spike`'s trigger placement was worth extra scrutiny given it's
  security-sensitive by nature (brute-force-adjacent): confirmed by
  reading `vw_auth_begin_login` end-to-end that `lockout_record_failure`
  truly cannot be reached while an account is already locked (the early
  `VW_ERR_AUTH_LOCKED` return happens first, unconditionally, before any
  password check) — the "genuinely new lockout every time" claim holds.
- No new secret-bearing content in any admin email body — none of the
  five categories have any reason to touch a password/token/OTP in the
  first place (they're all operational-health signals), and none of the
  bodies do.
- The one disclosed gap (fail-loud config check has no automated test
  yet) is exactly that — disclosed, not hidden — and was independently
  re-verified above rather than taken on faith.
- No blocking findings. Approved.

CQR.08 [2026-08-26]: Reviewed for code quality and consistency.

- The `..._set_notify` attach-after-create pattern
  (`vw_acme_ctx_set_notify`, `vw_auth_ctx_set_notify`) correctly mirrors
  this codebase's existing convention (`vw_server_ctx_set_recovery` etc.)
  instead of inventing a new wiring style, and both get real (non-stub)
  Windows-side handling where relevant — `vw_acme_ctx_set_notify`'s
  Windows stub correctly no-ops rather than being accidentally omitted
  from the `#ifdef _WIN32` branch (checked both branches compile, not
  just POSIX).
- `vw_gc_create`'s two new parameters were the one unavoidable
  constructor signature change in this task — confirmed both real call
  sites were updated (`vw_server_main.c`, `tests/unit/test_vw_gc.c`) by
  grepping for the symbol project-wide, not just fixing the obvious one
  and assuming.
- `vw_fs_disk_usage_pct`'s POSIX branch correctly uses `f_bavail` over
  `f_bfree` with a one-line rationale (matches `df`, reflects what this
  process can actually still write) — a real, considered choice, not a
  copy-pasted statvfs snippet.
- The honest, checked-in note that `TASK-205`'s own design left
  `acme_renewal_failure` uncategorized between the threshold-style and
  one-shot lists — and that this task resolved the ambiguity one way
  with reasoning given — is exactly the kind of gap other tasks in this
  project have surfaced and fixed rather than silently picked a side on.
- `seg_scan`'s new `out_truncated` param and `vw_oplog_did_recover_from_crash`
  are minimal, additive, and correctly scoped (static internal function
  signature change, only one call site; new public accessor with no
  other API disturbed).
- Test coverage extension (36 new assertions) mirrors the existing
  `quota_warning` state-machine test's shape for the two threshold-style
  admin categories, rather than inventing a different test pattern for
  no reason.
- No blocking findings. Approved.

Moving to `done`.
