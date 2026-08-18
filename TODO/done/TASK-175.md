---
id:          TASK-175
title:       GUI: fallback fields + read-only-fallback indicator
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-14
priority:    normal
depends_on:  [TASK-173]
blocks:      [TASK-178]
review_by:   [CQR.08]
tags:        [gui]
---

Surfaces `TASK-173`'s new per-account fallback config in the GUI.

## Work

- "Add account" dialog (`vw_view_login.cpp`, extended in `TASK-163`):
  optional fallback host/port/CA-cert fields, same
  all-three-or-none validation as `TASK-174`'s CLI.
- A clear, distinct visual state for "connected to fallback (read-only)"
  vs. plain "offline" (today's `render_offline_banner()` only knows
  about the daemon connection, not per-account fallback state) — the
  account switcher (`TASK-163`) is the natural place, since it already
  shows per-account state.
- Write-attempting UI actions (upload button, mkdir, delete, share
  grant, vault create, etc.) should give the user a clear reason when
  disabled/queued while on fallback, not a generic error — the daemon
  already queues rather than rejecting outright (`TASK-173`), so the GUI
  should reflect "queued, will sync when the primary is back," not
  "failed."

## Acceptance criteria

- Manual verification (no browser/GUI automation tooling in this
  project, per this session's own established precedent — state this
  limitation explicitly rather than skipping it): a human clicks through
  adding an account with a fallback configured, triggers a real failover,
  and confirms the indicator and queued-write messaging both make sense.
- `tsc`-equivalent (MSVC build) clean; existing GUI smoke-test discipline
  (launch against a real daemon, confirm no crash) followed.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**GUI.03, 2026-08-14 — implementation complete.**

- "Add account" dialog (`vw_view_login.cpp`): a checkbox reveals
  fallback host/port/CA-cert fields, collapsed by default since most
  accounts won't set one; unchecking clears the fields (never resubmits
  stale values). Validated all-or-none (host+port together; ca-cert
  independently optional, same interpretation TASK-174's CLI used) before
  submitting — a partial set shows an inline error rather than being sent.
  Threaded through `VwGuiIpc::account_add`/`ClientApp::ipc_account_add`
  (both signatures extended, one caller each, no other call sites to
  update).
- Fallback state indicator (`ClientApp.cpp`): two places, matching the
  task's own "clear, distinct visual state" requirement —
  (1) the account switcher's per-item labels now say `[fallback
  (read-only)]` instead of lumping it in with `[offline]`; (2) an
  always-visible amber warning line in the main menu bar itself when the
  *active* account is on its fallback, so the user doesn't have to open
  the switcher dropdown just to notice.
- **Found and fixed the same `ACCOUNT_LIST_RESP`/`STATUS_RESP` decode gaps
  TASK-173/174 had already found in the CLI, this time in
  `vw_gui_ipc.cpp`**: the trailing `conn_mode` byte was being consumed
  (to avoid the desync bug) but discarded rather than stored — now stored
  on `VwGuiAccountEntry::conn_mode`; `STATUS_RESP`'s trailing
  `any_on_fallback` byte was not yet read at all — added to `VwIpcStatus`.
- Write-attempting UI actions (share grant, public-link create, vault
  folder creation, vault upload — the four synchronous write-shaped IPC
  calls this GUI has buttons for) now show a specific "blocked — read-only
  fallback, will work again once the primary is back" message via a new
  shared `vw_gui_format_action_error()` helper, instead of a bare error
  code.
- **Correction to this task's own premise, worth flagging explicitly**:
  the Work section says "the daemon already queues rather than rejecting
  outright, so the GUI should reflect queued... not failed." That's true
  for the *automatic* sync engine's file actions (a file dropped into a
  watched folder while on fallback — `TASK-173`'s offline-queue path,
  which has no separate manual UI trigger in this GUI to begin with, only
  the existing Queue view's pending-count display, left unchanged), but
  NOT true for the four synchronous, button-triggered actions above —
  `TASK-173` explicitly rejects those outright (`VW_ERR_READ_ONLY_FALLBACK`)
  since they have no offline-queue representation. The messaging above
  says "blocked," not "queued," because that's what actually happens;
  saying "queued" for these would be inaccurate.
- **Acceptance criterion honestly not met, not silently claimed**: "a
  human clicks through adding an account with a fallback configured,
  triggers a real failover, and confirms the indicator and queued-write
  messaging both make sense" requires an actual human at a display — this
  session has no GUI automation/screenshot tooling (confirmed absent,
  matching this project's own established precedent of stating this
  limitation rather than skipping it or fabricating a claim). What WAS
  verified: `vapourwault-gui.exe` built clean on MSVC and stays running
  (no crash) both standalone and against a real running daemon for
  several seconds — a smoke test, not a functional click-through. A human
  should still do the real walkthrough before considering this fully
  signed off.
- Verified: MSVC build of `vapourwault-gui` clean; full `ctest` (18/18,
  unaffected — no unit tests exist for GUI code, C++ ImGui has none in
  this project) still green.
