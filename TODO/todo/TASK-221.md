---
id:          TASK-221
title:       "GUI: Settings view caches folder/notification data across account switches"
status:      todo
assignee:    GUI.03
created_by:  GUI.03
created:     2026-08-27
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [gui]
---

Discovered while implementing `TASK-210` (notification-preferences panel).
`vw_view_settings.cpp`'s static, single-window-always-open state
(`s_folders`/`s_folders_loaded`, and now `s_notify_prefs`/
`s_notify_loaded`) is never invalidated when the active account changes.
`ClientApp::switch_active_account()` already invalidates the browser/
shared/vault views (`vw_view_browser_invalidate()` etc.) but has no
equivalent call for the settings view — confirmed by reading
`switch_active_account()` and grepping this file for any account-id
comparison or invalidation call; there is none.

Practical effect: switching accounts while the Settings tab is open (or
switching, then opening Settings) shows the *previous* account's sync
folders and notification preferences until some other action happens to
call `refresh_folders`/`refresh_notify_prefs` again (e.g. clicking
"Refresh"). Not a security issue (never sends a request against the
wrong account_id — `ClientApp::ipc_notify_prefs_get/set` and
`ipc_folder_*` all read `active_account_id_` fresh at call time; this is
purely a stale-display bug), but a real, user-visible correctness gap.

Pre-existing for `s_folders`/`s_folders_loaded` already, before this
task — `TASK-210` inherited the same pattern for consistency with the
surrounding code rather than fixing only the new half and leaving the
older half inconsistently behaved, and is filing this rather than
silently expanding its own scope to fix both.

## Work

- Add a `vw_view_settings_invalidate()` (matching the naming convention
  `vw_view_browser_invalidate()` etc. already use) that resets
  `s_folders_loaded`/`s_notify_loaded` to false, called from
  `ClientApp::switch_active_account()` alongside the other three.

## Acceptance criteria

- Switching the active account while the Settings tab is open (or before
  opening it) shows that account's own folders and notification
  preferences on next render, not the previously-active account's.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

GUI.03 [2026-08-27]: Filed while implementing `TASK-210` — found by
reading `switch_active_account()` and this file's own state management
in full before assuming either was correct.
