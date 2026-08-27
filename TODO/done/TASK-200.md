---
id:          TASK-200
title:       "GUI: search bar in the file browser"
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-199]
blocks:      []
review_by:   [CQR.08]
tags:        [gui]
---

**Corrections (2026-08-26)**, found while starting this task:

1. **No async/threaded IPC pattern exists anywhere in this GUI to
   follow.** Checked: the only thread in the whole client
   (`ClientApp.cpp`'s `poll_thread_`, `SDL_CreateThread`) does status/
   account polling only, every 2s. Every on-demand data fetch this view
   already does (`refresh()`'s `ipc_file_list`, `open_share_dialog`'s
   `ipc_share_list`, `open_history_dialog`'s `ipc_version_list`, etc.)
   is a plain synchronous call on the render thread, triggered by a
   button/dialog-open. "Doesn't block the UI thread" is satisfied the
   same way those already are: debouncing so the (brief, localhost
   one-shot) IPC call fires once after typing pauses, not once per
   keystroke — not a new threading mechanism this codebase has never
   used.
2. **No "existing accessibility bar" exists** — grepped the whole GUI
   tree for any accessibility-specific component; there is none. What
   actually exists is `ImGuiConfigFlags_NavEnableKeyboard`
   (`main.cpp`), ImGui's own built-in keyboard nav applied app-wide.
   "Keyboard-navigable" below means: build the search bar and its
   results with the same standard `InputText`/`Selectable`-in-a-table
   widgets the rest of this view already uses, which already get free
   Tab/arrow-key/Enter nav from that flag — not a separate bar to wire
   into.

## Work

- `vw_view_browser.cpp`/`.h`: a search bar above the file list;
  debounced query-as-you-type (fire `ClientApp::ipc_search` once
  ImGui's `InputText` has reported no edit for a short interval, not on
  every keystroke), results shown in place of the normal directory
  listing while a query is active. "Jump to a result's actual location"
  is resolved only via data this view already has: if the result's
  `file_id` matches an entry already known from the last `ipc_file_list`
  fetch (i.e. already locally synced), clicking it navigates the normal
  browser to that entry's parent directory and clears the search —
  §7.12 deliberately returns no virtual path, so there's no path to
  jump to for a match that isn't already locally known. Checked before
  assuming otherwise: `ClientApp`'s `ipc_share_grant`/`ipc_version_list`
  (and the daemon IPC messages under them) are virtual-path-addressed,
  not file_id-addressed, so a not-locally-known result can't reuse the
  normal browser rows' Share/Version History actions either — those
  results are shown read-only (name/type/shared/size/modified) rather
  than promising actions this layer has no plumbing for yet.
- Clear empty-results and loading states.

## Acceptance criteria

- Typing a query doesn't fire one IPC round-trip per keystroke — the
  actual query call is debounced.
- The search bar and its results use standard ImGui nav-compatible
  widgets (InputText, Selectable), consistent with the rest of this
  view.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

GUI.03 [2026-08-26]: Implemented per the corrected Work section above.

- `vw_gui_ipc.h`/`.cpp`: new `VwGuiSearchEntry` + `VwGuiIpc::search()`,
  modeled directly on `share_list`'s error_code-bearing response
  convention (this is the first `VW_IPC_*_RESP` this file decodes that
  has one, alongside `share_list`/`link_list`/`version_list`).
- `ClientApp.h`/`.cpp`: thin `ipc_search()` wrapper, same
  lock-`status_mutex_`-then-delegate pattern every other `ipc_*` method
  here already uses.
- `vw_view_browser.cpp`: search bar + debounce state, `perform_search()`,
  `render_search_results()`, and a `find_local_entry_by_file_id()` helper
  for "jump to location." Query non-empty → search-results view replaces
  the normal directory table entirely for that frame (dialogs still
  render either way, since Share/Version History can be opened from
  either mode via the normal browser once you've jumped back to it).
  `vw_view_browser_invalidate()` (account switch) now also clears search
  state, so switching accounts can't leak one account's result names
  into another's view.
- Loading/empty/truncated states: `s_search_loading` (shown while the
  one-shot IPC call is in flight — brief, but a real distinct state, not
  just a placeholder), `(no matches)` for a completed empty result, and
  the `truncated` flag surfaced as an inline warning suggesting a
  narrower query (mirrors `TASK-199`'s CLI wording).
- Built clean on both toolchains (WSL/GCC — first had to configure this
  build directory with `-DVW_BUILD_GUI=ON`, which was off there;
  confirmed SDL2 is actually available in that environment so this is a
  real cross-platform build check, not skipped — and MSVC), zero
  warnings after fixing one (`ImGui::PushID` on a raw `int64_t` file_id
  narrows to `int`; switched to the string-keyed `PushID` overload,
  matching how the rest of this file already keys rows that aren't
  naturally an `int`, e.g. `virtual_path.c_str()`).

**Testing / verification limits, stated explicitly per this project's
own UI-testing guidance rather than silently skipped**: this GUI has no
automated test target at all (checked — `ctest -N` has zero GUI-related
entries; Dear ImGui's immediate-mode rendering isn't something this
codebase has ever unit-tested). This session has no display server
available (headless; `Xvfb` isn't installed, and installing system
packages to fabricate one was judged out of proportion to this task)
— **I could not visually run and click through this feature.**
Verification actually performed: full two-toolchain clean compile (zero
warnings after the one fix above) and careful code review against the
existing view's established patterns (state management, dialog
lifecycle, table/Selectable conventions). Full `ctest` suite (19/19,
WSL) confirmed no regression in anything the GUI links against. A human
with a display should click through this before considering it fully
verified — the corrections at the top of this file already narrowed
scope to what's honestly buildable, but a first real run is still owed.

Moving to `review`.

CQR.08 [2026-08-26]: Reviewed for code quality and consistency.

- Deferred-jump pattern in `render_search_results` (capture
  `jump_requested`/`jump_target`, apply after `EndTable()`) correctly
  avoids mutating `s_search_results` while a range-for over it is still
  live — the more direct "clear inside the loop then `break`" approach
  would have technically worked here too (the `break` precedes any
  further iterator use) but is fragile against future edits; the chosen
  form is the more robust one and costs nothing.
- `jump_target` path format (`vp.substr(0, pos)`, `"/"` when
  `pos == 0`) matches `navigate_up()`/double-click-navigate's own
  existing path convention exactly — verified by reading both, not
  assumed.
- `vw_view_browser_invalidate()` now clearing search state on account
  switch is the right call — a stale query and its results are also
  file-identity-scoped (`file_id` is meaningless across accounts, and
  `find_local_entry_by_file_id` would silently match the wrong account's
  entry otherwise).
- The session's own disclosed testing gap (no display available for a
  real click-through) is accurately and specifically described, not
  glossed over — advisory, not blocking, since two-toolchain compile
  plus code-pattern review is genuinely the ceiling reachable here, and
  the notes correctly flag that a human still owes this a first real run.
- No blocking findings. Approved, with the disclosed manual-verification
  gap carried forward rather than silently closed.
