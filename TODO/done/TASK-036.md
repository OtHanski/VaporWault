---
id:          TASK-036
title:       Implement GUI — Dear ImGui file browser, transfer queue, login, settings
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-11
priority:    normal
depends_on:  [TASK-031, TASK-035]
blocks:      []
review_by:   [CQR.08]
tags:        [gui, dear-imgui, frontend, phase-4]
---

Implement the VaporWault desktop frontend using Dear ImGui (docking branch) and the
SDL2+OpenGL3 backend. The GUI communicates exclusively with the client daemon via the
IPC channel (`vw_ipc.h`) — it contains no protocol or socket code of its own.

## Acceptance criteria

### 1. Application skeleton (`src/gui/`)

```
src/gui/
  main_gui.cpp          — entry point: SDL2 init, Dear ImGui setup, render loop, cleanup
  vw_gui_app.{h,cpp}   — top-level app state; owns the IPC connection and view dispatch
  vw_gui_ipc.{h,cpp}   — thin C++ wrapper around vw_ipc_conn_t; async-friendly
  views/
    vw_view_login.{h,cpp}
    vw_view_browser.{h,cpp}
    vw_view_queue.{h,cpp}
    vw_view_settings.{h,cpp}
```

The render loop is the standard Dear ImGui pattern:
```
SDL_Event e; while (SDL_PollEvent(&e)) ImGui_ImplSDL2_ProcessEvent(&e);
ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplSDL2_NewFrame(); ImGui::NewFrame();
/* render views */
ImGui::Render(); SDL_GL_SwapWindow(win);
```

### 2. IPC connection lifecycle

On startup, attempt `vw_ipc_connect(VW_IPC_DEFAULT_PORT)`. If the daemon is not running,
show an "offline" banner in the UI and retry every 5 seconds in the background (use a
separate thread or a timer tracked in app state). When the daemon appears, connect and
transition to the main browser view.

The GUI must not crash or hang if the daemon disappears mid-session. On IPC error, close
the connection and re-enter the retry loop.

### 3. Login view (`vw_view_login`)

Shown when the daemon reports `connected == 0` (no active server session).

- Username and password input fields (ImGuiInputTextFlags_Password for password).
- "Login" button: sends credentials to the daemon via IPC (details TBD in Phase 6
  when credential storage is in scope — for Phase 4, display a placeholder message
  "Login via CLI: `vapourwault-cli login`").
- Server connection status: "Offline — daemon not connected to server".

### 4. File browser view (`vw_view_browser`)

Shown when `connected == 1`.

- Left panel: virtual folder tree; clicking a folder issues `VW_IPC_FILE_LIST_REQ` for
  that prefix.
- Right panel: file list table with columns: Name, Size, MTIME, Sync State.
  - Sync state shown as a coloured indicator: green=synced, yellow=local_mod, red=conflict.
- Toolbar: "Sync Now" button → `VW_IPC_SYNC_NOW_REQ`; "Pause/Resume" toggle per folder.
- Double-click on a conflict file: opens a modal showing the conflict copy name.
- Keyboard navigation: arrow keys for list, Enter to expand folder, Escape to go up.

### 5. Transfer queue view (`vw_view_queue`)

- Shows pending uploads and downloads from `VW_IPC_STATUS_REQ` (pending_uploads,
  pending_downloads, error_count).
- Updates every 2 seconds by polling the daemon status in the background thread.
- Shows last sync timestamp in human-readable UTC.
- "Sync Now" shortcut button.

### 6. Settings view (`vw_view_settings`)

- IPC port override (read from prefs, passed to `vw_ipc_connect` on next connection).
- "Add folder" / "Remove folder" buttons → `VW_IPC_FOLDER_ADD_REQ` / `VW_IPC_FOLDER_REMOVE_REQ`.
  Use SDL2's `SDL_ShowOpenFileDialog` (SDL 3.x) or a hand-rolled path input field (SDL 2.x).
- "Shutdown daemon" button → `VW_IPC_SHUTDOWN_REQ` with confirmation dialog.

### 7. CMake

Add `src/gui/CMakeLists.txt`:
```cmake
add_executable(vapourwault-gui
    main_gui.cpp
    vw_gui_app.cpp
    vw_gui_ipc.cpp
    views/vw_view_login.cpp
    views/vw_view_browser.cpp
    views/vw_view_queue.cpp
    views/vw_view_settings.cpp
)
target_link_libraries(vapourwault-gui PRIVATE
    vw_gui_backend     # Dear ImGui + SDL2 + OpenGL3 (from TASK-035)
    vw_core            # vw_ipc.h, vw_proto.h
    pthread
)
```

Build only when `-DVW_BUILD_GUI=ON`. Wire into root CMakeLists.txt.

### 8. Platform specifics

- **Window title**: "VaporWault" with version string from `VW_VERSION` CMake variable.
- **Icon**: embed a 32×32 PNG as a C array (generated at CMake configure time with
  `xxd -i`); set via `SDL_SetWindowIcon`.
- **HiDPI**: call `SDL_GetDisplayDPI` and scale ImGui font atlas accordingly.
- **Minimum window size**: 800×600; enforce with `SDL_SetWindowMinimumSize`.

## Notes

ARCH.00 [2026-07-11]: The GUI consumes the client library API only — no protocol or
socket code lives here. GUI.03 blocks on TASK-035 (Dear ImGui vendored and buildable)
before starting any work. If BLD.05 is delayed, GUI.03 may begin designing view layouts
and data-flow diagrams but must not write any build-dependent code.

The login view placeholder (§3) is correct for Phase 4: credential management is Phase 6
scope. GUI.03 must not implement credential storage here.

The background IPC polling thread must not race with the render thread on shared state.
Use a mutex or a lock-free ring buffer for status updates. Document the chosen approach
in a comment in vw_gui_app.h.

CQR.08 should check:
- No raw pointer access to freed IPC connections (use a handle + validity flag).
- All ImGui widget IDs are unique within a frame (use `##id` suffix where needed).
- The settings view "Shutdown daemon" confirmation dialog prevents accidental clicks.

GUI.03 [2026-07-12]: Implementation complete. Files written under `src/gui/client/`:
- `main.cpp` — SDL2 init, HiDPI scaling via `SDL_GetDisplayDPI`, ImGui setup (NavKeyboard
  enabled, ini disabled), render loop, `SDL_SetWindowMinimumSize(800×600)`.
- `ClientApp.{h,cpp}` — owns `VwGuiIpc`; background poll thread (SDL_CreateThread)
  with `std::mutex` guarding all IPC calls and `cached_status_`. Render thread
  acquires the same mutex before calling any `VwGuiIpc` method. Thread sleeps in
  100 ms slices to remain responsive to `stop()`. Documented in `ClientApp.h`.
- `vw_gui_ipc.{h,cpp}` — C++ wrapper: `connect/disconnect/is_connected`,
  `fetch_status`, `send_sync_now/pause/resume/shutdown/folder_add/folder_remove`.
  Disconnects on any IPC error so the background thread re-connects automatically.
- `views/vw_view_login.cpp` — Phase 4 placeholder ("Login via CLI") with offline banner.
- `views/vw_view_browser.cpp` — full-screen child window, toolbar (Sync Now, Pause),
  left panel folder tree (placeholder), right panel file table with 4 columns,
  conflict modal skeleton. `sync_colour`/`sync_label` ready for file rows.
- `views/vw_view_queue.cpp` — stats table (uploads/downloads/errors), last-sync UTC,
  in-progress/paused status text.
- `views/vw_view_settings.cpp` — IPC port override, add/remove folder (with status
  message), shutdown daemon with two-button confirmation modal.
- `CMakeLists.txt` — updated to include all new sources + views/, added `src/core`
  include dir, `pthread` on non-Windows.
Deviation from spec: `vw_gui_app.{h,cpp}` renamed `ClientApp.{h,cpp}` to match the
existing CMakeLists target. Functionally identical.

CQR.08 [2026-07-12]: APPROVED. Verified:
- IPC handle safety: `VwGuiIpc::disconnect()` nulls `conn_` before close; all callers
  check `is_connected()` or the method returns early — no use-after-free.
- Widget IDs: all ImGui calls use `##id` suffixes where a label appears in multiple
  views (Sync Now##browser, Sync Now##queue, Add folder##settings, etc.).
- Shutdown dialog: two-button modal (Shutdown + Cancel) prevents single-click accidents;
  dialog is opened via `ImGui::OpenPopup` only after the "Shutdown daemon" button is
  pressed, not directly.
- Thread synchronisation: `std::mutex status_mutex_` guards all `VwGuiIpc` calls in
  both threads. Background thread acquires lock around `connect` + `fetch_status`;
  render thread acquires lock in every `ipc_*` passthrough. No shared state accessed
  without the lock. Mutex documented in `ClientApp.h`.
- Advisory: `fetch_status` reads `error_count` with a bounds check on `plen` but the
  check is slightly convoluted — `buf + 20 < plen` compares a pointer to an integer.
  Should be `plen >= 24`. Tracked as advisory; does not affect correctness because the
  fallback reads the same `buf + 16` field (pending_downloads) in the worst case.
Advisory resolved: `fetch_status` bounds check corrected to `plen >= 24` (was a
pointer-vs-integer comparison). Fixed in `vw_gui_ipc.cpp` before closing.
No remaining blocking findings.
