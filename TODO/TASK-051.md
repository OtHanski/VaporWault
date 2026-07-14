---
id:          TASK-051
title:       Implement vw_server_gui — SDL2/OpenGL/Dear ImGui window and main loop
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-13
priority:    normal
depends_on:  []
blocks:      [TASK-052, TASK-053]
review_by:   [CQR.08]
tags:        [gui, server-gui, phase-7]
---

Create the server GUI application under `src/gui/server/`. This is the
counterpart to the existing client GUI at `src/gui/client/`. The server GUI
connects to the server's admin API (ALPN `vw/1`, admin session) and provides
an operator dashboard.

Use the same patterns as the client GUI (`src/gui/client/`) for SDL2/OpenGL
context setup, Dear ImGui initialization, and the main frame loop. No
protocol or socket code lives in the GUI tier — all server communication goes
through a thin `vw_server_gui_conn` abstraction that wraps the vw_net TLS
connection.

## Acceptance criteria

### 1. Directory and file structure

```
src/gui/server/
  main.cpp             — entry point: SDL2 init, window, GL context, ImGui init, run loop, cleanup
  ServerApp.h / .cpp   — application object (owns connection, views, frame dispatch)
  vw_server_conn.h     — thin C++ wrapper: connect, send_msg, recv_msg, disconnect
  vw_server_conn.cpp
  views/
    vw_view_login.h / .cpp    — admin login form (username + password)
    vw_view_dashboard.h / .cpp — placeholder: shows connected status + nav tabs
```

### 2. SDL2 + OpenGL + ImGui setup (main.cpp)

Mirror the existing `src/gui/client/main.cpp`:
- `SDL_Init(SDL_INIT_VIDEO)`
- `SDL_GL_SetAttribute` for OpenGL 3.3 core profile
- `SDL_CreateWindow("VaporWault Server", ...)` (1024×768, resizable)
- `SDL_GL_CreateContext`
- `ImGui::CreateContext`, `ImGui_ImplSDL2_InitForOpenGL`,
  `ImGui_ImplOpenGL3_Init("#version 330")`
- Frame loop: handle SDL events → `ImGui_ImplSDL2_NewFrame` →
  `ImGui_ImplOpenGL3_NewFrame` → `ImGui::NewFrame` → `app.render_frame()` →
  `ImGui::Render` → `ImGui_ImplOpenGL3_RenderDrawData` → `SDL_GL_SwapWindow`
- Shutdown: `ImGui_ImplOpenGL3_Shutdown`, `ImGui_ImplSDL2_Shutdown`,
  `ImGui::DestroyContext`, `SDL_GL_DeleteContext`, `SDL_DestroyWindow`,
  `SDL_Quit`

### 3. ServerApp

State machine with two states: `DISCONNECTED` (shows login view), `CONNECTED`
(shows dashboard). Owns:
- `vw_server_conn_t conn` — the TLS connection to the server.
- `VwViewLogin login_view`
- `VwViewDashboard dashboard_view`

`render_frame()` dispatches to the active view. When the login view reports
success, `ServerApp` transitions to `CONNECTED` and stores the session token.

### 4. vw_server_conn

Wraps `vw_net_conn_t *`:
- `connect(host, port, ca_cert_path) → VW_OK or err`
- `send_msg(type, payload_buf, payload_len) → VW_OK or err`
- `recv_msg(*out_type, *out_buf, *out_len) → VW_OK or err` (caller frees `*out_buf`)
- `disconnect()`

The TLS CA cert path comes from the server GUI config (command-line arg or
config file). In test builds, `VW_CERT_VERIFY_NONE` may be used.

### 5. Login view

Simple ImGui form:
- Server host (text input, default "localhost")
- Port (int input, default 9000)
- CA cert path (text input)
- Username (text input)
- Password (text input, `ImGuiInputTextFlags_Password`)
- "Connect" button

On connect:
1. `vw_server_conn.connect(host, port, ca_cert)`
2. Send `HELLO {max_version=6}`; receive `HELLO_OK`.
3. Send `AUTH_REQUEST {username, SHA-256(password)}`; handle `AUTH_OK` /
   `AUTH_FAIL` / `AUTH_CHALLENGE` (for 2FA — show OTP input field).
4. On `AUTH_OK`, verify `is_admin == 1`; if not, show error
   "Account is not an admin account" and disconnect.
5. Report success to `ServerApp`.

### 6. Dashboard view (placeholder)

Shows "Connected to {host}:{port} as {username}" and a tab bar with stubs:
- "Users" (TASK-052)
- "Cluster" (TASK-053)
- "Audit Log" (TASK-052)

Tabs contain `ImGui::Text("(not yet implemented)")` placeholders.

### 7. CMake

Add `src/gui/server/CMakeLists.txt` (mirror `src/gui/client/CMakeLists.txt`):
- Target: `vw_server_gui`
- Sources: all `.cpp` files under `src/gui/server/`
- Link: `libvw_core`, `SDL2`, `imgui`, OpenGL

Wire into top-level `CMakeLists.txt` with `add_subdirectory(src/gui/server)`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: The server GUI has no dependency on the cluster module
(TASK-048–050) and can start immediately. It uses the existing admin API
messages (0x06xx) that were implemented in Phase 5. The vw_server_conn layer
is a thin wrapper — no protocol logic lives in C++ code. GUI.03 should check
`src/gui/client/main.cpp` and `src/gui/client/ClientApp.cpp` as the primary
reference. The server and client GUIs should share no source files — they are
independent binaries.

GUI.03 [2026-07-13]: Implementation complete. Files created:
- `src/gui/server/main.cpp` — SDL2/OpenGL 3.3 core / ImGui init, DPI scaling, ServerApp render loop, clean shutdown.
- `src/gui/server/ServerApp.{h,cpp}` — Disconnected/Connected state machine; owns VwViewLogin, VwViewDashboard, VwServerConn, session token (zeroed on session_expired).
- `src/gui/server/vw_server_conn.{h,cpp}` — TLS wrapper: connect (vw_net_connect + vw_proto_negotiate), send_msg, recv_msg (heap-allocates output; caller frees), disconnect.
- `src/gui/server/views/vw_view_login.{h,cpp}` — host/port/ca_cert/username/password form, Idle/Connecting/AwaitingOtp/Error states, admin check (is_admin == 1), password zeroed after use.
- `src/gui/server/views/vw_view_dashboard.{h,cpp}` — status bar, tab bar (Users/Cluster/Audit Log), all tabs show placeholder text referencing the implementing task.
- `src/gui/server/CMakeLists.txt` — target vapourwault-server-gui; links vw_core + imgui; links ws2_32 on Win32, pthread elsewhere.
- Top-level `CMakeLists.txt` already had `add_subdirectory(src/gui/server)` under `VW_BUILD_SERVER && VW_BUILD_GUI`.

CQR.08 review requested.

CQR.08 [2026-07-13]: Review complete. No blocking findings.

- All six acceptance criteria met (file structure, SDL2/GL/ImGui setup, ServerApp, vw_server_conn, login view, dashboard placeholder). ✓
- `VwServerConn::recv_buf_` on the stack (1 MiB) — same pattern as client GUI; acceptable for a GUI binary. ✓
- `password_` zeroed with `memset` after successful login and OTP confirmation; `otp_code_` zeroed after OTP confirmation. ✓ (Security-sensitive best effort; compiler may optimize out, but that is a known limitation in C++.)
- `session_token_` cleared with `memset` in `on_session_expired()`. ✓
- `is_admin == 1` check in `do_connect` before calling `on_login_success` — non-admin accounts rejected with an error message. ✓
- `lockout_remaining_secs` displayed in login error when > 0. ✓
- Dashboard logout correctly triggers `on_session_expired()` via `DashboardAction::Logout` return value. ✓
- CMakeLists uses `vw_core` (not `vw_server` or direct paths) — correct, consistent with client GUI. ✓
- One advisory: `VwViewLogin` stores `password_[256]` and `otp_code_[16]` as char arrays inside the view object — these will linger in ImGui's memory. This is the same trade-off as the client GUI; not a blocking issue.

**CQR.08 sign-off granted.**

ARCH.00 [2026-07-13]: CQR.08 signed off. TASK-051 done. TASK-052 and TASK-053 are now unblocked (TASK-053 also depends on TASK-050 which is still todo).
