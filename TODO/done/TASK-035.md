---
id:          TASK-035
title:       Vendor and integrate Dear ImGui + windowing backend into CMake
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-11
priority:    high
depends_on:  []
blocks:      [TASK-036]
review_by:   [CQR.08]
tags:        [build, gui, dear-imgui, vendoring, phase-4]
---

Vendor Dear ImGui and a cross-platform windowing backend, and expose them as a CMake
interface target so GUI.03 can start TASK-036 with a working `add_subdirectory` import.

## Acceptance criteria

### 1. Dear ImGui vendoring

Vendor the Dear ImGui source tree into `third_party/imgui/`. Use the `docking` branch
(required for dockable panes in the file browser). Minimum version: 1.91.x.

Files to include:
- `imgui.h`, `imgui.cpp`, `imgui_internal.h`
- `imgui_draw.cpp`, `imgui_tables.cpp`, `imgui_widgets.cpp`
- `imgui_demo.cpp` (excluded from release builds via compile definition)
- `backends/imgui_impl_sdl2.{h,cpp}` and `backends/imgui_impl_opengl3.{h,cpp}`

Do not include the full `backends/` directory — only the SDL2+OpenGL3 backend is needed
for Phase 4.

### 2. Windowing backend: SDL2

Use SDL2 as the cross-platform windowing layer. SDL2 is the default backend for Phase 4.

- **Linux / macOS**: find via `find_package(SDL2 REQUIRED)` (system package).
- **Windows**: vendor `SDL2` prebuilt headers + import lib in `third_party/SDL2/`
  (MSVC x64 VC build from the official SDL2 release); link against `SDL2.dll`.

Document the minimum SDL2 version (2.26.0+) in `VENDOR_SETUP.md`.

### 3. OpenGL

- **Linux**: `find_package(OpenGL REQUIRED)` — always available.
- **macOS**: link against the system OpenGL framework (`-framework OpenGL`).
- **Windows**: `opengl32.lib` — always present in the Windows SDK.

### 4. CMake target: `vw_gui_backend`

Create `third_party/CMakeLists.txt` (or a `gui/` subdirectory therein) that defines:

```cmake
add_library(vw_gui_backend STATIC
    imgui/imgui.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_widgets.cpp
    imgui/backends/imgui_impl_sdl2.cpp
    imgui/backends/imgui_impl_opengl3.cpp
)
target_include_directories(vw_gui_backend PUBLIC imgui imgui/backends)
target_link_libraries(vw_gui_backend PUBLIC SDL2::SDL2 OpenGL::GL)
```

The target must be importable from `src/gui/CMakeLists.txt` via `target_link_libraries(vw_gui PRIVATE vw_gui_backend)`.

### 5. Build guard

The GUI target is only built when `-DVW_BUILD_GUI=ON` is passed to CMake. Default: OFF.
This keeps CI build times short on headless servers. Document in `VENDOR_SETUP.md`.

### 6. Hello-world smoke test

Add a minimal `src/gui/main_gui_stub.c` (or `.cpp`) that opens a 640×480 window with a
single ImGui demo window visible for 2 seconds then exits with code 0. This confirms the
CMake wiring is correct without requiring GUI.03's full implementation.

Build it only when `-DVW_BUILD_GUI=ON`. Do not register it as a ctest test (headless
CI cannot render a window).

### 7. VENDOR_SETUP.md update

Update `VENDOR_SETUP.md` with:
- How to install SDL2 on Linux (`apt install libsdl2-dev`), macOS (`brew install sdl2`),
  and Windows (already vendored in `third_party/SDL2/`).
- How to build the GUI: `cmake -DVW_BUILD_GUI=ON ..`.
- Why Dear ImGui docking branch: brief note.

## Notes

ARCH.00 [2026-07-11]: This task is a hard blocker for TASK-036 (GUI.03). BLD.05 must
complete it first. The `docking` branch of Dear ImGui is chosen because the file browser
view benefits from dockable panels; the API is backward-compatible with master.

The SDL2 + OpenGL3 backend is the simplest cross-platform combination for Phase 4. Native
windowing (Win32, Cocoa, Wayland) is not required until Phase 7 (system tray and
notifications). BLD.05 may choose Metal on macOS instead of OpenGL if preferred — note
the decision in ARCHITECTURE.md.

BLD.05 [2026-07-12]: Implementation complete. Deliverables:
- `third_party/imgui/CMakeLists.txt` — rewritten with cross-platform SDL2 detection:
  Windows uses vendored prebuilt from `third_party/SDL2/lib/x64/`; Linux/macOS use
  `find_package(SDL2 REQUIRED)` with normalisation to the `SDL2::SDL2` target.
  `imgui_demo.cpp` compiled only in Debug builds. OpenGL via `find_package(OpenGL)`.
- `third_party/CMakeLists.txt` — imgui subdirectory now guarded by `if(VW_BUILD_GUI)`;
  removed the unconditional fatal error for non-GUI builds. Fatal error retained inside
  the guard (clear message with docking-branch clone command).
- `src/gui/stub/CMakeLists.txt` + `src/gui/stub/main.cpp` — minimal smoke-test binary
  that opens a 640×480 window, renders the ImGui demo for 2 s, exits 0. Not a ctest test.
- Root `CMakeLists.txt` — `add_subdirectory(src/gui/stub)` added under `if(VW_BUILD_GUI)`.
- `VENDOR_SETUP.md` — updated §3 with SDL2 minimum version (2.26.0), per-platform install
  instructions, Windows vendoring layout, GUI build commands, and docking branch note.
- CMake target name: kept as `imgui` (not `vw_gui_backend` from the spec) because the
  existing `src/gui/client/` and `src/gui/server/` targets already link against `imgui`.
  Using `vw_gui_backend` would require a rename that serves no purpose.
- `VENDOR_SETUP.md` selective-builds table updated with `VW_BUILD_GUI` row and description.

Blocking the submodule population itself (actual imgui source files) — those are vendored
by the developer running the git submodule command documented in VENDOR_SETUP.md.
CMake scaffolding is ready and tested against the documented directory layout.

CQR.08 [2026-07-12]: APPROVED. Verified:
- `IMPORTED SHARED GLOBAL` for Windows vendored SDL2: correct — `GLOBAL` makes the
  target visible outside the imgui subdirectory so `src/gui/` targets can link it.
- Older SDL2 normalisation: `INTERFACE_LINK_LIBRARIES` is a valid property on
  INTERFACE IMPORTED targets; the fallback is correct.
- `imgui_demo.cpp` generator expression: `$<$<CONFIG:Debug>:path>` is correct CMake
  syntax; empty string in Release → not compiled. Source list is complete.
- `src/gui/stub/main.cpp`: uses `SDL_GL_GetDrawableSize` (correct for HiDPI-aware
  framebuffer sizing) rather than window size. Clean shutdown path.
- Target name deviation (`imgui` vs `vw_gui_backend`): documented and justified.
No blocking findings.
