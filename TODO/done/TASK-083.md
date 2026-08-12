---
id:          TASK-083
title:       Fix release.yml build failure — Dear ImGui has no CMakeLists.txt, SDL2 never wired into CMake
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-21
priority:    critical
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [ci, build, bug]
---

The first real `v0.1.0` tag push triggered `release.yml` and both `build-linux` and
`build-windows` failed at the `Configure` step (GitHub Actions run `29830831717`):

```
CMake Error at third_party/CMakeLists.txt:59 (add_subdirectory):
  The source directory
    third_party/imgui
  does not contain a CMakeLists.txt file.
```

Root cause: Dear ImGui's upstream repo (confirmed via the GitHub API against the
exact pinned commit `81c008f90d488d18370dbe6741115e126d67f539`) does not ship a
`CMakeLists.txt` at all — it never has. Upstream imgui is designed to be compiled
directly into the consuming project's own build, not `add_subdirectory`'d as a
self-contained CMake subproject. `third_party/CMakeLists.txt:57-67`'s
`add_subdirectory(imgui)` was wrong from the start.

This went undetected until now because:
- `ci.yml` always builds with `VW_BUILD_GUI=OFF` (QA.06 flagged this exact gap
  during `TASK-081`'s review, tracked as a `TASK-082` follow-up).
- The local dev machine's `third_party/imgui` git submodule was never actually
  initialized either (`git submodule status` showed it uninitialized, empty
  directory) — so nobody had locally exercised a `VW_BUILD_GUI=ON` configure since
  this line was written.

A second, related gap discovered during the fix: SDL2 was never actually wired
into CMake anywhere in the tree (no `find_package`/`pkg_check_modules`/
`target_link_libraries` for it in `third_party/CMakeLists.txt` or any
`src/gui/*/CMakeLists.txt`) — `VENDOR_SETUP.md`'s claim that "CMake picks it up
automatically" once the files are dropped in `third_party/SDL2/` was never true;
it would have failed at the same `Configure` step immediately after the imgui fix
if left unaddressed.

## Acceptance criteria

- `third_party/CMakeLists.txt` builds Dear ImGui as an in-tree `STATIC` library
  target (core sources + the SDL2/OpenGL3 backend files actually used by
  `src/gui/*`), the same pattern already used for Argon2 in the same file —
  no `add_subdirectory(imgui)`.
- SDL2 is actually found and linked: Linux via `pkg-config` (matches what
  `apt install libsdl2-dev` ships), Windows via the vendored VC devel package's
  own CMake config (confirmed present: `third_party/SDL2/cmake/sdl2-config.cmake`,
  exposes `SDL2::SDL2` / `SDL2::SDL2main` imported targets).
- OpenGL is found via CMake's built-in `FindOpenGL` on both platforms.
- Validated locally before pushing: WSL (Ubuntu 24.04, matching the
  `ubuntu-latest` CI runner) with `cmake`, `ninja-build`, `pkg-config`,
  `libsdl2-dev`, `libgl1-mesa-dev` installed, submodules actually initialized,
  full `VW_BUILD_GUI=ON` configure + build succeeds.
- `release.yml`'s `v0.1.0` tag re-run succeeds end to end (all three jobs green,
  release published).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-21]: Created after the user reported the `v0.1.0` release run
failed. Root-caused via `gh run view --log-failed` / `gh api` against the pinned
imgui commit. Assigned to BLD.05 (CMake/vendoring integration is explicitly
BLD.05's domain per `CLAUDE.md`: "Dear ImGui vendoring and integration into the
build"). Critical priority — blocks the release.

BLD.05 [2026-07-21]: Fixed `third_party/CMakeLists.txt`:
- Replaced `add_subdirectory(imgui)` with an in-tree `imgui` STATIC library
  target listing the actual needed source files (`imgui.cpp`, `imgui_demo.cpp`,
  `imgui_draw.cpp`, `imgui_tables.cpp`, `imgui_widgets.cpp`,
  `backends/imgui_impl_sdl2.cpp`, `backends/imgui_impl_opengl3.cpp`) — same
  pattern the file already used for Argon2.
- Added the SDL2 wiring that never existed: `find_package(OpenGL REQUIRED)`
  (both platforms, via CMake's built-in `FindOpenGL`); Windows uses the vendored
  VC devel package's own CMake config (`find_package(SDL2 REQUIRED CONFIG PATHS
  third_party/SDL2/cmake NO_DEFAULT_PATH)`, confirmed to exist in the actual zip
  and expose `SDL2::SDL2`/`SDL2::SDL2main` imported targets); Linux/macOS uses
  `pkg-config` (`pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)`, since
  `apt install libsdl2-dev` ships a `.pc` file, not a CMake config).

Validated locally rather than relying on CI round-trips:
- **Linux**: WSL running Ubuntu 24.04 — the exact same OS as the `ubuntu-latest`
  CI runner. Installed `cmake`, `ninja-build`, `pkg-config`, `libsdl2-dev`,
  `libgl1-mesa-dev`; actually initialized the git submodules (they were
  uninitialized/empty in the working tree this whole time — `git submodule
  status` showed all three with a `-` prefix, and `third_party/imgui` was a
  literal empty directory, both locally and apparently never previously
  exercised by anyone). Ran the exact configure flags `release.yml` uses
  (`VW_BUILD_GUI=ON`, `VW_WERROR=ON`, Release). Configure succeeded; build
  surfaced 4 more bugs (all in `src/gui/*` app code, filed/fixed separately as
  `TASK-084`) plus one CMake wiring gap directly in this task's scope: `src/gui/
  client/CMakeLists.txt`'s `vapourwault-gui` target linked `vw_core`/`imgui` but
  never compiled `src/client/vw_ipc.c`, so it failed to link with undefined
  references to `vw_ipc_connect`/`vw_ipc_send`/`vw_ipc_recv`/`vw_ipc_conn_close`/
  `vw_ipc_write_str` — `vapourwault-cli`'s CMakeLists.txt already compiles that
  same file directly (no shared client library exists, unlike the server side's
  `vw_server_lib`), so fixed by adding `${CMAKE_SOURCE_DIR}/src/client/vw_ipc.c`
  to `vapourwault-gui`'s sources, matching that existing pattern. After both
  fixes plus `TASK-084`'s app-code fixes, a full `cmake --build` succeeded:
  all 8 expected binaries present in `bin/`, including `vapourwault-gui`,
  `vapourwault-server-gui`, `vw_gui_stub`.
- **Windows**: local MSVC BuildTools 2022 (17.14, `cl` 19.44.35207) — vendored
  the real SDL2 VC devel zip (`third_party/SDL2/`), confirmed its SHA-256
  matches the checksum already pinned in `release.yml`. Configure succeeded
  (found `OpenGL: opengl32`, SDL2 via the vendored CMake config). Build
  initially hit the same `TASK-084` app-code bugs (MSVC additionally caught one
  GCC didn't — `vw_view_browser.cpp`'s `(void)funcname;` unused-function
  suppression idiom trips MSVC's `C4551` under `/W4`, fixed with
  `[[maybe_unused]]` instead) plus a separate, unrelated, pre-existing
  `C4200`/`/WX` failure inside vendored mbedTLS headers that does NOT reproduce
  on the real CI Windows runner (verified against actual CI history — see
  `TASK-084`'s "separately noted" section for the full reasoning). After all
  `TASK-084` fixes, the only remaining local failure was that unrelated
  mbedTLS/toolchain-version issue — everything in this task's actual scope
  (imgui + SDL2 + the `vapourwault-gui` link fix) builds clean on both
  platforms locally.

Cleaned up local scratch build directories (`build-wsltest`, `build-msvctest`)
before committing. Left `third_party/{argon2,imgui,mbedtls}` submodules
initialized and `third_party/SDL2/` vendored in the working tree (matches
`VENDOR_SETUP.md`'s documented manual steps — helpful for local dev, not
something to undo). Handing off to CQR.08 for review of both this task and
`TASK-084` before pushing the fix and re-running `release.yml`.

CQR.08 [2026-07-21]: Independently reviewed (fresh read, not trusting the notes
above) against the actual submodule content. Confirmed the `imgui` CMake target
lists every source file actually needed — cross-checked every `imgui`/backend
API call across `src/gui/client`, `src/gui/server`, `src/gui/stub` (including
`ImGui::BeginTable`/`TableSetupColumn` needing `imgui_tables.cpp`, and
`vw_gui_stub`'s `ImGui::ShowDemoWindow` needing `imgui_demo.cpp`) — no gaps.
Confirmed `third_party/SDL2/cmake/sdl2-config.cmake` really defines
`SDL2::SDL2`/`SDL2::SDL2main`, and that `pkg_check_modules(... IMPORTED_TARGET
sdl2)` correctly matches what `apt`'s `sdl2.pc` provides. For the two
`ImGui_ImplOpenGL3_CreateFontsTexture()` removals, went further than "it
compiles": read the vendored backend's own changelog at the pinned commit,
which explicitly documents the function's removal and confirms the backend now
auto-manages font textures per-frame — the DPI-scaled font path in both
`main.cpp` files remains behaviorally correct since the font is added before
the first `NewFrame()`/render call. All other `TASK-084` fixes verified
correct, not just compiling. Two advisory-only findings (imgui version-pin
doc/comment staleness, pre-existing and unrelated to this diff) — already
resolved by BLD.05 in the same pass (`VENDOR_SETUP.md`, `third_party/
CMakeLists.txt` header comment and `FATAL_ERROR` message updated to reference
the actual pinned commit `81c008f90`). **Clean sign-off, no blocking findings.**

ARCH.00 [2026-07-21]: CQR.08 signed off clean on both `TASK-083` and
`TASK-084`. Closing — status: done. Proceeding to commit, move the `v0.1.0` tag
to the fixed commit, push, and re-run `release.yml`.

ARCH.00 [2026-07-21]: Confirmed via `gh run view`/`gh release view` — run
`29833861843` succeeded on the first retry (`Build / Linux`, `Build / Windows`,
`Publish GitHub Release` all green), and the `v0.1.0` GitHub Release is now
published with all 4 expected assets (both platform archives + `.sha256`
sidecars). This also retroactively confirms the local-validation methodology
(WSL Ubuntu-24.04 + local MSVC) was accurate enough to catch every real issue
before it reached CI — no further fix cycles were needed.
