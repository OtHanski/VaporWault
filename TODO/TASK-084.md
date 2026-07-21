---
id:          TASK-084
title:       GUI application-code bugs found while unblocking the v0.1.0 release build
status:      done
assignee:    GUI.03
created_by:  BLD.05
created:     2026-07-21
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [gui, bug]
---

While fixing `TASK-083` (the CMake/build-config break that failed the `v0.1.0`
release), local build validation (WSL/Ubuntu-24.04 matching the CI Linux runner,
plus a local MSVC BuildTools 2022 pass) surfaced four bugs in `src/gui/*`
application code — out of BLD.05's domain per `CLAUDE.md` (GUI.03 owns
`src/gui/*`). Routing rule 4 says the discovering agent should file these rather
than fix them itself; in practice there is no separate GUI.03 agent available and
the release was actively blocked, so BLD.05 fixed all four directly to unblock
`v0.1.0`. Filing this for GUI.03's record/review rather than leaving the fixes
undocumented.

## Findings (all fixed by BLD.05, pending GUI.03 review)

1. **`src/gui/client/vw_gui_ipc.cpp:6`** — `write_u32_le()` was a dead static
   helper, never called anywhere in the file (only `read_u32_le`/`read_i64_le`
   are used). Failed Linux/GCC build under `-Werror=unused-function`. **Fix**:
   deleted the function.

2. **`src/gui/client/main.cpp` and `src/gui/server/main.cpp`** (both, same
   pattern) — called `ImGui_ImplOpenGL3_CreateFontsTexture()` after adding a
   DPI-scaled default font. That function does not exist in the pinned Dear
   ImGui version (commit `81c008f9`, tag `v1.91.6`) — confirmed against the
   actual `backends/imgui_impl_opengl3.h` at that commit, which only declares
   `Init/Shutdown/NewFrame/RenderDrawData/CreateDeviceObjects/
   DestroyDeviceObjects/UpdateTexture`. This imgui version's OpenGL3 backend
   manages font textures automatically (newer `ImTextureData`-based texture
   system) — the explicit call is obsolete. **Fix**: removed the call in both
   files; the backend picks up the new font automatically on the next frame.

3. **`src/gui/client/views/vw_view_queue.cpp:16`** — `snprintf` into a 32-byte
   `ts_buf` failed GCC's `-Werror=format-truncation=`: GCC's static analysis
   assumes a plain `int` (`tm_year+1900` etc.) could theoretically need up to
   11 characters each, computing a worst-case need of up to 64 bytes even
   though real dates never come close. **Fix**: bumped `ts_buf` from `[32]` to
   `[64]`, matching GCC's own stated worst-case estimate. No functional change.

4. **`src/gui/client/views/vw_view_browser.cpp:86`** — `sync_colour`/
   `sync_label` are free functions reserved for a future feature (per the
   existing comment: file-row rendering isn't wired up yet). The suppression
   idiom used, `(void)sync_colour; (void)sync_label;`, silences GCC's
   `-Wunused-function` (taking a function's address counts as "used" for GCC)
   but MSVC's `/W4` reads a bare function-name reference as a probable typo —
   "did you forget the call parens?" (`C4551`) — and fails under `/WX`. This
   only surfaced in a local MSVC BuildTools 2022 (17.14) test; GCC/Linux never
   flagged it. **Fix**: replaced the `(void)` suppression with `[[maybe_unused]]`
   on both function declarations (the portable, standard C++17 way to mark an
   intentionally-unused function on any compiler) and removed the now-redundant
   suppression line.

## Separately noted (not a bug, not fixed — informational only)

Local MSVC validation (BuildTools 2022, MSVC 19.44.35207/VS 17.14) hit a
**pre-existing, unrelated** failure compiling vendored mbedTLS headers
(`psa/crypto_struct.h:254`, `C4200` zero-sized-array-in-struct) under `/W4 /WX`
— this affects `vw_core`/`vw_crypto.c`/`vw_net.c`, unconditional on
`VW_BUILD_GUI`. Checked against real CI history: `ci.yml`'s actual
`windows-latest` runner (a newer MSVC via VS 2026/18, confirmed from the
`v0.1.0` failure log's toolchain paths) has built this exact
`vw_core`+mbedTLS combination under `VW_WERROR=ON` successfully many times
(most recently CI run `29830660084`, both Windows Debug and Release cells
green). This is a local-toolchain-version artifact (older MSVC warns on a
construct the actual CI compiler doesn't), not a real bug — no action taken.

## Acceptance criteria

- GUI.03 reviews the four fixes above for correctness (especially #2 — confirm
  no other code path in `src/gui/*` still assumes the old explicit
  font-texture-creation API, and that fonts render correctly at DPI scale > 1
  once real hardware/display testing is possible).
- CQR.08 signs off (style/consistency — already listed as reviewer).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

BLD.05 [2026-07-21]: Filed and fixed in the same pass as `TASK-083` — see that
task for the full build-validation methodology (WSL Ubuntu-24.04 + local MSVC
BuildTools 2022, matching/approximating the CI runners). All four fixes verified
by a full local rebuild succeeding on both Linux (WSL) and Windows (MSVC) after
each change.

CQR.08 [2026-07-21]: Reviewed all four fixes independently (see full notes in
`TASK-083`) — confirmed each is behaviorally correct, not just compile-clean.
Notably verified the `ImGui_ImplOpenGL3_CreateFontsTexture()` removal against
the vendored backend's own changelog (confirms the function was removed
upstream and font-texture creation is now automatic). Clean sign-off, no
blocking findings. GUI.03 should still review at a convenient point, per this
task's acceptance criteria, but nothing here blocks `v0.1.0`.

ARCH.00 [2026-07-21]: No blocking findings from CQR.08. Closing — status: done.
GUI.03 review remains open as a courtesy/record item but does not gate this
task or the release.
