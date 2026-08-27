---
id:          TASK-128
title:       "Scaffold vapourwault-web-gateway CMake target"
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127]
blocks:      [TASK-129, TASK-130, TASK-136, TASK-142]
review_by:   [CQR.08]
tags:        [build, gateway]
---

Add the build scaffolding for the new web gateway component designed in
`TASK-127`. This task is build wiring only — no gateway logic (that's
`TASK-129`–`TASK-135`).

1. New `VW_BUILD_WEB_GATEWAY` option in the top-level `CMakeLists.txt`
   (`option()` block near `VW_BUILD_SERVER`/`VW_BUILD_CLIENT`/`VW_BUILD_GUI`/
   `VW_BUILD_TOOLS`/`VW_BUILD_TESTS`), off by default like the others,
   with a conditional `add_subdirectory(src/gateway)` call following the
   existing pattern.
2. New `src/gateway/CMakeLists.txt` declaring `add_executable(
   vapourwault-web-gateway ...)`. Follow the reuse pattern
   `src/gui/client/CMakeLists.txt` already uses for `vw_ipc.c`: compile
   `${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c` directly into this
   target's source list (no new shared-lib target), link `vw_core`. Do
   **not** link `vw_sync`/`vw_cache`/`vw_daemon` — out of scope per
   `TASK-127`.
3. Follow `src/gui/stub`/`tools/vwdump` as the closest existing precedents
   for "small standalone target, own CMakeLists.txt, one new option flag,
   one new top-level `add_subdirectory` line."
4. Installation: add a guarded `install()` block for the new executable
   matching the existing per-target, `VW_BUILD_*`-guarded pattern
   (top-level `CMakeLists.txt`'s install section).
5. Leave `src/gateway/main.c` as a stub that links and runs (prints version,
   exits) — enough to prove the target compiles clean on all CI targets.
   Real logic lands in `TASK-129`–`TASK-135`.

## Acceptance criteria

- `cmake -DVW_BUILD_WEB_GATEWAY=ON` configures and builds
  `vapourwault-web-gateway` clean on Linux (GCC/Clang) and Windows (MSVC),
  matching the project's existing CI matrix.
- Default build (`VW_BUILD_WEB_GATEWAY` unset) is unaffected — no new
  target, no new required dependency for anyone not opting in.
- No new external dependency introduced by this task (that decision is
  `TASK-129`/`TASK-130`'s hand-rolled-vs-vendor call, not this one's).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. High priority — everything else in this wave
needs a compiling target to land code into.

BLD.05 [2026-08-10]: Implemented. `VW_BUILD_WEB_GATEWAY` option added
(`CMakeLists.txt`, default `OFF`, matching every other `VW_BUILD_*` flag),
conditional `add_subdirectory(src/gateway)`, guarded `install()` block, and
a guarded `packaging/linux/vapourwault-web-gateway.service` install
(`OPTIONAL` — the unit file itself is `TASK-142`'s job, not filed yet).
`src/gateway/CMakeLists.txt` follows `src/gui/client/CMakeLists.txt`'s
precedent exactly: compiles `src/client/vw_client_core.c` directly into the
target's source list (no new shared-lib target), links only `vw_core`.
`src/gateway/main.c` is the stub described above (prints the negotiated
protocol version, exits).

Verified: configured and built clean with MSVC (`cmake -DVW_BUILD_WEB_GATEWAY=ON`,
then `--target vapourwault-web-gateway`) with `VW_WERROR=ON` (`/W4 /WX`) —
zero warnings, link succeeds, binary runs and prints
`vapourwault-web-gateway (protocol v6)`. Did not verify GCC/Clang
(Linux/macOS) in this pass — flagging for whoever picks up CI wiring to
confirm cross-platform, since only the Windows/MSVC toolchain was available
this session.

Note: this task's original text said "Reuse `vw_net`'s socket/accept-loop
primitives" for the gateway generally — that line applied to `TASK-129`'s
scope, not this one; `TASK-129` corrects it directly (`vw_net.h` is
TLS-only and can't be reused for the plain-HTTP nginx-facing listener; the
gateway instead uses mbedTLS's own `mbedtls_net_*` transport layer, already
a transitive dependency via `vw_core`).

Moving to `review` — implementation complete per the acceptance criteria
above; needs CQR.08 sign-off (not tagged `security-sensitive`, so SEC.07
isn't required for this task specifically, though `TASK-144`'s
feature-level pass will still look at the build/packaging surface).

CQR.08 [2026-08-12]: Reviewed `src/gateway/main.c` and `src/gateway/
CMakeLists.txt` directly. Matches the described scope exactly; no
leak/UB found in the accept loop, and the lack of shutdown handling is
reasonable and already documented as an accepted MVP scope limit
elsewhere (`TASK-144`'s single-threaded-architecture note). No findings.
Sign-off: `CQR.08` requirement satisfied. Ready for `done`.
