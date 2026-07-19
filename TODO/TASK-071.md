---
id:          TASK-071
title:       MSVC /WX build fails on vendored mbedTLS PSA header (C4200 zero-sized array)
status:      todo
assignee:    BLD.05
created_by:  SRV.01
created:     2026-07-19
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [bug, build, windows, msvc, mbedtls]
---

While building locally on Windows (MSVC 19.44.35207 / VS2022 17.14 Build Tools,
Ninja generator) to verify TASK-070, a full project build with the exact CI
flags (`-DCMAKE_BUILD_TYPE=Release -DVW_WERROR=ON` etc., matching
`.github/workflows/ci.yml`'s `build-windows` / `integration` jobs) fails —
**independently of the TASK-070 change** (reproduced on a clean `git stash`'d
tree at HEAD `86a6925`).

## Root cause (as far as SRV.01 traced it)

- `CMakeLists.txt:18` applies `/W4 /WX` globally via `add_compile_options`
  when `VW_WERROR=ON`, with no exemption for FetchContent'd third-party
  sources.
- `third_party/CMakeLists.txt` pins mbedTLS to `GIT_TAG v3.6.3`.
- Any translation unit that transitively includes
  `build/_deps/mbedtls-src/include/psa/crypto_struct.h` (e.g.
  `src/core/vw_crypto.c`, `src/core/vw_net.c`, `src/server/vw_smtp.c`) fails
  to compile under MSVC with:

  ```
  psa/crypto_struct.h(254): error C2220: the following warning is treated as an error
  psa/crypto_struct.h(254): warning C4200: nonstandard extension used: zero-sized array in struct/union
  ```

- `MBEDTLS_FATAL_WARNINGS` is already forced `OFF` (see comment at
  `third_party/CMakeLists.txt:15-18`), so this isn't mbedTLS's own
  `-Werror`/`/WX` bleeding in — it's the project's own `/WX` (from
  `VW_WERROR=ON`) applying to vendored mbedTLS headers that were never
  written to satisfy MSVC `/W4`.

## Suggested fix direction (BLD.05 to confirm/decide)

- Mark the mbedTLS (and Argon2) FetchContent include directories as `SYSTEM`
  so MSVC doesn't apply `/W4` diagnostics to them, and/or scope
  `add_compile_options(/W4 /WX)` to only the project's own targets
  (`vw_core`, `vw_server_lib`, etc.) rather than globally — mirroring how
  `MBEDTLS_FATAL_WARNINGS` is already special-cased.
- Alternatively (or additionally), suppress `C4200` specifically for
  translation units that must include PSA headers, if excluding the headers
  from `/W4` isn't practical.

## Why this isn't SRV.01's task

Per `CLAUDE.md`'s "Out-of-domain discovery" rule: this is a CMake
warnings-as-errors / cross-platform toolchain configuration issue
(`CMakeLists.txt`, `third_party/CMakeLists.txt`), squarely BLD.05's domain
("CMake configuration for all three targets", "Cross-platform toolchain").
SRV.01 confirmed the TASK-070 fix (`vw_server_main.c`) itself compiles clean
(`vw_server_main.c.obj` built with zero warnings/errors) and is not the
cause — this pre-exists at HEAD `86a6925` with or without that change.

## Acceptance criteria

- A full `cmake --build build` with `VW_WERROR=ON` (Windows/MSVC, matching
  `build-windows` and `integration`... — note: `integration` job actually
  runs on Linux/gcc, so this may currently be Windows-only breakage; BLD.05
  to confirm whether `build-windows` CI is actually green today or whether
  this is latent/undetected) succeeds without touching mbedTLS's own
  `-Werror` behavior.
- `vw_crypto.c`, `vw_net.c`, `vw_smtp.c` all compile clean under MSVC `/W4 /WX`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-07-19]: Discovered while locally verifying TASK-070 (build
validation step). Reproduced on unmodified HEAD via `git stash` before
filing — confirmed unrelated to the TASK-070 change. Not fixing myself per
CLAUDE.md out-of-domain protocol; routing to BLD.05.
