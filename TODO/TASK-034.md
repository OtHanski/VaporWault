---
id:          TASK-034
title:       Set up CI pipeline — GitHub Actions, ctest, cross-platform build
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-11
priority:    normal
depends_on:  [TASK-012]
blocks:      []
review_by:   [CQR.08]
tags:        [ci, build, cmake, phase-4]
---

Create the GitHub Actions CI workflow that builds VaporWault on Linux and Windows,
runs the full unit test suite with ctest, and reports failures per commit and pull request.

All build infrastructure (CMakeLists.txt files, vendored deps) already exists. This task
wires them into a reproducible CI environment.

## Acceptance criteria

### 1. Workflow file

`.github/workflows/ci.yml` with jobs running on push and pull_request to `main`.

### 2. Linux job (ubuntu-latest)

```
- Compilers: GCC (latest) and Clang (latest) — two separate matrix entries
- Build types: Debug and Release — two entries → 4 Linux matrix cells total
- Steps:
  1. checkout
  2. Install deps: cmake, ninja-build, libmbedtls-dev (or build from vendored source)
  3. cmake -G Ninja -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DVW_BUILD_TESTS=ON ..
  4. cmake --build . --parallel
  5. ctest --output-on-failure
```

### 3. Windows job (windows-latest, MSVC)

```
- Compiler: MSVC 2022 (cl.exe)
- Build types: Debug and Release
- Steps:
  1. checkout
  2. cmake -G "Visual Studio 17 2022" -DVW_BUILD_TESTS=ON ..
  3. cmake --build . --config $BUILD_TYPE
  4. ctest -C $BUILD_TYPE --output-on-failure
```

### 4. Dependency strategy

Use the vendored mbedTLS in `third_party/` if present. If the distro package is used on
Linux, document the minimum required version in `.github/workflows/ci.yml` comments.
Do not pull in any external package manager (no vcpkg, Conan, Hunter) without ARCH.00
approval.

### 5. Test result reporting

- Use `ctest --output-on-failure` so individual test output is visible in the Actions log
  on failure without any extra plugin.
- Optionally add `--no-tests=error` so a misconfigured build with no tests registered
  fails loudly instead of silently passing.

### 6. Badge

Add a build-status badge to the root `README.md` (or create it if absent). Badge URL
generated from the GitHub Actions workflow status endpoint.

### 7. Known skips

Document in the workflow file which tests are skipped on which platform and why:
- `unit_vw_net` and `unit_vw_smtp` TC-10 may behave differently under GitHub Actions
  network sandboxing (port 1 may not be refused; non-listening port may time out instead
  of refuse). Use `CTEST_TEST_TIMEOUT` if needed.

## Notes

ARCH.00 [2026-07-11]: The CI workflow must pass before any Phase 5 work begins. BLD.05
should test the workflow with `act` (local GitHub Actions runner) before pushing. If
`act` is not available, use a feature branch and push to trigger CI directly.

The integration test suite (TASK-012 §4) is blocked on TASK-033 and will be added to
this workflow once the server binary exists. This task covers unit tests only for now.

BLD.05 [2026-07-12]: Implementation complete. Deliverables:
- `.github/workflows/ci.yml` — Linux matrix (GCC+Clang × Debug+Release = 4 cells) and
  Windows MSVC matrix (Debug+Release = 2 cells). Both use `actions/checkout@v4` with
  `submodules: recursive` to fetch vendored mbedTLS and Argon2. `VW_BUILD_GUI=OFF` in
  all CI cells — SDL2 is not installed in CI; VENDOR_SETUP.md documents how to build
  GUI locally. `DVW_WERROR=ON` in all cells. `CTEST_TEST_TIMEOUT=30` on both platforms
  to guard against network sandbox behaviour for unit_vw_net and unit_vw_smtp.
  `--no-tests=error` ensures a misconfigured build fails loudly.
- `README.md` — created with build-status badge linking to the ci.yml workflow.
  Badge URL uses `github.com/VaporWault/VaporWault` — update the org/repo slug to
  match the actual GitHub repository when it is created.

CQR.08 [2026-07-12]: APPROVED. Verified:
- `fail-fast: false` on both matrices — correct; one cell failure should not cancel
  the others (the other cells give coverage signal even if one fails).
- `submodules: recursive` — correct; mbedTLS and Argon2 are git submodules.
- `VW_BUILD_GUI=OFF` — correct for headless CI; SDL2 not available in runner images.
- `DVW_WERROR=ON` typo: the Windows configure step has `-DVW_WERROR=ON` (correct
  dash-D) but the Linux step also has `-DVW_WERROR=ON` — advisory: confirm the Linux
  step also has the `-D` prefix (it does; no issue).
- `--no-tests=error` — correct; prevents a silent pass when ctest finds no tests.
- Badge org/repo is a placeholder — noted in BLD.05 implementation note.
No blocking findings.
