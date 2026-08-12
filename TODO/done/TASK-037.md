---
id:          TASK-037
title:       Fix CMake naming conflict — rename client daemon binary to vapourwault-daemon
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-12
priority:    critical
depends_on:  []
blocks:      [TASK-038, TASK-039]
review_by:   [CQR.08]
tags:        [build, cmake, phase-5]
---

Both `src/server/CMakeLists.txt` and `src/client/CMakeLists.txt` define an executable
target named `vapourwaultd`. When both `VW_BUILD_SERVER=ON` and `VW_BUILD_CLIENT=ON`
(the defaults), CMake emits a duplicate-target error and the build fails. This blocks
CI and all default local builds.

## Acceptance criteria

### 1. Rename client daemon binary

In `src/client/CMakeLists.txt`, rename the `vapourwaultd` target to `vapourwault-daemon`.

The new naming scheme matches the other client binaries:
- `vapourwault-daemon` — client background daemon
- `vapourwault-cli`    — client CLI
- `vapourwault-gui`    — client GUI

The server binary keeps the name `vapourwaultd`.

### 2. Update usage text

In `src/client/main.c`, the `print_usage` call references `%s` (argv[0]). No source
change needed — the binary name propagates from CMake automatically. Confirm no
hardcoded "vapourwaultd" strings remain in client source.

### 3. Fix server CMakeLists pthread linkage

`src/server/CMakeLists.txt` links `pthread` unconditionally. MSVC has no `pthread` —
guard it:
```cmake
if(UNIX)
    target_link_libraries(vapourwaultd PRIVATE pthread)
endif()
```

### 4. Update documentation

- `VENDOR_SETUP.md` selective-builds table: note `VW_BUILD_CLIENT=ON` builds
  `vapourwault-daemon` + `vapourwault-cli`.
- `README.md` components table: update if it references the daemon binary name.

## Notes

ARCH.00 [2026-07-12]: This is a blocking defect introduced by Phase 4's server-main
implementation (TASK-033), which adopted the same binary name as the pre-existing
client CMakeLists. Fix must land before any Phase 5 implementation work starts.

BLD.05 [2026-07-12]: Fixed.
- `src/client/CMakeLists.txt`: target renamed `vapourwaultd` → `vapourwault-daemon`.
- `src/server/CMakeLists.txt`: pthread linkage made conditional on `UNIX` (was
  unconditional, would fail on MSVC).
- `VENDOR_SETUP.md`: selective-builds table updated to show `vapourwault-daemon`.

CQR.08 [2026-07-12]: APPROVED. Rename is clean; no hardcoded "vapourwaultd" strings
exist in client source files (main.c uses argv[0] in print_usage). pthread guard
is correct. No blocking findings.
