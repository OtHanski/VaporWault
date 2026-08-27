---
id:          TASK-146
title:       "CMake/CPack component scaffolding for installer packages"
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-11
priority:    high
depends_on:  [TASK-145]
blocks:      [TASK-147, TASK-148, TASK-149, TASK-150]
review_by:   [CQR.08]
tags:        [build]
---

Foundation for `TASK-147`–`TASK-150`: wire CPack into the existing CMake
install graph with a `server`/`client` component split, per `TASK-145`'s
design.

1. Add `COMPONENT server` / `COMPONENT client` to every existing
   `install(TARGETS ...)`/`install(FILES ...)` call in the top-level
   `CMakeLists.txt` (`vapourwaultd`/`vapourwault-server-cli`/
   `vapourwault-server-gui`/`vwdump` → `server`; `vapourwault-daemon`/
   `vapourwault-cli`/`vapourwault-gui` → `client`). The web gateway
   (`vapourwault-web-gateway`, `TASK-128`) is out of scope for this task —
   file a follow-up if/when it needs its own installer.
2. New `cmake/Packaging.cmake`, `include()`-d at the end of the top-level
   `CMakeLists.txt`, containing:
   - `CPACK_PACKAGE_NAME`, `CPACK_PACKAGE_VENDOR`, `CPACK_PACKAGE_CONTACT`,
     `CPACK_PACKAGE_DESCRIPTION_SUMMARY`.
   - `CPACK_PACKAGE_VERSION` sourced from a new `VW_VERSION` cache variable
     (default `"0.0.0-dev"` for local builds; CI passes the real tag via
     `-DVW_VERSION=...`, per `TASK-151`).
   - `CPACK_COMPONENTS_ALL "server;client"`,
     `CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE OFF` (one package per component,
     per `TASK-145`'s design — not a single package with feature
     selection).
   - `CPACK_DEB_COMPONENT_INSTALL ON`, `CPACK_RPM_COMPONENT_INSTALL ON` (the
     generator-specific flags each format needs to actually honor
     per-component packaging — verify both; CPack's per-generator component
     support has historically had rough edges and needs checking against
     the CPack version pulled in by this project's CMake, not just assumed
     from documentation).
   - `include(CPack)` last.
3. `cpack --list-cmake-cache` / `cpack -G <X> --config CPackConfig.cmake`
   should be invocable from any configured build directory without
   additional setup beyond the generator-specific tools (WiX, dpkg-dev,
   rpm-build) `TASK-147`–`TASK-150` will need.

## Acceptance criteria

- `cmake --build <dir>` is unaffected — this task only adds packaging
  metadata, no new build target or behavior change for anyone not invoking
  `cpack`.
- From a built tree, `cpack -G TGZ` (a trivial, tool-free generator)
  produces two archives, one per component, each containing only that
  component's files — proves the component split itself is correct before
  `TASK-147`–`TASK-150` add per-format specifics.
- `VW_VERSION` flows into the produced package's version metadata
  (verify via the `TGZ` component archive's directory name, which CPack
  derives from `CPACK_PACKAGE_FILE_NAME`).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-11]: Filed as part of the `TASK-145` installer packaging
design's initial implementation wave. High priority — `TASK-147`–`TASK-150`
all build on this.

BLD.05 [2026-08-11]: Implemented (`COMPONENT server`/`COMPONENT client`
tags added to every relevant `install()` call in the top-level
`CMakeLists.txt`, including two that didn't exist before — `vwdump` had no
`install()` rule at all, and neither GUI binary did, since the tarball/zip
release process has always copied `build/bin/*` directly rather than going
through `cmake --install`; new `cmake/Packaging.cmake`, new `VW_VERSION`
cache variable).

**Two real bugs found and fixed via actual verification** (built a
throwaway `VW_BUILD_GUI=OFF` tree and ran `cpack -G TGZ` — chose TGZ
because it needs no extra tooling, unlike DEB/RPM/WIX):

1. `CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE OFF` alone did **not** stop the
   archive generator family from bundling both components into one file —
   `cpack --verbose` showed `[TGZ] requested component grouping =
   ALL_COMPONENTS_IN_ONE` regardless. Fixed by also setting
   `CPACK_COMPONENTS_GROUPING IGNORE`, after which `cpack -G TGZ` correctly
   produced `vaporwault-1.2.3-win64-server.tar.gz` and
   `...-client.tar.gz` separately, each containing only that component's
   binaries.
2. Before that fix (and before `CPACK_ARCHIVE_COMPONENT_INSTALL ON` was
   set at all), the single combined archive also contained mbedTLS's own
   dev headers and static libraries (`include/mbedtls/*.h`,
   `lib/mbedcrypto.lib`, etc.) — pulled in because mbedTLS's `CMakeLists.txt`
   (fetched via `FetchContent`) declares its own `install()` rules with no
   `COMPONENT` tag, landing in CPack's default "Unspecified" component,
   which was being swept into the package wholesale. This would have
   shipped ~600 KB of irrelevant static-link dev artifacts in every
   end-user package. Fixed as a side effect of enabling
   `CPACK_ARCHIVE_COMPONENT_INSTALL` and restricting
   `CPACK_COMPONENTS_ALL` to exactly `server;client` — confirmed by
   re-inspecting the resulting archives' contents (`tar tzf`), which now
   contain only the five/two expected binaries per component. Both bugs
   and their fixes are recorded as comments directly in
   `cmake/Packaging.cmake` so the reasoning isn't lost.

Verified end-to-end: configured (`-DVW_VERSION=1.2.3 -DVW_BUILD_GUI=OFF`),
built, and ran `cpack -G TGZ` — produced exactly two archives with the
version correctly embedded in the filename and the exact expected file set
in each (`server`: `vapourwaultd`, `vapourwault-server-cli`, `vwdump`;
`client`: `vapourwault-daemon`, `vapourwault-cli`). Did **not** verify
`VW_BUILD_GUI=ON` (GUI binaries pulled into their respective components) or
the DEB/RPM/WIX generators specifically in this pass — DEB/RPM need Linux
tooling not available in this session (`TASK-149`/`TASK-150`'s job to
verify for real), and WIX-specific variables are `TASK-147`/`TASK-148`'s
addition on top of this scaffolding.

Moving to `review` — needs CQR.08 sign-off. Not tagged `security-sensitive`
itself, though the mbedTLS-leak bug this pass caught is exactly the kind of
thing `TASK-153`'s feature-level review should double-check doesn't
regress once `TASK-147`–`TASK-150` add their own generator-specific
variables on top.

CQR.08 [2026-08-12]: Reviewed `cmake/Packaging.cmake` and every
`COMPONENT`-tagged `install()` call in the top-level `CMakeLists.txt`
directly. Component scoping is correct and consistent throughout;
WIX-specific variables are correctly kept out of this shared,
generator-agnostic file and supplied only via `-D` at `cpack`
invocation time (`TASK-147`/`148`/`151`), so there's no cross-
contamination risk between the server/client `cpack` invocations. One
pre-existing, already-flagged-elsewhere metadata gap noted but not this
task's own defect: `CPACK_RPM_PACKAGE_LICENSE "TBD"` is still literally
`"TBD"` — real, but belongs to whoever finalizes the project's license
metadata, not to this scaffolding task. No blocking findings.
Sign-off: `CQR.08` requirement satisfied. Ready for `done`.
