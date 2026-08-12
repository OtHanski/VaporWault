---
id:          TASK-151
title:       Wire installer packages into the release CI workflow
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-11
priority:    high
depends_on:  [TASK-146, TASK-147, TASK-148, TASK-149, TASK-150]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [build, ci, security-sensitive]
---

Extend `.github/workflows/release.yml` to build and publish the new
installer packages alongside the existing tarball/zip archives (kept, not
replaced — they remain useful for scripted/air-gapped deployments).

Scope:

1. Pass the real version into CMake: `-DVW_VERSION=${TAG#v}` (strip the
   leading `v` from the git tag, e.g. `v0.2.0` → `0.2.0`, since `.deb`/
   `.rpm`/MSI version fields don't accept an arbitrary leading letter) at
   configure time in both `build-linux` and `build-windows` jobs. Use the
   same "read from workflow-level `env:`, never interpolate `${{ }}`
   directly into a shell script" discipline `TASK-081` established — this
   is exactly the kind of ref-derived value that pattern exists to protect.
2. `build-linux`: install `dpkg-dev` and `rpm` (for `rpmbuild`) alongside
   the existing `ninja-build python3 git libsdl2-dev`. After the existing
   build step, run `cpack -G "DEB;RPM"` and stage all four resulting
   packages for upload (same `actions/upload-artifact` pattern already
   used for the tarball).
3. `build-windows`: add a step to fetch/install WiX Toolset v3
   (`candle.exe`/`light.exe`) before the CPack invocation — evaluate
   whether `choco install wixtoolset` works reliably in this specific CI
   image (this session's own attempt hit a Chocolatey lock-file permission
   error that may be sandbox-specific, not necessarily reproducible on a
   real `windows-latest` GitHub-hosted runner; if it recurs, fall back to
   downloading the `wix` NuGet package directly, e.g. via
   `Invoke-WebRequest https://www.nuget.org/api/v2/package/wix/3.11.2` and
   extracting `tools/candle.exe`+`tools/light.exe`+extension DLLs onto
   `PATH` — this is exactly what worked in this session's manual
   verification of `TASK-147`). After configure/build, run
   `cpack -G WIX` once per component (`server`, `client` — each has its
   own `CPACK_WIX_UPGRADE_GUID` per `TASK-147`/`TASK-148`) and stage both
   MSIs for upload.
4. `publish`: include the four `.deb`/`.rpm` files and two `.msi` files in
   the `gh release create`/`gh release upload` file list, alongside the
   existing tarball/zip.
5. Update the smoke-test step's rationale comment if the new artifacts
   change what "already validated" means — the existing smoke-test
   (`--help` on each CLI binary) is orthogonal to package-level
   installability and doesn't need to change, but note explicitly in the
   workflow that package *installability* is `TASK-152`'s manual/VM-based
   job, not something this CI run verifies.

## Acceptance criteria

- A `workflow_dispatch` dry run (no tag push required) builds all six new
  package artifacts without error, alongside the existing two archives.
- No ref-controlled value (`github.ref_name`, `github.event.inputs.version`)
  is interpolated directly into a `run:` shell/PowerShell block — routed
  through workflow-level `env:` only, matching `TASK-081`'s established
  pattern.
- A real tag push publishes all eight artifacts (2 archives + 4 Linux
  packages + 2 MSIs) to the GitHub Release.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-11]: Filed as part of the `TASK-145` installer packaging
design's initial implementation wave. Depends on all five packaging tasks
since it's the integration point that actually builds them in CI — the
last task in the critical path before a real tagged release includes
installers.

BLD.05 [2026-08-11]: While implementing `TASK-147` in this session,
`choco install wixtoolset` failed with a lock-file permission error
(`Access to the path 'C:\ProgramData\chocolatey\lib-bad' is denied`) —
this looked like a sandboxed-environment permissions artifact, not
necessarily a real GitHub Actions `windows-latest` runner issue (those
runners typically run with full admin rights). Worked around by fetching
the `wix` NuGet package directly (`https://www.nuget.org/api/v2/package/wix/3.11.2`,
a plain zip containing `tools/candle.exe`+`tools/light.exe`+extension
DLLs) and adding its `tools/` directory to `PATH` — this worked cleanly
and is what `TASK-147`'s verification actually used. Whoever implements
this task should **try `choco install wixtoolset` first** (simpler, one
line) and only fall back to the manual NuGet-zip approach if it also fails
on the real runner — but if it does fail the same way, the NuGet-zip
method is proven to work and the exact URL/extraction steps are recorded
in `TASK-147`'s implementation note.

BLD.05 [2026-08-11]: Implemented (`.github/workflows/release.yml`) and
verified end-to-end — not just YAML-syntax-checked, but the actual
extracted PowerShell/shell logic run for real against this session's build
outputs, matching the exact toolchain the workflow specifies.

**A real bug caught and fixed via this verification, not assumed safe**:
the two `cpack -G WIX` invocations (server, client) originally produced
the exact same default output filename — CPack's WIX generator, unlike
DEB/RPM, does not vary its default filename by component. Running the
literal two-invocation sequence end-to-end showed only one `.msi` surviving
on disk where two were expected: the client invocation silently overwrote
the server's file. Fixed by adding an explicit, distinct
`CPACK_PACKAGE_FILE_NAME` override to each invocation
(`vaporwault-{server,client}-$env:PKG_VERSION-win64`) — re-ran the exact
final script content afterward and confirmed both MSIs now survive with
correct, distinct hashes.

**Version plumbing**: `PKG_VERSION` (leading `v` stripped from `TAG`) is
computed once per job and passed to CMake via `-DVW_VERSION`, following
the same "derive from workflow-level `env:`, never interpolate a `${{ }}`
expression directly into a shell/PowerShell script" discipline `TASK-081`
established — verified the bash (`${TAG#v}`) and PowerShell
(`$env:TAG.TrimStart('v')`) expressions both produce the expected output
for a real tag (`v1.2.3` → `1.2.3`) and the `workflow_dispatch` default
(`v0.0.0-dryrun` → `0.0.0-dryrun`).

**Artifact staging**: package outputs are copied from `build/` up to the
workspace root before `upload-artifact`, rather than referencing
`build/*.deb`-style nested paths directly in the `path:` list — avoids
depending on exactly how `upload-artifact` v4 flattens (or doesn't)
directory structure across mixed top-level/nested path patterns, and
matches the existing tarball/zip staging convention already used in this
workflow. The `publish` job's existing `dist/linux-release/*` /
`dist/windows-release/*` globs needed no changes as a result — the new
packages land at the same flat level as the existing archives.

**Verified for real, using disposable Docker containers** (not just this
session's earlier per-package testing in isolation, but the *exact*
package-list/OS combination `release.yml` itself specifies):
- `ubuntu:24.04` with `dpkg-dev` + `rpm` installed: confirmed `rpmbuild` is
  actually provided by the `rpm` apt package on Ubuntu (not a given —
  Fedora's `rpm-build` package has a different name than Ubuntu's `rpm`
  package, and `TASK-150`'s own RPM testing had only used a Fedora
  container up to this point). Built the full project from scratch and ran
  both `cpack -G DEB` and `cpack -G RPM` — all four Linux packages
  (`server`/`client` × `deb`/`rpm`) produced successfully with correct
  Debian/RPM-convention filenames.
- The exact final Windows MSI-build script content (copied verbatim out of
  the committed workflow file, not retyped) run against a real build tree
  with WiX v3.11 — both MSIs produced, correctly named, correctly hashed.

**Not verified** (genuinely can't be, without actually running GitHub
Actions): the `choco install wixtoolset` fallback path specifically — this
session's sandbox hit a Chocolatey lock-file permission error that may or
may not reproduce on a real `windows-latest` hosted runner; the workflow
is written to try Chocolatey first and fall back automatically, but which
branch a real run actually takes is unconfirmed. Also not verified: the
`publish` job's `gh release create`/`upload` behavior with the larger
8-artifact file list (still structurally the same command shape as
before, just more files — low risk, but genuinely untested here). Flagging
both for whoever first runs this workflow for real (a `workflow_dispatch`
dry run, per `docs/RELEASE.md`'s existing guidance, before ever pushing a
real tag).

Moving to `review` — needs SEC.07 + CQR.08 sign-off per the
`security-sensitive` tag (this workflow handles a `GH_TOKEN` with
`contents: write` and fetches third-party binaries into the build).

BLD.05 [2026-08-11]: Update — actually dispatched this workflow for real
against a pushed branch (`workflow_dispatch`, not just local script
extraction), per the user's explicit request. Took three attempts, each
catching a real bug local testing never exercised:

1. First attempt: both `cpack -G WIX` invocations failed with a bare
   "Problem running WiX" and no visible cause — the workflow didn't
   surface `wix.log`'s actual content on failure at all. Added diagnostics
   (dump `wix.log` on non-zero exit) before investigating further, since
   guessing blindly wasn't productive.
2. Second attempt (with diagnostics): revealed `error CNDL0108: The
   Product/@Version attribute's value, '0.0.0-dryrun', is not a valid
   version` — MSI's `Product/@Version` must be strictly numeric dotted
   (`x.x.x.x`), unlike DEB/RPM (which had already succeeded with that same
   raw string in this exact run). The `workflow_dispatch` dry-run's
   default tag (`v0.0.0-dryrun`) is exactly the kind of value this bug
   needed to reproduce — a real release tag (`v0.2.0`) wouldn't have hit
   it, but dry runs are the documented way to validate this workflow
   before cutting one, so it was a real bug, not a dry-run-only
   non-issue. Fixed by computing a sanitized `$msiVersion` (strip
   anything from the first non-numeric/non-dot character onward,
   falling back to `0.0.0` if empty) and passing it via
   `-D CPACK_PACKAGE_VERSION=` to both WIX invocations specifically —
   verified the regex against `0.0.0-dryrun`, `0.2.0`, `1.2.3-rc1`, and
   empty-string inputs before pushing again.
3. This also incidentally confirms the `choco install wixtoolset` path
   works fine on the real `windows-latest` runner (the sandboxed local
   environment's earlier lock-file failure was indeed sandbox-specific,
   as suspected) — the WiX 3.14 toolset installed and was used
   successfully, no NuGet-zip fallback needed.
4. Third attempt: **fully green**. Both `Build / Linux / x86_64` and
   `Build / Windows / x86_64` succeeded; `Publish GitHub Release`
   correctly skipped (workflow_dispatch dry runs never publish, by
   design — confirmed this guard still works). Downloaded and inspected
   both artifact bundles directly: all 8 expected files present and
   correctly named — `linux-release/` has the tarball+checksum plus
   `vapourwault-{server,client}_..._amd64.deb` and
   `vapourwault-{server,client}-..-1.x86_64.rpm` (RPM's own tooling
   auto-sanitized the `-dryrun` suffix to `_dryrun` in version fields,
   handled gracefully unlike WiX); `windows-release/` has the zip+checksum
   plus `vaporwault-{server,client}-0.0.0-dryrun-win64.msi`.

This is now a workflow that has actually run successfully on GitHub's real
infrastructure, not just one that looks correct on paper.

SEC.07/CQR.08 [2026-08-12]: Reviewed `.github/workflows/release.yml`
directly, focused on CI logic quality beyond the checksum-gate
correctness `TASK-153` already verified. Confirmed by reading every
step: no `${{ }}` ref-derived expression is interpolated directly into
any `run:`/PowerShell block anywhere in the file — every such value
routes through job-level `env:` first, matching the `TASK-081`
discipline exactly. The `wix.log`-dump-on-failure diagnostic and the
version-sanitization regex are both sound and match their described
behavior. No blocking findings.
Sign-off: `SEC.07` + `CQR.08` requirements satisfied. Ready for `done`.
