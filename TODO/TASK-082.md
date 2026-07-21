---
id:          TASK-082
title:       Harden release pipeline follow-ups (GUI CI coverage, smoke test, action SHA-pinning)
status:      todo
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-21
priority:    normal
depends_on:  [TASK-081]
blocks:      []
review_by:   [CQR.08]
tags:        [ci, release, advisory]
---

CQR.08 and QA.06's review of `TASK-081` (the new `.github/workflows/release.yml`
build-and-release workflow) surfaced three non-blocking hardening items, deferred
out of that task to avoid scope creep. None of these block release.yml from being
used as-is; they reduce risk of a release-time surprise.

1. **GUI+SDL2 is only ever compiled in the release workflow.** `ci.yml` always
   builds with `VW_BUILD_GUI=OFF` (SDL2 isn't vendored there), so a GUI build/link
   regression currently surfaces for the first time when cutting a real release,
   not on a regular PR. Add a non-blocking CI job/cell (Linux at minimum, ideally
   both platforms) that builds with `VW_BUILD_GUI=ON`, mirroring the SDL2 setup
   `release.yml` already does (apt package on Linux, vendored VC devel zip on
   Windows).

2. **No smoke test before packaging/publishing.** A binary that links but crashes
   on startup (missing DLL, bad rpath, etc.) would still ship. Add a lightweight
   step in `release.yml` after `Build` that runs each built binary with `--version`
   or `--help` (whichever the binaries support) and fails the job on nonzero exit,
   before staging the archive.

3. **Third-party actions are tag-pinned, not SHA-pinned** (`actions/checkout@v4`,
   `actions/upload-artifact@v4`, `actions/download-artifact@v4`,
   `ilammy/msvc-dev-cmd@v1`) — in both `ci.yml` and `release.yml`. SEC.07 flagged
   this as advisory hardening (a compromised upstream tag could inject malicious
   action code). Since this affects both workflows consistently, fix them together
   rather than making `release.yml` inconsistent with `ci.yml`.

## Acceptance criteria

- A CI job builds `VW_BUILD_GUI=ON` on at least Linux (Windows if reasonably cheap
  to add) as a non-blocking (or blocking, ARCH.00's call at implementation time)
  check on regular pushes/PRs.
- `release.yml` smoke-tests built binaries before staging archives.
- `ci.yml` and `release.yml` both pin third-party actions to a commit SHA (with a
  version comment alongside, e.g. `actions/checkout@<sha> # v4.x.x`).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-21]: Split out from TASK-081's review findings (CQR.08 findings
#3–#4, #6; SEC.07 finding #3) as advisory, non-blocking follow-up work. Assigned to
BLD.05 (CI/build domain). Normal priority — none of these block release.yml's
current use.
