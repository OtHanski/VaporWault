---
id:          TASK-239
title:       "Add the Android app to the release cycle (release.yml)"
status:      todo
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-09-02
priority:    normal
depends_on:  [TASK-233]
blocks:      [TASK-236]
review_by:   [CQR.08]
tags:        []
---

`.github/workflows/release.yml` (see `docs/RELEASE.md`) currently has exactly
three jobs — `build-linux`, `build-windows`, `publish` — and produces zero
Android artifacts. `TASK-233` adds Android to `ci.yml` (build **validation**
only, `./gradlew assembleDebug` on every push) but was explicitly scoped to
CI, not the release pipeline; nothing wires an APK into an actual tagged
GitHub Release. Filed while auditing the Android milestone
(`ARCHITECTURE.md`'s Phase 21) for what's still missing before it can be
marked complete — this is a genuine gap, not a maybe.

Scope:
- New `build-android` job in `release.yml`: set up the same JDK/SDK/NDK
  toolchain `TASK-233`'s CI job establishes, run a release build
  (`./gradlew assembleRelease` or `bundleRelease` — decide which; an AAB is
  what Play Store submission actually wants, an APK is what direct/sideload
  distribution wants, and this project doesn't have a Play Store presence
  yet, so the right answer here isn't obvious and depends on how the app is
  meant to reach users first), and attach the resulting artifact (+
  `.sha256`, matching the existing Linux/Windows artifacts' convention) to
  the `publish` job's GitHub Release.
- **Signing is an open question, not a detail to quietly resolve alone**: an
  Android release build must be signed to be installable outside of
  `adb install`. This project has no signing keystore or Play Store
  presence today. Do not silently ship a debug-signed "release" APK and
  call it done — either set up a real release keystore (stored as a GitHub
  Actions secret, matching how this workflow already treats `SDL2_ZIP_SHA256`/
  `WIX_ZIP_SHA256`-style supply-chain-sensitive material) with ARCH.00/the
  user's sign-off, or explicitly document (in `docs/RELEASE.md`, alongside
  the existing per-platform artifact table) that the attached build is
  debug-signed / sideload-only until that decision is made, so nobody
  mistakes it for something it isn't.
- Update `docs/RELEASE.md`'s "What the workflow does" table to add the new
  job/artifact row, matching its existing per-platform documentation style.

## Acceptance criteria

- A tagged release produces an Android build artifact attached to the
  GitHub Release, the same way Linux/Windows artifacts already are.
- The signing question above has an explicit, documented answer (either a
  real signing setup, or a clearly-labeled sideload-only interim artifact)
  — not silently defaulted to whatever `assembleRelease` does out of the
  box.
- `docs/RELEASE.md` accurately describes the new job.

## Notes

ARCH.00, 2026-09-02: Filed in response to the user asking whether Android
was already in the release cycle (it wasn't) — added as a blocker on
`TASK-236` (Android milestone closure) so that task cannot mark the
milestone complete while this gap still exists.
