---
id:          TASK-233
title:       "CI: Android build job (Gradle + NDK)"
status:      todo
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-31
priority:    normal
depends_on:  [TASK-225]
blocks:      [TASK-235]
review_by:   [CQR.08]
tags:        []
---

Add Android build validation to CI so the app doesn't silently bit-rot the
way the web gateway's build did before it was wired in (`VW_BUILD_WEB_GATEWAY`
still defaults `OFF` and isn't in `release.yml` — don't repeat that gap here
if avoidable).

Scope:
- New job/matrix leg in `.github/workflows/ci.yml`: set up JDK + Android
  SDK/NDK, run `./gradlew assembleDebug` (and unit tests if any exist by this
  point) for the `android/` project.
- Document required SDK/NDK/Gradle versions — either a new
  `docs/ANDROID_BUILD.md` or an addendum to `VENDOR_SETUP.md` (which today
  has no Node.js/npm prerequisite documented for the existing web frontend
  either — don't leave the same gap for Android).
- Pin exact NDK version consistent with the 16 KB page-size compliance
  requirement for new Play Store submissions (AGP ≥ 8.5.1, NDK ≥ r28 handle
  this automatically; verify whatever gets pinned actually clears that bar).

## Acceptance criteria

- CI fails if the Android app fails to build, the same way it already does
  for the Linux/Windows targets.
- Toolchain version requirements are documented somewhere a new contributor
  would actually find them.

## Notes
