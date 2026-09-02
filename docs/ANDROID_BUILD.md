# VaporWault — Android Build Guide

**Audience**: anyone building or contributing to the Android client (`android/`).
**Owner**: MOB.10 (per `CLAUDE.md`).

This document covers the toolchain required to build `android/` locally and what
`.github/workflows/ci.yml`'s `build-android` job validates on every push. For the
desktop/server toolchain (mbedTLS, Argon2, SDL2), see `VENDOR_SETUP.md` — the Android
app is a separate Gradle project with its own, unrelated toolchain requirements.

---

## Required toolchain

| Component | Version | Why this exact version |
|-----------|---------|-------------------------|
| JDK | 17 (Temurin recommended) | Minimum required by the Android Gradle Plugin (AGP) version below. |
| Android Gradle Plugin | 8.5.2 (pinned in `android/build.gradle`) | Meets the ≥ 8.5.1 floor for automatic 16 KB memory-page-size compliance (see below) together with the NDK version pinned here. |
| Android SDK Platform | `android-34` (`compileSdk`/`targetSdk`) | Matches `android/app/build.gradle`. |
| Android Build-Tools | `34.0.0` | Matches the SDK platform above. |
| CMake (SDK side-by-side) | `3.22.1` | Used by Gradle's `externalNativeBuild` to drive the NDK/CMake build in `android/app/src/main/cpp/CMakeLists.txt`. |
| NDK | `28.2.13676358` (pinned in `android/app/build.gradle`'s `ndkVersion`, r28b — the latest stable release as of this writing) | **Not arbitrary — see below.** |
| Gradle | 8.7 (via the committed wrapper, `android/gradlew`) | Always use the wrapper; do not rely on a system-installed Gradle. |

### Why NDK ≥ r28 specifically

Google requires new Play Store app submissions to support 16 KB memory page
sizes (some newer/future Android devices use a 16 KB page size instead of the
traditional 4 KB). AGP ≥ 8.5.1 combined with NDK ≥ r28 satisfies this
automatically for native code built through Gradle's `externalNativeBuild` —
no manual linker-flag changes needed. This project was originally scaffolded
against NDK r27.2.12479018 (below that bar); it was bumped to r28.2.13676358
and **re-verified with a real clean build plus a runtime smoke test on an
emulator** (not just "it compiles") as part of `TASK-233` before being pinned
here.

If you bump the NDK version further, do the same: a clean rebuild
(`rm -rf android/app/.cxx` first — Gradle/CMake's NDK-version change
detection is not always reliable) and an actual install-and-launch smoke
test, not just a successful `assembleDebug`.

---

## Local setup

1. Install JDK 17 and point `JAVA_HOME` at it.
2. Install the Android SDK cmdline-tools, then fetch the exact components
   above:
   ```
   sdkmanager "platforms;android-34" "build-tools;34.0.0" \
              "cmake;3.22.1" "ndk;28.2.13676358"
   ```
3. From `android/`, run `./gradlew assembleDebug` (uses the committed
   Gradle wrapper — do not invoke a different Gradle install).

No Android emulator/device is required just to build; one is only needed to
actually run the app (see the Android client design plan's manual
verification section, and `TASK-235`'s automated instrumented tests, for how
this project tests against a real `vapourwaultd`).

---

## What CI validates

`.github/workflows/ci.yml`'s `build-android` job installs the same pinned
toolchain versions listed above on a GitHub-hosted `ubuntu-latest` runner
(which ships a preinstalled Android SDK cmdline-tools under `$ANDROID_HOME` —
no third-party marketplace action needed to bootstrap it, matching this
project's minimal-external-dependency stance) and runs `./gradlew
assembleDebug`. This is build validation only, matching every other CI job
in this repo (`VW_BUILD_TESTS=OFF` is this project's standing CI-build
convention) — there are no Android unit tests yet to run, and instrumented
UI tests (`TASK-235`) run against a real emulator + server, which is a
separate, heavier concern from a build-validation gate.

**Keep the version table above in sync with `android/app/build.gradle` and
the CI job's `sdkmanager` install line** — a mismatch would mean this
document, the CI job, and a contributor's local build could all be silently
validating three different toolchains.
