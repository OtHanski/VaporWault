# VaporWault — Release Guide

**Audience**: maintainers cutting a VaporWault release.
**Owner**: BLD.05 (per `CLAUDE.md`).

This document describes `.github/workflows/release.yml`, the workflow that builds
distributable binaries and publishes them as a GitHub Release. For building from
source for local development, see `VENDOR_SETUP.md`. For installing and operating a
built server/client, see `docs/DEPLOYMENT.md`.

---

## 1. What the workflow does

On every push of a tag matching `v*`, three jobs run:

| Job             | Runner           | Produces |
|-----------------|------------------|----------|
| `build-linux`   | `ubuntu-latest`  | `vaporwault-<tag>-linux-x86_64.tar.gz` (+ `.sha256`) |
| `build-windows` | `windows-latest` | `vaporwault-<tag>-windows-x86_64.zip` (+ `.sha256`) |
| `publish`       | `ubuntu-latest`  | A GitHub Release named `<tag>` with both archives attached |

Both platform builds compile with `CMAKE_BUILD_TYPE=Release`, `VW_WERROR=ON`
(matching CI's warning bar), `VW_BUILD_TESTS=OFF` (correctness is already validated
by `.github/workflows/ci.yml` on every push to `main` — this workflow's job is to
produce artifacts, not re-run the suite), and **`VW_BUILD_GUI=ON`** — unlike
`ci.yml`, which builds with GUI disabled. That means release archives include the
GUI binaries (`vapourwault-gui`, `vapourwault-server-gui`) alongside the headless
server/client/tools:

- `vapourwaultd`, `vapourwault-server-cli` (server)
- `vapourwault-daemon`, `vapourwault-cli` (client)
- `vapourwault-server-gui`, `vapourwault-gui` (GUI, GUI-enabled builds only)
- `vwdump` (admin tool)
- `README.md`

## 2. Cutting a release

```sh
git tag v0.2.0
git push origin v0.2.0
```

That's it — pushing the tag triggers the workflow. Watch it under the repo's
**Actions** tab. When all three jobs go green, the release is live under
**Releases** with both archives and their `.sha256` checksum files attached, and
auto-generated release notes (from commits/PRs since the previous tag, via
`gh release create --generate-notes`).

**Versioning**: tags follow `vMAJOR.MINOR.PATCH` (e.g. `v0.2.0`). There is no
in-repo `VERSION` file or embedded version string yet — the git tag is the only
source of truth for a release's version. Pre-release tags (e.g. `v0.2.0-rc1`) will
build and publish like any other tag; the workflow does not currently mark them as
a GitHub "pre-release" — treat that as a manual step (edit the release after
publishing) until that's automated.

**Re-running for the same tag**: if a run fails partway through, fix the issue and
re-run the workflow (or re-push the same tag after deleting and recreating it — not
recommended; prefer re-running the existing workflow run). The `publish` job
detects whether a release for the tag already exists and uploads/overwrites assets
(`gh release upload --clobber`) instead of failing with "release already exists".

## 3. Dry-running without publishing

The workflow also accepts manual triggers via **Actions → Release → Run workflow**
(`workflow_dispatch`), with a `version` input used only to name the build
artifacts. Manual runs execute `build-linux` and `build-windows` exactly as a real
tag push would, but **never run the `publish` job** — no GitHub Release is created
or modified. Use this to validate the build/packaging steps (e.g. after touching
the SDL2 vendoring step or the CMake configure flags) without cutting a real tag.

## 4. Verifying a downloaded release archive

Each archive ships with a `.sha256` sidecar file:

```sh
# Linux
sha256sum -c vaporwault-v0.2.0-linux-x86_64.tar.gz.sha256
```

```powershell
# Windows
(Get-FileHash vaporwault-v0.2.0-windows-x86_64.zip -Algorithm SHA256).Hash
# compare against the contents of the .sha256 file
```

## 5. SDL2 vendoring (Windows GUI build)

Linux release builds get SDL2 from the system package manager
(`apt install libsdl2-dev`). Windows has no equivalent, so the workflow downloads
the official SDL2 VC devel package and vendors it into `third_party/SDL2/` for the
duration of the build (same layout `VENDOR_SETUP.md` describes for manual local
setup).

The download is pinned to an exact version and verified against a pinned SHA-256
checksum before extraction (`env.SDL2_VERSION` / `env.SDL2_ZIP_SHA256` in
`release.yml`) — a build fails loudly rather than silently linking against a
tampered or unexpectedly-changed asset.

**Bumping the SDL2 version**: update both `SDL2_VERSION` and `SDL2_ZIP_SHA256` in
`release.yml`. Get the new checksum with:

```sh
curl -sL -o sdl2.zip \
  https://github.com/libsdl-org/SDL/releases/download/release-<version>/SDL2-devel-<version>-VC.zip
sha256sum sdl2.zip
```

`VENDOR_SETUP.md` documents only a *minimum* SDL2 version (currently 2.26.0) for
local/manual vendoring — keep that minimum consistent with whatever version
`release.yml` pins when bumping either one.

## 6. Security notes

- The workflow's default token permission is `contents: read`; only the `publish`
  job elevates to `contents: write` (needed for `gh release create`/`upload`).
- Tag/ref-derived values (`github.ref_name`) are only ever read through job-level
  `env:` and referenced as shell/PowerShell environment variables (`$TAG` /
  `$env:TAG`) — never interpolated directly as a `${{ }}` expression inside a
  `run:` block. Direct interpolation of ref-controlled values into a shell script
  is a known GitHub Actions script-injection vector; this workflow was reviewed
  and fixed for that pattern (see `TODO/TASK-081.md`).

## 7. Known limitations / follow-ups

Tracked in `TODO/TASK-082.md`:

- The GUI+SDL2 build combination is only ever compiled here, in the release
  workflow — `ci.yml` always builds with `VW_BUILD_GUI=OFF`. A GUI build/link
  regression would currently only surface when cutting a release, not on a
  regular PR.
- No smoke test runs the built binaries (e.g. `--version`/`--help`) before
  packaging/publishing — a binary that links but crashes on startup would still
  ship.
- Third-party actions (`actions/checkout`, `actions/upload-artifact`,
  `actions/download-artifact`, `ilammy/msvc-dev-cmd`) are pinned to version tags,
  not commit SHAs, matching `ci.yml`'s existing convention.
