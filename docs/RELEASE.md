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
| `build-linux`   | `ubuntu-latest`  | `vaporwault-<tag>-linux-x86_64.tar.gz` (+ `.sha256`), plus `vapourwault-server`/`vapourwault-client` `.deb` and `.rpm` packages |
| `build-windows` | `windows-latest` | `vaporwault-<tag>-windows-x86_64.zip` (+ `.sha256`), plus `vapourwault-server`/`vapourwault-client` `.msi` installers |
| `publish`       | `ubuntu-latest`  | A GitHub Release named `<tag>` with all of the above attached |

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

### Web gateway + frontend (`vapourwault-web-gateway`, `web/dist/`)

**Not currently produced by this workflow.** `vapourwault-web-gateway`
(`src/gateway/`, `TASK-127`–`TASK-135`) and the static frontend (`web/`,
`TASK-136`–`TASK-141`) are a real release-worthy artifact pair for
deployments that want the browser client (see `docs/DEPLOYMENT.md`'s "Web
gateway + nginx + frontend deployment" section, `TASK-142`) — but two things
stand in the way of `release.yml` producing them alongside everything above:

- `VW_BUILD_WEB_GATEWAY` defaults `OFF` and neither the `build-linux` nor
  `build-windows` job passes `-DVW_BUILD_WEB_GATEWAY=ON`, so the gateway
  binary is not compiled at all in a normal release build today.
- The workflow has no step that runs `web/`'s own build (`npm install &&
  npm run build`, `web/package.json`) — it's an entirely separate,
  non-CMake-orchestrated build step (by design, `TASK-136`) that
  `release.yml` has never been taught to invoke.

Until that's wired up, produce both manually from the same tagged source
checkout you'd otherwise download the release archive from:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DVW_BUILD_WEB_GATEWAY=ON
cmake --build build --target vapourwault-web-gateway
cd web && npm install && npm run build
```

This produces `build/bin/vapourwault-web-gateway` and `web/dist/` locally,
same as any other development build — see `docs/DEPLOYMENT.md` §11.2 for
the full build-and-deploy path. Flagged as a follow-up in §8 below; not
solved in this pass (`TASK-142` is scoped to packaging/deployment docs, not
`release.yml` itself).

### Installer packages (`.deb` / `.rpm` / `.msi`)

Since `TASK-145`–`TASK-151`, the workflow also builds proper OS-native
installer packages via CMake's CPack (`cmake/Packaging.cmake`), one per
component — **`server`** and **`client`** are independently installable,
matching how `packaging/linux/install.sh` vs `client_install.sh` (and the
two `Install-VaporWault*.ps1` scripts) were always split. These packages
are additive: the plain tarball/zip above is still produced and still
useful for scripted or air-gapped deployments.

| Format | Server package | Client package |
|--------|---------------|----------------|
| Debian/Ubuntu (`.deb`) | `vapourwault-server_<version>_amd64.deb` | `vapourwault-client_<version>_amd64.deb` |
| Fedora/RHEL (`.rpm`)   | `vapourwault-server-<version>-1.x86_64.rpm` | `vapourwault-client-<version>-1.x86_64.rpm` |
| Windows (`.msi`)       | `vapourwault-server-<version>-win64.msi` | `vapourwault-client-<version>-win64.msi` |

What each package does on install (maintainer scripts:
`packaging/linux/scripts/`; WiX fragments: `packaging/windows/wix/`):

- **Server** (`.deb`/`.rpm`/`.msi`, requires root/Administrator): creates
  the `vapourwault` system user, `/etc/vapourwault`, `/var/lib/vapourwault`,
  `/run/vapourwault` (or the Windows equivalents), installs a
  `server.conf` template only if one doesn't already exist, and registers
  the service (`systemd` unit on Linux, a real Windows Service —
  `ServiceInstall`/`ServiceControl` — plus a firewall rule on Windows). It
  does **not** enable/start the service automatically — configure
  `server.conf` first, then start it yourself (same philosophy
  `install.sh` always used).
- **Client** (`.deb`/`.rpm`/`.msi`, no elevation required): installs the
  daemon/CLI binaries and a systemd **user** unit
  (`/usr/lib/systemd/user/`, available to any user via `systemctl --user`)
  or, on Windows, registers a per-user Scheduled Task (logon trigger) via
  an MSI custom action. Since the daemon is a per-user service, the
  package itself does not (and cannot, from a root-run install script)
  start it for a specific user — run `systemctl --user enable --now
  vapourwault-daemon` (Linux) yourself after installing, or let the
  Windows Scheduled Task start at your next logon.

**Removing a package — DEB and RPM behave differently, by design of each
ecosystem, not a bug**:

| Action | DEB | RPM |
|--------|-----|-----|
| `apt remove` / `dnf remove` | Keeps config (`/etc/vapourwault`) and data (`/var/lib/vapourwault`) | **Deletes everything** — RPM has no separate "purge" concept distinct from final removal |
| `apt purge` | Deletes config, data, and the `vapourwault` system user | *(not applicable — `dnf remove` already does this)* |

If you're moving from Debian/Ubuntu habits to a Fedora/RHEL host, note that
`dnf remove` is the equivalent of `apt purge`, not `apt remove` — there is
no gentler removal option on the RPM side. An in-place **upgrade**
(`apt install` over an existing version, or `rpm -U`/`dnf upgrade`) never
deletes config or data on either format, and an admin-edited `server.conf`
is never overwritten by a reinstall or upgrade on any package format.

**These packages are unsigned.** No code-signing certificate or GPG
signing key currently exists for this project. Installing them will
trigger the normal OS warnings for unsigned software — `apt`/`dnf` will
warn about an unsigned package (still installable, since these aren't
pulled from a signed repository at all), and Windows will show its usual
SmartScreen/unknown-publisher prompt for the `.msi`. This is an accepted
gap, not an oversight — revisit if/when this project sets up
code-signing infrastructure.

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

## 6. WiX Toolset vendoring (Windows installer build)

CPack's WIX generator (used to build the `.msi` installers, `TASK-147`/`TASK-148`)
needs WiX Toolset **v3** (`candle.exe`/`light.exe` — not the newer v4/v5 unified
CLI). `windows-latest` doesn't ship it, so the workflow installs it via
Chocolatey (`choco install wixtoolset`) first. If that fails, it falls back to
fetching the `wix` NuGet package directly (a plain zip containing the same
binaries) and adding its `tools/` directory to `PATH` — this fallback path is
proven to work (it's exactly how this feature's own implementation was verified,
since the Chocolatey install hit a sandbox-specific permission error in that
environment) but has not been exercised by a real CI run yet, since the primary
`choco` path hasn't been confirmed to fail there. Watch the "Install WiX Toolset
v3" step's log on the first real release build to see which path was taken.

`cpack -G WIX` is invoked **twice** — once per component (`server`, `client`),
each with its own `CPACK_WIX_UPGRADE_GUID` (permanently fixed per product; never
regenerate) and its own `CPACK_PACKAGE_FILE_NAME` override. The explicit filename
override matters: without it, both invocations produce the same default filename
and the second silently overwrites the first's `.msi` — a real bug caught while
building this feature, not a hypothetical.

## 7. Security notes

- The workflow's default token permission is `contents: read`; only the `publish`
  job elevates to `contents: write` (needed for `gh release create`/`upload`).
- Tag/ref-derived values (`github.ref_name`) are only ever read through job-level
  `env:` and referenced as shell/PowerShell environment variables (`$TAG` /
  `$env:TAG`) — never interpolated directly as a `${{ }}` expression inside a
  `run:` block. Direct interpolation of ref-controlled values into a shell script
  is a known GitHub Actions script-injection vector; this workflow was reviewed
  and fixed for that pattern (see `TASK-081`). `PKG_VERSION` (the
  installer packages' version string, `TASK-151`) follows the same discipline —
  derived from `$TAG`/`$env:TAG`, never from a raw `${{ }}` expression.
- The installer packages' maintainer scripts (`packaging/linux/scripts/`) run as
  root during install/removal on the end user's machine, and the client MSI's
  custom action shells out to PowerShell (`packaging/windows/wix/`) — reviewed
  for the same class of argument-injection risk as above; see `TASK-153`.

## 8. Known limitations / follow-ups

Tracked in `TASK-082`:

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

Tracked in `TASK-151`/`TASK-152.md` (installer packages, `TASK-145`):

- The packages themselves have been installed, upgraded, and removed for real in
  disposable containers/build environments during development (see
  `TASK-149`/`TASK-150.md`'s implementation notes) — but never yet
  through an actual GitHub Actions run of this workflow. The `choco`-vs-NuGet-zip
  WiX fallback (§6 above) and the `gh release create`/`upload` step with the
  larger 8-artifact file list are both unverified against the real runner
  environment.
- No automated test installs the Windows MSIs on a real Windows machine — that
  remains manual/VM-based verification (`TASK-152`).

Tracked in `TASK-142` (web gateway + frontend deployment docs):

- `release.yml` does not build `vapourwault-web-gateway` or `web/`'s static
  frontend at all (`VW_BUILD_WEB_GATEWAY` stays at its `OFF` default in both
  `build-linux` and `build-windows`, and there's no `npm` build step) — see
  the "Web gateway + frontend" section above. A future task should add
  `-DVW_BUILD_WEB_GATEWAY=ON`, a Node.js setup step, and the `npm run build`
  invocation to both jobs, then decide whether the gateway binary and
  `web/dist/` ship inside the existing tarball/zip or as their own archive.
- Relatedly, the gateway has no CPack installer component yet either
  (`CMakeLists.txt`'s comment above its `install()` rules: "file a follow-up
  if/when it needs one") — it currently only installs as a plain executable
  via `cmake --install`, not via any `.deb`/`.rpm`/`.msi`. `docs/DEPLOYMENT.md`
  §11.5 documents the manual/`cmake --install` path as the only option today.
- `VENDOR_SETUP.md` does not yet list Node.js/npm as a build prerequisite,
  even though building `web/` now requires them (`docs/DEPLOYMENT.md` §11.6
  calls this out inline instead, since updating `VENDOR_SETUP.md` itself was
  out of this task's scope).
