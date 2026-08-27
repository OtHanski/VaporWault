---
id:          TASK-149
title:       "Linux .deb packages for server & client (CPack DEB + maintainer scripts)"
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-11
priority:    high
depends_on:  [TASK-145, TASK-146]
blocks:      [TASK-150]
review_by:   [SEC.07, CQR.08]
tags:        [build, linux, security-sensitive]
---

Build proper `.deb` packages for both components via CPack's DEB
generator, absorbing `install.sh`/`client_install.sh`'s logic into
maintainer scripts (kept as-is for the manual/tarball path — not removed).

Scope:

1. `CPACK_DEBIAN_SERVER_PACKAGE_NAME "vapourwault-server"`,
   `CPACK_DEBIAN_CLIENT_PACKAGE_NAME "vapourwault-client"` (+ `_DEPENDS`,
   `_SECTION`, `_PRIORITY` as appropriate).
2. New `packaging/linux/scripts/` — shared portable POSIX-`sh` logic,
   invoked as DEB scriptlets (this task) and RPM scriptlets (`TASK-150`),
   per `TASK-145`'s "write once, thin per-ecosystem wrapper" design:
   - `server-postinst.sh`: create the `vapourwault` system user (matching
     `install.sh`'s `useradd --system` block), create
     `/var/lib/vapourwault`, `/etc/vapourwault`, `/run/vapourwault` with
     correct ownership/permissions, install the config template to
     `/etc/vapourwault/server.conf` **only if absent**, `systemctl
     daemon-reload` — deliberately does NOT `systemctl enable --now`
     (matching `install.sh`'s existing behavior of letting the admin
     configure `server.conf` first).
   - `server-prerm.sh`: stop the service if running, before file removal.
   - `server-postrm.sh`: on full removal (not upgrade) only, remove
     `/var/lib/vapourwault`, `/run/vapourwault`, the service user — must
     correctly distinguish DEB's `postrm remove` (keep config/data) from
     `postrm purge` (delete everything, `dpkg`'s own established
     convention), i.e. only delete `/etc/vapourwault` on `purge`.
   - Equivalent `client-*` scripts for the `--user`/no-root client path
     (systemd `--user` unit reload; no system user to create/remove).
3. Wire via `CPACK_DEBIAN_SERVER_PACKAGE_CONTROL_EXTRA "...;postinst;
   prerm;postrm"` (and the `client` equivalents).

## Acceptance criteria

- `cpack -G DEB` (from a Linux build) produces
  `vapourwault-server_<version>_amd64.deb` and
  `vapourwault-client_<version>_amd64.deb`.
- `dpkg -c` on each package shows the expected file layout with correct
  ownership/permission metadata.
- Maintainer scripts pass `shellcheck` (or equivalent) with no warnings
  about unquoted variables/word-splitting — the same class of care
  `TASK-081` required for `release.yml`'s shell steps.
- **Not verified end-to-end in this pass** (no Linux environment available
  this session to actually `apt install`/`apt remove`/`apt purge` and
  confirm real behavior) — `TASK-152`'s job, and should block this task's
  `review` → `done` transition.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-11]: Filed as part of the `TASK-145` installer packaging
design's initial implementation wave. Tagged `security-sensitive` — these
scripts run as root during package install/removal.

BLD.05 [2026-08-11]: Implemented and — unlike `TASK-147`/`TASK-148` — fully
installed and uninstalled for real, in a disposable Docker container
(`ubuntu:24.04`, `docker run --rm`), since a Linux environment turned out
to be available in this session after all (WSL2 for building, Docker
Desktop for disposable install testing) where Windows MSI testing had to
stop at structural verification.

**Design correction from the original filing**: the client package's
maintainer scripts ended up **deliberately near-empty**, not a port of
`install.sh`'s logic. The client daemon is a per-user `systemd --user`
service; DEB/RPM maintainer scripts always run as root at package-install
time, before any specific end user is known, so there is no system-wide
directory/user to create the way `server-postinst` does. The systemd user
unit is installed to `/usr/lib/systemd/user/` (system-wide, available to
every user's `--user` manager — already the existing CMakeLists.txt
`install()` destination from the web-gateway work) rather than
`~/.config/systemd/user/` (which only makes sense for
`client_install.sh`'s single-specific-user tarball install). `client/prerm`
and `client/postrm` are intentionally no-ops with comments explaining why
reaching into other users' session buses from a root script would be
fragile — this is a real, documented design choice, not an oversight.

**One packaging-mechanics fix needed**: `CPACK_DEBIAN_<COMPONENT>_PACKAGE_CONTROL_EXTRA`
copies listed files as-is — it does not rename them — so maintainer
scripts must already be named exactly `postinst`/`prerm`/`postrm` (no
extension) for dpkg to recognize their role. Restructured from flat
`packaging/linux/scripts/server-postinst.sh`-style names into
`packaging/linux/scripts/{server,client}/{postinst,prerm,postrm}`
subdirectories with bare names. Also needed `CPACK_DEBIAN_FILE_NAME
"DEB-DEFAULT"` — without it, the per-component `PACKAGE_NAME` only changed
the package's internal `Package:` metadata field, not the actual output
filename (verified empirically: same class of "config variable set but
generator ignores it for this specific aspect" surprise as `TASK-146`'s
`CPACK_COMPONENTS_GROUPING` finding).

Also added, not in the original scope but required for `server-postinst`
to have something to template: `install(FILES
packaging/linux/{server,client}.conf.example DESTINATION
share/vapourwault COMPONENT {server,client})` in the top-level
`CMakeLists.txt` (these example configs had never been installed via
CMake before — only shipped inside the tarball via `packaging/linux/`
directly).

**Verified end-to-end, both packages, in `ubuntu:24.04`**:
- Fresh install: service user created (`vapourwault`, system UID),
  `/etc/vapourwault` `/var/lib/vapourwault` `/run/vapourwault` created
  `750` owned by that user, `server.conf` templated from the example,
  binaries on `PATH`, systemd unit files land at the correct system-wide
  paths (`/usr/lib/systemd/system/vapourwaultd.service`,
  `/usr/lib/systemd/user/vapourwault-daemon.service`).
- `apt remove`: binaries gone, config/data survive.
- Reinstall after `remove`: an admin-edited `server.conf` (appended a
  marker line) is **not** overwritten — confirmed by inspecting the file
  content after reinstall, not just assumed.
- `apt purge`: `/etc/vapourwault`, `/var/lib/vapourwault`, and the service
  user are all gone afterward — confirmed by explicit checks, not just
  "the script ran."
- Client package: install/remove/purge all completed cleanly; the
  informational postinst message printed as designed with no error, even
  though there's no real `systemd --user` session in a plain container to
  actually verify daemon startup against (that gap remains real, see
  below).

**Update, `TASK-152`**: `shellcheck` has since been run for real
(`TASK-153`) — clean, zero findings. The `systemctl --user` startup gap
noted below has also since been closed, and it was **not** a clean pass —
a real bug was found:

`packaging/linux/vapourwault-daemon.service` (the file this task's
`install()` rule originally shipped inside the package,
`ExecStart=%h/.local/bin/vapourwault-daemon ...`) was written for
`client_install.sh`'s manual/tarball install location, not this package's
`/usr/bin/vapourwault-daemon` location. Installed and started for real in
a `systemd`-enabled disposable container (`jrei/systemd-ubuntu`, a real
user session via `loginctl enable-linger` + `systemctl --user`): the
service failed immediately with systemd exit code 203 (executable not
found) every time, because `%h/.local/bin/vapourwault-daemon` simply
doesn't exist for a package install. Fixed by adding a separate
`packaging/linux/vapourwault-daemon-pkg.service` (identical except
`ExecStart=/usr/bin/vapourwault-daemon ...`) and pointing this task's
`install()` rule at it (via `RENAME vapourwault-daemon.service`, so
`systemctl --user` still sees the expected unit name either way) —
`client_install.sh`'s own copy of the original file is untouched. Rebuilt
and reinstalled in the same running container: `systemctl --user
enable --now vapourwault-daemon` now reaches `Active: active (running)`,
stayed running (checked again after 16+ seconds, not crash-looping),
created its state files (`cache.db`, `sync_folders.db`, `daemon.pid`) in
the correct per-user directory, and `disable --now` / `apt remove`
afterward both cleaned up correctly.

This is exactly the kind of bug that "the file lands at the right systemd
path" verification (what this task originally checked) cannot catch —
only actually starting the service does. Worth remembering: a shipped
artifact being present in the right place is not the same as it working.

Moving to `review` — needs SEC.07 + CQR.08 sign-off per the
`security-sensitive` tag. Given how much of this was actually verified
end-to-end already, expect this review to focus on the maintainer
scripts' shell-quoting discipline and the accepted client-side limitations
above, not "does this even work."

SEC.07/CQR.08 [2026-08-12]: Reviewed all six scripts
(`packaging/linux/scripts/{server,client}/{postinst,prerm,postrm}`)
directly, beyond the bare shellcheck-clean claim. All six are correctly
quoted throughout, idempotent, run under `set -e` with explicit `|| true`
on the specific calls where that's the correct behavior (non-critical
best-effort steps), and no unvalidated interpolation into `sh -c`/`eval`.

**Found and fixed**: `server/postinst`'s header comment claimed it runs
under RPM's `%post` "via a thin rpm-specific wrapper... see
packaging/linux/scripts/rpm/server-post" — no such file exists (only
`rpm/server-postun.sh` does; `Packaging.cmake` wires `%post` straight to
this same `postinst` file with no wrapper at all, since `%post`'s
argument convention doesn't differ from DEB's the way `%postun`'s does).
Stale/misleading comment, not a behavioral bug — corrected to describe
the actual wiring.

No blocking findings. Client-side limitations (near-empty maintainer
scripts, no root-run systemd --user reach) remain correctly documented
as accepted design, not oversights.
Sign-off: `SEC.07` + `CQR.08` requirements satisfied. Ready for `done`.
