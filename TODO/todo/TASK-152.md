---
id:          TASK-152
title:       "Verify installer install/uninstall/upgrade behavior end-to-end"
status:      todo
assignee:    QA.06
created_by:  ARCH.00
created:     2026-08-11
priority:    high
depends_on:  [TASK-147, TASK-148, TASK-149, TASK-150]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [test, build, security-sensitive]
---

None of `TASK-147`–`TASK-150`'s packages were installed on a real machine
during implementation (each explicitly avoided mutating the dev
environment's live system state — registering services, scheduled tasks,
system users, and firewall rules are real, hard-to-reverse actions). This
task is the actual install/uninstall/upgrade verification, ideally in
disposable VMs or containers, not a dev machine.

Required coverage, per package:

1. **Fresh install** — service/scheduled-task registers correctly, config
   template is created, binaries land where documented.
2. **Re-install / upgrade over an existing install** — an operator's
   edited config is NOT overwritten; the service/scheduled task correctly
   restarts with the new binary; `CPACK_WIX_UPGRADE_GUID` (Windows) is
   confirmed to actually trigger MSI's upgrade path rather than a
   side-by-side install or a hard failure.
3. **Uninstall (keep data)** — DEB `apt remove` / RPM `dnf remove` /
   MSI uninstall: service stopped and removed, binaries gone, but
   `/etc/vapourwault`, `/var/lib/vapourwault` (or Windows equivalents)
   survive. Note `TASK-150`'s documented DEB/RPM asymmetry here — confirm
   `dnf remove` really does behave like `apt purge`, not `apt remove`, and
   that this is accurately reflected in whatever `docs/RELEASE.md` ends up
   saying (`TASK-154`).
4. **Full purge** — DEB `apt purge` / MSI uninstall with data removal
   (however `TASK-148`'s custom action exposes that, if at all): data and
   config actually gone, service user removed (Linux).
5. **Client Scheduled Task specifically** (Windows): confirm it runs in the
   correct user's security context (not SYSTEM), survives logoff/logon,
   and that uninstall actually removes it — this is the concern SEC.07
   flagged during `TASK-145`'s design review as the reason the client MSI
   must be per-user/no-elevation; confirm that constraint actually holds in
   the built package, not just in the design.
6. Both Linux packages installed on a real (or containerized) Debian/Ubuntu
   and Fedora/RHEL system respectively — this project has no CI job
   exercising Linux package installability yet, so this may be the first
   time either package is actually installed anywhere.

## Acceptance criteria

- All six package/scenario combinations above pass.
- Any bug found gets a regression test or a fix filed against the
  responsible task (`TASK-147`–`TASK-150`), per standing QA.06 policy.
- Sign-off note added here before `TASK-145`'s milestone is considered
  closable.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-11]: Filed as part of the `TASK-145` installer packaging
design's initial implementation wave. This is the single most important
unverified gap in this wave — everything upstream was reasoned through
carefully but none of it has actually been installed anywhere yet.

BLD.05 [2026-08-11]: Update — significantly more of this task's scope got
covered than expected during `TASK-149`/`TASK-150`'s own implementation,
using disposable Docker containers (`ubuntu:24.04`, `fedora:40`) that
turned out to be available. Re-scoping what's actually left:

**Already verified for real, both DEB and RPM, in disposable containers**
(not simulated, not reasoned-through-only):
- Fresh install: service user, directories/permissions, config templating,
  binaries, systemd unit placement — all confirmed by direct inspection
  (`id`, `ls -la`, `cat`), not just "the script ran without error."
- `apt remove` keeps config/data; `apt purge` deletes everything including
  the service user — confirmed explicitly, including that an admin-edited
  config survives a reinstall.
- RPM upgrade (`rpm -U` between two actually-built versions, 1.2.3 →
  1.2.4): config edit and service user both survive — confirms the
  `%postun` `$1 >= 1` branch. Final removal after that (`dnf remove`,
  `$1 == 0`): confirms RPM's no-purge-distinction behavior for real.
- Client package install/remove/purge on both formats (binaries, systemd
  user unit at the correct system-wide path, informational postinst
  message).

**Item 3 (`systemctl --user` startup) is now done, and it wasn't clean** —
tested for real in a `jrei/systemd-ubuntu` disposable container with an
actual `loginctl enable-linger` user session (not root, not simulated):
found and fixed a real bug. `packaging/linux/vapourwault-daemon.service`
(shipped by this package's original `install()` rule) has
`ExecStart=%h/.local/bin/vapourwault-daemon`, written for
`client_install.sh`'s manual/tarball layout — but the `.deb`/`.rpm`
package installs the binary to `/usr/bin/`, so the shipped service failed
every single start with systemd exit code 203 (exec: file not found).
Fixed with a package-specific unit file
(`packaging/linux/vapourwault-daemon-pkg.service`,
`TASK-149`'s implementation note has the full detail); re-verified in the
same container afterward — `systemctl --user enable --now
vapourwault-daemon` reaches `active (running)`, stays running, creates its
state files correctly, and `disable`/`apt remove` clean up correctly. This
would have shipped completely non-functional if this specific check hadn't
been done — the earlier "unit file lands at the right systemd path"
verification (`TASK-149`) could not have caught it.

**Item 2 (real GitHub Actions run) is now done**, per the user's explicit
request to actually dispatch it. Took three attempts and found two more
real bugs neither local testing nor the earlier container-based Linux
testing could have caught (full detail in `TASK-151`'s implementation
note): a diagnostics gap (CPack's "Problem running WiX" hid the actual
`wix.log` content on failure), and an MSI version-format bug
(`Product/@Version` must be strictly numeric, and the dry run's own
default tag broke it). Third attempt was fully green: both platform
builds succeeded, `Publish GitHub Release` correctly skipped (dry runs
never publish), and all 8 expected artifacts were downloaded and confirmed
present with correct names.

**Item 1 (Windows real installs) is partially done, for real, on the
user's own dev machine** (explicitly authorized) — not a VM, since none
was available, but genuinely installed via `msiexec /i`, not simulated:

- **Client MSI**: installed and uninstalled for real. Found and fixed a
  real bug — the custom action never ran at all on the first attempt
  (WiX's linker drops any Fragment nothing references; confirmed via
  direct MSI-database inspection that the `CustomAction` table was
  completely empty of the intended entries). Fixed and re-verified the
  same way. After the fix, the custom action ran with correctly-resolved
  arguments (confirmed via the verbose MSI log), but `Register-ScheduledTask`
  itself failed with "Access is denied" — isolated to this specific
  machine's Group Policy blocking non-admin creation of **logon-triggered**
  scheduled tasks specifically (`/SC ONCE` succeeds, `/SC ONLOGON` doesn't,
  tested independently of the MSI entirely via bare `schtasks.exe`). Full
  task registration remains unverified — needs a machine without this
  specific policy (a personal/unmanaged Windows install, or a real VM).
- **Server MSI**: still not installed. This session is not running
  elevated (confirmed: `IsAdmin: False`), and the server MSI's
  `ServiceInstall` genuinely requires Administrator rights — there's no
  way to self-elevate without real admin credentials, which this session
  doesn't have access to. Offered the user two paths (run it themselves
  elevated and report back, or leave this as a follow-up); awaiting their
  choice.

Not moving to `review` yet — the server MSI real-install gap and the
client MSI's Scheduled-Task-under-Group-Policy gap are both still real,
unstarted verification, not formality sign-off.
