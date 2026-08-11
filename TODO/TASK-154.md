---
id:          TASK-154
title:       Document installer packages in docs/RELEASE.md and docs/DEPLOYMENT.md
status:      review
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-11
priority:    normal
depends_on:  [TASK-151]
blocks:      []
review_by:   [CQR.08]
tags:        [docs]
---

Document the new installer packages once `TASK-151` has them flowing
through CI. Update:

- `docs/RELEASE.md`: what the release workflow now produces (extend the
  existing artifact table with the four `.deb`/`.rpm` files and two
  `.msi` files), and explicitly document the DEB/RPM removal-semantics
  asymmetry `TASK-150` introduces (`dnf remove` behaves like `apt purge`,
  not `apt remove`) — a real, user-visible difference between the two
  formats, not an implementation detail to bury.
- `docs/DEPLOYMENT.md`: end-user install/uninstall/upgrade instructions per
  package format (`apt install ./vapourwault-server_*.deb`,
  `dnf install ./vapourwault-server-*.rpm`, double-clicking or
  `msiexec /i` the MSI), alongside the existing tarball/PowerShell-script
  instructions (kept, not replaced, per `TASK-145`'s design — this is now
  documented as the "manual/advanced" path with the packages as the
  standard path).
- Explicit note that all packages are **unsigned** — installing will
  trigger the OS's usual untrusted-publisher warnings
  (`apt`/`dnf`'s unsigned-package prompt, Windows SmartScreen) until
  code-signing infrastructure exists (not currently planned/budgeted).

## Acceptance criteria

- A new user can go from "downloaded a release" to "service running" using
  only `docs/DEPLOYMENT.md`, for any of the six package formats.
- The unsigned-package caveat and the DEB/RPM removal-semantics asymmetry
  are both stated plainly, not just implied.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-11]: Filed as part of the `TASK-145` installer packaging
design's initial implementation wave. Depends only on `TASK-151` (CI
wiring) since docs describe the shipped artifact shape, which isn't final
until that task lands — can start drafting earlier in practice, but
shouldn't claim final accuracy until `TASK-151` is done.

BLD.05 [2026-08-11]: `docs/RELEASE.md` updated — extended the artifact
table (§1), added a full "Installer packages" subsection covering what
each package does on install per component/format, an explicit DEB-vs-RPM
removal-semantics table (verified for real against `TASK-149`/`TASK-150`'s
actual container testing, not just described from the design), the
unsigned-packages disclosure, a new §6 on WiX Toolset vendoring (including
the real bug this session caught — both `cpack -G WIX` invocations
producing the same filename until `CPACK_PACKAGE_FILE_NAME` was added),
and extended §7 (security notes)/§8 (known limitations) for the new
surface. `docs/DEPLOYMENT.md`'s end-user install/uninstall instructions
(the other half of this task's scope) were **not** updated in this pass —
flagging as remaining work; `docs/RELEASE.md`'s new section already covers
the install commands at a reference level (`apt install ./...deb`, etc.)
but `docs/DEPLOYMENT.md` is the more end-user-facing document and deserves
its own pass rather than a rushed addition here.

Moving to `review` — needs CQR.08 sign-off, with the `docs/DEPLOYMENT.md`
gap called out explicitly as unfinished scope.
