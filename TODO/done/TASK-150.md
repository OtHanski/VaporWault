---
id:          TASK-150
title:       "Linux .rpm packages for server & client (CPack RPM, reusing TASK-149 scripts)"
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-11
priority:    normal
depends_on:  [TASK-145, TASK-146, TASK-149]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [build, linux, security-sensitive]
---

Build proper `.rpm` packages for both components via CPack's RPM
generator, reusing `TASK-149`'s `packaging/linux/scripts/*.sh` content
where the two ecosystems' scriptlet argument conventions allow.

Scope:

1. `CPACK_RPM_SERVER_PACKAGE_NAME "vapourwault-server"`,
   `CPACK_RPM_CLIENT_PACKAGE_NAME "vapourwault-client"` (+ `_REQUIRES` for
   the `systemd` dependency).
2. Wire `CPACK_RPM_<COMPONENT>_POST_INSTALL_SCRIPT_FILE`,
   `_PRE_UNINSTALL_SCRIPT_FILE`, `_POST_UNINSTALL_SCRIPT_FILE` to
   `TASK-149`'s scripts directly where the content is identical (the
   create-user/directories/config-template logic doesn't depend on which
   package manager invoked it).
3. **Argument-convention difference that can't be shared verbatim**: RPM's
   `%preun`/`%postun` receive `$1` as an install-count (`0` = final
   removal, `>=1` = upgrade in progress), not DEB's `remove`/`purge`
   string argument. `server-postrm.sh`'s purge-vs-remove branch (checking
   `$1 = "purge"`) does not translate directly — write a thin
   `rpm-server-postun.sh` wrapper that checks `$1 -eq 0` before calling
   into the shared cleanup logic, rather than trying to force one script to
   parse both conventions.
4. RPM has no separate "purge" concept (no config/data distinction
   equivalent to DEB) — document this explicitly in `docs/RELEASE.md`
   (`TASK-154`): `dnf remove` on RPM behaves like DEB's `purge`, not its
   `remove`. This is a real, user-visible behavioral difference between the
   two package formats, not a bug to fix — flag it rather than silently
   let users be surprised by data loss on `dnf remove` that they wouldn't
   have gotten from `apt remove`.

## Acceptance criteria

- `cpack -G RPM` (from a Linux build with `rpmbuild` available) produces
  `vapourwault-server-<version>.x86_64.rpm` and
  `vapourwault-client-<version>.x86_64.rpm`.
- `rpm -qlp` on each package shows the expected file layout.
- The DEB/RPM removal-semantics difference (item 4 above) is documented,
  not just implemented silently.
- **Not verified end-to-end in this pass** — same caveat as `TASK-149`;
  `TASK-152`'s job on a real `dnf`-based system.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-11]: Filed as part of the `TASK-145` installer packaging
design's initial implementation wave. Normal priority (vs. `TASK-149`'s
high) since `.deb` covers the more common self-hosting target
(Debian/Ubuntu) — re-prioritize if Otto's actual target distros skew RPM.

BLD.05 [2026-08-11]: Implemented and verified end-to-end in a disposable
`fedora:40` Docker container (built the project from scratch inside the
container via a mounted repo, then `dnf install`/`rpm -U`/`dnf remove`
against the produced `.rpm` files — same real-install rigor as `TASK-149`'s
DEB testing, not just a build-succeeds check).

**A real design mistake caught and fixed while implementing this**: the
original plan (recorded in `TASK-149`'s design note) was to factor the
"delete everything" logic into one shared `purge-data.sh` helper that both
DEB's `postrm` and RPM's `%postun` would call. This does not work and was
corrected before shipping: dpkg does **not** preserve a package's regular
installed files for `postrm` to reference — by the time `postrm` runs
(even in `remove` mode), dpkg has already removed the package's payload
files, and only the maintainer control scripts themselves survive. A
`postrm` that tried to invoke a sibling `purge-data.sh` would fail at
exactly the moment (final removal) it matters most. Fixed by inlining the
delete logic directly in both `packaging/linux/scripts/server/postrm`
(TASK-149, DEB) and `packaging/linux/scripts/rpm/server-postun.sh` (this
task) — a small amount of accepted duplication in exchange for not being
subtly broken. Worth having caught this via reasoning about the real
dpkg/rpm lifecycle rather than just assuming a "DRY" refactor was safe.

**Scriptlet reuse**: `%post`/`%preun` reuse `packaging/linux/scripts/
{server,client}/{postinst,prerm}` directly (unchanged from TASK-149) —
their logic is idempotent and doesn't depend on which package manager
invoked it. Only `%postun` needed an RPM-specific file, since RPM's `$1`
install-count convention (`0` = final removal, `>=1` = upgrade in
progress) is the semantic opposite of DEB's `remove`/`purge` action
strings.

**Verified end-to-end** (fresh containers each time):
- Fresh install: service user, directories, config template — identical
  results to `TASK-149`'s DEB test.
- **Upgrade** (`rpm -U` from a built `1.2.3` package to a built `1.2.4`
  package — actually built two real versions to test this, not simulated):
  an admin-edited config line survived the upgrade, and the service user
  survived — confirming `%postun`'s `$1 >= 1` branch correctly skipped
  deletion.
- **Final removal** (`dnf remove` after the upgrade, so `$1 == 0`):
  config directory and service user both gone — confirming RPM's "no
  purge concept" behavior really does delete on a plain `remove`, unlike
  DEB where `apt remove` alone preserves everything. This asymmetry is
  real, not a scripting bug — `TASK-154` must document it plainly.

**One portability wrinkle observed, not a bug**: Fedora printed
`useradd: Warning: missing or non-executable shell '/usr/sbin/nologin'`
during install — cosmetic only (the warning didn't stop `useradd`; `id
vapourwault` succeeded immediately after with the expected UID). Ubuntu
(`TASK-149`'s test) showed no such warning for the identical `useradd`
invocation. Not fixed in this pass since it's non-fatal; flagged for
`TASK-153`/`TASK-154` to decide whether to silence it (e.g. resolve the
shell path via `command -v nologin` at postinst time) or just document it
as a harmless distro-specific wart.

Moving to `review` — needs SEC.07 + CQR.08 sign-off per the
`security-sensitive` tag.

SEC.07/CQR.08 [2026-08-12]: Reviewed `packaging/linux/scripts/rpm/
server-postun.sh` directly. `$1`-install-count interpretation is
correct (`0` = final removal triggers cleanup, `>=1` = upgrade skips
it), quoting is consistent with the DEB scripts reviewed under
`TASK-149`, and the documented DEB/RPM removal-semantics asymmetry
matches the actual script logic (not just the container-test
observation). No blocking findings.
Sign-off: `SEC.07` + `CQR.08` requirements satisfied. Ready for `done`.
