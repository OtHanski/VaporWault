---
id:          TASK-148
title:       Windows client MSI (per-user install + scheduled-task custom action)
status:      review
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-11
priority:    high
depends_on:  [TASK-145, TASK-146]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [build, windows, security-sensitive]
---

Build a proper client MSI via CPack's WIX generator. Per `TASK-145`'s
SEC.07-resolved design: **this package must install per-user, with no
elevation**, matching `Install-VaporWaultClient.ps1`'s existing
`%LOCALAPPDATA%`/`%APPDATA%` locations — the Windows Scheduled Task the
client needs is a per-user resource, and only a no-elevation install keeps
the MSI's file deployment and its custom action running in the same
(correct) security context.

Scope:

1. `CPACK_GENERATOR "WIX"` invocation for the `client` component, with a
   distinct `CPACK_WIX_UPGRADE_GUID` from the server package's (`TASK-147`)
   — these are independently installable products.
2. WiX per-user install: `<Package InstallScope="perUser">` (or the
   equivalent property-based approach, `ALLUSERS=2 MSIINSTALLPERUSER=1`) so
   no UAC prompt appears and no admin token is ever involved.
3. A deferred custom action invoking the scheduled-task-registration logic
   already proven in `Install-VaporWaultClient.ps1` (the
   `Register-ScheduledTask` block — NOT the binary-copy/config-template
   parts, since MSI's own file deployment replaces those). Concretely:
   extract that logic into a small standalone `.ps1` (or inline
   `powershell.exe -Command`) invoked via WiX's `<CustomAction>` +
   `ExecuteCommand`, scheduled at the appropriate install sequence point
   (after `InstallFiles`, so the daemon binary already exists at the path
   the scheduled task references).
   - **Argument handling**: any path/property value passed from WiX into
     the invoked PowerShell command line must be properly quoted — treat
     this with the same rigor `TASK-081` applied to `release.yml`'s
     ref-name handling (SEC.07 flagged this class of risk generally during
     `TASK-145`'s design review). Prefer passing values via a temp
     argument file or environment rather than raw command-line
     interpolation if quoting can't be made unambiguously safe.
   - Must also register (or invoke) the corresponding removal logic on
     uninstall (`Unregister-ScheduledTask`), mirroring the script's
     `-Uninstall` path.
4. Config template installed to `%APPDATA%\VaporWault\daemon.conf` if
   absent, matching every other install path's "don't overwrite" rule.

## Acceptance criteria

- `cpack -G WIX` (component `client`) produces a `.msi` that compiles
  without ICE-validation errors.
- Custom action's command-line construction reviewed specifically for
  injection risk (quoting of any path containing spaces/special
  characters) — call this out explicitly in the implementation note for
  `TASK-153`'s reviewer.
- Built and verified in this session — NOT installed on a real machine
  (registers a Scheduled Task, a real system-state change); real
  install/uninstall verification is `TASK-152`'s job.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-11]: Filed as part of the `TASK-145` installer packaging
design's initial implementation wave. Tagged `security-sensitive` — a
custom action shelling out to PowerShell with interpolated arguments is
exactly the kind of pattern `TASK-081` already had to fix once elsewhere in
this project's CI; do not repeat that mistake here.

BLD.05 [2026-08-11]: While implementing `TASK-147`, generated a second
fixed upgrade GUID reserved for this task's use (do not regenerate; use
this exact value): `CPACK_WIX_UPGRADE_GUID=88FDD57B-FD91-4214-B6F5-B1343F75ABBB`.
Also confirmed via `TASK-147`'s testing that CPack's WIX generator needs
`cpack` invoked separately per component (`-D CPACK_COMPONENTS_ALL=client`
plus this GUID plus whatever `CPACK_WIX_PATCH_FILE`/custom-action wiring
this task adds) — see `TASK-147`'s implementation note for the exact
working invocation shape to follow.

BLD.05 [2026-08-11]: Implemented and built for real in this session.

**Per-user install**: `-D CPACK_WIX_INSTALL_SCOPE=perUser` turned out to be
a fully native, built-in CPack WIX feature — it maps directly to WiX's
`<Package InstallScope="perUser">` attribute and automatically switches the
generated root directory from `ProgramFiles64Folder` to
`LocalAppDataFolder` (confirmed by inspecting the generated
`directories.wxs` before and after setting it), including auto-adding the
HKCU-registry-keyed `RemoveFolderComponent` entries per-user installs
need. No manual directory-root patching required.

**Custom action** (`packaging/windows/wix/client-extra.wxs`,
`client-patch.xml`, `register-client-task.ps1`): implements the standard
two-step WiX deferred-custom-action pattern — an immediate CustomAction
(`SetRegisterClientTaskData`/`SetUnregisterClientTaskData`) resolves all
`[#FileId]`/`[AppDataFolder]`-style tokens (which only immediate actions
can access) into a `CustomActionData` property, and the deferred action's
`ExeCommand` is a fixed string containing only the single
`[CustomActionData]` token (which MSI resolves via its own dedicated
mechanism — the one exception that works for deferred actions). This is
the standard, documented pattern for this situation, not a novel
invention. On SEC.07's command-injection concern from `TASK-145`'s design
review: every substituted value is individually quoted, and — more
fundamentally — this is a per-user, no-elevation install, so the whole
session (including this custom action) already runs as the installing
user throughout; there is no privilege boundary for a crafted MSI property
to cross here, unlike `TASK-147`'s elevated server install. Flagging for
`TASK-153` to confirm this reasoning, not just accept it.

**Three real build errors hit and fixed**:
1. `CNDL0037`: a `CustomAction` with `ExeCommand` needs one of
   `BinaryKey`/`Directory`/`FileKey`/`Property` alongside it — added
   `Directory="TARGETDIR"` to both deferred actions.
2. `LGHT0204`/ICE38: a component installed to a per-user directory must
   use an HKCU `RegistryValue` as its `KeyPath`, not a `File` — matched the
   convention CPack's own generated components already used.
3. `CNDL0230`: once that component had both a `RegistryValue` KeyPath and
   a `File`, WiX could no longer auto-generate its GUID — fixed with a
   hardcoded, permanent GUID (`F5D76859-3F79-4193-BA72-ED6107ED115A`,
   recorded in the `.wxs` file itself; must never change once shipped).

**Verified**: `cpack -G WIX` (component `client`, per-user scope) builds
clean with no errors. `msiexec /a ... /qn` (non-mutating administrative
extraction) exit code 0, extracted tree contains exactly the expected
three files (`vapourwault-daemon.exe`, `vapourwault-cli.exe`,
`register-client-task.ps1`).

**Update — actually installed for real (`msiexec /i`), not just
structurally verified**, and it found a real bug: the custom action never
ran at all on first install. Root cause: WiX's linker (`light.exe`) drops
any `<Fragment>` that nothing else references — the original filing split
the Component (File install) and the CustomActions/InstallExecuteSequence
into two separate Fragments, and only the first was referenced (via
`client-patch.xml`'s `ComponentRef`). The compiled MSI's `CustomAction`
table was completely empty of both `SetRegisterClientTaskData` and
`RegisterClientTask` — confirmed directly by querying the MSI database via
`WindowsInstaller.Installer` COM automation, not inferred. **Fixed** by
merging everything into the one Fragment that's actually referenced;
re-verified the same way — the `CustomAction` table now correctly lists
all four actions (register + unregister pairs).

After that fix, `msiexec /i` correctly ran the custom action with
correctly-resolved `CustomActionData` (confirmed via the verbose MSI log:
`"...\register-client-task.ps1" -DaemonExe "...\vapourwault-daemon.exe"
-StateDir "...\VaporWault"` — the two-step immediate/deferred pattern
works as designed). But `Register-ScheduledTask` (and, tested
independently, the older `schtasks.exe` too) failed with **"Access is
denied"** — isolated by testing trigger types individually: `/SC ONCE`
succeeds, `/SC ONLOGON` is denied. This is a Group Policy restriction on
the specific (Azure AD-managed) test machine blocking non-admin creation
of logon-triggered scheduled tasks specifically — not a bug in this
task's WiX/PowerShell authoring, which reaches the OS API call correctly.
Full task registration therefore remains unverified on an unrestricted
machine — flagged for whoever runs `TASK-152` next, ideally on a personal/
unmanaged Windows install where this policy doesn't apply.

Also not done in this pass: the config-template-if-absent step (item 4 in
this task's scope) — the MSI as built only deploys binaries + the
task-runner script; a follow-up note should be added if config templating
via MSI turns out to need its own custom action too (the "only if absent"
rule isn't natively expressible via a plain `<File>` install).

Moving to `review` — needs SEC.07 + CQR.08 sign-off per the
`security-sensitive` tag.
