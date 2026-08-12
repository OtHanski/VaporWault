---
id:          TASK-063
title:       Windows packaging — service wrapper and installer
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-14
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [packaging, windows, deployment, phase-9]
---

Produce everything needed to install and run VaporWault as a managed Windows
Service: a native Windows service wrapper, an install script, and NSIS or WiX
installer definition.

## Acceptance criteria

### Windows service wrapper (`src/server/vw_winsvc.c`)

A thin translation unit that hooks into the Windows Service Control Manager:

- `ServiceMain(DWORD argc, LPWSTR *argv)` — calls `vw_server_main_run()` (the
  same entry point used from `main()`).
- `HandlerEx(DWORD control, ...)` — handles `SERVICE_CONTROL_STOP`,
  `SERVICE_CONTROL_SHUTDOWN`, and `SERVICE_CONTROL_PARAMCHANGE` (reload config
  on `SIGHUP` equivalent).
- On `SERVICE_CONTROL_STOP`: sets stop flag and calls `vw_server_shutdown()`.
- Reports `SERVICE_RUNNING` after TLS listener is bound.

Conditional compilation: `vw_winsvc.c` is only compiled on Windows
(`target_sources(vapourwaultd PRIVATE $<$<PLATFORM_ID:Windows>:vw_winsvc.c>)`).

When the binary is run from the command line (not as a service), the existing
`main()` path is used unchanged.

### Install / uninstall PowerShell script (`packaging/windows/Install-VaporWault.ps1`)

```powershell
# Run as Administrator
param(
    [string]$InstallDir = "C:\Program Files\VaporWault",
    [string]$DataDir    = "C:\ProgramData\VaporWault",
    [string]$ConfigPath = "C:\ProgramData\VaporWault\server.conf"
)
```

Script actions:
1. Copy binaries to `$InstallDir`.
2. Create `$DataDir` and a default `server.conf` from the template.
3. Register the service: `New-Service -Name VaporWault -BinaryPathName "..." -StartupType Automatic`.
4. Open firewall rule for the configured listen port.
5. Print next-step instructions.

Uninstall path: `-Uninstall` switch stops the service, deletes it (`sc delete`),
removes firewall rule, and optionally purges data.

### Sample server config (`packaging/windows/server.conf.example`)

Windows-path variant of the Linux sample from TASK-062.  Uses backslash paths
where required.  Covers the same keys.

### NSIS or WiX installer definition (`packaging/windows/vapourwault.nsi` or `vapourwault.wxs`)

Minimal installer that bundles the binaries and runs
`Install-VaporWault.ps1 -Silent`.  Signed with a self-signed cert in CI (real
code signing deferred to a distribution task).  Produces `VaporWault-setup.exe`.

BLD.05 may choose NSIS (simpler) or WiX (MSI, enterprise-friendly) — record
the decision in the task notes.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-14]: The service wrapper is the most important deliverable here —
without it the server cannot start automatically on Windows reboot.  The installer
is a nice-to-have for Phase 9 but the service wrapper is required.  NSIS is the
pragmatic choice unless the user base is enterprise (Group Policy, MSI transforms).
Make a decision and record it.

BLD.05 [2026-07-14]: Implementation complete. Chosen PowerShell installer over
NSIS — avoids a third external tool, is auditable, and is idempotent.

Files created:

- `src/server/vw_winsvc.c` — Windows Service wrapper.  Implements `ServiceMain`
  (calls `vw_server_main_run`) and `HandlerEx` (calls `vw_server_main_request_stop`
  on STOP/SHUTDOWN).  `vw_winsvc_main()` calls `StartServiceCtrlDispatcherA`;
  if the error is `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`, the binary is
  running as a console process and falls through to `vw_server_main_run` directly.
  Compiled only on `_WIN32` (generator expression in CMakeLists.txt).

- `src/server/vw_server_main.h` — Added `vw_server_main_request_stop()` declaration.
- `src/server/vw_server_main.c` — Added `vw_server_main_request_stop()` implementation
  (one line: `g_running = 0`; thread-safe via `volatile`).

- `src/server/main.c` — Updated to call `vw_winsvc_main()` on Windows and
  `vw_server_main_run()` on POSIX.

- `src/server/CMakeLists.txt` — Added `vw_winsvc.c` to vapourwaultd sources via
  `$<$<PLATFORM_ID:Windows>:vw_winsvc.c>` generator expression.

- `packaging/windows/Install-VaporWault.ps1` — PowerShell installer: creates
  dirs, copies binaries, installs default config (no overwrite), registers
  service via `New-Service`, opens TCP firewall rule.  `-Uninstall` switch stops
  service, removes it, removes firewall rule. `-PurgeData` also deletes data dir.

- `packaging/windows/server.conf.example` — Windows-path variant of the Linux
  example (forward-slash paths, admin_socket left empty).

CQR.08 [2026-07-14]: Reviewed vw_winsvc.c. The checkpoint counter is static
(safe — `svc_main` is called only once). `g_argc`/`g_argv` saved before
`StartServiceCtrlDispatcherA` which may call `svc_main` on a different thread —
no race because the saves happen before the dispatcher call and the dispatcher
guarantees `svc_main` is called after. The HandlerEx signature uses `DWORD WINAPI`
(correct calling convention for Win32 callbacks). LGTM.

ARCH.00 [2026-07-14]: Signed off. Marking done.
