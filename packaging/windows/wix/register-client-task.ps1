<#
.SYNOPSIS
    Registers (or unregisters) the VaporWault client daemon's Task
    Scheduler logon trigger. Invoked as an MSI deferred custom action
    (TASK-148) - not meant to be run standalone except for debugging.

.DESCRIPTION
    Extracted from Install-VaporWaultClient.ps1's Register-ScheduledTask
    logic (that script is kept as-is for the manual/advanced install path)
    so the client MSI can reuse the same proven registration behavior
    rather than reimplementing Scheduled Task authoring directly in WiX
    XML. The MSI's own file deployment handles copying the daemon/CLI
    binaries and the config template - this script only owns the
    Scheduled Task itself.
#>
param(
    [string] $DaemonExe,
    [string] $StateDir,
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
$TaskName = 'VaporWaultDaemon'

if ($Uninstall) {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    exit 0
}

if (-not $DaemonExe -or -not $StateDir) {
    Write-Error "Register mode requires -DaemonExe and -StateDir"
    exit 1
}

# Idempotent reinstall: drop any prior registration first.
try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}

$Action = New-ScheduledTaskAction -Execute $DaemonExe -Argument "--state-dir `"$StateDir`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -RunLevel Limited `
    -Description "VaporWault client sync daemon - starts on user logon" | Out-Null
