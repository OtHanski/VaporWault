<#
.SYNOPSIS
    Registers (or unregisters) the VaporWault client daemon's Task
    Scheduler logon trigger. Invoked from two places: the MSI's
    deferred custom action at install time (TASK-148 -- best-effort,
    usually fails, see TASK-250 below), and vapourwault-daemon.exe's own
    startup (main.c's ensure_scheduled_task_registered(), TASK-250 --
    the mechanism that actually works). Not meant to be run standalone
    except for debugging.

.DESCRIPTION
    Extracted from Install-VaporWaultClient.ps1's Register-ScheduledTask
    logic (that script is kept as-is for the manual/advanced install path)
    so the client MSI can reuse the same proven registration behavior
    rather than reimplementing Scheduled Task authoring directly in WiX
    XML. The MSI's own file deployment handles copying the daemon/CLI
    binaries and the config template - this script only owns the
    Scheduled Task itself.

    TASK-250: registering from inside the MSI's own install transaction
    doesn't actually work at all -- Register-ScheduledTask needs a real
    interactive logon session, which no MSI deferred custom action has,
    confirmed for real (Access is denied, reproduces even on an
    unrestricted personal session, regardless of impersonation). The
    daemon itself calls this script unconditionally on every startup
    instead, since by the time it's running it genuinely is in such a
    session. That means this script now needs to be idempotent and
    cheap to call often, not just once at install: it skips the
    register/unregister/re-register dance entirely when a task already
    exists and still points at this exact daemon path, and only redoes
    it when the task is missing or stale (an in-place upgrade changes
    $DaemonExe, since the install directory name includes the version,
    so a task left pointing at a previous version's now-removed binary
    needs replacing, not leaving alone).

    -DaemonExe/-StateDir were originally passed in from the MSI via the
    standard immediate-action-sets-a-property / deferred-action-reads-
    [CustomActionData] two-step pattern. Found for real (TASK-152/247)
    that this project's exact WiX v3.11.2 + msiexec combination never
    actually delivers CustomActionData to this deferred action at all -
    [CustomActionData] resolves to an empty string at real execution
    time, confirmed by redirecting the literal invoked command's own
    stdout to a file (not just reading the MSI log's property-table
    dump, which always looks correct since it's just showing what the
    immediate action set, not what the deferred action actually
    received). Tried removing Impersonate, tried an all-uppercase
    (public) property name, tried a single-word value with no spaces or
    quotes to rule out a quoting issue, tried both a direct elevated
    msiexec /i and a de-elevated one via a temporary scheduled task -
    every combination reproduced the same empty substitution. Rather
    than keep chasing an unexplained engine-level quirk, both parameters
    are now derived at runtime instead of templated in: $PSScriptRoot is
    always this script's own real install directory (same directory as
    vapourwault-daemon.exe, since CPack installs them together), and
    %APPDATA%\VaporWault is a fixed, well-known path that never varies
    per install. client-extra.wxs now invokes this script with
    Directory="CM_DP_client.bin" and a plain relative filename instead
    of any CustomActionData token, sidestepping the whole mechanism.
#>
param(
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
$TaskName = 'VaporWaultDaemon'
$DaemonExe = Join-Path $PSScriptRoot 'vapourwault-daemon.exe'
$StateDir  = Join-Path $env:APPDATA 'VaporWault'

if ($Uninstall) {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    exit 0
}

if (-not (Test-Path -LiteralPath $DaemonExe)) {
    Write-Error "Expected daemon binary not found next to this script: $DaemonExe"
    exit 1
}

# TASK-250: this now runs on every daemon startup (self-registration, since
# the MSI can't do it from the install transaction), not just once from the
# installer -- so skip the work entirely when a task already exists AND
# still points at this exact daemon path. Re-register (not skip) when it's
# missing OR stale: an in-place upgrade changes $DaemonExe (the install
# directory name includes the version), so a task left pointing at a
# previous version's now-removed binary needs to be replaced, not left
# alone as "already there."
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    $existingExe = ($existing.Actions | Select-Object -First 1).Execute
    if ($existingExe -and ($existingExe -eq $DaemonExe)) {
        exit 0
    }
}

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
