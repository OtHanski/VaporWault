<#
.SYNOPSIS
    Install or uninstall the VaporWault client daemon on Windows.

.DESCRIPTION
    Copies vapourwault-daemon.exe and vapourwault-cli.exe to the install
    directory and registers a Task Scheduler logon trigger so the daemon
    starts automatically when the current user logs in.

.PARAMETER InstallDir
    Directory where the binaries are copied (default: %LOCALAPPDATA%\VaporWault).

.PARAMETER StateDir
    Directory for daemon.conf, session.tok, and cache.db
    (default: %APPDATA%\VaporWault).

.PARAMETER BuildDir
    Directory containing the compiled binaries (default: build\bin).

.PARAMETER Uninstall
    Stop and remove the scheduled task, and remove the install directory.

.PARAMETER PurgeData
    Used with -Uninstall: also remove StateDir (daemon.conf, session.tok, etc.).

.EXAMPLE
    # Install
    .\Install-VaporWaultClient.ps1

    # Install from a custom build directory
    .\Install-VaporWaultClient.ps1 -BuildDir C:\src\vapourwault\build\bin

    # Uninstall (keep user data)
    .\Install-VaporWaultClient.ps1 -Uninstall

    # Uninstall and remove all data
    .\Install-VaporWaultClient.ps1 -Uninstall -PurgeData
#>
param(
    [string] $InstallDir = "$env:LOCALAPPDATA\VaporWault",
    [string] $StateDir   = "$env:APPDATA\VaporWault",
    [string] $BuildDir   = "build\bin",
    [switch] $Uninstall,
    [switch] $PurgeData
)

$ErrorActionPreference = 'Stop'
$TaskName = 'VaporWaultDaemon'

# ── Uninstall ─────────────────────────────────────────────────────────────────

if ($Uninstall) {
    Write-Host "Stopping scheduled task '$TaskName' (if running)..."
    try {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    } catch {}

    Write-Host "Unregistering scheduled task '$TaskName'..."
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}

    if (Test-Path $InstallDir) {
        Write-Host "Removing install directory: $InstallDir"
        Remove-Item -Recurse -Force $InstallDir
    }

    if ($PurgeData -and (Test-Path $StateDir)) {
        Write-Host "Removing state directory: $StateDir"
        Remove-Item -Recurse -Force $StateDir
    }

    Write-Host "VaporWault client daemon uninstalled."
    exit 0
}

# ── Install ───────────────────────────────────────────────────────────────────

$DaemonExe = Join-Path $BuildDir 'vapourwault-daemon.exe'
$CliExe    = Join-Path $BuildDir 'vapourwault-cli.exe'

if (-not (Test-Path $DaemonExe)) {
    Write-Error "vapourwault-daemon.exe not found at '$DaemonExe'.`nBuild the project first: cmake --build build"
}
if (-not (Test-Path $CliExe)) {
    Write-Error "vapourwault-cli.exe not found at '$CliExe'."
}

# Create directories
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir   | Out-Null

# Copy binaries
Copy-Item -Force $DaemonExe (Join-Path $InstallDir 'vapourwault-daemon.exe')
Copy-Item -Force $CliExe    (Join-Path $InstallDir 'vapourwault-cli.exe')
Write-Host "Installed: $InstallDir\vapourwault-daemon.exe"
Write-Host "Installed: $InstallDir\vapourwault-cli.exe"

# Restrict state directory ACL to current user only
$acl  = Get-Acl $StateDir
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
)
$acl.AddAccessRule($rule)
Set-Acl $StateDir $acl

# Install default config template (do not overwrite an existing config)
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ConfSource = Join-Path $ScriptDir 'client.conf.example'
$ConfDest   = Join-Path $StateDir 'daemon.conf'
if (-not (Test-Path $ConfDest)) {
    if (Test-Path $ConfSource) {
        Copy-Item $ConfSource $ConfDest
        # Restrict config file to current user only
        $acl  = Get-Acl $ConfDest
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule($rule)
        Set-Acl $ConfDest $acl
        Write-Host "Created:   $ConfDest (template — edit before starting the daemon)"
    }
} else {
    Write-Host "Skipped:   $ConfDest already exists"
}

# ── Register Task Scheduler logon trigger ─────────────────────────────────────

$DaemonPath = Join-Path $InstallDir 'vapourwault-daemon.exe'
$Action = New-ScheduledTaskAction `
    -Execute $DaemonPath `
    -Argument "--state-dir `"$StateDir`""

$Trigger  = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

# Remove existing task if present (idempotent reinstall)
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action   $Action `
    -Trigger  $Trigger `
    -Settings $Settings `
    -RunLevel Limited `
    -Description "VaporWault client sync daemon — starts on user logon" | Out-Null

Write-Host "Registered: Task Scheduler task '$TaskName'"

# ── Next steps ────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Next steps:"
Write-Host ""
Write-Host "  1. Edit the daemon configuration:"
Write-Host "       notepad `"$ConfDest`""
Write-Host ""
Write-Host "  2. Start the daemon now (it also starts automatically on next logon):"
Write-Host "       Start-ScheduledTask -TaskName $TaskName"
Write-Host ""
Write-Host "  3. Log in to your VaporWault account:"
Write-Host "       & `"$InstallDir\vapourwault-cli.exe`" login <password>"
Write-Host ""
