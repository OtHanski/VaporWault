<#
.SYNOPSIS
    Install or uninstall VaporWault as a Windows Service.

.DESCRIPTION
    Copies binaries, creates data/config directories, registers the Windows
    Service, and opens the firewall port.  Run as Administrator.

.PARAMETER InstallDir
    Directory where binaries are installed.
    Default: C:\Program Files\VaporWault

.PARAMETER DataDir
    Directory for server data (users, files, oplog).
    Default: C:\ProgramData\VaporWault\data

.PARAMETER ConfigPath
    Full path to server.conf.
    Default: C:\ProgramData\VaporWault\server.conf

.PARAMETER BuildDir
    Path to the CMake build output directory.
    Default: build\bin (relative to the repo root)

.PARAMETER Uninstall
    Stop and remove the service, remove the firewall rule, and optionally
    delete all data.

.PARAMETER PurgeData
    Used with -Uninstall: also delete DataDir and ConfigPath.

.EXAMPLE
    # Install (run from repo root)
    powershell -ExecutionPolicy Bypass -File packaging\windows\Install-VaporWault.ps1

.EXAMPLE
    # Uninstall, keeping data
    powershell -ExecutionPolicy Bypass -File packaging\windows\Install-VaporWault.ps1 -Uninstall

.EXAMPLE
    # Uninstall and delete all data
    powershell -ExecutionPolicy Bypass -File packaging\windows\Install-VaporWault.ps1 -Uninstall -PurgeData
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDir  = "C:\Program Files\VaporWault",
    [string] $DataDir     = "C:\ProgramData\VaporWault\data",
    [string] $ConfigPath  = "C:\ProgramData\VaporWault\server.conf",
    [string] $BuildDir    = "build\bin",
    [switch] $Uninstall,
    [switch] $PurgeData
)

$ServiceName = "VaporWault"
$FirewallRule = "VaporWault-TLS"
$ListenPort   = 4430

# ── Elevation check ───────────────────────────────────────────────────────────
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Host "Uninstalling $ServiceName..."

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
            Write-Host "  Stopped service."
        }
        & sc.exe delete $ServiceName | Out-Null
        Write-Host "  Removed service."
    } else {
        Write-Host "  Service not found; skipping."
    }

    $fwRule = Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
    if ($fwRule) {
        Remove-NetFirewallRule -DisplayName $FirewallRule
        Write-Host "  Removed firewall rule."
    }

    if ($PurgeData) {
        if (Test-Path $DataDir)    { Remove-Item -Recurse -Force $DataDir }
        if (Test-Path $ConfigPath) { Remove-Item -Force $ConfigPath }
        $confDir = Split-Path $ConfigPath
        if ((Test-Path $confDir) -and -not (Get-ChildItem $confDir)) {
            Remove-Item $confDir
        }
        Write-Host "  Deleted data and config."
    }

    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Host "  Removed install dir: $InstallDir"
    }

    Write-Host "Uninstall complete."
    exit 0
}

# ── Install ───────────────────────────────────────────────────────────────────

# Locate binaries
$ServerBin = Join-Path $BuildDir "vapourwaultd.exe"
$AdminBin  = Join-Path $BuildDir "vapourwault-server-cli.exe"
$GuiBin    = Join-Path $BuildDir "vapourwault-server-gui.exe"

if (-not (Test-Path $ServerBin)) {
    Write-Error "Server binary not found: $ServerBin`nBuild the project first: cmake --build build"
    exit 1
}
if (-not (Test-Path $AdminBin)) {
    Write-Error "Admin CLI binary not found: $AdminBin"
    exit 1
}

Write-Host "Installing VaporWault..."
Write-Host "  Install dir : $InstallDir"
Write-Host "  Data dir    : $DataDir"
Write-Host "  Config      : $ConfigPath"

# Create directories
$dirs = @($InstallDir, $DataDir, (Split-Path $ConfigPath))
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host "  Created: $d"
    }
}

# Copy binaries
Copy-Item -Force $ServerBin (Join-Path $InstallDir "vapourwaultd.exe")
Copy-Item -Force $AdminBin  (Join-Path $InstallDir "vapourwault-server-cli.exe")
if (Test-Path $GuiBin) {
    Copy-Item -Force $GuiBin (Join-Path $InstallDir "vapourwault-server-gui.exe")
}
Write-Host "  Copied binaries to $InstallDir"

# Install default config (do not overwrite)
if (-not (Test-Path $ConfigPath)) {
    $scriptDir = Split-Path $MyInvocation.MyCommand.Path
    $example   = Join-Path $scriptDir "server.conf.example"
    if (Test-Path $example) {
        Copy-Item $example $ConfigPath
    } else {
        # Write a minimal inline template if example is absent
        @"
listen_host      = 0.0.0.0
listen_port      = $ListenPort
data_dir         = $($DataDir -replace '\\', '/')
cert_pem_path    = C:/ProgramData/VaporWault/server.crt
key_pem_path     = C:/ProgramData/VaporWault/server.key
log_level        = INFO
max_connections  = 256
max_workers      = 4
admin_socket     =
gc_interval_secs = 300
"@ | Set-Content -Encoding utf8 $ConfigPath
    }
    Write-Host "  Installed default config: $ConfigPath"
    Write-Host "  --> Edit $ConfigPath before starting the service."
} else {
    Write-Host "  Config already exists — not overwritten."
}

# Register the Windows Service
$binPath = "`"$(Join-Path $InstallDir 'vapourwaultd.exe')`" --config `"$ConfigPath`""
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  Service already registered; updating binary path."
    & sc.exe config $ServiceName binpath= $binPath | Out-Null
} else {
    New-Service -Name $ServiceName `
                -DisplayName "VaporWault Cloud File Server" `
                -Description "VaporWault self-hosted file sync server" `
                -BinaryPathName $binPath `
                -StartupType Automatic | Out-Null
    Write-Host "  Registered Windows Service: $ServiceName"
}

# Firewall rule
$fwRule = Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule -DisplayName $FirewallRule `
                        -Direction Inbound `
                        -Protocol TCP `
                        -LocalPort $ListenPort `
                        -Action Allow | Out-Null
    Write-Host "  Added firewall rule: TCP $ListenPort inbound"
} else {
    Write-Host "  Firewall rule already exists."
}

# Done
Write-Host ""
Write-Host "Installation complete.  Next steps:"
Write-Host "  1. Edit $ConfigPath (set cert_pem_path, key_pem_path, etc.)"
Write-Host "  2. Start the service:"
Write-Host "       Start-Service $ServiceName"
Write-Host "  3. Create the first admin user (after the service starts):"
Write-Host "       & '$InstallDir\vapourwault-server-cli.exe' user-create admin YourPassword --admin"
Write-Host "  4. Check service status:"
Write-Host "       Get-Service $ServiceName"
Write-Host "       Get-EventLog -LogName Application -Source $ServiceName -Newest 20"
