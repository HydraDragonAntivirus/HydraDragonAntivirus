#Requires -Version 5.1
<#
.SYNOPSIS
    Multron scan server binary migration: stages a new multron_server.exe with
    maintenance gating, health verification and automatic rollback.

.DESCRIPTION
    1. Maintenance ON via the dashboard (new scans get 503, in-flight finish).
    2. Stops the running multron_server process.
    3. Backs the live exe up to multron_server.prev.exe, puts the new one in.
    4. Starts it and polls /health until status ok (timeout -> rollback).
    5. On failure: restores the backup, restarts, re-checks health.

    Fresh processes always boot with maintenance OFF, so no OFF call is needed.

.PARAMETER NewExe
    Full path of the new binary (default: target\release\multron_server.exe
    next to this script, i.e. a local CI/dev build).

.PARAMETER InstallDir
    Directory the server runs from (holds multron_server.exe + config).

.PARAMETER DashboardBase
    Dashboard base URL (default http://127.0.0.1:9440).

.PARAMETER HealthUrl
    Scan listener health URL (default http://127.0.0.1:5306/health).

.PARAMETER HealthTimeoutSec
    How long to wait for a healthy status before rollback (default 90).
#>
[CmdletBinding()]
param(
    [string]$NewExe = (Join-Path -Path $PSScriptRoot -ChildPath "target\release\multron_server.exe"),
    [string]$InstallDir = (Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath "OpenMalwareScannerPortable"),
    [string]$DashboardBase = "http://127.0.0.1:9440",
    [string]$HealthUrl = "http://127.0.0.1:5306/health",
    [int]$HealthTimeoutSec = 90
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "[migrate] $Message"
}

function Set-Maintenance([bool]$Enabled) {
    $body = @{ enabled = $Enabled } | ConvertTo-Json -Compress
    try {
        Invoke-RestMethod -Method Post -Uri "$DashboardBase/api/maintenance" `
            -Headers @{ "X-Multron-Dashboard" = "1" } `
            -ContentType "application/json" -Body $body -TimeoutSec 15 | Out-Null
        Write-Step "maintenance -> $Enabled"
    }
    catch {
        Write-Warning "[migrate] dashboard maintenance call failed: $($_.Exception.Message)"
    }
}

function Test-Health {
    try {
        $res = Invoke-RestMethod -Method Get -Uri $HealthUrl -TimeoutSec 10
        return ($res.status -eq "ok")
    }
    catch {
        return $false
    }
}

function Wait-Health([string]$Phase) {
    $deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Health) {
            Write-Step "health ok ($Phase)"
            return $true
        }
        Start-Sleep -Seconds 3
    }
    Write-Warning "[migrate] health check timed out ($Phase)"
    return $false
}

function Stop-ServerProcess {
    $procs = Get-Process -Name "multron_server" -ErrorAction SilentlyContinue
    if ($null -eq $procs) {
        Write-Step "no running multron_server process"
        return
    }
    Write-Step "stopping running multron_server process"
    Stop-Process -InputObject $procs -Force
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $left = Get-Process -Name "multron_server" -ErrorAction SilentlyContinue
        if ($null -eq $left) {
            Write-Step "process exited"
            return
        }
        Start-Sleep -Seconds 2
    }
    throw "multron_server process did not exit in 30s, aborting"
}

function Start-ServerProcess {
    $exe = Join-Path -Path $InstallDir -ChildPath "multron_server.exe"
    Write-Step "starting $exe"
    Start-Process -FilePath $exe -WorkingDirectory $InstallDir | Out-Null
}

# ---- Preconditions ---------------------------------------------------------
if (-not (Test-Path -LiteralPath $NewExe -PathType Leaf)) {
    throw "new binary not found: $NewExe"
}
if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    throw "install dir not found: $InstallDir"
}
$liveExe = Join-Path -Path $InstallDir -ChildPath "multron_server.exe"
$backupExe = Join-Path -Path $InstallDir -ChildPath "multron_server.prev.exe"
if (-not (Test-Path -LiteralPath $liveExe -PathType Leaf)) {
    throw "live binary not found: $liveExe"
}

$newHash = (Get-FileHash -LiteralPath $NewExe -Algorithm SHA256).Hash
$liveHash = (Get-FileHash -LiteralPath $liveExe -Algorithm SHA256).Hash
Write-Step "new: $newHash"
Write-Step "live: $liveHash"
if ($newHash -eq $liveHash) {
    Write-Step "identical binaries, nothing to do"
    exit 0
}

# ---- Migrate ---------------------------------------------------------------
Set-Maintenance -Enabled $true
try {
    Stop-ServerProcess

    if (Test-Path -LiteralPath $backupExe -PathType Leaf) {
        Remove-Item -LiteralPath $backupExe -Force
    }
    Rename-Item -LiteralPath $liveExe -NewName "multron_server.prev.exe" -Force
    Copy-Item -LiteralPath $NewExe -Destination $liveExe -Force
    Write-Step "swapped binary, backup at multron_server.prev.exe"

    Start-ServerProcess
    if (Wait-Health -Phase "new binary") {
        Write-Step "migration complete (fresh boot starts with maintenance OFF)"
        exit 0
    }

    # ---- Rollback ----------------------------------------------------------
    Write-Warning "[migrate] new binary unhealthy, rolling back"
    Stop-ServerProcess
    Remove-Item -LiteralPath $liveExe -Force -ErrorAction SilentlyContinue
    Rename-Item -LiteralPath $backupExe -NewName "multron_server.exe" -Force
    Start-ServerProcess
    if (Wait-Health -Phase "rollback") {
        Write-Step "rollback complete, old binary serving again"
        exit 1
    }
    throw "rollback binary also unhealthy, manual intervention required"
}
finally {
    # Maintenance flag lives only in memory; a fresh process boots with it OFF.
    # If the old process is still the one running (pre-swap failure), lift it.
    Set-Maintenance -Enabled $false
}
