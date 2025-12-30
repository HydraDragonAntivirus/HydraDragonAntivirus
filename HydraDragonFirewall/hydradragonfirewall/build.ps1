# HydraDragon Firewall Build Script
# Run as Administrator for WinDivert driver

param(
    [switch]$Release,
    [switch]$Run
)

$ErrorActionPreference = "Stop"

# Set WinDivert paths
$env:WINDIVERT_PATH = Join-Path $PSScriptRoot "..\everything"
$env:WINDIVERT_LIB_DIR = Join-Path $PSScriptRoot "..\everything"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  HydraDragon Firewall Build System" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Build UI with Trunk
Write-Host "[1/3] Building UI with Trunk..." -ForegroundColor Yellow
Push-Location ui
try {
    # Ensure dist exists in root and trunk uses it
    trunk build --dist ../dist
    if ($LASTEXITCODE -ne 0) { throw "UI build failed" }
    Write-Host "      UI build complete!" -ForegroundColor Green
}
finally {
    Pop-Location
}

# Build Rust backend
$buildType = if ($Release) { "--release" } else { "" }
Write-Host "[2/3] Building Rust backend $buildType..." -ForegroundColor Yellow

# Build Hook DLL first
Write-Host "      Building Hook DLL..." -ForegroundColor Gray
Push-Location hook_dll
try {
    cargo build $buildType
    if ($LASTEXITCODE -ne 0) { throw "Hook DLL build failed" }
}
finally {
    Pop-Location
}

# Build Firewall Engine
cargo build $buildType
if ($LASTEXITCODE -ne 0) { throw "Firewall Engine build failed" }
Write-Host "      Rust build complete!" -ForegroundColor Green

# Copy WinDivert and Hook DLL files if needed
$targetDir = if ($Release) { "target\release" } else { "target\debug" }
$hookDllSrc = if ($Release) { "hook_dll\target\release\hook_dll.dll" } else { "hook_dll\target\debug\hook_dll.dll" }

# Copy Hook DLL to engine target
if (Test-Path $hookDllSrc) {
    Write-Host "      Copying hook_dll.dll to $targetDir" -ForegroundColor Gray
    Copy-Item $hookDllSrc $targetDir -Force
}

$dlls = @("WinDivert.dll", "WinDivert64.sys")
foreach ($dll in $dlls) {
    $src = Join-Path $env:WINDIVERT_PATH $dll
    $dst = Join-Path $targetDir $dll
    if (Test-Path $src) {
        Write-Host "      Copying $dll to $targetDir" -ForegroundColor Gray
        Copy-Item $src $dst -Force
    }
}

# Also copy exe and hook_dll to 'everything' folder for easy deployment
$exeSrc = Join-Path $targetDir "hydradragonfirewall.exe"
$exeDst = Join-Path $env:WINDIVERT_PATH "hydradragonfirewall.exe"
if (Test-Path $exeSrc) {
    Write-Host "      Deploying exe to $env:WINDIVERT_PATH" -ForegroundColor Gray
    Copy-Item $exeSrc $exeDst -Force
}

$hookDst = Join-Path $env:WINDIVERT_PATH "hook_dll.dll"
if (Test-Path $hookDllSrc) {
    Write-Host "      Deploying hook_dll.dll to $env:WINDIVERT_PATH" -ForegroundColor Gray
    Copy-Item $hookDllSrc $hookDst -Force
}

Write-Host ""
Write-Host "[3/3] Build Successful!" -ForegroundColor Green
Write-Host ""
Write-Host "Executable: $targetDir\hydradragonfirewall.exe" -ForegroundColor Cyan
Write-Host ""

# Run if requested
if ($Run) {
    Write-Host "Starting application (Run as Admin for WinDivert)..." -ForegroundColor Magenta
    $exe = Join-Path $targetDir "hydradragonfirewall.exe"
    Start-Process $exe -Verb RunAs
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "IMPORTANT: Run the executable as Administrator" -ForegroundColor Yellow
Write-Host "for WinDivert network capture to work!" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan
