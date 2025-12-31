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

function Robust-Copy($src, $dst) {
    if (Test-Path $src) {
        try {
            Copy-Item $src $dst -Force -ErrorAction Stop
            Write-Host "      Successfully copied to $dst" -ForegroundColor Gray
        }
        catch {
            $err = $_.Exception.Message
            Write-Warning "      Failed to copy $src to $dst : $err"
            Write-Host "      Hint: Make sure the application is not running." -ForegroundColor Yellow
        }
    }
    else {
        Write-Warning "      Source not found: $src"
    }
}

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

# Build Hook DLLs (64-bit and 32-bit)
Write-Host "      Building Hook DLLs..." -ForegroundColor Gray
Push-Location hook_dll
try {
    # 64-bit build
    Write-Host "        - Building 64-bit..." -ForegroundColor Gray
    cargo build $buildType --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "64-bit Hook DLL build failed" }

    # 32-bit build
    Write-Host "        - Building 32-bit..." -ForegroundColor Gray
    cargo build $buildType --target i686-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "32-bit Hook DLL build failed" }
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
$hook64Src = if ($Release) { "hook_dll\target\x86_64-pc-windows-msvc\release\hook_dll.dll" } else { "hook_dll\target\x86_64-pc-windows-msvc\debug\hook_dll.dll" }
$hook32Src = if ($Release) { "hook_dll\target\i686-pc-windows-msvc\release\hook_dll.dll" } else { "hook_dll\target\i686-pc-windows-msvc\debug\hook_dll.dll" }

# Copy Hook DLLs to engine target
Robust-Copy $hook64Src (Join-Path $targetDir "hook_dll.dll")
Robust-Copy $hook32Src (Join-Path $targetDir "hook_dll.32.dll")

$dlls = @("WinDivert.dll", "WinDivert64.sys")
foreach ($dll in $dlls) {
    Robust-Copy (Join-Path $env:WINDIVERT_PATH $dll) (Join-Path $targetDir $dll)
}

# Also copy exe and hook_dll to 'everything' folder for easy deployment
$exeSrc = Join-Path $targetDir "hydradragonfirewall.exe"
$exeDst = Join-Path $env:WINDIVERT_PATH "hydradragonfirewall.exe"
Robust-Copy $exeSrc $exeDst

Robust-Copy $hook64Src (Join-Path $env:WINDIVERT_PATH "hook_dll.dll")
Robust-Copy $hook32Src (Join-Path $env:WINDIVERT_PATH "hook_dll.32.dll")

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
