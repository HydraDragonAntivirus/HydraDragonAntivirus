# HydraDragon Firewall Build Script
# Run as Administrator for WinDivert driver

param(
    [switch]$Release,
    [switch]$Run,
    [switch]$Clean,
    [string]$WinDivertPath
)

$ErrorActionPreference = "Stop"

# Set WinDivert paths if provided (otherwise rely on vendored build)
$configuredPaths = @(
    $WinDivertPath,
    $env:WINDIVERT_PATH
)

$resolvedWinDivert = $configuredPaths |
    Where-Object { $_ -and (Test-Path $_) } |
    Select-Object -First 1

if ($resolvedWinDivert) {
    $env:WINDIVERT_PATH = $resolvedWinDivert
    $env:WINDIVERT_LIB_DIR = $resolvedWinDivert
    Write-Host "Using WinDivert binaries at '$resolvedWinDivert'" -ForegroundColor Gray
} else {
    Write-Warning "No valid WinDivert path provided; using vendored WinDivert build instead."
    Remove-Item Env:WINDIVERT_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:WINDIVERT_LIB_DIR -ErrorAction SilentlyContinue
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  HydraDragon Firewall Build System" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Clean if requested
if ($Clean) {
    Write-Host "[1/3] Cleaning build artifacts..." -ForegroundColor Yellow
    cargo clean
    if (Test-Path "ui\dist") { Remove-Item -Recurse -Force "ui\dist" }
    Write-Host "      Cleaned!" -ForegroundColor Green
}

# Build UI with Trunk
Write-Host "[1/3] Building UI with Trunk..." -ForegroundColor Yellow
Push-Location ui
try {
    trunk build
    if ($LASTEXITCODE -ne 0) { throw "UI build failed" }
    Write-Host "      UI build complete!" -ForegroundColor Green
}
finally {
    Pop-Location
}

# Build Rust backend
$buildType = if ($Release) { "--release" } else { "" }
Write-Host "[2/3] Building Rust backend $buildType..." -ForegroundColor Yellow
cargo build $buildType
if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }
Write-Host "      Rust build complete!" -ForegroundColor Green

# Copy WinDivert files if needed
$targetDir = if ($Release) { "target\release" } else { "target\debug" }
$dlls = @("WinDivert.dll", "WinDivert64.sys")
if ($env:WINDIVERT_PATH) {
    foreach ($dll in $dlls) {
        $src = Join-Path $env:WINDIVERT_PATH $dll
        $dst = Join-Path $targetDir $dll
        if (Test-Path $src) {
            Write-Host "      Copying $dll to $targetDir" -ForegroundColor Gray
            Copy-Item $src $dst -Force
        }
    }
}

# Also copy exe to 'everything' folder for easy deployment
$exeSrc = Join-Path $targetDir "hydradragonfirewall.exe"
$exeDst = if ($env:WINDIVERT_PATH) { Join-Path $env:WINDIVERT_PATH "hydradragonfirewall.exe" } else { $null }
if ($exeSrc -and (Test-Path $exeSrc) -and $exeDst) {
    Write-Host "      Deploying exe to $env:WINDIVERT_PATH" -ForegroundColor Gray
    Copy-Item $exeSrc $exeDst -Force
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
