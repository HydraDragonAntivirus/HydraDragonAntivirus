# This script will configure a clean VM to have the right folders / required files which are statically pulled
# from github.

If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

# 1) Ensure Sanctum exists under Program Files
$programFilesRoot = if ($env:ProgramW6432) { $env:ProgramW6432 } elseif ($env:ProgramFiles) { $env:ProgramFiles } else { 'C:\Program Files' }
$sanctumDir = Join-Path $programFilesRoot 'HydraDragonAntivirus\hydradragon\Sanctum'
if (Test-Path $sanctumDir) {
    Write-Host "Directory '$sanctumDir' already exists." -ForegroundColor Yellow
} else {
    New-Item -Path $sanctumDir -ItemType Directory -Force | Out-Null
    Write-Host "Created directory: $sanctumDir"
}

# 2) Trust local files (IOCs and Configurations) already copied during installation.
$iocFilePath   = Join-Path $sanctumDir 'clean_files\ioc_list.txt'
$configFilePath= Join-Path $sanctumDir 'clean_files\config.cfg'

if (Test-Path $iocFilePath) {
    Write-Host "Local ioc_list.txt found at $iocFilePath." -ForegroundColor Green
    Copy-Item -Path $iocFilePath -Destination (Join-Path $sanctumDir 'ioc_list.txt') -Force
} else {
    Write-Host "WARNING: Local ioc_list.txt NOT found at $iocFilePath." -ForegroundColor Yellow
}

if (Test-Path $configFilePath) {
    Write-Host "Local config.cfg found at $configFilePath." -ForegroundColor Green
    Copy-Item -Path $configFilePath -Destination (Join-Path $sanctumDir 'config.cfg') -Force
} else {
    Write-Host "WARNING: Local config.cfg NOT found at $configFilePath." -ForegroundColor Yellow
}

Write-Host "Configuring BCD for test-signing and kernel debug..."
bcdedit /set TESTSIGNING ON
bcdedit /debug ON
bcdedit /dbgsettings serial debugport:1 baudrate:115200

Write-Host "Clean VM setup complete. Sanctum is ready at $sanctumDir. Please follow the remaining instructions to install." -ForegroundColor Green
