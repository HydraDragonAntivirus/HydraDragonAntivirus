# This script will configure a clean VM to have the right folders / required files which are statically pulled
# from github.

If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

# 1) Create %AppData%\Sanctum
$appDataDir = Join-Path $env:APPDATA 'Sanctum'
if (Test-Path $appDataDir) {
    Write-Host "Directory '$appDataDir' already exists. Exiting." -ForegroundColor Yellow
    exit 1
} else {
    New-Item -Path $appDataDir -ItemType Directory -Force | Out-Null
    Write-Host "Created directory: $appDataDir"
}

# 2) Create ~/Desktop/sanctum
$desktopDir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'sanctum'
if (Test-Path $desktopDir) {
    Write-Host "Directory '$desktopDir' already exists. Exiting." -ForegroundColor Yellow
    exit 1
} else {
    New-Item -Path $desktopDir -ItemType Directory -Force | Out-Null
    Write-Host "Created directory: $desktopDir"
}

# 3) Download iocs
$githubUrl    = 'https://raw.githubusercontent.com/0xflux/Sanctum/refs/heads/main/clean_files/ioc_list.txt'
$outFilePath  = Join-Path $appDataDir 'ioc_list.txt'

Write-Host "Downloading from $githubUrl to $outFilePath..."
try {
    Invoke-WebRequest -Uri $githubUrl -OutFile $outFilePath -UseBasicParsing
    Write-Host 'Download completed successfully.' -ForegroundColor Green
} catch {
    Write-Error "Failed to download file: $_"
    exit 1
}

# 3) Download config
$githubUrl    = 'https://raw.githubusercontent.com/0xflux/Sanctum/refs/heads/main/clean_files/config.cfg'
$outFilePath  = Join-Path $appDataDir 'config.cfg'

Write-Host "Downloading from $githubUrl to $outFilePath..."
try {
    Invoke-WebRequest -Uri $githubUrl -OutFile $outFilePath -UseBasicParsing
    Write-Host 'Download completed successfully.' -ForegroundColor Green
} catch {
    Write-Error "Failed to download file: $_"
    exit 1
}

Write-Host "Configuring BCD for test-signing and kernel debug..."
bcdedit /set TESTSIGNING ON
bcdedit /debug ON
bcdedit /dbgsettings serial debugport:1 baudrate:115200

Write-Host 'Clean VM setup complete. Created %AppData%\Sanctum and ~Desktop\sanctum. Please follow the remaining instructions to install.' -ForegroundColor Green