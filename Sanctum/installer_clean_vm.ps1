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

# 2) Download iocs
$githubUrl    = 'https://raw.githubusercontent.com/0xflux/Sanctum/refs/heads/main/clean_files/ioc_list.txt'
$outFilePath  = Join-Path $sanctumDir 'ioc_list.txt'

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
$outFilePath  = Join-Path $sanctumDir 'config.cfg'

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

Write-Host "Clean VM setup complete. Sanctum is ready at $sanctumDir. Please follow the remaining instructions to install." -ForegroundColor Green
