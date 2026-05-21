param(
    [string]$SdkBin = "",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$runtimeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $runtimeDir "..\..")

if ([string]::IsNullOrWhiteSpace($SdkBin)) {
    $SdkBin = Join-Path $repoRoot "ZillyaAVEngineSDK\bin"
}

$sdkBinPath = Resolve-Path $SdkBin
$avengSource = Join-Path $sdkBinPath "aveng"
$avengTarget = Join-Path $runtimeDir "aveng"

if (-not (Test-Path $avengSource)) {
    throw "Zillya aveng directory not found: $avengSource"
}

if ($Clean -and (Test-Path $avengTarget)) {
    Remove-Item -LiteralPath $avengTarget -Recurse -Force
}

Copy-Item -LiteralPath (Join-Path $sdkBinPath "AVEngineService.exe") -Destination $runtimeDir -Force
Copy-Item -LiteralPath (Join-Path $sdkBinPath "AVEngineClient.exe") -Destination $runtimeDir -Force
Copy-Item -LiteralPath (Join-Path $sdkBinPath "InstallAVEngineService.bat") -Destination $runtimeDir -Force
Copy-Item -LiteralPath (Join-Path $sdkBinPath "UninstallAVEngineService.bat") -Destination $runtimeDir -Force
Copy-Item -LiteralPath (Join-Path $sdkBinPath "Readme.txt") -Destination $runtimeDir -Force
Copy-Item -LiteralPath $avengSource -Destination $runtimeDir -Recurse -Force

Write-Host "Zillya runtime synced to $runtimeDir"
