param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("Win32")]
    [string]$Platform = "Win32",

    [switch]$Publish
)

$ErrorActionPreference = "Stop"

$processPath = [Environment]::GetEnvironmentVariable("Path", "Process")
if (-not $processPath) {
    $processPath = [Environment]::GetEnvironmentVariable("PATH", "Process")
}
[Environment]::SetEnvironmentVariable("PATH", $null, "Process")
[Environment]::SetEnvironmentVariable("Path", $processPath, "Process")

$sdkRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$solution = Join-Path $sdkRoot "ZillyaAVEngineSDK-vs2022.sln"
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"

if (Test-Path $vswhere) {
    $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
}

if (-not $msbuild) {
    $msbuildCommand = Get-Command msbuild -ErrorAction SilentlyContinue
    if ($msbuildCommand) {
        $msbuild = $msbuildCommand.Source
    }
}

if (-not $msbuild) {
    throw "MSBuild bulunamadi. Visual Studio 2022 Build Tools ve C++ workload kurulu olmali."
}

& $msbuild $solution /m /restore /p:Configuration=$Configuration /p:Platform=$Platform
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($Publish) {
    $outDir = Join-Path $sdkRoot "out\$Platform\$Configuration"
    $publishDir = Join-Path $sdkRoot "bin\vs2022\$Configuration"
    New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

    Get-ChildItem -Path (Join-Path $outDir "*") -File -Include *.exe,*.dll,*.lib,*.pdb | Copy-Item -Destination $publishDir -Force
    Copy-Item (Join-Path $sdkRoot "bin\aveng") (Join-Path $publishDir "aveng") -Recurse -Force

    Write-Host "Published to $publishDir"
}
