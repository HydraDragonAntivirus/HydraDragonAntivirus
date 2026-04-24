param(
    [Parameter(Mandatory = $true)]
    [string]$MsBuildExe,

    [Parameter(Mandatory = $true)]
    [string]$Platform,

    [Parameter(Mandatory = $true)]
    [string]$Configuration
)

$ErrorActionPreference = 'Stop'

Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))

# Some Windows environments expose both Path and PATH, which breaks VC tool task
# process creation under newer MSBuild. Keep the canonical Path entry only.
[Environment]::SetEnvironmentVariable('PATH', $null, 'Process')

$projects = @(
    'TinyAvCore\TinyAvCore.vcxproj',
    'TinyAvConsole\TinyAvConsole.vcxproj',
    'MinimalOpenHeuristics\MinimalOpenHeuristics.vcxproj',
    'SalityKiller\SalityKiller.vcxproj',
    'tests\Unittests\Unittests.vcxproj'
)

foreach ($project in $projects) {
    & $MsBuildExe $project "/p:Configuration=$Configuration" "/p:Platform=$Platform" '/m' '/nologo' '/v:minimal'
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
