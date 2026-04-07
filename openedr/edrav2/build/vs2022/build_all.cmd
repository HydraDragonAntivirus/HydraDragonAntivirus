@echo off
setlocal EnableExtensions EnableDelayedExpansion

if /I not "%~1"=="--internal" (
    set "ForwardArgs="
    if /I "%~1"=="--full" set "ForwardArgs= --full"
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = 'cmd.exe'; $psi.Arguments = '/c ""%~f0"" --internal%ForwardArgs%'; $psi.UseShellExecute = $false; $envMap = @{}; foreach ($line in (cmd /c set)) { $idx = $line.IndexOf('='); if ($idx -gt 0) { $name = $line.Substring(0, $idx); $value = $line.Substring($idx + 1); $envMap[$name.ToUpperInvariant()] = @{ Name = $name; Value = $value } } }; foreach ($entry in $envMap.Values) { $psi.EnvironmentVariables[$entry.Name] = $entry.Value }; $proc = [System.Diagnostics.Process]::Start($psi); $proc.WaitForExit(); exit $proc.ExitCode"
    exit /b %errorlevel%
)

shift /1

for %%I in ("%~dp0.") do set "ScriptDir=%%~fI"
for %%I in ("%ScriptDir%\..\..") do set "EdrRoot=%%~fI"
for %%I in ("%ScriptDir%\..\..\..\..") do set "RepoRoot=%%~fI"

set "OutDir=%EdrRoot%\out"
set "OutBinDir=%OutDir%\bin\win-Release-x64"
set "CrashpadRoot=%EdrRoot%\eprj\crashpad"
set "FirewallProjectDir=%RepoRoot%\HydraDragonFirewall\hydradragonfirewall"
set "FirewallTargetDir=%FirewallProjectDir%\target\release"
set "WinDivertDir=%RepoRoot%\HydraDragonFirewall\everything"
set "vcvarsall=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%vcvarsall%" (
    echo Error: Could not find Visual Studio 2022 Build Tools.
    echo Searched path: %vcvarsall%
    exit /b 1
)

echo [INFO] Cleaning "%OutDir%" to remove stale build outputs...
if exist "%OutDir%" rd /s /q "%OutDir%"
if exist "%OutDir%" (
    echo [ERROR] Failed to remove "%OutDir%".
    exit /b 1
)

if /I "%~1"=="--full" (
    echo [INFO] Full rebuild requested. Building external dependencies...

    pushd "%EdrRoot%"
    for /d %%D in (eprj\*) do (
        if exist "%%~fD\build.cmd" (
            echo.
            echo ========================================================
            echo [INFO] Building dependency: %%~nxD
            echo ========================================================
            pushd "%%~fD"
            call build.cmd
            if errorlevel 1 (
                set "BuildRc=!errorlevel!"
                echo [ERROR] Build failed for %%~nxD
                popd
                popd
                exit /b !BuildRc!
            )
            popd
        )
    )
    popd

    call :EnsureCrashpadArtifacts
    if errorlevel 1 exit /b %errorlevel%

    call :BuildHydraDragonFirewall
    if errorlevel 1 exit /b %errorlevel%
) else (
    echo [INFO] Skipping external dependency builds... Run with "--full" to rebuild dependencies and HydraDragonFirewall.
)

echo [INFO] Initializing Visual Studio 2022 x64 Environment...
call "%vcvarsall%" x64
if errorlevel 1 (
    echo [ERROR] Failed to initialize Visual Studio 2022 x64 environment.
    exit /b !errorlevel!
)

echo [INFO] Building HydraDragon EDR Solution...
msbuild edrav2.sln /p:Configuration=Release /p:Platform=x64 /t:Build /m
if errorlevel 1 (
    echo [ERROR] Build failed! errorlevel: !errorlevel!
    exit /b !errorlevel!
)

call :CopyHydraDragonFirewallRuntime
if errorlevel 1 exit /b %errorlevel%

echo [SUCCESS] Build completed successfully!
exit /b 0

:EnsureCrashpadArtifacts
set "MissingCrashpad="
for %%F in (
    "%CrashpadRoot%\out\Debug-Win32\obj\client\client.lib"
    "%CrashpadRoot%\out\Debug-Win32\obj\util\util.lib"
    "%CrashpadRoot%\out\Debug-Win32\obj\third_party\mini_chromium\mini_chromium\base\base.lib"
    "%CrashpadRoot%\out\Debug-x64\obj\client\client.lib"
    "%CrashpadRoot%\out\Debug-x64\obj\util\util.lib"
    "%CrashpadRoot%\out\Debug-x64\obj\third_party\mini_chromium\mini_chromium\base\base.lib"
    "%CrashpadRoot%\out\Release-Win32\obj\client\client.lib"
    "%CrashpadRoot%\out\Release-Win32\obj\util\util.lib"
    "%CrashpadRoot%\out\Release-Win32\obj\third_party\mini_chromium\mini_chromium\base\base.lib"
    "%CrashpadRoot%\out\Release-x64\obj\client\client.lib"
    "%CrashpadRoot%\out\Release-x64\obj\util\util.lib"
    "%CrashpadRoot%\out\Release-x64\obj\third_party\mini_chromium\mini_chromium\base\base.lib"
) do (
    if not exist "%%~fF" (
        echo [ERROR] Missing Crashpad artifact: %%~fF
        set "MissingCrashpad=1"
    )
)

if defined MissingCrashpad (
    echo [ERROR] Crashpad static libraries are incomplete. Rebuild "%CrashpadRoot%" before continuing.
    exit /b 1
)

echo [INFO] Crashpad artifacts are present.
exit /b 0

:BuildHydraDragonFirewall
if not exist "%FirewallProjectDir%\Cargo.toml" (
    echo [WARN] HydraDragonFirewall project not found at "%FirewallProjectDir%". Skipping firewall build.
    exit /b 0
)

if not exist "%WinDivertDir%\WinDivert.lib" (
    echo [ERROR] Missing WinDivert import library at "%WinDivertDir%\WinDivert.lib".
    exit /b 1
)

echo [INFO] Initializing Visual Studio 2022 x64 Environment for HydraDragonFirewall...
call "%vcvarsall%" x64 >nul
if errorlevel 1 (
    echo [ERROR] Failed to initialize Visual Studio 2022 x64 environment for HydraDragonFirewall.
    exit /b !errorlevel!
)

echo [INFO] Building HydraDragonFirewall release artifacts...
pushd "%FirewallProjectDir%"
set "WINDIVERT_PATH=%WinDivertDir%"
set "WINDIVERT_DLL_OUTPUT=%FirewallTargetDir%"
cargo build --release
set "BuildRc=%errorlevel%"
popd

if not "%BuildRc%"=="0" (
    echo [ERROR] HydraDragonFirewall build failed! errorlevel: %BuildRc%
    exit /b %BuildRc%
)

if not exist "%FirewallTargetDir%\hydradragonfirewall.exe" (
    echo [ERROR] Expected HydraDragonFirewall executable was not produced.
    exit /b 1
)

if not exist "%FirewallTargetDir%\hydradragonfirewall.dll" (
    echo [ERROR] Expected HydraDragonFirewall bridge DLL was not produced.
    exit /b 1
)

call :CopyHydraDragonFirewallRuntime
if errorlevel 1 exit /b %errorlevel%
exit /b 0

:CopyHydraDragonFirewallRuntime
if not exist "%FirewallTargetDir%\hydradragonfirewall.exe" (
    echo [WARN] HydraDragonFirewall runtime is not built yet. Skipping runtime copy.
    exit /b 0
)

if not exist "%OutBinDir%" mkdir "%OutBinDir%"

call :CopyIfExists "%FirewallTargetDir%\hydradragonfirewall.exe" "%OutBinDir%"
call :CopyIfExists "%FirewallTargetDir%\hydradragonfirewall.dll" "%OutBinDir%"
call :CopyIfExists "%FirewallTargetDir%\hydradragonfirewall.pdb" "%OutBinDir%"
call :CopyIfExists "%FirewallTargetDir%\WinDivert.dll" "%OutBinDir%"
call :CopyIfExists "%FirewallTargetDir%\WinDivert64.sys" "%OutBinDir%"
call :CopyIfExists "%FirewallProjectDir%\rules.yaml" "%OutBinDir%"
call :CopyIfExists "%FirewallProjectDir%\settings.json" "%OutBinDir%"

if exist "%FirewallProjectDir%\dist" (
    robocopy "%FirewallProjectDir%\dist" "%OutBinDir%\dist" /MIR /NFL /NDL /NJH /NJS /NP >nul
    if errorlevel 8 (
        echo [ERROR] Failed to copy HydraDragonFirewall UI assets.
        exit /b !errorlevel!
    )
)

echo [INFO] HydraDragonFirewall runtime copied to "%OutBinDir%".
exit /b 0

:CopyIfExists
if exist "%~1" (
    xcopy "%~1" "%~2\" /Y /I >nul
) else (
    echo [WARN] Optional HydraDragonFirewall artifact not found: %~1
)
exit /b 0
