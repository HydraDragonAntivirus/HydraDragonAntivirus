@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "NormalizedPath=%PATH%"
set "Path="
set "PATH=%NormalizedPath%"

for %%I in ("%~dp0.") do set "ScriptDir=%%~fI"
for %%I in ("%ScriptDir%\..\..") do set "EdrRoot=%%~fI"
for %%I in ("%ScriptDir%\..\..\..\..") do set "RepoRoot=%%~fI"

set "SolutionPath=%ScriptDir%\edrav2.sln"
set "OutDir=%EdrRoot%\out"
set "CrashpadRoot=%EdrRoot%\eprj\crashpad"
set "FirewallProjectDir=%RepoRoot%\HydraDragonFirewall\hydradragonfirewall"
set "FirewallTargetDir=%FirewallProjectDir%\target\release"
set "WinDivertDir=%RepoRoot%\HydraDragonFirewall\everything"
set "vcvarsall="
if exist "%ScriptDir%\vcvarsall.bat" set "vcvarsall=%ScriptDir%\vcvarsall.bat"
if exist "%ScriptDir%\vcvarsall.cmd" set "vcvarsall=%ScriptDir%\vcvarsall.cmd"

if not defined vcvarsall (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
        for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
            set "VSInstallDir=%%i"
            if exist "!VSInstallDir!\VC\Auxiliary\Build\vcvarsall.bat" set "vcvarsall=!VSInstallDir!\VC\Auxiliary\Build\vcvarsall.bat"
            if exist "!VSInstallDir!\VC\Auxiliary\Build\vcvarsall.cmd" set "vcvarsall=!VSInstallDir!\VC\Auxiliary\Build\vcvarsall.cmd"
        )
    )
)

if not defined vcvarsall (
    for %%P in (Community Professional Enterprise BuildTools) do (
        if not defined vcvarsall (
            if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat" set "vcvarsall=%ProgramFiles%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat"
            if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat" set "vcvarsall=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat"
        )
    )
)

set "NeedsVcvars=1"
if defined VSCMD_ARG_TGT_ARCH (
    if /i "%VSCMD_ARG_TGT_ARCH%"=="x64" (
        echo [INFO] x64 environment already active.
        set "NeedsVcvars=0"
    )
)

if "!NeedsVcvars!"=="1" (
    if not defined vcvarsall (
        echo [ERROR] Could not find vcvarsall.bat/cmd. Please run this script from an x64 Native Tools Command Prompt or install VS 2022.
        exit /b 1
    )
    echo [INFO] Initializing Visual Studio 2022 x64 Environment...
    call "!vcvarsall!" x64
    if errorlevel 1 (
        echo [ERROR] Failed to initialize Visual Studio 2022 x64 environment.
        exit /b !errorlevel!
    )
)

rem Cleaning will be handled by the --clean flag or within the build flow if needed.

set "DoFullBuild="
set "DoClean="
set "BuildConfig=Release"

:ParseArgs
if "%~1"=="" goto :ArgsDone
if /I "%~1"=="--full" set "DoFullBuild=1"
if /I "%~1"=="--clean" set "DoClean=1"
if /I "%~1"=="--debug" set "BuildConfig=Debug"
if /I "%~1"=="--release" set "BuildConfig=Release"
shift
goto :ParseArgs
:ArgsDone

if defined DoClean (
    echo [INFO] Cleaning build artifacts...
    if exist "%OutDir%" rd /s /q "%OutDir%"
    if exist "%OutDir%" (
        echo [ERROR] Failed to remove "%OutDir%".
        exit /b 1
    )
    echo [SUCCESS] Clean completed successfully.
    if not defined DoFullBuild exit /b 0
)

if defined DoFullBuild (
    if not defined DoClean (
        echo [INFO] Cleaning "%OutDir%" to remove stale build outputs...
        if exist "%OutDir%" rd /s /q "%OutDir%"
    )
    
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

echo [INFO] Building HydraDragon EDR Solution (!BuildConfig!)...
msbuild "%SolutionPath%" /p:Configuration=!BuildConfig! /p:Platform=x64 /t:Build /m:1
if errorlevel 1 (
    echo [ERROR] Build failed! errorlevel: !errorlevel!
    exit /b !errorlevel!
)

echo [SUCCESS] Build completed successfully!
exit /b 0

:EnsureCrashpadArtifacts
set "CrashpadUnavailable="
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
        echo [WARN] Missing Crashpad artifact: %%~fF
        set "CrashpadUnavailable=1"
    ) else if %%~zF lss 1024 (
        echo [WARN] Crashpad artifact looks like a placeholder: %%~fF
        set "CrashpadUnavailable=1"
    )
)

if defined CrashpadUnavailable (
    echo [WARN] Crashpad static libraries are unavailable or invalid. OpenEDR will continue with the built-in minidump crash handler.
    exit /b 0
)

echo [INFO] Crashpad artifacts are present.
exit /b 0

:BuildHydraDragonFirewall
if not exist "%FirewallProjectDir%\Cargo.toml" (
    echo [WARN] HydraDragonFirewall project not found at "%FirewallProjectDir%". Skipping firewall build.
    exit /b 0
)

if not exist "%FirewallProjectDir%\build.py" (
    echo [ERROR] HydraDragonFirewall build script not found at "%FirewallProjectDir%\build.py".
    exit /b 1
)

set "PythonLauncher="
where py >nul 2>&1 && set "PythonLauncher=py -3"
if not defined PythonLauncher (
    where python >nul 2>&1 && set "PythonLauncher=python"
)
if not defined PythonLauncher (
    echo [ERROR] Python launcher not found. Install Python or the Windows py launcher to build HydraDragonFirewall.
    exit /b 1
)

echo [INFO] Building HydraDragonFirewall in its original project location via build.py...
pushd "%FirewallProjectDir%"
call %PythonLauncher% build.py --release
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

echo [INFO] HydraDragonFirewall runtime remains in "%FirewallTargetDir%".
exit /b 0
