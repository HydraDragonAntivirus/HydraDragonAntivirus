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
set "OutBinDir=%OutDir%\bin\win-Release-x64"
set "CrashpadRoot=%EdrRoot%\eprj\crashpad"
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

) else (
    echo [INFO] Skipping external dependency builds... Run with "--full" to rebuild dependencies.
)

echo [INFO] Initializing Visual Studio 2022 x64 Environment...
call "%vcvarsall%" x64
if errorlevel 1 (
    echo [ERROR] Failed to initialize Visual Studio 2022 x64 environment.
    exit /b !errorlevel!
)

echo [INFO] Building HydraDragon EDR Solution...
msbuild "%SolutionPath%" /p:Configuration=Release /p:Platform=x64 /t:Build /m:1
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
