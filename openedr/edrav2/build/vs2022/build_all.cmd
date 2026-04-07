@echo off
setlocal

rem Path to VS2022 Developer Prompt
set vcvarsall="%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"

if not exist %vcvarsall% (
    echo Error: Could not find Visual Studio 2022 Build Tools.
    echo Searched path: %vcvarsall%
    exit /b 1
)

rem Option to rebuild all dependencies first
if /I "%~1"=="--full" (
    echo [INFO] Full rebuild requested. Building all external dependencies first...
    
    cd ..\..\
    for /d %%D in (eprj\*) do (
        if exist "%%D\build.cmd" (
            echo.
            echo ========================================================
            echo [INFO] Building dependency: %%D
            echo ========================================================
            pushd "%%D"
            call build.cmd
            if %errorlevel% neq 0 (
                echo [ERROR] Build failed for %%D
                exit /b %errorlevel%
            )
            popd
        )
    )
    cd build\vs2022
) else (
    echo [INFO] Skipping external dependency builds... Run with '--full' to build dependencies as well.
)

rem Initialize MSVC environment
echo [INFO] Initializing Visual Studio 2022 x64 Environment...
call %vcvarsall% x64

echo [INFO] Building HydraDragon EDR Solution...

rem Build the solution Release x64
msbuild edrav2.sln /p:Configuration=Release /p:Platform=x64 /t:Build /m

if %errorlevel% neq 0 (
    echo [ERROR] Build failed! errorlevel: %errorlevel%
    exit /b %errorlevel%
)

echo [SUCCESS] Build completed successfully!
exit /b 0
