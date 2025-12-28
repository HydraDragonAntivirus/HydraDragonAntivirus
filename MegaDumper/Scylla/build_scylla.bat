@echo off
REM Scylla Auto Builder Script
REM Builds Scylla.dll (x64 Release) and copies to MegaDumper

echo ========================================
echo  Scylla Build Script
echo ========================================
echo.

cd /d "%~dp0"

REM Set up Visual Studio environment
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find Common7\Tools\VsDevCmd.bat`) do (
        call "%%i" -arch=amd64 -no_logo
    )
)

echo [1/3] Configuring x64 build...
cmake -B build -A x64
if %ERRORLEVEL% neq 0 (
    echo ERROR: CMake configuration failed!
    pause
    exit /b 1
)

echo.
echo [2/3] Building x64 Release...
cmake --build build --config Release --target Scylla
if %ERRORLEVEL% neq 0 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo [3/3] Copying Scylla.dll to MegaDumper Publish...

set "DEST=..\MegaDumper\bin\Release\Publish"
if not exist "%DEST%" mkdir "%DEST%"
copy /y "build\src\Release\Scylla.dll" "%DEST%\" >nul
echo   Copied to: %DEST%

echo.
echo ========================================
echo  Build Complete!
echo ========================================
pause
