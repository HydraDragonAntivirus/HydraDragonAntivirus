@echo off
setlocal enabledelayedexpansion

REM --- check g++ exists ---
where g++ >nul 2>&1
if errorlevel 1 (
  echo ERROR: g++ not found in PATH.
  echo Install MinGW/MSYS2 or add g++ to PATH and retry.
  exit /b 1
)

REM --- try to detect target from g++ -dumpmachine ---
set "DUMP="
for /f "usebackq tokens=*" %%I in (`g++ -dumpmachine 2^>nul`) do set "DUMP=%%I"

REM fallback: parse g++ -v output for "Target:" line (some toolchains)
if "%DUMP%"=="" (
  for /f "usebackq tokens=*" %%I in (`g++ -v 2^>^&1 ^| findstr /i "Target"`) do set "DUMP=%%I"
)

echo g++ reported: %DUMP%

REM --- choose arch default 32, switch to 64 if we see common 64-bit markers ---
set "ARCH=32"
echo %DUMP% | findstr /i "x86_64 amd64 win64 aarch64 x64" >nul && set "ARCH=64"

echo Detected architecture: %ARCH%-bit

REM --- create output directory ---
if not exist bin (
  mkdir bin
)

set "ARCH_FLAG=-m32"
if "%ARCH%"=="64" (
  set "OUT=bin\hook64.dll"
  set "ARCH_FLAG=-m64"
) else (
  set "OUT=bin\hook32.dll"
)

echo Compiling hook_dll.cpp -> %OUT% ...
echo Using architecture flag: %ARCH_FLAG%

REM --- FINAL COMMAND: Using the powerful -static flag to ensure ZERO external dependencies ---
g++ hook_dll.cpp -o "%OUT%" %ARCH_FLAG% -s -O2 -shared -fPIC -static -lshlwapi -lpsapi -lshell32
if errorlevel 1 (
  echo.
  echo Build FAILED.
  exit /b 1
) else (
  echo.
  echo Build succeeded: %OUT%
)

endlocal
exit /b 0
