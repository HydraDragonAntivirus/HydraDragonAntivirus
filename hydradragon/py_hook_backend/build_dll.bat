@echo off
setlocal EnableDelayedExpansion

rem Always switch to the directory this script lives in.
cd /d "%~dp0"

echo ============================================================
echo  hook64.dll + hook32.dll  --  MSVC VS 2022
echo  Script dir: %~dp0
echo ============================================================

set "VC_ROOT="
for %%E in (Community Professional Enterprise) do (
    set "CANDIDATE=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build"
    if exist "!CANDIDATE!\vcvars64.bat" (
        set "VC_ROOT=!CANDIDATE!"
        goto :found_vc
    )
)

echo [ERROR] Could not find VS 2022.
echo         Install the "Desktop development with C++" workload.
pause
exit /b 1

:found_vc
echo [INFO]  VC root: %VC_ROOT%

set "SRC=hook_dll.cpp"
if not exist "%SRC%" (
    echo [ERROR] %SRC% not found in: %CD%
    pause
    exit /b 1
)

if not exist "bin" mkdir bin

set "CFLAGS=/std:c++17 /EHsc /W4 /O2 /GL /MP /nologo /D NDEBUG /D _WINDOWS /D _USRDLL"
set "LIBS=kernel32.lib user32.lib psapi.lib shlwapi.lib shell32.lib advapi32.lib"

echo.
echo [64-bit] Initialising x64 environment...
call "%VC_ROOT%\vcvars64.bat" >nul 2>&1

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cl.exe not found after vcvars64.bat
    pause
    exit /b 1
)

echo [64-bit] Compiling %SRC% -^> bin\hook64.dll ...
echo.
cl.exe %CFLAGS% ^
    /D HOOK_BUILD_64 ^
    /LD "%SRC%" ^
    /Fe:"bin\hook64.dll" ^
    /Fo:"bin\hook64.obj" ^
    /link /OPT:REF /OPT:ICF /LTCG /MACHINE:X64 %LIBS%

if errorlevel 1 (
    echo.
    echo [ERROR] 64-bit build FAILED.
    pause
    exit /b 1
)

echo.
echo [64-bit] SUCCESS: bin\hook64.dll

echo.
echo [32-bit] Initialising x86 environment...
call "%VC_ROOT%\vcvars32.bat" >nul 2>&1

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cl.exe not found after vcvars32.bat
    pause
    exit /b 1
)

echo [32-bit] Compiling %SRC% -^> bin\hook32.dll ...
echo.
cl.exe %CFLAGS% ^
    /D HOOK_BUILD_32 ^
    /LD "%SRC%" ^
    /Fe:"bin\hook32.dll" ^
    /Fo:"bin\hook32.obj" ^
    /link /OPT:REF /OPT:ICF /LTCG /MACHINE:X86 %LIBS%

if errorlevel 1 (
    echo.
    echo [ERROR] 32-bit build FAILED.
    pause
    exit /b 1
)

echo.
echo [32-bit] SUCCESS: bin\hook32.dll

echo.
echo ============================================================
echo  ALL BUILDS COMPLETE
echo    bin\hook64.dll   (x64)
echo    bin\hook32.dll   (x86)
echo ============================================================
pause
exit /b 0
