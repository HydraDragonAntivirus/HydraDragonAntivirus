@echo off
setlocal EnableExtensions

if /I "%1"=="clean" (
    echo Cleaning...
    del /Q blob_loader.exe *.obj 2>nul
    echo Done.
    goto :eof
)

echo Building blob_loader.exe with MSVC...

cl /nologo /TC /O2 /Iinclude /D_CRT_SECURE_NO_WARNINGS ^
   src\main.c ^
   src\blob_loader.c ^
   src\blob_export.c ^
   src\crc32.c ^
   /Fe:blob_loader.exe ^
   /link /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED.
    echo Make sure you are using a Developer Command Prompt for Visual Studio.
    exit /b 1
)

if not exist pyc_helper.py (
    echo.
    echo WARNING: pyc_helper.py not found next to build.bat / blob_loader.exe
    echo blob_loader.exe --save-pyc will fail until pyc_helper.py is placed there.
)

where py >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo.
    echo WARNING: py launcher not found in PATH.
    echo Runtime export expects: py -3.12 pyc_helper.py ...
)

echo.
echo Built: blob_loader.exe
echo Runtime requires:
echo   1) py launcher with Python 3.12
ECHO   2) pyc_helper.py next to blob_loader.exe

echo.
echo Usage:
echo   blob_loader.exe rcdata_10_3.bin --toc
echo   blob_loader.exe rcdata_10_3.bin --save-pyc output
echo   blob_loader.exe --help

endlocal
