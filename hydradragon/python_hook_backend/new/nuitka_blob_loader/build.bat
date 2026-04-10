@echo off
setlocal

if /I "%1"=="clean" (
    echo Cleaning...
    del /Q blob_loader.exe *.obj 2>nul
    echo Done.
    goto :eof
)

echo Building blob_loader.exe with MSVC...

cl /TC /O2 /Iinclude /D_CRT_SECURE_NO_WARNINGS ^
   src\main.c ^
   src\blob_loader.c ^
   src\blob_export.c ^
   src\crc32.c ^
   /Fe:blob_loader.exe ^
   /link /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED. Make sure you are running from a
    echo "Developer Command Prompt for Visual Studio".
    exit /b 1
)

echo.
echo Built: blob_loader.exe
echo.
echo Usage:
echo   blob_loader.exe rcdata_10_3.bin --toc
echo   blob_loader.exe rcdata_10_3.bin --save-pyc output
echo   blob_loader.exe --help

endlocal
