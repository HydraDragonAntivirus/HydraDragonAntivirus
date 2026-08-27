@echo off
echo [i] Starting PTM compilation process...

cd /d "C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenEDR\edrav2\out\bin\win-Release-x64"

:: Terminate any stuck edrcon instances
taskkill /F /IM edrcon.exe >nul 2>&1

:: Run edrcon compile
echo [i] Executing edrcon.exe compile...
.\edrcon.exe compile -o ptm.act common.src ptm.local.src

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] ERROR: Compilation failed!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [+] ptm.act generated successfully!
echo [i] Syncing to Install and Upgrade directories...

if exist "..\..\srcBinInstall\win-Release-x64" (
    copy /Y "ptm.act" "..\..\srcBinInstall\win-Release-x64\ptm.act"
)
if exist "..\..\srcBinUpgrade\win-Release-x64\x64" (
    copy /Y "ptm.act" "..\..\srcBinUpgrade\win-Release-x64\x64\ptm.act"
)

echo.
echo [OK] All tasks completed successfully!
pause
