@echo off
setlocal enabledelayedexpansion

echo HydraDragon Setup
echo ==================

REM Get administrative privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrative privileges confirmed.
) else (
    echo.
    echo ********************************************************
    echo * ERROR: This script must be run as Administrator.   *
    echo * Please right-click and select "Run as administrator". *
    echo ********************************************************
    pause
    exit /b 1
)

echo.
echo [1/4] Enabling Test Signing Mode...
bcdedit /set testsigning on >nul 2>&1
if !errorLevel! neq 0 (
    echo [WARNING] Failed to enable Test Signing mode automatically. 
    echo Please ensure Secure Boot is disabled in BIOS.
) else (
    echo Test Signing mode enabled.
)

echo.
echo [2/4] Signing the Driver...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign_driver.ps1" -DriverPath "%~dp0hydradragonfirewalldrv.sys"
if !errorLevel! neq 0 (
    echo [WARNING] Driver signing failed.
    echo Possible reason: File is in use or Certificate error.
    echo Tip: Try running "sc stop hydradragonfirewalldrv" before retrying.
    echo Continuing anyway...
    timeout /t 3 >nul
)

echo.
echo [3/4] Installing HydraDragon Firewall Driver...
set "DRIVER_PATH=%~dp0hydradragonfirewalldrv.sys"
set "DRIVER_NAME=HydraDragonFirewall"

REM Stop and delete if already exists
sc stop !DRIVER_NAME! >nul 2>&1
sc delete !DRIVER_NAME! >nul 2>&1

REM Create service
sc create !DRIVER_NAME! binPath= "!DRIVER_PATH!" type= kernel start= auto
if !errorLevel! == 0 (
    echo Driver service created successfully.
) else (
    echo Failed to create driver service.
    pause
    exit /b 1
)

echo Starting driver...
sc start !DRIVER_NAME!
if !errorLevel! == 0 (
    echo Driver started successfully.
) else (
    echo.
    echo [IMPORTANT] Driver failed to start (Error 577).
    echo This is EXPECTED if you haven't rebooted since enabling Test Signing.
    echo.
    echo ACTIONS REQUIRED:
    echo 1. REBOOT YOUR COMPUTER.
    echo 2. Run this setup.bat again after reboot.
    echo.
)

echo.
echo [4/4] Setting WinDivert Environment Variable...
set "CURRENT_DIR=%~dp0"
if "%CURRENT_DIR:~-1%"=="\" set "CURRENT_DIR=%CURRENT_DIR:~0,-1%"
setx WINDIVERT_PATH "%CURRENT_DIR%" /M
if !errorLevel! == 0 (
    echo  WINDIVERT_PATH set to !CURRENT_DIR!
) else (
    echo  Failed to set WINDIVERT_PATH. You may need to set it manually to: !CURRENT_DIR!
)

echo.
echo Setup Process Finished!
echo =======================
echo You can run HydraDragonClient.exe or hydradragonfirewall.exe.
echo.
echo [!] NOTE: Close and reopen your terminal/IDE for the WINDIVERT_PATH change to take effect.
echo.
pause
