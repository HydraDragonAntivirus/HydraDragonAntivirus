@echo off
setlocal

:: --------------------------------------------------------
:: 1) Ensure we're elevated
:: --------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script must be run as Administrator.
    echo [*] Relaunching elevated...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

:: --------------------------------------------------------
:: 2) Run ELAM installer first (if exists)
:: --------------------------------------------------------
set "DESKTOP_SANCTUM=%USERPROFILE%\Desktop\sanctum"
set "ELAM_EXE=%DESKTOP_SANCTUM%\elam_installer.exe"

if exist "%ELAM_EXE%" (
    echo [*] Running ELAM installer: "%ELAM_EXE%"
    "%ELAM_EXE%"
    echo [+] ELAM installer completed.
) else (
    echo [!] ELAM installer not found at "%ELAM_EXE%".
)

:: --------------------------------------------------------
:: 3) Install the unsigned driver INFs
:: --------------------------------------------------------
echo Installing OwlyshieldRansomFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] OwlyshieldRansomFilter driver install failed. Make sure Test-Signing is enabled or the driver is signed.
    pause
    exit /b
)
echo [+] OwlyshieldRansomFilter driver installed.

:: --------------------------------------------------------
:: 4) Install MBRFilter driver INF
:: --------------------------------------------------------
echo Installing MBRFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\MBRFilter\MBRFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] MBRFilter driver install failed. Make sure Test-Signing is enabled or the driver is signed.
    pause
    exit /b
)
echo [+] MBRFilter driver installed.

:: --------------------------------------------------------
:: 5) Create and configure the service
:: --------------------------------------------------------
echo Creating 'Owlyshield Service'...
sc create "Owlyshield Service" binPath= "%~dp0hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe" start= auto
if %errorlevel% neq 0 (
    echo [!] Failed to create 'Owlyshield Service'.
) else (
    echo [+] Service created and set to auto-start.
)

:: --------------------------------------------------------
:: 6) Cleanup and restart
:: --------------------------------------------------------
echo Cleaning up installer script and restarting system in 10 seconds...
shutdown -r -t 10
del "%~f0"
endlocal
