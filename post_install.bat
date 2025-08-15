@echo off
setlocal

:: --------------------------------------------------------
:: 1) Ensure we’re elevated
:: --------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script must be run as Administrator.
    echo [*] Relaunching elevated...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

:: --------------------------------------------------------
:: 2) Install the unsigned driver INF
:: --------------------------------------------------------
echo Installing driver INF...
pnputil /add-driver "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] Driver install failed. Make sure Test-Signing is enabled or the driver is signed.
    pause
    exit /b
)
echo [+] Driver installed.

:: --------------------------------------------------------
:: 3) Create and configure the service
:: --------------------------------------------------------
echo Creating 'Owlyshield Service'...
sc create "Owlyshield Service" binPath= "%~dp0hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe"
sc config "Owlyshield Service" depend= OwlyshieldRansomFilter
sc config "Owlyshield Service" start= demand
echo [+] Service configured.

:: --------------------------------------------------------
:: 4) Cleanup
:: --------------------------------------------------------
echo Cleaning up installer script...
del "%~f0"

endlocal
