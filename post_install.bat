@echo off
:: Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script must be run as Administrator.
    echo [!] Restarting as Administrator...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)
echo [+] Installing driver INF...
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf"
echo [+] Creating 'Owlyshield Service'...
sc create "Owlyshield Service" binPath= "\"%~dp0hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe\""
echo [+] Setting service dependency: OwlyshieldRansomFilter
sc config "Owlyshield Service" depend= OwlyshieldRansomFilter
echo [+] Setting service start mode: demand
sc config "Owlyshield Service" start= demand
echo Done.
pause
:: Delete the script after running
del "%~f0"