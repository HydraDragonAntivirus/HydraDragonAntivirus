@echo off
:: Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    rem [!] This script must be run as Administrator.
    rem [!] Restarting as Administrator...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

rem [+] Installing driver INF...
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf"

rem [+] Creating 'Owlyshield Service'...
sc create "Owlyshield Service" binPath= "%~dp0hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe"

rem [+] Setting service dependency: OwlyshieldRansomFilter
sc config "Owlyshield Service" depend= OwlyshieldRansomFilter

rem [+] Setting service start mode: demand
sc config "Owlyshield Service" start= demand

rem [+] Starting service...
sc start "Owlyshield Service"

rem Done.
pause

:: Delete the script after running
del "%~f0"
