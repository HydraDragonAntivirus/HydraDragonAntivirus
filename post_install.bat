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
:: 2) Environment setup
:: --------------------------------------------------------
set "DESKTOP_SANCTUM=%USERPROFILE%\Desktop\sanctum"
set "HYDRADRAGON_ROOT_PATH=%ProgramW6432%\HydraDragonAntivirus"

echo [*] Desktop sanctum path: %DESKTOP_SANCTUM%
echo [*] HydraDragon root path: %HYDRADRAGON_ROOT_PATH%

:: --------------------------------------------------------
:: 3) Run ELAM installer first (if exists)
:: --------------------------------------------------------
set "ELAM_EXE=%DESKTOP_SANCTUM%\elam_installer.exe"

if exist "%ELAM_EXE%" (
    echo [*] Running ELAM installer: "%ELAM_EXE%"
    "%ELAM_EXE%"
    echo [+] ELAM installer completed.
) else (
    echo [!] ELAM installer not found at "%ELAM_EXE%".
)

:: --------------------------------------------------------
:: 4) Install the unsigned driver INFs
:: --------------------------------------------------------
echo Installing OwlyshieldRansomFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] OwlyshieldRansomFilter driver install failed. Make sure Test-Signing is enabled or the driver is signed.
    pause
    exit /b
)
echo [+] OwlyshieldRansomFilter driver installed.

echo Installing MBRFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\MBRFilter\MBRFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] MBRFilter driver install failed. Make sure Test-Signing is enabled or the driver is signed.
    pause
    exit /b
)
echo [+] MBRFilter driver installed.

:: --------------------------------------------------------
:: 5) Install ProcessRegeditFileProtection driver (PYAS -> modified for HydraDragon)
:: --------------------------------------------------------
set "PROCESS_REG_FILE_PROT_INF=%~dp0hydradragon\ProcessProtection\ProcessProtection.inf"

if exist "%PROCESS_REG_FILE_PROT_INF%" (
    echo [*] Installing ProcessRegeditFileProtection driver INF from "%PROCESS_REG_FILE_PROT_INF%"...
    pnputil /add-driver "%PROCESS_REG_FILE_PROT_INF%" /install
    if %errorlevel% neq 0 (
        echo [!] ProcessRegeditFileProtection driver install failed. Make sure Test-Signing is enabled or the driver is signed.
        pause
        exit /b
    )
    echo [+] ProcessRegeditFileProtection driver installed.
) else (
    echo [!] ProcessRegeditFileProtection INF not found at "%PROCESS_REG_FILE_PROT_INF%".
)

:: --------------------------------------------------------
:: 6) Create and configure Owlyshield Service
:: --------------------------------------------------------
echo Creating 'Owlyshield Service'...
sc create "Owlyshield Service" binPath= "%~dp0hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe" start= auto
if %errorlevel% neq 0 (
    echo [!] Failed to create 'Owlyshield Service'.
) else (
    echo [+] 'Owlyshield Service' created and set to auto-start.
)

:: --------------------------------------------------------
:: 7) Create HydraDragonAntivirusService auto-start service
:: --------------------------------------------------------
set "HD_SERVICE_EXE=%HYDRADRAGON_ROOT_PATH%\HydraDragonAntivirusService.exe"

if exist "%HD_SERVICE_EXE%" (
    echo Creating 'HydraDragonAntivirusService' service...
    sc create "HydraDragonAntivirusService" binPath= "%HD_SERVICE_EXE%" start= auto DisplayName= "HydraDragon Antivirus Service"
    if %errorlevel% neq 0 (
        echo [!] Failed to create 'HydraDragonAntivirusService'.
    ) else (
        echo [+] 'HydraDragonAntivirusService' created and set to auto-start.
        echo Starting service...
        sc start "HydraDragonAntivirusService"
    )
) else (
    echo [!] HydraDragonAntivirusService.exe not found at "%HD_SERVICE_EXE%".
)

:: --------------------------------------------------------
:: 8) Cleanup and restart
:: --------------------------------------------------------
echo Cleaning up installer script and restarting system in 10 seconds...
shutdown -r -t 10
del "%~f0"
endlocal
