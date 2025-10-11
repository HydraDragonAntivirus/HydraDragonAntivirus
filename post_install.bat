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
:: 4) Install unsigned driver INFs
:: --------------------------------------------------------
echo Installing OwlyshieldRansomFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] OwlyshieldRansomFilter driver install failed.
    pause
    exit /b
)
echo [+] OwlyshieldRansomFilter driver installed.

echo Installing MBRFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\MBRFilter\MBRFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] MBRFilter driver install failed.
    pause
    exit /b
)
echo [+] MBRFilter driver installed.

:: --------------------------------------------------------
:: 5) Install ProcessRegeditFileProtection driver
:: --------------------------------------------------------
set "PROCESS_REG_FILE_PROT_INF=%~dp0hydradragon\ProcessRegeditFileProtection\SimplePYASProtection.inf"

if exist "%PROCESS_REG_FILE_PROT_INF%" (
    echo [*] Installing ProcessRegeditFileProtection driver INF...
    pnputil /add-driver "%PROCESS_REG_FILE_PROT_INF%" /install
    if %errorlevel% neq 0 (
        echo [!] ProcessRegeditFileProtection driver install failed.
        pause
        exit /b
    )
    echo [+] ProcessRegeditFileProtection driver installed.
) else (
    echo [!] ProcessRegeditFileProtection INF not found.
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
:: 7) Register HydraDragonAntivirus scheduled task (autostart after reboot)
:: --------------------------------------------------------
set "HD_SERVICE_EXE=%HYDRADRAGON_ROOT_PATH%\HydraDragonAntivirusService.exe"

if exist "%HD_SERVICE_EXE%" (
    echo Checking for existing HydraDragonAntivirus scheduled task...
    schtasks /query /tn "HydraDragonAntivirus" >nul 2>&1
    if %errorlevel% equ 0 (
        echo Existing task found, deleting...
        schtasks /delete /tn "HydraDragonAntivirus" /f >nul 2>&1
    )

    echo Creating HydraDragonAntivirus auto-start task...
    schtasks /create ^
        /tn "HydraDragonAntivirus" ^
        /tr "\"%HD_SERVICE_EXE%\"" ^
        /sc ONSTART ^
        /ru SYSTEM ^
        /rl HIGHEST ^
        /f

    if %errorlevel% neq 0 (
        echo [!] Failed to create HydraDragonAntivirus auto-start task.
    ) else (
        echo [+] HydraDragonAntivirus auto-start task created successfully.
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
exit /b 0
