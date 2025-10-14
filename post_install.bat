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
:: 4) Install Owlyshield driver
:: --------------------------------------------------------
echo Installing OwlyshieldRansomFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] OwlyshieldRansomFilter driver install failed.
    pause
    exit /b
)
echo [+] OwlyshieldRansomFilter driver installed.

:: --------------------------------------------------------
:: 5) Install MBRFilter driver
:: --------------------------------------------------------
echo Installing MBRFilter driver INF...
pnputil /add-driver "%~dp0hydradragon\MBRFilter\MBRFilter.inf" /install
if %errorlevel% neq 0 (
    echo [!] MBRFilter driver install failed.
    pause
    exit /b
)
echo [+] MBRFilter driver installed.

:: --------------------------------------------------------
:: 6) Install ProcessRegeditFileProtection driver as a service
:: --------------------------------------------------------
set "PROCESS_REG_FILE_PROT_SYS=%~dp0hydradragon\ProcessRegeditFileProtection\SimplePYASProtection.sys"
set "PROCESS_REG_FILE_PROT_SERVICE=SimplePYASProtection"

if exist "%PROCESS_REG_FILE_PROT_SYS%" (
    echo [*] Creating ProcessRegeditFileProtection service...
    
    :: Delete service if it exists
    sc query "%PROCESS_REG_FILE_PROT_SERVICE%" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [*] Existing service found, deleting...
        sc delete "%PROCESS_REG_FILE_PROT_SERVICE%"
        timeout /t 2 >nul
    )

    :: Create the service
    sc create "%PROCESS_REG_FILE_PROT_SERVICE%" binPath= "%PROCESS_REG_FILE_PROT_SYS%" type= kernel start= auto error= normal

    if %errorlevel% neq 0 (
        echo [!] Failed to create ProcessRegeditFileProtection service.
        pause
        exit /b
    )
) else (
    echo [!] SimplePYASProtection.sys not found at "%PROCESS_REG_FILE_PROT_SYS%".
)

:: --------------------------------------------------------
:: 7) Register HydraDragonAntivirus scheduled task (autostart after reboot)
:: --------------------------------------------------------
set "HD_LAUNCHER_EXE=%HYDRADRAGON_ROOT_PATH%\HydraDragonAntivirusLauncher.exe"

if exist "%HD_LAUNCHER_EXE%" (
    echo Checking for existing HydraDragonAntivirus scheduled task...
    schtasks /query /tn "HydraDragonAntivirus" >nul 2>&1
)

if %errorlevel%==0 (
    echo Existing task found, deleting...
    schtasks /delete /tn "HydraDragonAntivirus" /f >nul 2>&1
)

echo Creating HydraDragonAntivirus auto-start task (user interactive)...
schtasks /create /tn "HydraDragonAntivirus" /tr "\"%HD_LAUNCHER_EXE%\"" /sc ONLOGON /rl HIGHEST /f

if %errorlevel% neq 0 (
    echo [!] Failed to create HydraDragonAntivirus auto-start task.
) else (
    echo [+] HydraDragonAntivirus auto-start task created successfully.
)

:: --------------------------------------------------------
:: 8) Cleanup and restart
:: --------------------------------------------------------
echo Cleaning up installer script and restarting system in 10 seconds...
shutdown -r -t 10
del "%~f0"
endlocal
