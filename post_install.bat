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

echo [*] Desktop sanctum path: %DESKTOP_SANCTUM%

:: --------------------------------------------------------
:: 3) Check %APPDATA%\Sanctum and auto-download missing files
:: --------------------------------------------------------
set "SANCTUM_DIR=%APPDATA%\Sanctum"
set "FILE1=ioc_list.txt"
set "FILE2=config.cfg"

set "URL_BASE=https://raw.githubusercontent.com/0xflux/Sanctum/refs/heads/main/clean_files"

echo [*] Checking Sanctum directory: "%SANCTUM_DIR%"

if not exist "%SANCTUM_DIR%" (
    echo [!] Sanctum folder missing — creating it...
    mkdir "%SANCTUM_DIR%" >nul 2>&1
    if errorlevel 1 (
        echo [!] ERROR: Could not create "%SANCTUM_DIR%".
        pause
        exit /b
    )
)

echo [*] Checking required files...

:: ----------------------------
:: 3.1) Check/download ioc_list.txt
:: ----------------------------
if exist "%SANCTUM_DIR%\%FILE1%" (
    echo [+] Found: %FILE1%
) else (
    echo [!] Missing %FILE1%, downloading...
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%URL_BASE%/%FILE1%', '%SANCTUM_DIR%\%FILE1%')"
    if not exist "%SANCTUM_DIR%\%FILE1%" (
        echo [!] ERROR: Failed to download %FILE1%
        pause
        exit /b
    )
    echo [+] Downloaded %FILE1%
)

:: ----------------------------
:: 3.2) Check/download config.cfg
:: ----------------------------
if exist "%SANCTUM_DIR%\%FILE2%" (
    echo [+] Found: %FILE2%
) else (
    echo [!] Missing %FILE2%, downloading...
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%URL_BASE%/%FILE2%', '%SANCTUM_DIR%\%FILE2%')"
    if not exist "%SANCTUM_DIR%\%FILE2%" (
        echo [!] ERROR: Failed to download %FILE2%
        pause
        exit /b
    )
    echo [+] Downloaded %FILE2%
)

echo [+] All required Sanctum files are present.

:: --------------------------------------------------------
:: 4) Run ELAM installer first (if exists)
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
:: 5) Install OwlyshieldRansomFilter driver
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
:: 6) Install MBRFilter driver
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
:: 7) Install ProcessRegeditFileProtection driver
:: --------------------------------------------------------
echo Installing ProcessRegeditFileProtection driver INF...
pnputil /add-driver "%~dp0hydradragon\ProcessRegeditFileProtection\SimplePYASProtection.inf" /install
if %errorlevel% neq 0 (
    echo [!] ProcessRegeditFileProtection driver install failed.
    pause
    exit /b
)
echo [+] ProcessRegeditFileProtection driver installed.

:: --------------------------------------------------------
:: 8) Register HydraDragonAntivirus scheduled task (autostart after reboot)
:: --------------------------------------------------------
set "HD_TASK_EXE=%~dp0Service\HydraDragonTaskScheduler.exe"

if exist "%HD_TASK_EXE%" (
    echo Checking for existing HydraDragonAntivirus scheduled task...
    schtasks /query /tn "HydraDragonAntivirus" >nul 2>&1
)

if %errorlevel%==0 (
    echo Existing task found, deleting...
    schtasks /delete /tn "HydraDragonAntivirus" /f >nul 2>&1
)

echo Creating HydraDragonAntivirus auto-start task (user interactive)...
schtasks /create /tn "HydraDragonAntivirus" /tr "\"%HD_TASK_EXE%\"" /sc ONLOGON /rl HIGHEST /f

if %errorlevel% neq 0 (
    echo [!] Failed to create HydraDragonAntivirus auto-start task.
) else (
    echo [+] HydraDragonAntivirus auto-start task created successfully.
)

:: --------------------------------------------------------
:: 7) Cleanup and restart
:: --------------------------------------------------------
echo Cleaning up installer script and restarting system in 10 seconds...
shutdown -r -t 10
del "%~f0"
endlocal
