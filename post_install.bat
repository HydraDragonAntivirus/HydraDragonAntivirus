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
:: 4) Install OwlyshieldRansomFilter driver
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
    ) else (
        echo [+] ProcessRegeditFileProtection service created.
    )
) else (
    echo [!] SimplePYASProtection.sys not found at "%PROCESS_REG_FILE_PROT_SYS%".
)

:: --------------------------------------------------------
:: 7) Install OwlyShield anti-ransom service (auto)
::    - Creates folder: %HYDRADRAGON_ROOT_PATH%\OwlyShield Service\OwlyShieldService\
::    - Copies owlyshield_ransom.exe from installer tree if present
::    - Creates a service named "OwlyShieldService"
:: NOTE: sc.exe has no 'runhidden' flag; service runs in session 0.
:: --------------------------------------------------------
set "OWLY_SRC_EXE=%~dp0hydradragon\Owlyshield\owlyshield_ransom.exe"
set "OWLY_TARGET_DIR=%HYDRADRAGON_ROOT_PATH%\OwlyShield Service\OwlyShieldService"
set "OWLY_TARGET_EXE=%OWLY_TARGET_DIR%\owlyshield_ransom.exe"
set "OWLY_SERVICE_NAME=OwlyShieldService"

echo [*] Preparing OwlyShield anti-ransom service...

:: create target folder if missing
if not exist "%OWLY_TARGET_DIR%" (
    echo [*] Creating OwlyShield target directory: "%OWLY_TARGET_DIR%"
    mkdir "%OWLY_TARGET_DIR%"
)

:: copy exe if present in installer tree
if exist "%OWLY_SRC_EXE%" (
    echo [*] Copying OwlyShield executable to target directory...
    copy /Y "%OWLY_SRC_EXE%" "%OWLY_TARGET_EXE%" >nul
    if %errorlevel% neq 0 (
        echo [!] Failed to copy OwlyShield executable.
    ) else (
        echo [+] OwlyShield executable copied to "%OWLY_TARGET_EXE%".
    )
) else (
    echo [!] OwlyShield executable not found at installer path: "%OWLY_SRC_EXE%"
    echo [!] Please ensure owlyshield_ransom.exe is packaged at that location or copy it manually to "%OWLY_TARGET_EXE%"
)

:: create or replace service
sc query "%OWLY_SERVICE_NAME%" >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Existing service "%OWLY_SERVICE_NAME%" found, deleting it first...
    sc delete "%OWLY_SERVICE_NAME%"
    timeout /t 2 >nul
)

if exist "%OWLY_TARGET_EXE%" (
    echo [*] Creating service "%OWLY_SERVICE_NAME%" pointing to "%OWLY_TARGET_EXE%"...
    sc create "%OWLY_SERVICE_NAME%" binPath= "\"%OWLY_TARGET_EXE%\"" start= auto
    if %errorlevel% neq 0 (
        echo [!] Failed to create OwlyShield service.
    ) else (
        echo [+] OwlyShield service "%OWLY_SERVICE_NAME%" created successfully.
        sc description "%OWLY_SERVICE_NAME%" "OwlyShield anti-ransom service (HydraDragon)"
    )
) else (
    echo [!] OwlyShield target executable not present; service not created.
)

:: --------------------------------------------------------
:: 8) Register HydraDragonAntivirus scheduled task (autostart after reboot)
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
:: 9) Cleanup and restart
:: --------------------------------------------------------
echo Cleaning up installer script and restarting system in 10 seconds...
shutdown -r -t 10
del "%~f0"
endlocal
