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
:: --------------------------------------------------------
set "OWLY_TARGET_EXE=%~dp0hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe"
set "OWLY_SERVICE_NAME=OwlyShield Service"

echo [*] Preparing OwlyShield anti-ransom service...

:: if an existing service exists, delete it first
sc query "%OWLY_SERVICE_NAME%" >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Existing service "%OWLY_SERVICE_NAME%" found, deleting it first...
    sc delete "%OWLY_SERVICE_NAME%" >nul 2>&1
    timeout /t 2 >nul
)

:: create service (note the required space after binPath= and start=)
if exist "%OWLY_TARGET_EXE%" (
    echo [*] Creating service "%OWLY_SERVICE_NAME%" pointing to "%OWLY_TARGET_EXE%"...
    sc create "%OWLY_SERVICE_NAME%" binPath= "\"%OWLY_TARGET_EXE%\"" start= auto
    if %errorlevel% neq 0 (
        echo [!] Failed to create OwlyShield service.
    ) else (
        echo [+] OwlyShield service "%OWLY_SERVICE_NAME%" created successfully.
        sc description "%OWLY_SERVICE_NAME%" "OwlyShield anti-ransom service (HydraDragon)" >nul 2>&1
    )
) else (
    echo [!] OwlyShield target executable not present; service not created.
)

:: --------------------------------------------------------
:: 8) Register HydraDragonAntivirus scheduled task (autostart after reboot)
:: --------------------------------------------------------
set "HD_LAUNCHER_EXE=%~dp0HydraDragonAntivirusLauncher.exe"

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
