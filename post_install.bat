@echo off
setlocal

:: --------------------------------------------------------
:: 1) Ensure we're elevated
:: --------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script must be run as Administrator.
    echo [*] Relaunching elevated...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
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
set "PROCESS_REG_FILE_PROT_INF=%~dp0hydradragon\ProcessRegeditFileProtection\SimplePYASProtection.inf"

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
:: 7) Create Run\HydraDragonAntivirus autorun (not a Windows service)
:: --------------------------------------------------------
set "HD_SERVICE_EXE=%HYDRADRAGON_ROOT_PATH%\HydraDragonAntivirusService.exe"
set "RUN_KEY=Software\Microsoft\Windows\CurrentVersion\Run"
set "RUN_NAME=HydraDragonAntivirus"

if exist "%HD_SERVICE_EXE%" (
    echo [*] Adding Run key entry for "%RUN_NAME%" pointing to "%HD_SERVICE_EXE%"

    :: Add to HKLM (per-machine). We're elevated so HKLM should succeed.
    reg add "HKLM\%RUN_KEY%" /v "%RUN_NAME%" /t REG_SZ /d "\"%HD_SERVICE_EXE%\"" /f >nul 2>&1
    if %errorlevel% equ 0 (
        echo [+] HKLM\%RUN_KEY%\%RUN_NAME% created successfully.
        set "REG_TARGET=HKLM"
    ) else (
        echo [!] Failed to write to HKLM. Attempting to write to HKCU instead...
        reg add "HKCU\%RUN_KEY%" /v "%RUN_NAME%" /t REG_SZ /d "\"%HD_SERVICE_EXE%\"" /f >nul 2>&1
        if %errorlevel% equ 0 (
            echo [+] HKCU\%RUN_KEY%\%RUN_NAME% created successfully.
            set "REG_TARGET=HKCU"
        ) else (
            echo [!] Failed to create Run entry in both HKLM and HKCU.
            set "REG_TARGET="
        )
    )

    if defined REG_TARGET (
        echo [*] Verifying registry entry...
        reg query "%REG_TARGET%\%RUN_KEY%" /v "%RUN_NAME%" >nul 2>&1
        if %errorlevel% equ 0 (
            echo [+] Registry Run entry verified.
        ) else (
            echo [!] Registry verification failed.
        )

        echo [*] Launching "%HD_SERVICE_EXE%" now...
        start "" "%HD_SERVICE_EXE%"
        if %errorlevel% neq 0 (
            echo [!] Failed to launch "%HD_SERVICE_EXE%". Start it manually if needed.
        ) else (
            echo [+] Launched successfully.
        )
    )
) else (
    echo [!] HydraDragonAntivirusService.exe not found at "%HD_SERVICE_EXE%". Skipping Run key creation.
)

:: --------------------------------------------------------
:: 8) Cleanup and restart
:: --------------------------------------------------------
echo Cleaning up installer script and restarting system in 10 seconds...
shutdown -r -t 10

:: Attempt to delete the installer script (may fail if in use)
del "%~f0" >nul 2>&1

endlocal
exit /b 0
