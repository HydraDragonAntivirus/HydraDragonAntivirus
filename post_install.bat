@echo off
setlocal EnableExtensions

set "POSTINSTALL_STAGE=initial"
if /I "%~1"=="--after-hypervisor-reboot" set "POSTINSTALL_STAGE=after_hypervisor_reboot"

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
:: 2) Disable Windows hypervisor/VBS stack if needed
:: --------------------------------------------------------
if /I "%POSTINSTALL_STAGE%"=="after-hypervisor-reboot" (
    echo [*] Continuing post-install after hypervisor/VBS reboot...
) else (
    call :prepare_hypervisor_stack
    if "%HYPERVISOR_REBOOT_REQUIRED%"=="1" (
        echo [*] Hypervisor/VBS settings were changed. A reboot is required before driver installation.
        echo [*] Scheduling post-install continuation after reboot...
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "HydraDragonPostInstallContinue" /t REG_SZ /d "\"%~f0\" --after-hypervisor-reboot" /f >nul 2>&1
        echo [*] Restarting system in 15 seconds...
        shutdown -r -t 15
        exit /b
    )
)

:: --------------------------------------------------------
:: 3) Environment setup
:: --------------------------------------------------------
set "DESKTOP_SANCTUM=%USERPROFILE%\Desktop\sanctum"

echo [*] Desktop sanctum path: %DESKTOP_SANCTUM%

:: --------------------------------------------------------
:: 4) Check %APPDATA%\Sanctum and auto-download missing files
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
:: 5) Run ELAM installer first (if exists)
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
:: 6) Install OwlyshieldRansomFilter driver
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
:: 7) Install MBRFilter driver
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
:: 8) Install SimplePYASProtection driver
:: --------------------------------------------------------
echo Installing SimplePYASProtection driver INF...
pnputil /add-driver "%~dp0hydradragon\SimplePYASProtection\SimplePYASProtection.inf" /install
if %errorlevel% neq 0 (
    echo [!] SimplePYASProtection driver install failed.
    pause
    exit /b
)
echo [+] SimplePYASProtection driver installed.

:: --------------------------------------------------------
:: 8.0) Trust RedDbg/HyperDbg test certificates
:: --------------------------------------------------------
call :trust_driver_cert_if_exists "%~dp0hydradragon\Owlyshield\RedDbg\RedDbgDrv.cer" "RedDbg"
call :trust_driver_cert_if_exists "%~dp0hydradragon\Owlyshield\HyperDbg\hyperhv.cer" "HyperDbg"

:: --------------------------------------------------------
:: 8.1) Install RedDbg driver (AMD Hypervisor)
:: --------------------------------------------------------
echo Installing RedDbg driver INF...
pnputil /add-driver "%~dp0hydradragon\Owlyshield\RedDbg\RedDbgDrv.inf" /install
if %errorlevel% neq 0 (
    echo [!] RedDbg driver install failed (non-fatal if on Intel).
) else (
    echo [+] RedDbg driver installed.
)

:: --------------------------------------------------------
:: 8.2) Install HyperDbg driver (Intel Hypervisor)
:: --------------------------------------------------------
echo Installing HyperDbg driver INF...
pnputil /add-driver "%~dp0hydradragon\Owlyshield\HyperDbg\hyperhv.inf" /install
if %errorlevel% neq 0 (
    echo [!] HyperDbg driver install failed (non-fatal if on AMD).
) else (
    echo [+] HyperDbg driver installed.
)

:: --------------------------------------------------------
:: 9) Register HydraDragonAntivirus scheduled task (autostart after reboot)
:: --------------------------------------------------------
set "HD_TASK_EXE=%~dp0Service\HydraDragonAntivirusTaskScheduler.exe"

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
:: 10) Install OpenEDR service
:: --------------------------------------------------------
set "EDR_EXE=%~dp0OpenEDR\edrsvc.exe"
if exist "%EDR_EXE%" (
    echo [*] Installing OpenEDR service...
    "%EDR_EXE%" install
    echo [+] OpenEDR service installed.
) else (
    echo [!] OpenEDR service not found at "%EDR_EXE%".
)

:: --------------------------------------------------------
:: 11) Cleanup and restart
:: --------------------------------------------------------
echo Cleaning up installer script and restarting system in 10 seconds...
shutdown -r -t 10
del "%~f0"
endlocal
goto :eof

:prepare_hypervisor_stack
set "HYPERVISOR_REBOOT_REQUIRED=0"
echo [*] Disabling VBS/HVCI/Hyper-V features for hypervisor-based testing compatibility...
echo [*] Note: this only refers to Windows Hyper-V/VBS settings used by this installer.
echo [*] It is separate from the hypervisor material documented in the wiki or other folders.

call :mark_reboot_if_reg_enabled "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
call :mark_reboot_if_reg_enabled "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
call :mark_reboot_if_feature_enabled Microsoft-Hyper-V-All
call :mark_reboot_if_feature_enabled Microsoft-Hyper-V-Hypervisor
call :mark_reboot_if_feature_enabled VirtualMachinePlatform
call :mark_reboot_if_feature_enabled HypervisorPlatform

reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
bcdedit /set hypervisorlaunchtype off >nul 2>&1
bcdedit /set vsmlaunchtype off >nul 2>&1

call :disable_feature_if_present Microsoft-Hyper-V-All
call :disable_feature_if_present Microsoft-Hyper-V-Hypervisor
call :disable_feature_if_present VirtualMachinePlatform
call :disable_feature_if_present HypervisorPlatform

if "%HYPERVISOR_REBOOT_REQUIRED%"=="1" (
    echo [+] Hypervisor-conflicting Windows settings were updated.
) else (
    echo [+] Hypervisor-conflicting Windows settings already appear disabled.
)
exit /b 0

:mark_reboot_if_reg_enabled
for /f "tokens=3" %%A in ('reg query "%~1" /v "%~2" 2^>nul ^| find /i "%~2"') do (
    if /I not "%%A"=="0x0" set "HYPERVISOR_REBOOT_REQUIRED=1"
)
exit /b 0

:mark_reboot_if_feature_enabled
dism.exe /Online /English /Get-FeatureInfo /FeatureName:%~1 | findstr /c:"State : Enabled" >nul 2>&1
if not errorlevel 1 set "HYPERVISOR_REBOOT_REQUIRED=1"
exit /b 0

:disable_feature_if_present
dism.exe /Online /Disable-Feature /FeatureName:%~1 /NoRestart >nul 2>&1
if errorlevel 1 (
    echo [*] Optional feature not changed: %~1
) else (
    echo [+] Optional feature disable requested: %~1
)
exit /b 0

:trust_driver_cert_if_exists
if not exist "%~1" (
    echo [*] Test certificate not found for %~2, skipping import.
    exit /b 0
)

echo [*] Importing %~2 test certificate...
certutil -addstore -f Root "%~1" >nul 2>&1
if errorlevel 1 (
    echo [!] Failed to import %~2 certificate into the Root store.
    exit /b 0
)

certutil -addstore -f TrustedPublisher "%~1" >nul 2>&1
if errorlevel 1 (
    echo [!] Failed to import %~2 certificate into the TrustedPublisher store.
    exit /b 0
)

echo [+] %~2 test certificate imported.
exit /b 0
