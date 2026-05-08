@echo off
setlocal EnableExtensions

set "POSTINSTALL_STAGE=initial"
if /I "%~1"=="--after-hypervisor-reboot" set "POSTINSTALL_STAGE=after_hypervisor_reboot"
set "POSTINSTALL_LOG_DIR=%ProgramData%\HydraDragonAntivirus"
set "POSTINSTALL_LOG=%POSTINSTALL_LOG_DIR%\post_install.log"
set "POSTINSTALL_LAST_OUTPUT=%TEMP%\HydraDragonPostInstall-last-command.txt"
if not exist "%POSTINSTALL_LOG_DIR%" mkdir "%POSTINSTALL_LOG_DIR%" >nul 2>&1
if not exist "%POSTINSTALL_LOG_DIR%" set "POSTINSTALL_LOG=%TEMP%\HydraDragonAntivirus-post_install.log"
> "%POSTINSTALL_LOG%" (
    echo HydraDragon post-install output
    echo Started: %DATE% %TIME%
    echo Stage: %POSTINSTALL_STAGE%
    echo.
)
call :log [*] Writing post-install log to "%POSTINSTALL_LOG%"

:: --------------------------------------------------------
:: 1) Ensure we're elevated
:: --------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    call :log [!] This script must be run as Administrator.
    call :log [*] Relaunching elevated...
    call :run_and_log powershell -Command "Start-Process '%~f0' -Verb runAs"
    if errorlevel 1 (
        call :show_failure "Could not relaunch post-install elevated."
        exit /b 1
    )
    exit /b 0
)

:: --------------------------------------------------------
:: 2) Disable Windows hypervisor/VBS stack if needed
:: --------------------------------------------------------
if /I "%POSTINSTALL_STAGE%"=="after_hypervisor_reboot" (
    echo [*] Continuing post-install after hypervisor/VBS reboot...
    goto hypervisor_stack_ready
)

call :prepare_hypervisor_stack
if "%TESTSIGNING_ENABLE_FAILED%"=="1" (
    call :log [!] Test signing mode could not be enabled.
    call :log [!] Secure Boot may be blocking test-signed RedDbg/HyperDbg drivers.
    call :log [!] Disable Secure Boot or use production-signed driver packages.
    call :show_failure "Post-install cannot continue because test signing mode could not be enabled."
    exit /b 1
)
if "%HYPERVISOR_REBOOT_REQUIRED%"=="1" (
    call :log [*] Hypervisor/VBS settings were changed. A manual reboot is required before driver installation.
    call :log [*] Scheduling post-install continuation...
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "HydraDragonPostInstallContinue" /t REG_SZ /d "\"%~f0\" --after-hypervisor-reboot" /f > "%POSTINSTALL_LAST_OUTPUT%" 2>&1
    if errorlevel 1 (
        call :show_last_output
        call :show_failure "Failed to schedule post-install continuation after reboot."
        exit /b 1
    )
    call :show_last_output
    call :log [+] Ready for manual reboot.
    exit /b 0
)

:hypervisor_stack_ready

:: --------------------------------------------------------
:: 3) Environment setup
:: --------------------------------------------------------
set "APP_DIR=C:\Program Files\HydraDragonAntivirus"
set "HYDRADRAGON_DIR=%APP_DIR%\hydradragon"
set "OPENEDR_DIR=%APP_DIR%\OpenEDR"
set "SANCTUM_DIR=%HYDRADRAGON_DIR%\Sanctum"

echo [*] Sanctum install path: %SANCTUM_DIR%

:: --------------------------------------------------------
:: 4) Check installed Sanctum folder and auto-download missing files
:: --------------------------------------------------------
echo [*] Checking Sanctum directory: "%SANCTUM_DIR%"

if not exist "%SANCTUM_DIR%" (
    echo [!] Sanctum folder missing - creating it...
    mkdir "%SANCTUM_DIR%" >nul 2>&1
    if errorlevel 1 (
        call :show_failure "Could not create ""%SANCTUM_DIR%""."
        exit /b 1
    )
)



:: --------------------------------------------------------
:: 5) Run ELAM installer first (if exists)
:: --------------------------------------------------------
set "ELAM_EXE=%SANCTUM_DIR%\elam_installer.exe"

if exist "%ELAM_EXE%" (
    echo [*] Running ELAM installer: "%ELAM_EXE%"
    call :run_and_log "%ELAM_EXE%"
    if errorlevel 1 (
        call :show_failure "ELAM installer failed."
        exit /b 1
    )
    echo [+] ELAM installer completed.
) else (
    echo [!] ELAM installer not found at "%ELAM_EXE%".
)

:: --------------------------------------------------------
:: 6) Install OwlyshieldRansomFilter driver
:: --------------------------------------------------------
call :install_driver_inf "OwlyshieldRansomFilter" "%HYDRADRAGON_DIR%\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf" required
if errorlevel 1 exit /b 1

:: --------------------------------------------------------
:: 7) Install MBRFilter driver
:: --------------------------------------------------------
call :install_driver_inf "MBRFilter" "%HYDRADRAGON_DIR%\MBRFilter\MBRFilter.inf" required
if errorlevel 1 exit /b 1

:: --------------------------------------------------------
:: 8) Install SimplePYASProtection driver
:: --------------------------------------------------------
call :install_driver_inf "SimplePYASProtection" "%HYDRADRAGON_DIR%\SimplePYASProtection\SimplePYASProtection.inf" required
if errorlevel 1 exit /b 1

:: --------------------------------------------------------
:: 9) Install RedDbg driver (AMD Hypervisor)
:: --------------------------------------------------------
call :install_driver_inf "RedDbg" "%HYDRADRAGON_DIR%\Owlyshield\RedDbg\RedDbgDrv.inf" optional

:: --------------------------------------------------------
:: 10) Install HyperDbg driver (Intel Hypervisor)
:: --------------------------------------------------------
call :install_driver_inf "HyperDbg" "%HYDRADRAGON_DIR%\Owlyshield\HyperDbg\hyperhv.inf" optional

:: --------------------------------------------------------
:: 11) Register HydraDragonAntivirus scheduled task (autostart after reboot)
:: --------------------------------------------------------
set "HD_TASK_EXE=%HYDRADRAGON_DIR%\HydraDragonService\HydraDragonService.exe"
set "HD_TASK_EXISTS=0"

if not exist "%HD_TASK_EXE%" (
    echo [!] HydraDragon service executable not found at "%HD_TASK_EXE%".
    echo [*] Skipping HydraDragonAntivirus scheduled task creation.
    goto after_hd_task
)

echo Checking for existing HydraDragonAntivirus scheduled task...
call :log [cmd] schtasks /query /tn "HydraDragonAntivirus"
schtasks /query /tn "HydraDragonAntivirus" >nul 2>&1
if errorlevel 1 (
    call :log [*] No existing HydraDragonAntivirus scheduled task found.
) else (
    set "HD_TASK_EXISTS=1"
    call :log [+] Existing HydraDragonAntivirus scheduled task found.
)

if "%HD_TASK_EXISTS%"=="1" (
    echo Existing task found, deleting...
    call :run_and_log schtasks /delete /tn "HydraDragonAntivirus" /f
)

echo Creating HydraDragonAntivirus auto-start task (user interactive)...
schtasks /create /tn "HydraDragonAntivirus" /tr "\"%HD_TASK_EXE%\"" /sc ONLOGON /rl HIGHEST /f > "%POSTINSTALL_LAST_OUTPUT%" 2>&1
set "RUN_EXIT=%errorlevel%"
call :show_last_output

if not "%RUN_EXIT%"=="0" (
    echo [!] Failed to create HydraDragonAntivirus auto-start task.
) else (
    echo [+] HydraDragonAntivirus auto-start task created successfully.
)

:after_hd_task

:: --------------------------------------------------------
:: 12) Install OpenEDR service
:: --------------------------------------------------------
set "EDR_EXE=%OPENEDR_DIR%\edrsvc.exe"
call :log [*] Checking for OpenEDR at "%EDR_EXE%"...
if exist "%EDR_EXE%" (
    call :log [*] Installing OpenEDR service (Native mode)...
    call :run_and_log "%EDR_EXE%" install
    if errorlevel 1 (
        call :log [!] OpenEDR service install returned error code %errorlevel%.
    ) else (
        call :log [+] OpenEDR service install command completed.
    )

    call :log [*] Configuring OpenEDR kernel driver (edrdrv)...
    call :run_and_log sc config edrdrv start= system
    call :run_and_log sc start edrdrv
    if errorlevel 1 (
        call :log [!] edrdrv driver start pending or failed (check logs after reboot).
    ) else (
        call :log [+] edrdrv driver started successfully.
    )
) else (
    call :log [!] OpenEDR service executable NOT FOUND at "%EDR_EXE%".
    call :log [!] Skipping OpenEDR service installation.
)

:: --------------------------------------------------------
:: 13) Cleanup
:: --------------------------------------------------------
echo Cleaning up installer script...
if exist "%POSTINSTALL_LAST_OUTPUT%" del "%POSTINSTALL_LAST_OUTPUT%" >nul 2>&1
echo [+] Installation steps complete. Please RESTART manually to activate all drivers.
del "%~f0"
endlocal
goto :eof

:log
echo %*
if defined POSTINSTALL_LOG >> "%POSTINSTALL_LOG%" echo %*
exit /b 0

:run_and_log
call :log [cmd] %*
%* > "%POSTINSTALL_LAST_OUTPUT%" 2>&1
set "RUN_EXIT=%errorlevel%"
call :show_last_output
exit /b %RUN_EXIT%

:show_last_output
if exist "%POSTINSTALL_LAST_OUTPUT%" (
    type "%POSTINSTALL_LAST_OUTPUT%"
    if defined POSTINSTALL_LOG type "%POSTINSTALL_LAST_OUTPUT%" >> "%POSTINSTALL_LOG%"
)
exit /b 0

:show_failure
set "FAIL_MESSAGE=%~1"
echo.
echo [!] %FAIL_MESSAGE%
if defined POSTINSTALL_LOG (
    >> "%POSTINSTALL_LOG%" echo.
    >> "%POSTINSTALL_LOG%" echo [!] %FAIL_MESSAGE%
    >> "%POSTINSTALL_LOG%" echo [!] Finished with errors: %DATE% %TIME%
    echo [!] Full output saved to "%POSTINSTALL_LOG%".
    echo [*] Opening failure output in Notepad...
    start "" notepad.exe "%POSTINSTALL_LOG%"
)
pause
exit /b 0

:install_driver_inf
set "DRIVER_NAME=%~1"
set "DRIVER_INF=%~2"
set "DRIVER_REQUIRED=%~3"

if /I "%DRIVER_REQUIRED%"=="required" (
    set "DRIVER_IS_REQUIRED=1"
) else (
    set "DRIVER_IS_REQUIRED=0"
)

if not exist "%DRIVER_INF%" (
    echo [!] %DRIVER_NAME% driver INF not found at "%DRIVER_INF%".
    if "%DRIVER_IS_REQUIRED%"=="1" (
        call :show_failure "%DRIVER_NAME% driver INF is missing."
        exit /b 1
    )
    echo [*] Skipping optional %DRIVER_NAME% driver.
    exit /b 0
)

echo Installing %DRIVER_NAME% driver INF...
call :run_and_log pnputil /add-driver "%DRIVER_INF%" /install
if errorlevel 1 (
    if "%DRIVER_IS_REQUIRED%"=="1" (
        call :show_failure "%DRIVER_NAME% driver install failed."
        exit /b 1
    )
    echo [!] %DRIVER_NAME% driver install failed or is not applicable on this machine; continuing.
    exit /b 0
)

echo [+] %DRIVER_NAME% driver installed.
exit /b 0

:prepare_hypervisor_stack
set "HYPERVISOR_REBOOT_REQUIRED=0"
set "TESTSIGNING_ENABLE_FAILED=0"
echo [*] Disabling VBS/HVCI/Hyper-V features for hypervisor-based testing compatibility...
echo [*] Note: this only refers to Windows Hyper-V/VBS settings used by this installer.
echo [*] It is separate from the hypervisor material documented in the wiki or other folders.

call :mark_reboot_if_reg_enabled "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
call :mark_reboot_if_reg_enabled "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
call :mark_reboot_if_feature_enabled Microsoft-Hyper-V-All
call :mark_reboot_if_feature_enabled Microsoft-Hyper-V-Hypervisor
call :mark_reboot_if_feature_enabled VirtualMachinePlatform
call :mark_reboot_if_feature_enabled HypervisorPlatform
call :mark_reboot_if_testsigning_disabled

call :run_and_log reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
call :run_and_log reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
call :run_and_log bcdedit /set hypervisorlaunchtype off
call :run_and_log bcdedit /set vsmlaunchtype off
call :run_and_log bcdedit /set testsigning on
if errorlevel 1 (
    set "TESTSIGNING_ENABLE_FAILED=1"
)

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

:mark_reboot_if_testsigning_disabled
set "TESTSIGNING_STATE="
for /f "tokens=2" %%A in ('bcdedit /enum {current} ^| findstr /i "testsigning"') do (
    set "TESTSIGNING_STATE=%%A"
)
if /I not "%TESTSIGNING_STATE%"=="Yes" if /I not "%TESTSIGNING_STATE%"=="Evet" set "HYPERVISOR_REBOOT_REQUIRED=1"
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
call :run_and_log dism.exe /Online /Disable-Feature /FeatureName:%~1 /NoRestart
if errorlevel 1 (
    echo [*] Optional feature not changed: %~1
) else (
    echo [+] Optional feature disable requested: %~1
)
exit /b 0

