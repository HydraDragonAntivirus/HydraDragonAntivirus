@echo off
setlocal EnableExtensions

set "POSTINSTALL_STAGE=initial"
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
:: 2) Environment setup
:: --------------------------------------------------------
set "APP_DIR=C:\Program Files\HydraDragonAntivirus"
set "HYDRADRAGON_DIR=%APP_DIR%\hydradragon"
set "OPENEDR_DIR=%APP_DIR%\OpenEDR"
set "SANCTUM_DIR=%HYDRADRAGON_DIR%\Sanctum"

echo [*] Sanctum install path: %SANCTUM_DIR%

:: --------------------------------------------------------
:: 3) Check installed Sanctum folder and auto-download missing files
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
:: 4) Run ELAM installer first (if exists)
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
:: 5) Install Sanctum kernel driver service
:: --------------------------------------------------------
set "SANCTUM_SYS=%SANCTUM_DIR%\AppData\sanctum.sys"

if not exist "%SANCTUM_SYS%" (
    call :show_failure "Sanctum kernel driver is missing at ""%SANCTUM_SYS%""."
    exit /b 1
)

call :log [*] Installing Sanctum kernel driver service...
sc query Sanctum >nul 2>&1
if errorlevel 1 (
    call :run_and_log sc create Sanctum type= kernel start= demand error= normal binPath= "%SANCTUM_SYS%"
    if errorlevel 1 (
        call :show_failure "Sanctum kernel driver service creation failed."
        exit /b 1
    )
    call :log [+] Sanctum kernel driver service created.
) else (
    call :log [*] Sanctum service already exists, refreshing driver path and start type...
    call :run_and_log sc config Sanctum type= kernel start= demand error= normal binPath= "%SANCTUM_SYS%"
    if errorlevel 1 (
        call :show_failure "Sanctum kernel driver service configuration failed."
        exit /b 1
    )
    call :log [+] Sanctum kernel driver service configured.
)

:: --------------------------------------------------------
:: 6) Install MBRFilter driver
:: --------------------------------------------------------
call :install_driver_inf "MBRFilter" "%HYDRADRAGON_DIR%\MBRFilter\MBRFilter.inf" required
if errorlevel 1 exit /b 1

:: --------------------------------------------------------
:: 7) Install RedDbg driver (AMD Hypervisor)
:: --------------------------------------------------------
call :install_driver_inf "RedDbg" "%HYDRADRAGON_DIR%\Owlyshield\RedDbg\RedDbgDrv.inf" optional

:: --------------------------------------------------------
:: 8) Install HyperDbg driver (Intel Hypervisor)
:: --------------------------------------------------------
call :install_driver_inf "HyperDbg" "%HYDRADRAGON_DIR%\Owlyshield\HyperDbg\hyperhv.inf" optional

:: --------------------------------------------------------
:: 9) Register HydraDragonAntivirus scheduled task (autostart after reboot)
:: --------------------------------------------------------
set "HD_TASK_EXE=%HYDRADRAGON_DIR%\HydraDragonController\hydradragoncontroller.exe"
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
:: 10) Install OpenEDR service
:: --------------------------------------------------------
set "EDR_EXE=C:\Program Files\HydraDragonAntivirus\OpenEDR\edrsvc.exe"
call :log [*] Checking for OpenEDR at "%EDR_EXE%"...

if not exist "%EDR_EXE%" (
    call :log [!] OpenEDR service executable NOT FOUND.
    call :log [!] Skipping OpenEDR service installation.
    goto :after_openedr
)

call :log [*] Installing OpenEDR service (Native mode)...
call :run_and_log "%EDR_EXE%" install

:: We use a temporary variable for errorlevel to avoid block expansion issues
set "EDR_INSTALL_RES=%errorlevel%"
if not "%EDR_INSTALL_RES%"=="0" (
    call :log [!] OpenEDR service install returned error code %EDR_INSTALL_RES%.
) else (
    call :log [+] OpenEDR service install command completed successfully.
)

call :log [*] Configuring OpenEDR kernel driver (edrdrv)...
sc query edrdrv >nul 2>&1
if not errorlevel 1 (
    call :log [*] Setting edrdrv to AUTO start...
    sc config edrdrv start= auto >nul 2>&1
    call :log [+] edrdrv start type set to auto.
) else (
    call :log [!] edrdrv service not found, skipping config.
)

:after_openedr

:: --------------------------------------------------------
:: 11) Disable Code Integrity for OpenEDR DLL injection
:: --------------------------------------------------------
call :log [*] Configuring system for OpenEDR DLL injection...
call :log [*] Disabling Code Integrity checks to allow edrpm DLL injection...

bcdedit /set nointegritychecks on >nul 2>&1
if errorlevel 1 (
    call :log [!] Failed to disable integrity checks. OpenEDR DLL injection may fail.
) else (
    call :log [+] Code Integrity checks disabled.
)

bcdedit /set testsigning on >nul 2>&1
if errorlevel 1 (
    call :log [!] Failed to enable test signing.
) else (
    call :log [+] Test signing enabled.
)

bcdedit /set hypervisorlaunchtype off >nul 2>&1
if errorlevel 1 (
    call :log [!] Failed to disable hypervisor launch.
) else (
    call :log [+] Hypervisor launch disabled.
)

call :log [*] Disabling Hypervisor-Protected Code Integrity (HVCI/Memory Integrity)...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
if errorlevel 1 (
    call :log [!] Failed to disable HVCI. OpenEDR DLL injection may fail.
) else (
    call :log [+] HVCI/Memory Integrity disabled.
)

call :log [*] These settings allow edrpm32.dll and edrpm64.dll to be injected into processes.
call :log [*] To re-enable security later, run: OpenEDR\edrav2\iprj\edrpm\enable_ci_back.bat

:: --------------------------------------------------------
:: 12) Cleanup and Restart
:: --------------------------------------------------------
echo [+] All installation steps complete!
echo [*] Restarting system in 10 seconds to activate security drivers...

if exist "%POSTINSTALL_LAST_OUTPUT%" del "%POSTINSTALL_LAST_OUTPUT%" >nul 2>&1

shutdown -r -t 10 /f /c "HydraDragon Antivirus installation complete. Restarting to activate security drivers."

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
