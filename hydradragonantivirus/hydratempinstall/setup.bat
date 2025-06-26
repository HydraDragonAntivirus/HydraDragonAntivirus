@echo off
setlocal enabledelayedexpansion

rem Define base paths without hardcoding full HydraDragonAntivirus path
set "HYDRADRAGON_PATH=%ProgramFiles%\HydraDragonAntivirus\hydradragonantivirus"
set "CLAMAV_DIR=%ProgramFiles%\ClamAV"
set "SNORT_DIR=%ProgramFiles%\Snort"
set "SBIE_INI=%ProgramFiles%\Sandboxie\SbieIni.exe"
set "SBIE_SANDBOX=DefaultBox"
set "INJECT_DLL=%HYDRADRAGON_PATH%\sandboxie_plugins\SbieHide\SbieHide.x64.dll"

rem 1. Copy clamavconfig
if exist "%HYDRADRAGON_PATH%\clamavconfig" (
    xcopy /Y "%HYDRADRAGON_PATH%\clamavconfig\*.*" "%CLAMAV_DIR%\"
    rmdir /s /q "%HYDRADRAGON_PATH%\clamavconfig"
) else (
    echo clamavconfig directory not found.
)

rem 2. Copy hipsconfig
if exist "%HYDRADRAGON_PATH%\hipsconfig" (
    xcopy /Y "%HYDRADRAGON_PATH%\hipsconfig\*.*" "%SNORT_DIR%\etc\"
    rmdir /s /q "%HYDRADRAGON_PATH%\hipsconfig"
) else (
    echo hipsconfig directory not found.
)

rem 3. Copy hips rules
if exist "%HYDRADRAGON_PATH%\hips" (
    xcopy /Y "%HYDRADRAGON_PATH%\hips\snort2.9.rules" "%SNORT_DIR%\rules\"
    xcopy /Y "%HYDRADRAGON_PATH%\hips\snort2.rules" "%SNORT_DIR%\rules\" 2>nul
    xcopy /Y "%HYDRADRAGON_PATH%\hips\emergingthreats\*.*" "%SNORT_DIR%\rules\" /S /E /I
    rmdir /s /q "%HYDRADRAGON_PATH%\hips"
) else (
    echo hips directory not found.
)

rem 4. Copy database
if exist "%HYDRADRAGON_PATH%\database" (
    xcopy /Y "%HYDRADRAGON_PATH%\database\*.*" "%CLAMAV_DIR%\database\"
    rmdir /s /q "%HYDRADRAGON_PATH%\database"
) else (
    echo database directory not found.
)

rem 5. Update ClamAV virus definitions
echo Updating ClamAV virus definitions...
"%CLAMAV_DIR%\freshclam.exe"
if %errorlevel% equ 0 (
    echo ClamAV virus definitions updated successfully.
) else (
    echo Failed to update ClamAV virus definitions.
)

rem 6. Install clamd service
echo Installing clamd service...
"%CLAMAV_DIR%\clamd.exe" --install
if %errorlevel% equ 0 (
    echo clamd service installed successfully.
) else (
    echo Failed to install clamd service.
)

rem 7. Upgrade pip
echo Upgrading pip...
py.exe -3.11 -m pip install --upgrade pip
if %errorlevel% equ 0 (
    echo pip was upgraded successfully.
) else (
    echo Failed to upgrade pip.
)

rem 8. Create Python virtual environment inside HydraDragonAntivirus folder
echo Creating Python virtual environment...

cd /d "%HYDRADRAGON_PATH%"
if errorlevel 1 (
    echo ERROR: "%HYDRADRAGON_PATH%" directory not found.
    goto :end
)

py.exe -3.11 -m venv venv
if %errorlevel% neq 0 (
    echo Failed to create Python virtual environment.
    goto :end
)

rem 9. Install Poetry
echo Installing Poetry...
call venv\Scripts\activate.bat
python -m pip install poetry
if %errorlevel% neq 0 (
    echo Failed to install Poetry.
    goto :end
)
echo Poetry installed successfully.

rem 10. Install dependencies with Poetry
echo Installing project dependencies with Poetry...
py -3.11 -m poetry install
if %errorlevel% neq 0 (
    echo Failed to install dependencies with Poetry.
    goto :end
)
echo Dependencies installed successfully.

rem 11. Configure Sandboxie if available
if not exist "%SBIE_INI%" (
    echo ERROR: %SBIE_INI% not found.
    goto :end
)

echo Modifying Sandboxie settings...
"%SBIE_INI%" set %SBIE_SANDBOX% BlockNetworkFiles n
"%SBIE_INI%" set %SBIE_SANDBOX% InjectDll64 "%INJECT_DLL%"
"%SBIE_INI%" set %SBIE_SANDBOX% ClosedFilePath ""

echo Done.

:end
pause >nul
endlocal
