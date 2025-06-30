@echo off
setlocal enabledelayedexpansion

set "HYDRADRAGON_PATH=%ProgramW6432%\HydraDragonAntivirus\hydradragon"
set "HYDRADRAGON_ROOT_PATH=%ProgramW6432%\HydraDragonAntivirus"
set "CLAMAV_DIR=%ProgramW6432%\ClamAV"
set "SNORT_DIR=%SystemDrive%\Snort"
set "SBIE_INI=%ProgramW6432%\Sandboxie\SbieIni.exe"
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
py.exe -3.12 -m pip install --upgrade pip
if %errorlevel% equ 0 (
    echo pip was upgraded successfully.
) else (
    echo Failed to upgrade pip.
)

rem 8. Create Python virtual environment inside HydraDragonAntivirus folder
echo Creating Python virtual environment...

cd /d "%HYDRADRAGON_ROOT_PATH%"
if errorlevel 1 (
    echo ERROR: "%HYDRADRAGON_PATH%" directory not found.
    goto :end
)

py.exe -3.12 -m venv venv
if %errorlevel% neq 0 (
    echo Failed to create Python virtual environment.
    goto :end
)

rem 9. Activate virtual environment
echo Activating virtual environment...
call "venv\Scripts\activate.bat"
if %errorlevel% neq 0 (
    echo Failed to activate virtual environment.
    goto :end
)

rem 10. Install Poetry in the activated virtual environment
echo Installing Poetry in virtual environment...
pip install poetry
if %errorlevel% neq 0 (
    echo Failed to install Poetry.
    goto :cleanup
)
echo Poetry installed successfully.

rem 11. Install dependencies with Poetry (if pyproject.toml exists)
if exist "pyproject.toml" (
    echo Installing project dependencies with Poetry...
    poetry install
    if %errorlevel% neq 0 (
        echo Failed to install dependencies with Poetry.
        goto :cleanup
    )
    echo Dependencies installed successfully.
) else (
    echo No pyproject.toml found, skipping Poetry dependency installation.
)

rem 12. Install spaCy English medium model
echo Installing spaCy 'en_core_web_md' model...
python -m spacy download en_core_web_md
if %errorlevel% equ 0 (
    echo spaCy model 'en_core_web_md' installed successfully.
) else (
    echo Failed to install spaCy model 'en_core_web_md'.
)

rem 13. Configure Sandboxie if available
if not exist "%SBIE_INI%" (
    echo WARNING: %SBIE_INI% not found. Skipping Sandboxie configuration.
    goto :end
)

echo Modifying Sandboxie settings...
"%SBIE_INI%" set %SBIE_SANDBOX% BlockNetworkFiles n
"%SBIE_INI%" set %SBIE_SANDBOX% InjectDll64 "%INJECT_DLL%"
"%SBIE_INI%" set %SBIE_SANDBOX% ClosedFilePath ""

echo Setup completed successfully!

:end
echo.
echo Press any key to exit...
pause >nul
endlocal
