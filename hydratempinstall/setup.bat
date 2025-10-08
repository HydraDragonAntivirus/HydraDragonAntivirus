@echo off
setlocal enabledelayedexpansion

set "HYDRADRAGON_PATH=%ProgramW6432%\HydraDragonAntivirus\hydradragon"
set "HYDRADRAGON_ROOT_PATH=%ProgramW6432%\HydraDragonAntivirus"
set "CLAMAV_DIR=%ProgramW6432%\ClamAV"
set "SURICATA_DIR=%ProgramW6432%\Suricata"
set "NODEJS_PATH=%ProgramW6432%\nodejs"
set "PKG_UNPACKER_DIR=%HYDRADRAGON_PATH%\pkg-unpacker"
set "CLEAN_VM_PSB_PATH=%HYDRADRAGON_PATH%\hydradragon\Sanctum\clean_vm\installer_clean_vm.ps1"
set "SANCTUM_APPDATA_PATH=%HYDRADRAGON_PATH%\hydradragon\Sanctum\AppData"
set "SANCTUM_APPDATA_PATH=%HYDRADRAGON_PATH%\hydradragon\Sanctum"

rem 1. Copy clamavconfig
if exist "%HYDRADRAGON_PATH%\clamavconfig" (
    xcopy /Y "%HYDRADRAGON_PATH%\clamavconfig\*.*" "%CLAMAV_DIR%\"
    rmdir /s /q "%HYDRADRAGON_PATH%\clamavconfig"
) else (
    echo clamavconfig directory not found.
)

rem 2. Copy suricata.yaml from hipsconfig to suricata directory
if exist "%HYDRADRAGON_PATH%\hipsconfig\suricata.yaml" (
    copy /Y "%HYDRADRAGON_PATH%\hipsconfig\suricata.yaml" "%SURICATA_DIR%\suricata.yaml"
    echo Copied suricata.yaml to %SURICATA_DIR%
) else (
    echo suricata.yaml not found in hipsconfig directory.
)

rem 3. Copy threshold.config from hipsconfig to suricata directory
if exist "%HYDRADRAGON_PATH%\hipsconfig\threshold.config" (
    copy /Y "%HYDRADRAGON_PATH%\hipsconfig\threshold.config" "%SURICATA_DIR%\threshold.config"
    echo Copied threshold.config to %SURICATA_DIR%
) else (
    echo threshold.config not found in hipsconfig directory.
)

rem 4. Copy hips rules
if exist "%HYDRADRAGON_PATH%\hips" (
    xcopy /Y "%HYDRADRAGON_PATH%\hips\emerging-all.rules" "%SURICATA_DIR%\rules\"
    rmdir /s /q "%HYDRADRAGON_PATH%\hips"
) else (
    echo hips directory not found.
)

rem 5. Copy database
if exist "%HYDRADRAGON_PATH%\database" (
    xcopy /Y "%HYDRADRAGON_PATH%\database\*.*" "%CLAMAV_DIR%\database\"
    rmdir /s /q "%HYDRADRAGON_PATH%\database"
) else (
    echo database directory not found.
)

rem 6. Update ClamAV virus definitions
echo Updating ClamAV virus definitions...
"%CLAMAV_DIR%\freshclam.exe"
if %errorlevel% equ 0 (
    echo ClamAV virus definitions updated successfully.
) else (
    echo Failed to update ClamAV virus definitions.
)

rem ------------------------------------------------------------------------
rem 7. Run installer_clean_vm.ps1 if present (silent, bypass policy)

if exist "%CLEAN_VM_PSB_PATH%" (
    echo Running installer_clean_vm.ps1...
    powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%CLEAN_VM_PSB_PATH%"
    if %errorlevel% neq 0 (
        echo installer_clean_vm.ps1 exited with code %errorlevel%.
    ) else (
        echo installer_clean_vm.ps1 completed successfully.
    )
) else (
    echo installer_clean_vm.ps1 not found at "%CLEAN_VM_PSB_PATH%". Skipping.
)

rem ------------------------------------------------------------------------
rem 8. Copy Sanctum AppData to Roaming and move leftover to Desktop
set "ROAMING_SANCTUM=%APPDATA%\Sanctum"
set "DESKTOP_SANCTUM=%USERPROFILE%\Desktop\sanctum"

if exist "%SANCTUM_APPDATA_PATH%" (
    echo Copying Sanctum AppData to "%ROAMING_SANCTUM%"...
    xcopy /E /I /H /R /Y "%SANCTUM_APPDATA_PATH%\*" "%ROAMING_SANCTUM%\" >nul
    if %errorlevel% equ 0 (
        echo Copy succeeded - removing original Sanctum folder "%SANCTUM_APPDATA_PATH%"...
        rmdir /S /Q "%SANCTUM_APPDATA_PATH%"
        if %errorlevel% equ 0 (
            echo Original Sanctum folder removed.
        ) else (
            echo WARNING: Failed to remove "%SANCTUM_APPDATA_PATH%".
        )
    ) else (
        echo ERROR: Failed to copy Sanctum AppData to "%ROAMING_SANCTUM%". Original left intact.
    )
) else (
    echo Sanctum source folder "%SANCTUM_APPDATA_PATH%" not found — skipping copy.
)

rem 9. Now copy any remaining Sanctum data (if any) to Desktop\sanctum
if exist "%SANCTUM_APPDATA_PATH%" (
    echo Copying any remaining Sanctum files to "%DESKTOP_SANCTUM%"...
    xcopy /E /I /H /R /Y "%SANCTUM_APPDATA_PATH%\*" "%DESKTOP_SANCTUM%\" >nul
    if %errorlevel% equ 0 (
        echo Remaining Sanctum data copied to "%DESKTOP_SANCTUM%".
    ) else (
        echo No remaining Sanctum data copied (or copy failed).
    )
) else (
    echo No remaining Sanctum folder at "%SANCTUM_APPDATA_PATH%" to copy to Desktop.
)

rem 10. Create Python virtual environment inside HydraDragonAntivirus folder
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

rem 11. Activate virtual environment
echo Activating virtual environment...
call "venv\Scripts\activate.bat"
if %errorlevel% neq 0 (
    echo Failed to activate virtual environment.
    goto :end
)

rem 12. Upgrade pip
echo Upgrading pip...
py.exe -3.12 -m pip install --upgrade pip
if %errorlevel% equ 0 (
    echo pip was upgraded successfully.
) else (
    echo Failed to upgrade pip.
)

rem 13. Install Poetry in the activated virtual environment
echo Installing Poetry in virtual environment...
pip install poetry
if %errorlevel% neq 0 (
    echo Failed to install Poetry.
    goto :cleanup
)
echo Poetry installed successfully.

rem 14. Install dependencies with Poetry (if pyproject.toml exists)
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

rem 15. Install spaCy English medium model
echo Installing spaCy 'en_core_web_md' model...
python -m spacy download en_core_web_md
if %errorlevel% equ 0 (
    echo spaCy model 'en_core_web_md' installed successfully.
) else (
    echo Failed to install spaCy model 'en_core_web_md'.
)

rem 16. Install asar globally with npm
echo Installing 'asar' npm package globally...
"%NODEJS_PATH%\npm.cmd" install -g asar
if %errorlevel% equ 0 (
    echo 'asar' package installed successfully.
) else (
    echo Failed to install 'asar' package.
)

rem 17. Install webcrack globally with npm
echo Installing 'webcrack' npm package globally...
"%NODEJS_PATH%\npm.cmd" install -g webcrack
if %errorlevel% equ 0 (
    echo 'webcrack' package installed successfully.
) else (
    echo Failed to install 'webcrack' package.
)

rem 18. Install nexe_unpacker globally with npm
echo Installing 'nexe_unpacker' npm package globally...
"%NODEJS_PATH%\npm.cmd" install -g nexe_unpacker
if %errorlevel% equ 0 (
    echo 'nexe_unpacker' package installed successfully.
) else (
    echo Failed to install 'nexe_unpacker' package.
)

rem --------------------------------------------------------------------------
rem 19. Navigate to HydraDragon pkg-unpacker folder and build npm project
if exist "%PKG_UNPACKER_DIR%" (
    echo Navigating to HydraDragon pkg-unpacker folder...
    cd /d "%PKG_UNPACKER_DIR%"
    if errorlevel 1 (
        echo ERROR: Failed to change directory to %PKG_UNPACKER_DIR%
        goto :end
    )

    rem Install npm dependencies
    echo Installing npm dependencies...
    "%NODEJS_PATH%\npm.cmd" install
    if %errorlevel% neq 0 (
        echo Failed to install npm dependencies.
        goto :end
    )
    echo npm dependencies installed successfully.

    rem Build the npm project
    echo Building npm project...
    "%NODEJS_PATH%\npm.cmd" run build
    if %errorlevel% neq 0 (
        echo Failed to build npm project.
        goto :end
    )
    echo npm project built successfully.
) else (
    echo HydraDragon pkg-unpacker folder not found, skipping npm build.
)

echo Setup completed successfully!

:end
echo.
echo Press any key to exit...
pause >nul
endlocal
