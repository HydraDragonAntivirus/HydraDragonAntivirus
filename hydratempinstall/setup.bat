@echo off
setlocal enabledelayedexpansion

:: ───────────────────────────────────────────────────────────────────────────
:: 1. Copy files from clamavconfig to C:\Program Files\ClamAV
if exist "C:\Program Files\HydraDragonAntivirus\clamavconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\clamavconfig\*.*" "C:\Program Files\ClamAV\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\clamavconfig"
) else (
    echo clamavconfig directory not found.
)

:: 2. Copy files from hipsconfig to C:\Snort\etc
if exist "C:\Program Files\HydraDragonAntivirus\hipsconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hipsconfig\*.*" "C:\Snort\etc\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hipsconfig"
) else (
    echo hipsconfig directory not found.
)

:: 3. Copy specific files from hips to C:\Snort\rules
if exist "C:\Program Files\HydraDragonAntivirus\hips" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.9.rules" "C:\Snort\rules\" 
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.rules"   "C:\Snort\rules\" 2>nul
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\emergingthreats\*.*" "C:\Snort\rules\" /S /E /I
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hips"
) else (
    echo hips directory not found.
)

:: 4. Copy database files to C:\Program Files\ClamAV\database
if exist "C:\Program Files\HydraDragonAntivirus\database" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\database\*.*" "C:\Program Files\ClamAV\database\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\database"
) else (
    echo database directory not found.
)

:: 5. Update ClamAV virus definitions
echo Updating ClamAV virus definitions...
"C:\Program Files\ClamAV\freshclam.exe"
if %errorlevel% equ 0 (
    echo ClamAV virus definitions updated successfully.
) else (
    echo Failed to update ClamAV virus definitions.
)

:: 6. Install or reinstall clamd service
echo Installing clamd service...
"C:\Program Files\ClamAV\clamd.exe" --install
if %errorlevel% equ 0 (
    echo clamd service installed successfully.
) else (
    echo Failed to install clamd service.
)

:: 7. Upgrade pip
echo Upgrading pip...
py.exe -3.12 -m pip install --upgrade pip
if %errorlevel% equ 0 (
    echo pip was upgraded successfully.
) else (
    echo Failed to upgrade pip.
)

:: 8. Install Python requirements
echo Installing Python requirements...
py.exe -3.12 -m pip install -r "C:\Program Files\HydraDragonAntivirus\requirements.txt"
if %errorlevel% equ 0 (
    echo Python requirements installed successfully.
) else (
    echo Failed to install Python requirements.
)

:: 9. Install spaCy English medium model
echo Installing spaCy 'en_core_web_md' model...
py.exe -3.12 -m spacy download en_core_web_md
if %errorlevel% equ 0 (
    echo spaCy model 'en_core_web_md' installed successfully.
) else (
    echo Failed to install spaCy model 'en_core_web_md'.
)

:: ───────────────────────────────────────────────────────────────────────────
echo --- Starting Sandboxie Configuration Update ---

set "SourceIni=C:\Program Files\HydraDragonAntivirus\SandboxieSettings\Sandboxie.ini"
set "DestIni=C:\Windows\Sandboxie.ini"
set "TmpDest=%DestIni%.tmp"
set "SectionFile=%~dp0DefaultBox.section"

if not exist "%SourceIni%" (
    echo ERROR: Source INI not found: "%SourceIni%"
    goto SkipSandboxie
)
if not exist "%DestIni%" (
    echo ERROR: Destination INI not found: "%DestIni%"
    goto SkipSandboxie
)

:: 10. Extract [DefaultBox] section from source
> "%SectionFile%" (
  set "inSection="
  for /f "usebackq delims=" %%L in ("%SourceIni%") do (
    set "line=%%L"
    if /i "!line!"=="[DefaultBox]" (
      set "inSection=1"
    )
    if defined inSection (
      echo !line!
      echo !line! | findstr /b "[" | findstr /i /v "[DefaultBox]" >nul && set "inSection="
    )
  )
)

:: 11. Rewrite destination INI, swapping in new section
> "%TmpDest%" (
  set "skipping="
  for /f "usebackq delims=" %%L in ("%DestIni%") do (
    set "line=%%L"

    if /i "!line!"=="[DefaultBox]" (
      set "skipping=1"
      type "%SectionFile%"
      goto :continue
    )

    if defined skipping (
      echo !line! | findstr /b "[" >nul && (
        set "skipping="
        echo !line!
      )
      goto :continue
    )

    echo !line!

    :continue
  )
)

move /Y "%TmpDest%" "%DestIni%" >nul && (
  echo [DefaultBox] section replaced successfully.
) || (
  echo ERROR: Failed to update "%DestIni%".
)

:: Clean up extracted section file
if exist "%SectionFile%" del /q "%SectionFile%"

:SkipSandboxie
:: 12. Remove the source settings folder
if exist "C:\Program Files\HydraDragonAntivirus\SandboxieSettings" (
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\SandboxieSettings"
    echo SandboxieSettings folder deleted.
) else (
    echo SandboxieSettings folder not found.
)

:: 13. Restart Sandboxie service
echo Restarting Sandboxie service...
net stop SbieSvc
net start SbieSvc

echo --- All tasks complete. Press any key to exit. ---
pause >nul
endlocal
