@echo off
setlocal enabledelayedexpansion

rem 1. Copy files from clamavconfig to C:\Program Files\ClamAV
if exist "C:\Program Files\HydraDragonAntivirus\clamavconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\clamavconfig\*.*" "C:\Program Files\ClamAV\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\clamavconfig"
) else (
    echo clamavconfig directory not found.
)

rem 2. Copy files from hipsconfig to C:\Snort\etc
if exist "C:\Program Files\HydraDragonAntivirus\hipsconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hipsconfig\*.*" "C:\Snort\etc\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hipsconfig"
) else (
    echo hipsconfig directory not found.
)

rem 3. Copy specific files from hips to C:\Snort\rules
if exist "C:\Program Files\HydraDragonAntivirus\hips" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.9.rules" "C:\Snort\rules\" 
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.rules"   "C:\Snort\rules\" 2>nul
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\emergingthreats\*.*" "C:\Snort\rules\" /S /E /I
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hips"
) else (
    echo hips directory not found.
)

rem 4. Copy database files to C:\Program Files\ClamAV\database
if exist "C:\Program Files\HydraDragonAntivirus\database" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\database\*.*" "C:\Program Files\ClamAV\database\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\database"
) else (
    echo database directory not found.
)

rem 5. Update ClamAV virus definitions
echo Updating ClamAV virus definitions...
"C:\Program Files\ClamAV\freshclam.exe"
if %errorlevel% equ 0 (
    echo ClamAV virus definitions updated successfully.
) else (
    echo Failed to update ClamAV virus definitions.
)

rem 6. Install clamd service
echo Installing clamd service...
"C:\Program Files\ClamAV\clamd.exe" --install
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

rem 8. Install Python requirements
echo Installing Python requirements...
py.exe -3.12 -m pip install -r "C:\Program Files\HydraDragonAntivirus\requirements.txt"
if %errorlevel% equ 0 (
    echo Python requirements installed successfully.
) else (
    echo Failed to install Python requirements.
)

rem 9. Install spaCy English medium model
echo Installing spaCy 'en_core_web_md' model...
py.exe -3.12 -m spacy download en_core_web_md
if %errorlevel% equ 0 (
    echo spaCy model 'en_core_web_md' installed successfully.
) else (
    echo Failed to install spaCy model 'en_core_web_md'.
)

rem Path to SbieIni.exe
set "SbieIniPath=C:\Program Files\Sandboxie\SbieIni.exe"
set "SandboxName=DefaultBox"  rem We're modifying the DefaultBox sandbox.
set "InjectLine=C:\Program Files\HydraDragonAntivirus\sandboxie_plugins\SbieHide\SbieHide.x64.dll"

rem Check if SbieIni.exe exists
if not exist "%SbieIniPath%" (
    echo ERROR: %SbieIniPath% not found.
    goto :end
)

rem Modify BlockNetworkFiles for DefaultBox
echo Modifying BlockNetworkFiles to 'n' for %SandboxName%...
"%SbieIniPath%" set %SandboxName% BlockNetworkFiles n

rem Add InjectDll64 for DefaultBox
echo Adding InjectDll64 for %SandboxName%...
"%SbieIniPath%" set %SandboxName% InjectDll64 "%InjectLine%"

rem Remove ClosedFilePath for DefaultBox
echo Removing ClosedFilePath for %SandboxName%...
"%SbieIniPath%" set %SandboxName% ClosedFilePath "" 

echo Done.
:end
pause >nul
endlocal
