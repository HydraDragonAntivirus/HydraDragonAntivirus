@echo off

:: Copy files from clamavconfig to C:\Program Files\ClamAV
if exist "C:\Program Files\HydraDragonAntivirus\clamavconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\clamavconfig\*.*" "C:\Program Files\ClamAV\"
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\clamavconfig"
) else (
    echo clamavconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Copy files from hipsconfig to C:\Snort\etc
if exist "C:\Program Files\HydraDragonAntivirus\hipsconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hipsconfig\*.*" "C:\Snort\etc\"
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hipsconfig"
) else (
    echo hipsconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Copy specific files from hips to C:\Snort\rules
if exist "C:\Program Files\HydraDragonAntivirus\hips" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.9.rules" "C:\Snort\rules\"
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.rules" "C:\Snort\rules\" 2>nul
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\emergingthreats\*.*" "C:\Snort\rules\" /S /E /I
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hips"
) else (
    echo hips directory not found. Please ensure it is in the same directory as this script.
)

:: Copy database files to C:\Program Files\ClamAV\database
if exist "C:\Program Files\HydraDragonAntivirus\database" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\database\*.*" "C:\Program Files\ClamAV\database\"
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\database"
) else (
    echo database directory not found. Please ensure it is in the same directory as this script.
)

:: Run freshclam to update virus definitions
echo Updating ClamAV virus definitions...
"C:\Program Files\ClamAV\freshclam.exe"
if %errorlevel% equ 0 (
    echo ClamAV virus definitions updated successfully.
) else (
    echo Failed to update ClamAV virus definitions.
)

:: Install clamd
echo Installing clamd...
"C:\Program Files\ClamAV\clamd.exe" --install
if %errorlevel% equ 0 (
    echo clamd installed successfully.
) else (
    echo Failed to install clamd.
)

:: Install python requirements
echo Installing python requirements..
pip install -r "C:\Program Files\HydraDragonAntivirus\requirements.txt"
if %errorlevel% equ 0 (
    echo python requirements installed successfully.
) else (
    echo Failed to install python requirements.
)

:: Install spaCy English medium model
echo Installing spaCy 'en_core_web_md' model...
python -m spacy download en_core_web_md
if %errorlevel% equ 0 (
    echo spaCy model 'en_core_web_md' installed successfully.
) else (
    echo Failed to install spaCy model 'en_core_web_md'.
)

echo --- Starting Sandboxie Configuration Update ---

REM 1. Copy Sandboxie.ini file to the target location
if exist "C:\Program Files\HydraDragonAntivirus\SandboxieSettings\Sandboxie.ini" (
    copy /Y "C:\Program Files\HydraDragonAntivirus\SandboxieSettings\Sandboxie.ini" "C:\Windows\Sandboxie.ini"
    echo Sandboxie.ini was successfully copied.
) else (
    echo Source file not found: Sandboxie.ini
)

REM 2. Delete the SandboxieSettings folder
if exist "C:\Program Files\HydraDragonAntivirus\SandboxieSettings" (
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\SandboxieSettings"
    echo SandboxieSettings folder has been deleted.
) else (
    echo SandboxieSettings folder not found.
)

REM 3. Restart Sandboxie configuration (restart the Sandboxie service)
echo Restarting Sandboxie configuration...
net stop SbieSvc
net start SbieSvc

echo Setup complete.
pause