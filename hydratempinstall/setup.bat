@echo off
:: ────────────────────────────────────────────────────────────────
:: Refresh PATH from registry (picks up any newly installed entries)
:: ────────────────────────────────────────────────────────────────
for /F "tokens=2*" %%A in ('
  reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path
') do set "SYS_PATH=%%B"

for /F "tokens=2*" %%A in ('
  reg query "HKCU\Environment" /v Path 2^>nul
') do set "USER_PATH=%%B"

if defined USER_PATH (
  set "PATH=%USER_PATH%;%SYS_PATH%"
) else (
  set "PATH=%SYS_PATH%"
)

echo Refreshed PATH from registry:
echo   %PATH%
:: ────────────────────────────────────────────────────────────────

:: Now you can safely call py.exe (or any other newly added tools)
:: without specifying full paths or restarting.

:: Copy files from clamavconfig to C:\Program Files\ClamAV
if exist "C:\Program Files\HydraDragonAntivirus\clamavconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\clamavconfig\*.*" "C:\Program Files\ClamAV\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\clamavconfig"
) else (
    echo clamavconfig directory not found.
)

:: Copy files from hipsconfig to C:\Snort\etc
if exist "C:\Program Files\HydraDragonAntivirus\hipsconfig" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hipsconfig\*.*" "C:\Snort\etc\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hipsconfig"
) else (
    echo hipsconfig directory not found.
)

:: Copy specific files from hips to C:\Snort\rules
if exist "C:\Program Files\HydraDragonAntivirus\hips" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.9.rules" "C:\Snort\rules\" 
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\snort2.rules"   "C:\Snort\rules\" 2>nul
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\hips\emergingthreats\*.*" "C:\Snort\rules\" /S /E /I
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\hips"
) else (
    echo hips directory not found.
)

:: Copy database files to C:\Program Files\ClamAV\database
if exist "C:\Program Files\HydraDragonAntivirus\database" (
    xcopy /Y "C:\Program Files\HydraDragonAntivirus\database\*.*" "C:\Program Files\ClamAV\database\" 
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\database"
) else (
    echo database directory not found.
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

:: Upgrade pip
echo Upgrading pip...
py.exe -3.12 -m pip install --upgrade pip
if %errorlevel% equ 0 (
    echo pip was upgraded successfully.
) else (
    echo Failed to upgrade pip.
)

:: Install python requirements
echo Installing python requirements...
py.exe -3.12 -m pip install -r "C:\Program Files\HydraDragonAntivirus\requirements.txt"
if %errorlevel% equ 0 (
    echo Python requirements installed successfully.
) else (
    echo Failed to install Python requirements.
)

:: Install spaCy English medium model
echo Installing spaCy 'en_core_web_md' model...
spacy download en_core_web_md
if %errorlevel% equ 0 (
    echo spaCy model 'en_core_web_md' installed successfully.
) else (
    echo Failed to install spaCy model 'en_core_web_md'.
)

echo --- Starting Sandboxie Configuration Update ---

:: 1. Copy Sandboxie.ini
if exist "C:\Program Files\HydraDragonAntivirus\SandboxieSettings\Sandboxie.ini" (
    copy /Y "C:\Program Files\HydraDragonAntivirus\SandboxieSettings\Sandboxie.ini" "C:\Windows\Sandboxie.ini"
    echo Sandboxie.ini was successfully copied.
) else (
    echo Sandboxie.ini not found.
)

:: 2. Delete the SandboxieSettings folder
if exist "C:\Program Files\HydraDragonAntivirus\SandboxieSettings" (
    rmdir /s /q "C:\Program Files\HydraDragonAntivirus\SandboxieSettings"
    echo SandboxieSettings folder deleted.
) else (
    echo SandboxieSettings folder not found.
)

:: 3. Restart Sandboxie service
echo Restarting Sandboxie service...
net stop SbieSvc
net start SbieSvc

echo Setup complete.
pause
