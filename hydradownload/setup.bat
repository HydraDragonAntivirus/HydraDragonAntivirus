@echo off

:: Check for administrator rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator access...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && %~nx0' -Verb RunAs"
    exit /b
)

:: Change to the specified working directory
cd /d "C:\Program Files\HydraDragonAntivirus"

echo Setting PATH environment variable...

set "CLAMAV_PATH=C:\Program Files\ClamAV"
set "SNORT_PATH=C:\Snort\bin"
set "SANDBOXIE_PATH=C:\Program Files\Sandboxie"

rem Add paths to the system PATH variable
setx PATH "%PATH%;%CLAMAV_PATH%;%SNORT_PATH%;%SANDBOXIE_PATH%" /M

echo PATH variable updated with ClamAV, Snort, and Sandboxie paths.

:: Move files from clamavconfig to C:\Program Files\ClamAV
if exist clamavconfig (
    move clamavconfig\*.* "C:\Program Files\ClamAV" /Y
    move clamavconfig\freshclam.conf "C:\Program Files\ClamAV" /Y
    move clamavconfig\clamd.conf "C:\Program Files\ClamAV" /Y
    rmdir /s /q clamavconfig
) else (
    echo clamavconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Move files from hipsconfig to C:\Snort\etc
if exist hipsconfig (
    move hipsconfig\*.* "C:\Snort\etc" /Y
    rmdir /s /q hipsconfig
) else (
    echo hipsconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Move specific files from hips to C:\Snort\rules
if exist hips (
    if exist hips\snort2.9.rules (
        move hips\snort2.9.rules "C:\Snort\rules" /Y
    )
    if exist hips\snort2.rules (
        move hips\snort2.rules "C:\Snort\rules" /Y
    )
    if exist hips\emergingthreats (
        move hips\emergingthreats\*.* "C:\Snort\rules" /Y
    )
    rmdir /s /q hips
) else (
    echo hips directory not found. Please ensure it is in the same directory as this script.
)

:: Move database files to C:\Program Files\ClamAV\database
if exist database (
    move database\*.* "C:\Program Files\ClamAV\database" /Y
    rmdir /s /q database
) else (
    echo database directory not found. Please ensure it is in the same directory as this script.
)

:: Run freshclam to update virus definitions
echo Updating ClamAV virus definitions...
"C:\Program Files\ClamAV\freshclam.exe"
echo ClamAV virus definitions updated.

:: Install clamd
echo Installing clamd...
"C:\Program Files\ClamAV\clamd.exe" --install
if %errorlevel% equ 0 (
    echo clamd installed successfully.
) else (
    echo Failed to install clamd.
)

echo Setup complete.
pause