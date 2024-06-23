@echo off

:: Check for administrator rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator access...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && %~nx0' -Verb RunAs"
    exit /b
)

:: Change to the directory of the script
cd /d %~dp0

:: Ensure required Python packages are installed
if exist requirements.txt (
    pip install -r requirements.txt
) else (
    echo requirements.txt not found. Please ensure it is in the same directory as this script.
)

:: Set the PATH variable
set PATH=%PATH%;C:\Program Files\ClamAV;C:\Snort\bin;C:\Program Files\Sandboxie

:: Copy files from clamavconfig to C:\Program Files\ClamAV
if exist clamavconfig (
    xcopy clamavconfig\*.* "C:\Program Files\ClamAV" /Y
) else (
    echo clamavconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Copy files from hipsconfig to C:\Snort\etc
if exist hipsconfig (
    xcopy hipsconfig\*.* "C:\Snort\etc" /Y
) else (
    echo hipsconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Copy specific files from hips to C:\Snort\etc
if exist hips (
    if exist hips\snort2.9.rules (
        xcopy hips\snort2.9.rules "C:\Snort\etc" /Y
    )
    if exist hips\snort2.rules (
        xcopy hips\snort2.rules "C:\Snort\etc" /Y
    )
    if exist hips\emergingthreats (
        xcopy hips\emergingthreats\*.* "C:\Snort\etc" /Y
    )
) else (
    echo hips directory not found. Please ensure it is in the same directory as this script.
)

:: Copy database files to C:\Program Files\ClamAV\database
if exist database (
    xcopy database\*.* "C:\Program Files\ClamAV\database" /E /Y
) else (
    echo database directory not found. Please ensure it is in the same directory as this script.
)

echo Setup complete.
pause