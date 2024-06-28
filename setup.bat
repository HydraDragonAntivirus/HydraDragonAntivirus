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

echo Setting PATH environment variable...

set "CLAMAV_PATH=C:\Program Files\ClamAV"
set "SNORT_PATH=C:\Snort\bin"
set "SANDBOXIE_PATH=C:\Program Files\Sandboxie"

rem Add paths to the system PATH variable
setx PATH "%PATH%;%CLAMAV_PATH%;%SNORT_PATH%;%SANDBOXIE_PATH%" /M

echo PATH variable updated with ClamAV, Snort, and Sandboxie paths.

:: Create C:\Program Files\ClamAV\database directory if it does not exist
if not exist "C:\Program Files\ClamAV\database" (
    mkdir "C:\Program Files\ClamAV\database"
    echo Created C:\Program Files\ClamAV\database directory.
)

:: Run freshclam to update virus definitions
echo Updating ClamAV virus definitions...
"C:\Program Files\ClamAV\freshclam.exe"
echo ClamAV virus definitions updated.

:: Copy files from clamavconfig to C:\Program Files\ClamAV
if exist clamavconfig (
    xcopy clamavconfig\*.* "C:\Program Files\ClamAV" /Y
) else (
    echo clamavconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Install clamd
echo Installing clamd...
clamd --install
if %errorlevel% equ 0 (
    echo clamd installed successfully.
) else (
    echo Failed to install clamd.
)

:: Copy files from hipsconfig to C:\Snort\etc
if exist hipsconfig (
    xcopy hipsconfig\*.* "C:\Snort\etc" /Y
) else (
    echo hipsconfig directory not found. Please ensure it is in the same directory as this script.
)

:: Copy specific files from hips to C:\Snort\rules
if exist hips (
    if exist hips\snort2.9.rules (
        xcopy hips\snort2.9.rules "C:\Snort\rules" /Y
    )
    if exist hips\snort2.rules (
        xcopy hips\snort2.rules "C:\Snort\rules" /Y
    )
    if exist hips\emergingthreats (
        xcopy hips\emergingthreats\*.* "C:\Snort\rules" /Y
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

:: Install Python requirements
if exist requirements.txt (
    echo Installing Python requirements...
    pip install -r requirements.txt
    echo Python requirements installed.
) else (
    echo requirements.txt not found. Please ensure it is in the same directory as this script.
)

echo Setting up MBRFilter...
set "MBRFILTER_DIR=%~dp0\mbrfilter"

rem Assume infdefaultinstall.exe is in the system PATH

if exist "%MBRFILTER_DIR%" (
    if %PROCESSOR_ARCHITECTURE%==AMD64 (
        infdefaultinstall.exe "%MBRFILTER_DIR%\x64\MBRFilter.inf"
    ) else (
        infdefaultinstall.exe "%MBRFILTER_DIR%\x86\MBRFilter.inf"
    )
    echo MBRFilter setup completed.
) else (
    echo MBRFilter directory not found. Please ensure it is in the same directory as this script.
)

echo Setup complete.
pause