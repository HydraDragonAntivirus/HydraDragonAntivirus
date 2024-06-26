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

:: Set the PATH variable to include ClamAV, Snort, and Sandboxie
set "PATH=%PATH%;C:\Program Files\ClamAV;C:\Snort\bin;C:\Program Files\Sandboxie"

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

:: Install Python requirements
if exist requirements.txt (
    echo Installing Python requirements...
    pip install -r requirements.txt
    echo Python requirements installed.
) else (
    echo requirements.txt not found. Please ensure it is in the same directory as this script.
)

:: Setup MBRFilter
:: Check system architecture and copy appropriate MBRFilter files
echo Setting up MBRFilter...
set "MBRFILTER_DIR=%~dp0\mbrfilter"
if exist "%MBRFILTER_DIR%" (
    if %PROCESSOR_ARCHITECTURE%==AMD64 (
        xcopy "%MBRFILTER_DIR%\x64\MBRFilter.inf" "%SYSTEMROOT%\System32\DriverStore\FileRepository" /Y
    ) else (
        xcopy "%MBRFILTER_DIR%\x86\MBRFilter.inf" "%SYSTEMROOT%\System32\DriverStore\FileRepository" /Y
    )
    echo MBRFilter setup completed.
) else (
    echo MBRFilter directory not found. Please ensure it is in the same directory as this script.
)

echo Setup complete.
pause