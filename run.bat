@echo off
:: Check for administrator rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator access...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && %~nx0' -Verb RunAs"
    exit /b
)

:: Administrator privileges granted, proceed with setup
echo Administrator privileges confirmed.

:: Change to the directory of the script
cd /d %~dp0

:: Run the antivirus.py script
python antivirus.py

echo Setup and script execution complete.
pause