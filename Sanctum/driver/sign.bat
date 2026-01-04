@echo off
setlocal

:: paths
set DRIVER_PATH=target\debug\sanctum_package\sanctum.sys
set PFX_FILE=sanctum.pfx
set PFX_PASSWORD=password

:: remove WDK test cert from driver
echo Removing WDK test signature from %DRIVER_PATH%...
signtool remove /s "%DRIVER_PATH%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to remove WDK signature.
    exit /b 1
)

:: sign the driver with sanctum.pfx
echo Signing %DRIVER_PATH% with %PFX_FILE%...
signtool.exe sign /fd SHA256 /v /ph /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%DRIVER_PATH%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to sign the driver.
    exit /b 1
)

echo [SUCCESS] Driver signed successfully!

endlocal
exit /b 0