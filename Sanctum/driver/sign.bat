@echo off
setlocal

:: paths
set BUILD_PROFILE=%~1
if "%BUILD_PROFILE%"=="" set BUILD_PROFILE=debug
if /I "%BUILD_PROFILE%"=="help" goto :usage
if /I "%BUILD_PROFILE%"=="/?" goto :usage
if /I "%BUILD_PROFILE%"=="-h" goto :usage
if /I "%BUILD_PROFILE%"=="--help" goto :usage

if /I not "%BUILD_PROFILE%"=="debug" if /I not "%BUILD_PROFILE%"=="release" (
    echo [ERROR] Unknown build profile "%BUILD_PROFILE%".
    goto :usage_error
)

set DRIVER_PATH=target\%BUILD_PROFILE%\sanctum_package\sanctum.sys
set PFX_FILE=sanctum.pfx
set PFX_PASSWORD=password

if not exist "%DRIVER_PATH%" (
    echo [ERROR] Driver not found: %DRIVER_PATH%
    echo Build it first with:
    if /I "%BUILD_PROFILE%"=="release" (
        echo   cargo make release
    ) else (
        echo   cargo make
    )
    exit /b 1
)

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

:usage
echo Usage: sign.bat [debug^|release]
echo.
echo Examples:
echo   sign.bat
echo   sign.bat debug
echo   sign.bat release
endlocal
exit /b 0

:usage_error
echo Usage: sign.bat [debug^|release]
endlocal
exit /b 1
