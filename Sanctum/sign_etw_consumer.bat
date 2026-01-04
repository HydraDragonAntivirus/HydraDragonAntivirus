@echo off
setlocal

:: paths
set SERVICE_BINARY=target\release\etw_consumer.exe
set PFX_FILE=driver\sanctum.pfx
set PFX_PASSWORD=password

:: Check if signtool.exe is available
for /f "delims=" %%A in ('where signtool 2^>nul') do set SIGNTOOL_PATH=%%A

if not defined SIGNTOOL_PATH (
    echo [ERROR] signtool.exe not found. Ensure Windows SDK is installed.
    exit /b 1
)

:: Verify that the PFX file exists
if not exist "%PFX_FILE%" (
    echo [ERROR] Certificate file %PFX_FILE% not found.
    exit /b 1
)

:: Verify that the binary exists
if not exist "%SERVICE_BINARY%" (
    echo [ERROR] Service binary %SERVICE_BINARY% not found.
    exit /b 1
)

:: Sign the service binary
echo Signing %SERVICE_BINARY% with %PFX_FILE%...
"%SIGNTOOL_PATH%" sign /fd SHA256 /v /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%SERVICE_BINARY%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to sign the service binary.
    exit /b 1
)

:: Verify the signature
echo Verifying signature on %SERVICE_BINARY%...
"%SIGNTOOL_PATH%" verify /pa /v "%SERVICE_BINARY%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Signature verification failed.
    exit /b 1
)

echo [SUCCESS] Service binary signed successfully!

endlocal
exit /b 0