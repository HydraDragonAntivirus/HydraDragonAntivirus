@echo off
setlocal

:: paths
set BINARY_DIR=..\hydradragon\HydraDragonFirewall
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

:: Sign the EXE
if exist "%BINARY_DIR%\hydradragonfirewall.exe" (
    echo Signing hydradragonfirewall.exe...
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /ph /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%BINARY_DIR%\hydradragonfirewall.exe"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to sign hydradragonfirewall.exe.
        exit /b 1
    )
) else (
    echo [ERROR] %BINARY_DIR%\hydradragonfirewall.exe not found.
    exit /b 1
)

:: Sign the DLL
if exist "%BINARY_DIR%\hydradragonfirewall.dll" (
    echo Signing hydradragonfirewall.dll...
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /ph /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%BINARY_DIR%\hydradragonfirewall.dll"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to sign hydradragonfirewall.dll.
        exit /b 1
    )
)

:: Sign WinDivert
if exist "%BINARY_DIR%\WinDivert.dll" (
    echo Signing WinDivert.dll...
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /ph /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%BINARY_DIR%\WinDivert.dll"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to sign WinDivert.dll.
        exit /b 1
    )
)

echo [SUCCESS] Firewall binaries signed successfully!

endlocal
exit /b 0
