@echo off
setlocal

:: paths
set BINARY_DIR=..\hydradragon\Owlyshield\Owlyshield Service
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
if exist "%BINARY_DIR%\owlyshield_ransom.exe" (
    echo Signing owlyshield_ransom.exe...
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%BINARY_DIR%\owlyshield_ransom.exe"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to sign owlyshield_ransom.exe.
        exit /b 1
    )
) else (
    echo [ERROR] %BINARY_DIR%\owlyshield_ransom.exe not found.
    exit /b 1
)

:: Sign tensorflow DLLs
for %%F in ("%BINARY_DIR%\tensorflowlite*.dll") do (
    echo Signing %%F...
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%%F"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to sign %%F.
        exit /b 1
    )
)

echo [SUCCESS] Owlyshield binaries signed successfully!

endlocal
exit /b 0
