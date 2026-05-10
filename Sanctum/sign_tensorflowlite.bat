@echo off
setlocal

set "PFX_FILE=driver\sanctum.pfx"
set "PFX_PASSWORD=password"
set "TARGET=..\hydradragon\Owlyshield\Owlyshield Service\tensorflowlite_c.dll"

echo Signing tensorflowlite_c.dll...
signtool.exe sign /fd SHA256 /v /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%TARGET%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to sign tensorflowlite_c.dll.
    exit /b 1
)

echo [SUCCESS] tensorflowlite_c.dll signed successfully!

endlocal
exit /b 0
