@echo off
setlocal enabledelayedexpansion

set DLL_PATH=%~1
set CERT_NAME=HydraDragonTestCert

if not exist "%DLL_PATH%" exit /b 0

REM Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

certutil -store My "%CERT_NAME%" >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    powershell -ExecutionPolicy Bypass -Command "New-SelfSignedCertificate -DnsName '%CERT_NAME%' -CertStoreLocation 'Cert:\CurrentUser\My' -Type CodeSigningCert -Subject 'CN=%CERT_NAME%'" >nul 2>&1
)

signtool sign /a /n "%CERT_NAME%" /fd SHA256 "%DLL_PATH%" >nul 2>&1
exit /b 0
