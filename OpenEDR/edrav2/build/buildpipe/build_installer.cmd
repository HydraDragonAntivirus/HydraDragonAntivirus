@echo off
for %%I in ("%~dp0.") do set "ScriptDir=%%~fI"
pushd "%ScriptDir%"
for %%I in ("%ScriptDir%\..\..") do set "EdrRoot=%%~fI"
for %%I in ("%ScriptDir%\..\..\..\..") do set "RepoRoot=%%~fI"
set "tag=%~1"
set "branch=%tag%"
set "vs_ver=2022"
set "vcvarsall="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VSInstallDir=%%i"
        if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" set "vcvarsall=%%i\VC\Auxiliary\Build\vcvarsall.bat"
    )
)
if not defined vcvarsall (
    for %%P in (Community Professional Enterprise BuildTools) do (
        if not defined vcvarsall (
            if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat" (
                set "VSInstallDir=%ProgramFiles%\Microsoft Visual Studio\2022\%%P"
                set "vcvarsall=%ProgramFiles%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat"
            )
        )
    )
)
if not defined vcvarsall (
    echo [ERROR] Visual Studio 2022 not found.
    exit /b 1
)
set "vsdevcmd=%VSInstallDir%\Common7\Tools\VsDevCmd.bat"
set "msbuild=msbuild"
set "inst_sln=%ScriptDir%\_Build_\edrav2\build\vs2022\edrav2-install.sln"
set "product=edrav2"
set "CL=/Zm500"
rem ========SFTP settings============
set sftphost={sftp_host}
set sftpport={sftp_port}
set sftpuser={sftp_user}
set sftppwd={sftp_password}
rem ========Email settings============
set mailrecipients=-to:{mail_address1} -to:{mail_address2}
set mailserver={mail_server}
set mailsender={mail_sender}
set mailpwd={mail_password}
rem ========Utils settings============
set arc="%ScriptDir%\tools\7za.exe"
set mail="%ScriptDir%\tools\cmail.exe"
set sftp="%ScriptDir%\tools\psftp.exe"

call :checkstate || exit /b 1


if not exist "%ScriptDir%\_Build_" mkdir "%ScriptDir%\_Build_"
if not exist "%ScriptDir%\Logs" mkdir "%ScriptDir%\Logs"

rem call :sendmail "Build started"
echo.>"%ScriptDir%\.buildinprocess"
call :git || ((call :error "Cannot download source files") & exit /b 1)

call :setbuildinfo
echo.Building %ver_full%

if not defined VSINSTALLDIR call "%vsdevcmd%" || exit /b 1

REM Release
rem call :build "%sln%" Release || ((call :error "Compillation failed") & exit /b 1)
rem timeout /t 5 /NOBREAK
echo.Place signed binaries into folders "%ScriptDir%\_Build_\edrav2\out\bin\win-Release-Win32" and "%ScriptDir%\_Build_\edrav2\out\bin\win-Release-x64"
pause
call :build "%inst_sln%" Release || ((call :error "Compillation failed") & exit /b 1)
timeout /t 5 /NOBREAK
call :pack Release || ((call :error "Cannot pack binaries into archive") & exit /b 1)


rem call :finalyze
rem timeout /t 5 /NOBREAK

pause
CHOICE /C yn /m "Do you want to cleanup?"
if %errorlevel% EQU 1 (call :cleanup)

exit /b 0


:checkstate

if "%tag%"=="" (
  set /p tag=Input a tag name to build for: 
)

if "%tag%"=="" ((echo.[ERRO] Tag name is missed) & exit /b 1)
set "branch=%tag%"
  
SETLOCAL EnableDelayedExpansion
if exist "%ScriptDir%\.error" (
  CHOICE /T 10 /C yn /D n /m "Previous run was finished with error. Do you want to delete all data from previous run and proceed from scratch?"
  if !errorlevel! EQU 1 (call :cleanup) else exit /b 1
)
endlocal

if exist "%ScriptDir%\.buildinprocess" (
  echo.[ERRO] Build is already running
  exit /b 1
)

exit /b 0


:git
echo.Downloading source files...
echo.Downloading source files...  2>&1 >>"%ScriptDir%\Logs\script.log"

git -C "%RepoRoot%" rev-parse --is-inside-work-tree >"%ScriptDir%\Logs\git.log" 2>&1 || exit /b 1
git -C "%RepoRoot%" rev-parse --verify "%tag%^{commit}" >>"%ScriptDir%\Logs\git.log" 2>&1 || (
  echo.[ERRO] Branch or tag "%tag%" was not found in "%RepoRoot%".
  echo.[ERRO] Branch or tag "%tag%" was not found in "%RepoRoot%". >>"%ScriptDir%\Logs\script.log"
  exit /b 1
)
for /F %%I in ('git -C "%RepoRoot%" rev-parse "%tag%^{commit}"') do set gitsha1=%%I

if exist "%ScriptDir%\_Build_\%product%" rmdir /q /s "%ScriptDir%\_Build_\%product%"
if exist "%ScriptDir%\_Build_\source.tar" del /q /f "%ScriptDir%\_Build_\source.tar"
git -C "%RepoRoot%" archive --format=tar --output="%ScriptDir%\_Build_\source.tar" "%gitsha1%" OpenEDR/edrav2 >>"%ScriptDir%\Logs\git.log" 2>&1 || exit /b 1
tar -xf "%ScriptDir%\_Build_\source.tar" -C "%ScriptDir%\_Build_" >>"%ScriptDir%\Logs\git.log" 2>&1 || exit /b 1
move "%ScriptDir%\_Build_\OpenEDR\edrav2" "%ScriptDir%\_Build_\%product%" >>"%ScriptDir%\Logs\git.log" 2>&1 || exit /b 1
rmdir /q /s "%ScriptDir%\_Build_\OpenEDR" >nul 2>&1
del /q /f "%ScriptDir%\_Build_\source.tar" >nul 2>&1

if not exist "%ScriptDir%\upload" mkdir "%ScriptDir%\upload"
echo.%gitsha1%>"%ScriptDir%\upload\git.sha1"
set gitshortsha1=%gitsha1:~0,8%

pushd "%ScriptDir%"
exit /b 0


:setbuildinfo
echo.Configuring build info... 2>&1 >>"%ScriptDir%\Logs\script.log"
for /F "delims=b." %%I in ("%tag%") do set buildnum=%%I

for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_MAJOR" "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_major=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_MINOR" "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_minor=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_REVISION" "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_rev=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_SUFFIX " "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_suff=%%~I
set ver_short=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%
if not "%ver_suff%"=="" (set ver_full=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%-%ver_suff%) else set ver_full=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%

for /F "usebackq delims=" %%I in (`powershell -command "& {get-date -uformat '%%Y.%%m.%%d %%T'}"`) do set buildtime=%%I
set extra_info=Branch: %branch% (%gitshortsha1%), build time: %buildtime%
set destdir=%branch%/%ver_short%
echo.#define CMD_BUILD_EXTRA "%extra_info%">"%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\build_info.h"
echo.#define CMD_VERSION_BUILD %buildnum% >>"%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\build_info.h"

set buildinfowxi="%ScriptDir%\_Build_\edrav2\iprj\installation\src\BuildInfo.wxi"
for /f %%i in ('powershell '{0:D12}' -f %buildnum%') do set hexbuildnum=%%i
echo.^<?xml version="1.0" encoding="utf-8"?^>>%buildinfowxi%
echo.^<Include^>>>%buildinfowxi%
echo. ^<?define strproductid = "{45CC556C-A03B-42FF-A2FE-%hexbuildnum%}" ?^>>>%buildinfowxi%
echo. ^<?define strversion = "%ver_short%" ?^>>>%buildinfowxi%
echo.^</Include^>>>%buildinfowxi%

pushd "%ScriptDir%"
goto :eof


:build
SETLOCAL
set "sln=%~1"
set "type=%~2"
rem set arch=%~3
for %%I in ("%sln%") do set "sln_name=%%~nxI"

echo.Building %type%^(x86^) for %sln_name%...
echo.Building %type%^(x86^) for %sln_name%... 2>&1 >>"%ScriptDir%\Logs\script.log"
if /I "%sln_name%"=="edrav2-install.sln" (
  dotnet build "%sln%" -c %type% -p:Platform=x86 -nologo >>"%ScriptDir%\Logs\build.log" 2>&1 || exit /b 1
) else (
  %msbuild% "%sln%" /t:Build /p:Configuration=%type% /p:Platform=x86 /m:2 /p:CL_MPCount=2 /noconlog /fl /flp:LogFile="%ScriptDir%\Logs\build.log";append /nologo || exit /b 1
)

echo.Building %type%^(x64^) for %sln_name%...
echo.Building %type%^(x64^) for %sln_name%... 2>&1 >>"%ScriptDir%\Logs\script.log"
if /I "%sln_name%"=="edrav2-install.sln" (
  dotnet build "%sln%" -c %type% -p:Platform=x64 -nologo --no-restore >>"%ScriptDir%\Logs\build.log" 2>&1 || exit /b 1
) else (
  %msbuild% "%sln%" /t:Build /p:Configuration=%type% /p:Platform=x64 /m:2 /p:CL_MPCount=2 /noconlog /fl /flp:LogFile="%ScriptDir%\Logs\build.log";append /nologo || exit /b 1
)

ENDLOCAL
exit /b 0


:unit_test
echo.Performing unit-testing:
echo.Performing unit-testing: 2>&1 >>"%ScriptDir%\Logs\script.log"
for /D %%I in ("%ScriptDir%\_Build_\edrav2\out\bin\*.*") do (
  for %%J in ("%%~I\tests\*.exe") do (
    echo.     %%~nI\%%~nJ...
    echo.     %%~nI\%%~nJ... 2>&1 >>"%ScriptDir%\Logs\script.log"
    if exist "%ScriptDir%\_Build_\edrav2\iprj\ats\scenarios\%%~nJ\data" pushd "%ScriptDir%\_Build_\edrav2\iprj\ats\scenarios\%%~nJ\data"
    "%%~J" --out="%ScriptDir%\Logs\%%~nJ_%%~nI.log" >nul 2>&1 || (
        echo. Failed unit-test: %%~nI\%%~nJ >>"%ScriptDir%\testserror.txt"
        if not exist "%ScriptDir%\Upload\failed_ut" mkdir "%ScriptDir%\Upload\failed_ut"
        copy /b "%ScriptDir%\Logs\%%~nJ_%%~nI.log" "%ScriptDir%\Upload\failed_ut\%%~nJ_%%~nI.log"
     )
  )
)
pushd "%ScriptDir%"
for /R "%ScriptDir%\_Build_" %%I in (*.dmp) do echo.%%I>>"%ScriptDir%\testsdump.txt"
exit /b 0


:pack
SETLOCAL
set buildtype=%~1
echo.Performing archiving...
echo.Performing archiving... 2>&1 >>"%ScriptDir%\Logs\script.log"
if not exist %arc% (
  echo.[WARN] Archive tool not found: %arc%. Skipping package archive creation.
  echo.[WARN] Archive tool not found: %arc%. Skipping package archive creation. >>"%ScriptDir%\Logs\script.log"
  ENDLOCAL
  exit /b 0
)
if exist "%ScriptDir%\_Build_\edrav2\out\install" (
  for /D %%I in ("%ScriptDir%\_Build_\edrav2\out\install\*%buildtype%*") do (
    for %%J in ("%%~I\*.msi") do copy /b "%%~J" "%ScriptDir%\Upload\%product%-%ver_full%-%%~nI-%%~nxJ" >>"%ScriptDir%\Logs\7zip.log" 2>&1|| exit /b 1
    %arc% a -ssw -r- -tzip "%ScriptDir%\Upload\%product%-%ver_full%-%%~nI-pdb.zip" "%%~I\*.*pdb" >>"%ScriptDir%\Logs\7zip.log" 2>&1|| exit /b 1
  )
)
if exist "%ScriptDir%\_Build_\edrav2\out\upgrade" (
  for /D %%I in ("%ScriptDir%\_Build_\edrav2\out\upgrade\*%buildtype%*") do (
    for %%J in ("%%~I\*.msi") do copy /b "%%~J" "%ScriptDir%\Upload\%product%-%ver_full%-%%~nI-%%~nxJ" >>"%ScriptDir%\Logs\7zip.log" 2>&1|| exit /b 1
    %arc% a -ssw -r- -tzip "%ScriptDir%\Upload\%product%-%ver_full%-%%~nI-pdb.zip" "%%~I\*.*pdb" >>"%ScriptDir%\Logs\7zip.log" 2>&1|| exit /b 1
  )
)
if exist "%ScriptDir%\testsdump.txt" %arc% a -ssw "%ScriptDir%\Upload\failed_ut\dumps" @"%ScriptDir%\testsdump.txt"
ENDLOCAL
exit /b 0


:upload
echo.Uploading files to storage...
echo.Uploading files to storage... 2>&1 >>"%ScriptDir%\Logs\script.log"

if not exist %sftp% (
  echo.[WARN] SFTP tool not found: %sftp%. Skipping upload.
  echo.[WARN] SFTP tool not found: %sftp%. Skipping upload. >>"%ScriptDir%\Logs\script.log"
  exit /b 0
)

if exist %arc% %arc% a -ssw -r -tzip "%ScriptDir%\logs" "%ScriptDir%\logs\*.*" >nul 2>&1 && copy /b "%ScriptDir%\logs.zip" "%ScriptDir%\Upload\logs.zip" >nul 2>&1

if exist "%ScriptDir%\sftp.batch" del /q "%ScriptDir%\sftp.batch"

echo.mkdir repository/%product%/%branch%>"%ScriptDir%\sftp.batch"
%sftp% -P %sftpport% -l %sftpuser% -pw %sftppwd% -batch -bc -be -b "%ScriptDir%\sftp.batch" %sftphost% >>"%ScriptDir%\Logs\sftp.log" 2>&1

if exist "%ScriptDir%\testserror.txt" set destdir=%destdir%_utfailed

echo.put -r -- "%ScriptDir%\Upload" "repository/%product%/%destdir%">"%ScriptDir%\sftp.batch"
echo.quit>>"%ScriptDir%\sftp.batch"
%sftp% -P %sftpport% -l %sftpuser% -pw %sftppwd% -batch -bc -b "%ScriptDir%\sftp.batch" %sftphost% >"%ScriptDir%\Logs\sftp.log" 2>&1 || exit /b 1
exit /b 0


:error
SETLOCAL EnableDelayedExpansion
set errmessage=%~1
cd "%ScriptDir%"

echo.>"%ScriptDir%\.error"
echo.[ERRO]  %errmessage%
echo.[ERRO]  %errmessage% 2>&1 >>"%ScriptDir%\Logs\script.log"
echo.[ERRO]  %errmessage% >"%ScriptDir%\mailbody.txt"
del /q /f "%ScriptDir%\.buildinprocess" >nul 2>&1


if "%errmessage%"=="Compillation failed" (
  powershell -command "& {get-content '%ScriptDir%\logs\build.log' | select-object -skip (Select-String 'Build FAILED.' '%ScriptDir%\logs\build.log' | Select-Object -ExpandProperty LineNumber)}">>"%ScriptDir%\mailbody.txt"
)

if exist %arc% %arc% a -ssw -r -tzip "%ScriptDir%\logs" "%ScriptDir%\logs\*.*" >nul 2>&1
call :sendmail "Build failed"
ENDLOCAL
goto :eof

:finalyze
if exist "%ScriptDir%\testserror.txt" (
   echo.[ERRO]  Some unit-test is failed>>"%ScriptDir%\mailbody.txt"
   type "%ScriptDir%\testserror.txt">>"%ScriptDir%\mailbody.txt"
   echo.>>"%ScriptDir%\mailbody.txt"
   echo.>>"%ScriptDir%\mailbody.txt"
)

cd "%ScriptDir%\_Build_\%product%"
git rev-parse --is-inside-work-tree >nul 2>&1
if not errorlevel 1 (
  git tag b.%buildnum% %gitsha1% >>"%ScriptDir%\Logs\git.log" 2>&1
  git push origin --tags >>"%ScriptDir%\Logs\git.log" 2>&1 || echo.[ERRO] Cannot set tag to build>>"%ScriptDir%\mailbody.txt"
) else (
  echo.[WARN] Source snapshot is not a git checkout. Skipping build tag push.>>"%ScriptDir%\mailbody.txt"
)
pushd "%ScriptDir%"

echo.SFTP: repository/%product%/%destdir%>>"%ScriptDir%\mailbody.txt"
for %%I in ("%ScriptDir%\upload\*.*") do echo.     %%~nxI>>"%ScriptDir%\mailbody.txt"

if exist %arc% %arc% u -ssw -r -tzip "%ScriptDir%\logs" "%ScriptDir%\logs\*.*" >nul 2>&1
call :sendmail "Build finished"
goto :eof


:cleanup
echo.Cleaning up...
cd "%ScriptDir%"
del /q /f "%ScriptDir%\*.txt" >nul 2>&1
del /q /f "%ScriptDir%\.error" >nul 2>&1
del /q /f "%ScriptDir%\sftp.batch" >nul 2>&1
del /q /f "%ScriptDir%\logs.zip" >nul 2>&1
rmdir /q /s "%ScriptDir%\_Build_" >nul 2>&1
rmdir /q /s "%ScriptDir%\Logs" >nul 2>&1
rmdir /q /s "%ScriptDir%\Upload" >nul 2>&1
del /q /f "%ScriptDir%\.buildinprocess"

goto :eof

:sendmail
SETLOCAL
set subject=%~1 for branch '%branch%'
echo.Sending mail "%subject%"...
echo.Sending mail "%subject%"... 2>&1 >>"%ScriptDir%\Logs\script.log"
if not exist %mail% (
  echo.[WARN] Mail tool not found: %mail%. Skipping email.
  echo.[WARN] Mail tool not found: %mail%. Skipping email. >>"%ScriptDir%\Logs\script.log"
  ENDLOCAL
  goto :eof
)
if exist "%ScriptDir%\mailbody.txt" (set body=-body-file:"%ScriptDir%\mailbody.txt") else set body=
if exist "%ScriptDir%\logs.zip" (set attach=-a:"%ScriptDir%\logs.zip") else set attach=

%mail% -starttls -host:%mailsender%:%mailpwd%@%mailserver% -from:"%mailsender%:EDRBuilder" %mailrecipients% -subject:"%subject%" %body% %attach%
ENDLOCAL
goto :eof
