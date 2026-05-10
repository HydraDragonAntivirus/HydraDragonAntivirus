@echo off
for %%I in ("%~dp0.") do set "ScriptDir=%%~fI"
pushd "%ScriptDir%"
for %%I in ("%ScriptDir%\..\..") do set "EdrRoot=%%~fI"
for %%I in ("%ScriptDir%\..\..\..\..") do set "RepoRoot=%%~fI"
set "SavedPath=%PATH%"
set "PATH="
set "Path=%SavedPath%"
set "SavedPath="
set "tag=%~1"
set "vs_ver=2022"
set "vcvarsall="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VSInstallDir=%%i"
        if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" set "vcvarsall=%%i\VC\Auxiliary\Build\vcvarsall.bat"
    )
)
for %%P in (Community Professional Enterprise) do (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat" (
        set "VSInstallDir=%ProgramFiles%\Microsoft Visual Studio\2022\%%P"
        set "vcvarsall=%ProgramFiles%\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvarsall.bat"
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
set "msbuild=%VSInstallDir%\MSBuild\Current\Bin\amd64\MSBuild.exe"
if not exist "%msbuild%" set "msbuild=%VSInstallDir%\MSBuild\Current\Bin\MSBuild.exe"
if not exist "%msbuild%" set "msbuild=msbuild"
set "inst_sln=%EdrRoot%\build\vs2022\edrav2-install.sln"
set "VersionHeader=%EdrRoot%\iprj\libcore\inc\version.h"
set "BuildInfoHeader=%EdrRoot%\iprj\libcore\inc\build_info.h"
set "BuildInfoWxi=%EdrRoot%\iprj\installation\src\BuildInfo.wxi"
set "CL=/Zm500"

call :checkstate || exit /b 1

if not exist "%ScriptDir%\Logs" mkdir "%ScriptDir%\Logs"

>"%ScriptDir%\.buildinprocess" echo running %DATE% %TIME%
call :git_check || ((call :error "Cannot inspect source repository") & exit /b 1)
call :backup_generated_files || ((call :error "Cannot back up generated build metadata") & exit /b 1)

call :setbuildinfo
echo.Building %ver_full%

if not defined VSINSTALLDIR call "%vsdevcmd%" || exit /b 1

REM Release
call :build "%inst_sln%" Release || ((call :error "Compillation failed") & exit /b 1)
timeout /t 5 /NOBREAK
call :verify_output
call :restore_generated_files


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
  
SETLOCAL EnableDelayedExpansion
if exist "%ScriptDir%\.error" (
  CHOICE /T 10 /C yn /D n /m "Previous run was finished with error. Do you want to delete all data from previous run and proceed from scratch?"
  if !errorlevel! EQU 1 (call :cleanup) else exit /b 1
)
endlocal

if exist "%ScriptDir%\.buildinprocess" (
  for %%I in ("%ScriptDir%\.buildinprocess") do (
    if %%~zI GTR 2 (
      echo.[ERRO] Build is already running
      exit /b 1
    )
  )
)

exit /b 0


:git_check
echo.Checking local source state...
echo.Checking local source state...  2>&1 >>"%ScriptDir%\Logs\script.log"

git -C "%RepoRoot%" rev-parse --is-inside-work-tree >"%ScriptDir%\Logs\git.log" 2>&1 || exit /b 1
for /F %%I in ('git -C "%RepoRoot%" rev-parse HEAD') do set gitsha1=%%I

set gitshortsha1=%gitsha1:~0,8%

pushd "%ScriptDir%"
exit /b 0


:backup_generated_files
set "GeneratedBackupDir=%ScriptDir%\Logs\generated_backup"
if not exist "%GeneratedBackupDir%" mkdir "%GeneratedBackupDir%"
copy /y "%BuildInfoHeader%" "%GeneratedBackupDir%\build_info.h" >nul || exit /b 1
copy /y "%BuildInfoWxi%" "%GeneratedBackupDir%\BuildInfo.wxi" >nul || exit /b 1
exit /b 0


:restore_generated_files
set "GeneratedBackupDir=%ScriptDir%\Logs\generated_backup"
if not exist "%GeneratedBackupDir%" exit /b 0
if exist "%GeneratedBackupDir%\build_info.h" copy /y "%GeneratedBackupDir%\build_info.h" "%BuildInfoHeader%" >nul 2>&1
if exist "%GeneratedBackupDir%\BuildInfo.wxi" copy /y "%GeneratedBackupDir%\BuildInfo.wxi" "%BuildInfoWxi%" >nul 2>&1
rmdir /q /s "%GeneratedBackupDir%" >nul 2>&1
exit /b 0


:setbuildinfo
echo.Configuring build info... 2>&1 >>"%ScriptDir%\Logs\script.log"
for /F "delims=b." %%I in ("%tag%") do set buildnum=%%I

for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_MAJOR" "%VersionHeader%"') do SET ver_major=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_MINOR" "%VersionHeader%"') do SET ver_minor=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_REVISION" "%VersionHeader%"') do SET ver_rev=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_SUFFIX " "%VersionHeader%"') do SET ver_suff=%%~I
set ver_short=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%
if not "%ver_suff%"=="" (set ver_full=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%-%ver_suff%) else set ver_full=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%

for /F "usebackq delims=" %%I in (`powershell -command "& {get-date -uformat '%%Y.%%m.%%d %%T'}"`) do set buildtime=%%I
set extra_info=Commit: %gitshortsha1%, build time: %buildtime%
echo.#define CMD_BUILD_EXTRA "%extra_info%">"%BuildInfoHeader%"
echo.#define CMD_VERSION_BUILD %buildnum% >>"%BuildInfoHeader%"

set buildinfowxi="%BuildInfoWxi%"
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

echo.Building %type%^(x64^) for %sln_name%...
echo.Building %type%^(x64^) for %sln_name%... 2>&1 >>"%ScriptDir%\Logs\script.log"
if /I "%sln_name%"=="edrav2-install.sln" (
  dotnet build "%sln%" -c %type% -p:Platform=x64 -nologo --no-restore >>"%ScriptDir%\Logs\build.log" 2>&1 || exit /b 1
) else (
  "%msbuild%" "%sln%" /t:Build /p:Configuration=%type% /p:Platform=x64 /m:1 /nr:false /noconlog /fl /flp:LogFile="%ScriptDir%\Logs\build.log";append;verbosity=normal /nologo || exit /b 1
)

ENDLOCAL
exit /b 0


:unit_test
echo.Performing unit-testing:
echo.Performing unit-testing: 2>&1 >>"%ScriptDir%\Logs\script.log"
for /D %%I in ("%EdrRoot%\out\bin\*.*") do (
  for %%J in ("%%~I\tests\*.exe") do (
    echo.     %%~nI\%%~nJ...
    echo.     %%~nI\%%~nJ... 2>&1 >>"%ScriptDir%\Logs\script.log"
    if exist "%EdrRoot%\iprj\ats\scenarios\%%~nJ\data" pushd "%EdrRoot%\iprj\ats\scenarios\%%~nJ\data"
    "%%~J" --out="%ScriptDir%\Logs\%%~nJ_%%~nI.log" >nul 2>&1 || (
        echo. Failed unit-test: %%~nI\%%~nJ >>"%ScriptDir%\testserror.txt"
        if not exist "%ScriptDir%\Logs\failed_ut" mkdir "%ScriptDir%\Logs\failed_ut"
        copy /b "%ScriptDir%\Logs\%%~nJ_%%~nI.log" "%ScriptDir%\Logs\failed_ut\%%~nJ_%%~nI.log"
     )
  )
)
pushd "%ScriptDir%"
for /R "%EdrRoot%\out" %%I in (*.dmp) do echo.%%I>>"%ScriptDir%\testsdump.txt"
exit /b 0


:verify_output
set "dst_out=%EdrRoot%\out"

if not exist "%dst_out%" (
  echo.[WARN] Build output directory was not created: "%dst_out%".
  echo.[WARN] Build output directory was not created: "%dst_out%". >>"%ScriptDir%\Logs\script.log"
  exit /b 0
)

dir /b /a "%dst_out%" >nul 2>&1 || (
  echo.[WARN] Build output directory is empty: "%dst_out%".
  echo.[WARN] Build output directory is empty: "%dst_out%". >>"%ScriptDir%\Logs\script.log"
  exit /b 0
)

echo.[INFO] Build outputs are in "%dst_out%".
echo.[INFO] Build outputs are in "%dst_out%". >>"%ScriptDir%\Logs\script.log"
exit /b 0


:error
SETLOCAL EnableDelayedExpansion
set errmessage=%~1
cd "%ScriptDir%"

echo.>"%ScriptDir%\.error"
echo.[ERRO]  %errmessage%
echo.[ERRO]  %errmessage% 2>&1 >>"%ScriptDir%\Logs\script.log"
echo.>"%ScriptDir%\.buildinprocess"
call :restore_generated_files
ENDLOCAL
goto :eof

:finalyze
if exist "%ScriptDir%\testserror.txt" (
   echo.[ERRO] Some unit-test is failed.
   type "%ScriptDir%\testserror.txt"
)

pushd "%ScriptDir%"
goto :eof


:cleanup
echo.Cleaning up...
cd "%ScriptDir%"
call :restore_generated_files
del /q /f "%ScriptDir%\*.txt" >nul 2>&1
del /q /f "%ScriptDir%\.error" >nul 2>&1
rmdir /q /s "%ScriptDir%\Logs" >nul 2>&1
echo.>"%ScriptDir%\.buildinprocess"

goto :eof
