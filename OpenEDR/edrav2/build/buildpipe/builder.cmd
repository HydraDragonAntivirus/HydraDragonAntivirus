@echo off
for %%I in ("%~dp0.") do set "ScriptDir=%%~fI"
pushd "%ScriptDir%"
for %%I in ("%ScriptDir%\..\..") do set "EdrRoot=%%~fI"
for %%I in ("%ScriptDir%\..\..\..\..") do set "RepoRoot=%%~fI"

set "forcemode=false"
rem ========MSBuild settings======
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
set "CL=/Zm500"
rem ========Project settings=======
set "sln=%ScriptDir%\_Build_\edrav2\build\vs2022\edrav2.sln"
set "inst_sln=%ScriptDir%\_Build_\edrav2\build\vs2022\edrav2-install.sln"
set "product=edrav2"

call :parse_args %*
call :checkstate || exit /b 1


if not exist "%ScriptDir%\_Build_" mkdir "%ScriptDir%\_Build_"
if not exist "%ScriptDir%\Logs" mkdir "%ScriptDir%\Logs"

echo.>"%ScriptDir%\.buildinprocess"
call :git_check
if errorlevel 11 ((call :error "Cannot inspect source repository") & exit /b 1)
if errorlevel 1 ((call :error "Cannot inspect source repository") & exit /b 1)
call :git_download || ((call :error "Cannot copy source files") & exit /b 1)

call :setbuildinfo
echo.Building %ver_full%

if not defined VSINSTALLDIR call "%vsdevcmd%" || exit /b 1

REM Release
call :build "%sln%" Release || ((call :error "Compillation failed") & exit /b 1)
timeout /t 5 /NOBREAK
call :build "%inst_sln%" Release || ((call :error "Compillation failed") & exit /b 1)
timeout /t 5 /NOBREAK

REM Debug
call :build "%sln%" Debug || ((call :error "Compillation failed") & exit /b 1)
timeout /t 5 /NOBREAK
call :build "%inst_sln%" Debug || ((call :error "Compillation failed") & exit /b 1)
timeout /t 5 /NOBREAK

call :unit_test

call :publish_local_out || ((call :error "Cannot publish local build output") & exit /b 1)

call :finalyze
timeout /t 5 /NOBREAK

:nothingtobuild
call :cleanup

exit /b 0


:parse_args
if "%~1"=="" exit /b 0
if /I "%~1"=="/force" set "forcemode=true"
shift
goto :parse_args


:checkstate

SETLOCAL EnableDelayedExpansion
if exist "%ScriptDir%\.error" (
  if not "%forcemode%"=="true" (
	CHOICE /T 10 /C yn /D n /m "Previous run was finished with error. Do you want to delete all data from previous run and proceed from scratch?"
    if !errorlevel! EQU 1 (call :cleanup) else exit /b 1
  ) else (call :cleanup)  
)
endlocal

if exist "%ScriptDir%\.buildinprocess" (
  echo.[ERRO] Build is already running
  exit /b 1
)

exit /b 0


:git_check
echo.Checking local source state...
echo.Checking local source state...  2>&1 >>"%ScriptDir%\Logs\script.log"

git -C "%RepoRoot%" rev-parse --is-inside-work-tree >"%ScriptDir%\Logs\git.log" 2>&1 || exit /b 2

for /F %%I in ('git -C "%RepoRoot%" rev-parse HEAD') do set gitsha1=%%I
set gitshortsha1=%gitsha1:~0,8%

set "lastbuild="
for /f "tokens=1* delims=." %%I in ('git -C "%RepoRoot%" tag -l "b.*" --sort=-v:refname') do (
  if not defined lastbuild if /I "%%I"=="b" set "lastbuild=%%J"
)
if not "%lastbuild%"=="" (set /a buildnum=%lastbuild%+1) else (set buildnum=0)

pushd "%ScriptDir%"
exit /b 0

:git_download
echo.Copying local source files...
echo.Copying local source files...  2>&1 >>"%ScriptDir%\Logs\script.log"

if exist "%ScriptDir%\_Build_\%product%" rmdir /q /s "%ScriptDir%\_Build_\%product%"

robocopy "%EdrRoot%" "%ScriptDir%\_Build_\%product%" /E /XD "%ScriptDir%\_Build_" "%ScriptDir%\Logs" "%EdrRoot%\out" /XF "%ScriptDir%\.error" "%ScriptDir%\.buildinprocess" >>"%ScriptDir%\Logs\git.log" 2>&1
if errorlevel 8 exit /b 1

pushd "%ScriptDir%"
exit /b 0


:setbuildinfo
echo.Configuring build info... 2>&1 >>"%ScriptDir%\Logs\script.log"

for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_MAJOR" "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_major=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_MINOR" "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_minor=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_REVISION" "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_rev=%%I
for /F "tokens=3" %%I in ('findstr /C:"#define CMD_VERSION_SUFFIX " "%ScriptDir%\_Build_\edrav2\iprj\libcore\inc\version.h"') do SET ver_suff=%%~I
set ver_short=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%
if not "%ver_suff%"=="" (set ver_full=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%-%ver_suff%) else set ver_full=%ver_major%.%ver_minor%.%ver_rev%.%buildnum%

for /F "usebackq delims=" %%I in (`powershell -command "& {get-date -uformat '%%Y.%%m.%%d %%T'}"`) do set buildtime=%%I
set extra_info=Commit: %gitshortsha1%, build time: %buildtime%
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
        if not exist "%ScriptDir%\Logs\failed_ut" mkdir "%ScriptDir%\Logs\failed_ut"
        copy /b "%ScriptDir%\Logs\%%~nJ_%%~nI.log" "%ScriptDir%\Logs\failed_ut\%%~nJ_%%~nI.log"
     )
  )
)
pushd "%ScriptDir%"
for /R "%ScriptDir%\_Build_" %%I in (*.dmp) do echo.%%I>>"%ScriptDir%\testsdump.txt"
exit /b 0


:publish_local_out
set "src_out=%ScriptDir%\_Build_\edrav2\out"
set "dst_out=%EdrRoot%\out"

if not exist "%src_out%" (
  echo.[WARN] Build output directory was not created: "%src_out%".
  echo.[WARN] Build output directory was not created: "%src_out%". >>"%ScriptDir%\Logs\script.log"
  exit /b 0
)

dir /b /a "%src_out%" >nul 2>&1 || (
  echo.[WARN] Build output directory is empty: "%src_out%".
  echo.[WARN] Build output directory is empty: "%src_out%". >>"%ScriptDir%\Logs\script.log"
  exit /b 0
)

if not exist "%dst_out%" mkdir "%dst_out%"
robocopy "%src_out%" "%dst_out%" /E /NFL /NDL /NJH /NJS /NP >>"%ScriptDir%\Logs\script.log" 2>&1
if errorlevel 8 exit /b 1
echo.[INFO] Build outputs copied to "%dst_out%".
echo.[INFO] Build outputs copied to "%dst_out%". >>"%ScriptDir%\Logs\script.log"
exit /b 0


:error
SETLOCAL EnableDelayedExpansion
set errmessage=%~1
cd "%ScriptDir%"

echo.>"%ScriptDir%\.error"
echo.[ERRO]  %errmessage%
echo.[ERRO]  %errmessage% 2>&1 >>"%ScriptDir%\Logs\script.log"
del /q /f "%ScriptDir%\.buildinprocess" >nul 2>&1
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
del /q /f "%ScriptDir%\*.txt" >nul 2>&1
del /q /f "%ScriptDir%\.error" >nul 2>&1
rmdir /q /s "%ScriptDir%\_Build_" >nul 2>&1
rmdir /q /s "%ScriptDir%\Logs" >nul 2>&1
del /q /f "%ScriptDir%\.buildinprocess"

goto :eof
