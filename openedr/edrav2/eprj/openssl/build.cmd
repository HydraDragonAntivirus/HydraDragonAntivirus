@echo off
setlocal EnableExtensions

set configure=threads no-shared no-asm no-engine no-tests
set "root_dir=%~dp0"
set "root_dir=%root_dir:~0,-1%"
set "work_dir=%root_dir%\openssl"

call :normalize_path
call :resolve_perl
if errorlevel 1 exit /b 1

pushd "%work_dir%"
if errorlevel 1 exit /b 1

call :build x64 Debug VC-WIN64A "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" "%root_dir%\build-x64\Debug" "%root_dir%\lib\win-Debug-x64" --debug
if errorlevel 1 goto :fail
call :build x64 Release VC-WIN64A "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" "%root_dir%\build-x64\Release" "%root_dir%\lib\win-Release-x64"
if errorlevel 1 goto :fail
call :build x86 Debug VC-WIN32 "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" "%root_dir%\build-x86\Debug" "%root_dir%\lib\win-Debug-Win32" --debug
if errorlevel 1 goto :fail
call :build x86 Release VC-WIN32 "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" "%root_dir%\build-x86\Release" "%root_dir%\lib\win-Release-Win32"
if errorlevel 1 goto :fail

popd
exit /b 0

:fail
set "BuildError=%errorlevel%"
popd
exit /b %BuildError%

:normalize_path
set "NormalizedPath=%PATH%"
set "Path="
set "PATH=%NormalizedPath%"
exit /b 0

:resolve_perl
set "PerlExe="
where perl.exe >nul 2>&1
if not errorlevel 1 set "PerlExe=perl.exe"
if not defined PerlExe if exist "C:\Strawberry\perl\bin\perl.exe" set "PerlExe=C:\Strawberry\perl\bin\perl.exe"
if not defined PerlExe if exist "C:\Perl64\bin\perl.exe" set "PerlExe=C:\Perl64\bin\perl.exe"
if not defined PerlExe if exist "C:\Program Files\Git\usr\bin\perl.exe" set "PerlExe=C:\Program Files\Git\usr\bin\perl.exe"
if not defined PerlExe (
	echo Unable to locate a usable perl.exe
	exit /b 1
)
echo Using Perl: %PerlExe%
exit /b 0

:build
setlocal
set "Arch=%~1"
set "Config=%~2"
set "Target=%~3"
set "VcVars=%~4"
set "Prefix=%~5"
set "OutLibDir=%~6"
set "OpenSslDir=%Prefix%\ssl"

echo ==== Building OpenSSL %Arch% %Config% ====

call "%VcVars%" >nul
if errorlevel 1 goto :build_fail
call :normalize_path

if exist makefile (
	nmake clean
	if errorlevel 1 goto :build_fail
)
"%PerlExe%" Configure %Target% %configure% --prefix="%Prefix%" --openssldir="%OpenSslDir%" %7
if errorlevel 1 goto :build_fail
nmake install_sw
if errorlevel 1 goto :build_fail

xcopy "%Prefix%\lib\libcrypto.lib" "%OutLibDir%\" /I /Y >nul
if errorlevel 1 goto :build_fail
if not exist "%OutLibDir%\libcrypto.lib" goto :build_fail

xcopy "%Prefix%\lib\libssl.lib" "%OutLibDir%\" /I /Y >nul
if errorlevel 1 goto :build_fail
if not exist "%OutLibDir%\libssl.lib" goto :build_fail

xcopy "%Prefix%\lib\ossl_static.pdb" "%OutLibDir%\" /I /Y >nul

endlocal & exit /b 0

:build_fail
endlocal & exit /b 1
