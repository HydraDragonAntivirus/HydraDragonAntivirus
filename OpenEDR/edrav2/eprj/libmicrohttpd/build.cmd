@echo off
setlocal

set vcvarsall="%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %vcvarsall% (
    echo Error: Could not find Visual Studio 2022.
    exit /b 1
)

call %vcvarsall% x64

set SLN=w32\VS2019\libmicrohttpd.sln

echo [INFO] Building libmicrohttpd x64 Release-static...
msbuild %SLN% /p:Configuration=Release-static /p:Platform=x64 /p:PlatformToolset=v143 /t:libmicrohttpd /m
if %errorlevel% neq 0 exit /b %errorlevel%

echo [INFO] Building libmicrohttpd x64 Debug-static...
msbuild %SLN% /p:Configuration=Debug-static /p:Platform=x64 /p:PlatformToolset=v143 /t:libmicrohttpd /m
if %errorlevel% neq 0 exit /b %errorlevel%

echo [INFO] Organizing output files into legacy VS2017 directory structure...

rem x64 Release
if not exist "lib\x86_64\VS2017\Release-static" mkdir "lib\x86_64\VS2017\Release-static"
copy /Y "w32\VS2019\Output\x64\libmicrohttpd.lib" "lib\x86_64\VS2017\Release-static\"
copy /Y "w32\VS2019\Output\x64\libmicrohttpd.pdb" "lib\x86_64\VS2017\Release-static\"

rem x64 Debug
if not exist "lib\x86_64\VS2017\Debug-static" mkdir "lib\x86_64\VS2017\Debug-static"
copy /Y "w32\VS2019\Output\x64\libmicrohttpd_d.lib" "lib\x86_64\VS2017\Debug-static\libmicrohttpd.lib"
copy /Y "w32\VS2019\Output\x64\libmicrohttpd_d.lib" "lib\x86_64\VS2017\Debug-static\libmicrohttpd_d.lib"
copy /Y "w32\VS2019\Output\x64\libmicrohttpd_d.pdb" "lib\x86_64\VS2017\Debug-static\"

echo [INFO] libmicrohttpd build and organization completed successfully.
exit /b 0
