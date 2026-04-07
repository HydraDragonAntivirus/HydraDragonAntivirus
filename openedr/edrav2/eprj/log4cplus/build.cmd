@echo off
setlocal
@set vcvarsall="%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
@set cmake=cmake -G "Visual Studio 17 2022"

call :buildx64
call :buildx86

exit /b %errorlevel%

:buildx64
call %vcvarsall% x64

%cmake% -Bbuild-x64 -A x64 ^
 -DBUILD_SHARED_LIBS=OFF ^
 -DLOG4CPLUS_BUILD_TESTING=OFF ^
 -DLOG4CPLUS_BUILD_LOGGINGSERVER=OFF ^
 -DCMAKE_CXX_STANDARD=17 ^
 -DUNICODE=ON ^
 -D_UNICODE=ON ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/std:c++17 /MT /Zi /O2 /Ob2 /DNDEBUG /D_UNICODE /DUNICODE" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/std:c++17 /MTd /Zi /Ob0 /Od /RTC1 /D_UNICODE /DUNICODE"

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build build-x64 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Release-x64" mkdir "lib\win-Release-x64"
copy /Y build-x64\src\Release\log4cplusS.lib lib\win-Release-x64\
copy /Y build-x64\src\log4cplus.dir\Release\log4cplusS.pdb lib\win-Release-x64\

cmake --build build-x64 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Debug-x64" mkdir "lib\win-Debug-x64"
copy /Y build-x64\src\Debug\log4cplusSD.lib lib\win-Debug-x64\
copy /Y build-x64\src\log4cplus.dir\Debug\log4cplusSD.pdb lib\win-Debug-x64\

exit /b 0

:buildx86
call %vcvarsall% x64_x86

%cmake% -Bbuild-x86 -A Win32 ^
 -DBUILD_SHARED_LIBS=OFF ^
 -DLOG4CPLUS_BUILD_TESTING=OFF ^
 -DLOG4CPLUS_BUILD_LOGGINGSERVER=OFF ^
 -DCMAKE_CXX_STANDARD=17 ^
 -DUNICODE=ON ^
 -D_UNICODE=ON ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/std:c++17 /MT /Zi /O2 /Ob2 /DNDEBUG /D_UNICODE /DUNICODE" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/std:c++17 /MTd /Zi /Ob0 /Od /RTC1 /D_UNICODE /DUNICODE"

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build build-x86 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Release-Win32" mkdir "lib\win-Release-Win32"
copy /Y build-x86\src\Release\log4cplusS.lib lib\win-Release-Win32\
copy /Y build-x86\src\log4cplus.dir\Release\log4cplusS.pdb lib\win-Release-Win32\

cmake --build build-x86 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Debug-Win32" mkdir "lib\win-Debug-Win32"
copy /Y build-x86\src\Debug\log4cplusSD.lib lib\win-Debug-Win32\
copy /Y build-x86\src\log4cplus.dir\Debug\log4cplusSD.pdb lib\win-Debug-Win32\

exit /b 0
