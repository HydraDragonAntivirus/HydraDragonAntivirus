@echo off
setlocal
@set vcvarsall="%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
@set cmake=cmake -G "Visual Studio 17 2022"

call :buildx64
call :buildx86

exit /b %errorlevel%

:buildx64
if exist build-x64 rd /s /q build-x64
call %vcvarsall% x64

%cmake% -Bbuild-x64 -A x64 ^
 -DUri_BUILD_TESTS=OFF ^
 -DUri_BUILD_DOCS=OFF ^
 -DBOOST_INCLUDEDIR=..\boost ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/MT /EHsc /Zi /O2 /Ob2 /DEBUG:FULL /DNDEBUG /D_UNICODE /DUNICODE" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/MTd /EHsc /Zi /Ob0 /Od /DEBUG:FULL /RTC1 /D_UNICODE /DUNICODE"

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build build-x64 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Release-x64" mkdir "lib\win-Release-x64"
copy /Y build-x64\src\Release\network-uri.lib lib\win-Release-x64\
copy /Y build-x64\src\network-uri.dir\Release\network-uri.pdb lib\win-Release-x64\

cmake --build build-x64 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Debug-x64" mkdir "lib\win-Debug-x64"
copy /Y build-x64\src\Debug\network-uri.lib lib\win-Debug-x64\
copy /Y build-x64\src\network-uri.dir\Debug\network-uri.pdb lib\win-Debug-x64\

exit /b 0

:buildx86
if exist build-x86 rd /s /q build-x86
call %vcvarsall% x64_x86

%cmake% -Bbuild-x86 -A Win32 ^
 -DUri_BUILD_TESTS=OFF ^
 -DUri_BUILD_DOCS=OFF ^
 -DBOOST_INCLUDEDIR=..\boost ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/MT /EHsc /Zi /O2 /Ob2 /DEBUG:FULL /DNDEBUG /D_UNICODE /DUNICODE" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/MTd /EHsc /Zi /Ob0 /Od /DEBUG:FULL /RTC1 /D_UNICODE /DUNICODE"

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build build-x86 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Release-Win32" mkdir "lib\win-Release-Win32"
copy /Y build-x86\src\Release\network-uri.lib lib\win-Release-Win32\
copy /Y build-x86\src\network-uri.dir\Release\network-uri.pdb lib\win-Release-Win32\

cmake --build build-x86 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "lib\win-Debug-Win32" mkdir "lib\win-Debug-Win32"
copy /Y build-x86\src\Debug\network-uri.lib lib\win-Debug-Win32\
copy /Y build-x86\src\network-uri.dir\Debug\network-uri.pdb lib\win-Debug-Win32\

exit /b 0
