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
 -DHTTP_ONLY=YES ^
 -DENABLE_IPV6=NO ^
 -DBUILD_TESTING=NO ^
 -DBUILD_CURL_EXE=NO ^
 -DCURL_STATIC_CRT=YES ^
 -DBUILD_SHARED_LIBS=NO ^
 -DCURL_STATICLIB=YES ^
 -DCMAKE_C_FLAGS_RELEASE:STRING="/MT /Zi /O2 /Ob2 /DNDEBUG /D_UNICODE /DUNICODE /DCURL_STATICLIB" ^
 -DCMAKE_C_FLAGS_DEBUG:STRING="/MTd /Zi /Ob0 /Od /RTC1 /D_UNICODE /DUNICODE /DCURL_STATICLIB"

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build build-x64 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "out\win-Release-x64" mkdir "out\win-Release-x64"
copy /Y build-x64\lib\Release\libcurl.lib out\win-Release-x64\
copy /Y build-x64\lib\libcurl.dir\Release\libcurl.pdb out\win-Release-x64\

cmake --build build-x64 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "out\win-Debug-x64" mkdir "out\win-Debug-x64"
copy /Y build-x64\lib\Debug\libcurl-d.lib out\win-Debug-x64\
copy /Y build-x64\lib\libcurl.dir\Debug\libcurl.pdb out\win-Debug-x64\

exit /b 0

:buildx86
call %vcvarsall% x64_x86

%cmake% -Bbuild-x86 -A Win32 ^
 -DHTTP_ONLY=YES ^
 -DENABLE_IPV6=NO ^
 -DBUILD_TESTING=NO ^
 -DBUILD_CURL_EXE=NO ^
 -DCURL_STATIC_CRT=YES ^
 -DBUILD_SHARED_LIBS=NO ^
 -DCURL_STATICLIB=YES ^
 -DCMAKE_C_FLAGS_RELEASE:STRING="/MT /Zi /O2 /Ob2 /DNDEBUG /D_UNICODE /DUNICODE /DCURL_STATICLIB" ^
 -DCMAKE_C_FLAGS_DEBUG:STRING="/MTd /Zi /Ob0 /Od /RTC1 /D_UNICODE /DUNICODE /DCURL_STATICLIB"

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build build-x86 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "out\win-Release-Win32" mkdir "out\win-Release-Win32"
copy /Y build-x86\lib\Release\libcurl.lib out\win-Release-Win32\
copy /Y build-x86\lib\libcurl.dir\Release\libcurl.pdb out\win-Release-Win32\

cmake --build build-x86 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "out\win-Debug-Win32" mkdir "out\win-Debug-Win32"
copy /Y build-x86\lib\Debug\libcurl-d.lib out\win-Debug-Win32\
copy /Y build-x86\lib\libcurl.dir\Debug\libcurl.pdb out\win-Debug-Win32\

exit /b 0
