@echo off
@set vcvarsall="%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
@set cmake=cmake -G "Visual Studio 17 2022"

call :buildx64
call :buildx86

exit /b %errorlevel%

:buildx64
call %vcvarsall% x64
setlocal

%cmake% -Bcmake-build-x64 ^
 -DJSONCPP_WITH_TESTS=OFF ^
 -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF ^
 -DJSONCPP_WITH_PKGCONFIG_SUPPORT=OFF ^
 -DBUILD_SHARED_LIBS=OFF ^
 -DBUILD_STATIC_LIBS=ON ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/MT /Zi /O2 /Ob2 /DNDEBUG" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/MTd /Zi /Ob0 /Od /RTC1" ^
 -DCMAKE_GENERATOR_PLATFORM=x64

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build cmake-build-x64 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "build\x64\Release" mkdir "build\x64\Release"
copy /Y cmake-build-x64\src\lib_json\Release\jsoncpp.lib build\x64\Release\jsoncpp_lib.lib
copy /Y cmake-build-x64\src\lib_json\Release\jsoncpp.lib build\x64\Release\json_lib.lib

cmake --build cmake-build-x64 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "build\x64\Debug" mkdir "build\x64\Debug"
copy /Y cmake-build-x64\src\lib_json\Debug\jsoncpp.lib build\x64\Debug\jsoncpp_lib.lib
copy /Y cmake-build-x64\src\lib_json\Debug\jsoncpp.lib build\x64\Debug\json_lib.lib

endlocal
exit /b 0

:buildx86
call %vcvarsall% x64_x86
setlocal

%cmake% -Bcmake-build-x86 -A Win32 ^
 -DJSONCPP_WITH_TESTS=OFF ^
 -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF ^
 -DJSONCPP_WITH_PKGCONFIG_SUPPORT=OFF ^
 -DBUILD_SHARED_LIBS=OFF ^
 -DBUILD_STATIC_LIBS=ON ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/MT /Zi /O2 /Ob2 /DNDEBUG" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/MTd /Zi /Ob0 /Od /RTC1"

if %errorlevel% neq 0 exit /b %errorlevel%

cmake --build cmake-build-x86 --config Release
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "build\Win32\Release" mkdir "build\Win32\Release"
copy /Y cmake-build-x86\src\lib_json\Release\jsoncpp.lib build\Win32\Release\jsoncpp_lib.lib
copy /Y cmake-build-x86\src\lib_json\Release\jsoncpp.lib build\Win32\Release\json_lib.lib

cmake --build cmake-build-x86 --config Debug
if %errorlevel% neq 0 exit /b %errorlevel%

if not exist "build\Win32\Debug" mkdir "build\Win32\Debug"
copy /Y cmake-build-x86\src\lib_json\Debug\jsoncpp.lib build\Win32\Debug\jsoncpp_lib.lib
copy /Y cmake-build-x86\src\lib_json\Debug\jsoncpp.lib build\Win32\Debug\json_lib.lib

endlocal
exit /b 0
