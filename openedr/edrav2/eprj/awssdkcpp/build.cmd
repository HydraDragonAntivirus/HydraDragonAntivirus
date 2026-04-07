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
 -DCMAKE_BUILD_TYPE=Release ^
 -DBUILD_ONLY="firehose" ^
 -DBUILD_SHARED_LIBS=OFF ^
 -DFORCE_SHARED_CRT=OFF ^
 -DENABLE_TESTING=OFF ^
 -DCPP_STANDARD=17 ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/MT /Zi /O2 /Ob2 /DNDEBUG /D_UNICODE /DUNICODE" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/MTd /Zi /Ob0 /Od /RTC1 /D_UNICODE /DUNICODE"

if %errorlevel% neq 0 exit /b %errorlevel%

cd build-x64
msbuild AWSSDK.sln /p:Configuration=Release /p:Platform=x64 /t:Build /m
if %errorlevel% neq 0 exit /b %errorlevel%
xcopy aws-cpp-sdk-core\Release\aws-cpp-sdk-core.lib ..\lib\win-Release-x64\ /I /Y
xcopy aws-cpp-sdk-core\aws-cpp-sdk-core.dir\Release\aws-cpp-sdk-core.pdb ..\lib\win-Release-x64\ /I /Y
xcopy aws-cpp-sdk-firehose\Release\aws-cpp-sdk-firehose.lib ..\lib\win-Release-x64\ /I /Y
xcopy aws-cpp-sdk-firehose\aws-cpp-sdk-firehose.dir\Release\aws-cpp-sdk-firehose.pdb ..\lib\win-Release-x64\ /I /Y

msbuild AWSSDK.sln /p:Configuration=Debug /p:Platform=x64 /t:Build /m
if %errorlevel% neq 0 exit /b %errorlevel%
xcopy aws-cpp-sdk-core\Debug\aws-cpp-sdk-core.lib ..\lib\win-Debug-x64\ /I /Y
xcopy aws-cpp-sdk-core\aws-cpp-sdk-core.dir\Debug\aws-cpp-sdk-core.pdb ..\lib\win-Debug-x64\ /I /Y
xcopy aws-cpp-sdk-firehose\Debug\aws-cpp-sdk-firehose.lib ..\lib\win-Debug-x64\ /I /Y
xcopy aws-cpp-sdk-firehose\aws-cpp-sdk-firehose.dir\Debug\aws-cpp-sdk-firehose.pdb ..\lib\win-Debug-x64\ /I /Y
cd ..

exit /b 0

:buildx86
call %vcvarsall% x64_x86

%cmake% -Bbuild-x86 -A Win32 ^
 -DCMAKE_BUILD_TYPE=Release ^
 -DBUILD_ONLY="firehose" ^
 -DBUILD_SHARED_LIBS=OFF ^
 -DFORCE_SHARED_CRT=OFF ^
 -DENABLE_TESTING=OFF ^
 -DCPP_STANDARD=17 ^
 -DCMAKE_CXX_FLAGS_RELEASE:STRING="/MT /Zi /O2 /Ob2 /DNDEBUG /D_UNICODE /DUNICODE" ^
 -DCMAKE_CXX_FLAGS_DEBUG:STRING="/MTd /Zi /Ob0 /Od /RTC1 /D_UNICODE /DUNICODE"

if %errorlevel% neq 0 exit /b %errorlevel%

cd build-x86
msbuild AWSSDK.sln /p:Configuration=Release /p:Platform=Win32 /t:Build /m
if %errorlevel% neq 0 exit /b %errorlevel%
xcopy aws-cpp-sdk-core\Release\aws-cpp-sdk-core.lib ..\lib\win-Release-Win32\ /I /Y
xcopy aws-cpp-sdk-core\aws-cpp-sdk-core.dir\Release\aws-cpp-sdk-core.pdb ..\lib\win-Release-Win32\ /I /Y
xcopy aws-cpp-sdk-firehose\Release\aws-cpp-sdk-firehose.lib ..\lib\win-Release-Win32\ /I /Y
xcopy aws-cpp-sdk-firehose\aws-cpp-sdk-firehose.dir\Release\aws-cpp-sdk-firehose.pdb ..\lib\win-Release-Win32\ /I /Y

msbuild AWSSDK.sln /p:Configuration=Debug /p:Platform=Win32 /t:Build /m
if %errorlevel% neq 0 exit /b %errorlevel%
xcopy aws-cpp-sdk-core\Debug\aws-cpp-sdk-core.lib ..\lib\win-Debug-Win32\ /I /Y
xcopy aws-cpp-sdk-core\aws-cpp-sdk-core.dir\Debug\aws-cpp-sdk-core.pdb ..\lib\win-Debug-Win32\ /I /Y
xcopy aws-cpp-sdk-firehose\Debug\aws-cpp-sdk-firehose.lib ..\lib\win-Debug-Win32\ /I /Y
xcopy aws-cpp-sdk-firehose\aws-cpp-sdk-firehose.dir\Debug\aws-cpp-sdk-firehose.pdb ..\lib\win-Debug-Win32\ /I /Y

cd ..
exit /b 0
