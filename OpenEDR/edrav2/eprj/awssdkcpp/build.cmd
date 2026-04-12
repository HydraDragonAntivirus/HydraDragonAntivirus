@echo off
setlocal EnableExtensions EnableDelayedExpansion

for %%I in ("%~dp0.") do set "ScriptRoot=%%~fI"
set "StageRoot=%SystemDrive%\aws_tmp\awssdkcpp"

if /I not "%AWS_SDKCPP_SHORT_PATH_STAGE%"=="1" if /I not "%ScriptRoot%"=="%StageRoot%" (
    echo [INFO] Staging AWS SDK build to "%StageRoot%" to avoid long-path failures...
    if exist "%StageRoot%" rd /s /q "%StageRoot%"
    robocopy "%ScriptRoot%" "%StageRoot%" /MIR /XD build-x64 build-x86 /NFL /NDL /NJH /NJS /NP >nul
    if errorlevel 8 (
        echo [ERROR] Failed to stage AWS SDK sources.
        exit /b !errorlevel!
    )

    pushd "%StageRoot%"
    set "AWS_SDKCPP_SHORT_PATH_STAGE=1"
    set "AWS_SDKCPP_ORIGINAL_ROOT=%ScriptRoot%"
    call build.cmd
    set "BuildRc=%errorlevel%"
    popd

    if not "%BuildRc%"=="0" exit /b %BuildRc%

    robocopy "%StageRoot%\lib" "%AWS_SDKCPP_ORIGINAL_ROOT%\lib" /MIR /NFL /NDL /NJH /NJS /NP >nul
    if errorlevel 8 (
        echo [ERROR] Failed to copy staged AWS SDK artifacts back to "%AWS_SDKCPP_ORIGINAL_ROOT%\lib".
        exit /b !errorlevel!
    )

    echo [INFO] AWS SDK artifacts copied back from short-path staging area.
    exit /b 0
)

@set vcvarsall="%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
set "CMakeExe="
for %%I in (cmake.exe) do if not defined CMakeExe set "CMakeExe=%%~$PATH:I"
if not defined CMakeExe if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "CMakeExe=%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not defined CMakeExe (
    echo [ERROR] Could not find cmake.exe. Install Visual Studio CMake tools or add CMake to PATH.
    exit /b 1
)
@set cmake="%CMakeExe%" -G "Visual Studio 17 2022"

call :buildx64
if errorlevel 1 exit /b %errorlevel%
call :buildx86
if errorlevel 1 exit /b %errorlevel%

exit /b %errorlevel%
 
:buildx64
call %vcvarsall% x64

if exist build-x64 rd /s /q build-x64

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

if exist build-x86 rd /s /q build-x86

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
