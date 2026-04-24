:: Build script for TinyAntivirus and all submodules
:: compiler and linker: Visual Studio 2022
@ECHO OFF
setlocal

:: verify parameters
if "%1" == "" ( 
	echo   [!] Configure Projects to Target Platform
	exit /b 1
)

if "%2" == "" ( 
	echo   [!] Configure projects configuration
	exit /b 1
)

set devcmd_arch=x86
if /I "%1" == "x64" (set devcmd_arch=x64)

set VSWHERE_EXE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE_EXE%" (
    echo   [!] vswhere.exe not found
    exit /b 1
)

set VS_INSTALL_PATH=
for /f "usebackq delims=" %%i in (`"%VSWHERE_EXE%" -latest -products * -property installationPath`) do set VS_INSTALL_PATH=%%i
if "%VS_INSTALL_PATH%" == "" (
    echo   [!] Visual Studio 2022 installation path not found
    exit /b 1
)

set VSDEVCMD=%VS_INSTALL_PATH%\Common7\Tools\VsDevCmd.bat
if not exist "%VSDEVCMD%" (
    echo   [!] VsDevCmd.bat not found
    exit /b 1
)

:: build googletest library
set build_gtest_dir=libs\googletest\googletest\build\%2
if exist "%build_gtest_dir%" (
    rmdir /S /Q "%build_gtest_dir%"
) 
md "%build_gtest_dir%"
set GTEST_RUNTIME=MultiThreaded
set GTEST_OUTPUT=gtest.lib
if /I "%2" == "Debug" set GTEST_RUNTIME=MultiThreadedDebug
if /I "%2" == "Debug" set GTEST_OUTPUT=gtestd.lib
cmd /c ""%VSDEVCMD%" -arch=%devcmd_arch% -host_arch=x64 && cd /d "%build_gtest_dir%" && cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE="%2" -DCMAKE_MSVC_RUNTIME_LIBRARY=%GTEST_RUNTIME% -Dgtest_force_shared_crt=OFF ..\.. && cmake --build ."
if errorlevel 1 exit /b 1
copy /Y "%build_gtest_dir%\lib\%GTEST_OUTPUT%" "%build_gtest_dir%\gtest.lib" >nul

:: build zlib library
set build_zlib_dir=libs\zlib\build\%2
if exist "%build_zlib_dir%" (
    rmdir /S /Q "%build_zlib_dir%"
) 
md "%build_zlib_dir%"
set ZLIB_RUNTIME=MultiThreaded
set ZLIB_OUTPUT=zs.lib
set ZLIB_EXPECTED=zlibstatic.lib
if /I "%2" == "Debug" (
    set ZLIB_RUNTIME=MultiThreadedDebug
    set ZLIB_OUTPUT=zsd.lib
    set ZLIB_EXPECTED=zlibstaticd.lib
)
cmd /c ""%VSDEVCMD%" -arch=%devcmd_arch% -host_arch=x64 && cd /d "%build_zlib_dir%" && cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE="%2" -DCMAKE_MSVC_RUNTIME_LIBRARY=%ZLIB_RUNTIME% -DZLIB_BUILD_SHARED=OFF -DZLIB_BUILD_TESTING=OFF ..\.. && cmake --build ."
if errorlevel 1 exit /b 1
copy /Y "%build_zlib_dir%\%ZLIB_OUTPUT%" "%build_zlib_dir%\%ZLIB_EXPECTED%" >nul

set MSBUILD_EXE=
for /f "usebackq delims=" %%i in (`"%VSWHERE_EXE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set MSBUILD_EXE=%%i
if "%MSBUILD_EXE%" == "" (
    echo   [!] MSBuild.exe for Visual Studio 2022 not found
    exit /b 1
)

:: build all projects
powershell -NoProfile -ExecutionPolicy Bypass -File ci\windows\build_msbuild_projects.ps1 -MsBuildExe "%MSBUILD_EXE%" -Platform "%1" -Configuration "%2"
if errorlevel 1 exit /b 1
