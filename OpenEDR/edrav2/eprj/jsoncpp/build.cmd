@echo off
setlocal EnableExtensions

set "vcvarsall=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%vcvarsall%" (
    echo Visual Studio vcvarsall.bat not found: %vcvarsall%
    exit /b 1
)

call :buildx64
if errorlevel 1 exit /b %errorlevel%

exit /b 0

:buildx64
call "%vcvarsall%" x64
if errorlevel 1 exit /b %errorlevel%

call :buildconfig x64 Release x64 "/MT /Zi /O2 /Ob2 /DNDEBUG"
if errorlevel 1 exit /b %errorlevel%

call :buildconfig x64 Debug x64 "/MTd /Zi /Ob0 /Od /RTC1 /D_DEBUG"
exit /b %errorlevel%

:buildconfig
setlocal
set "OBJDIR=build\manual-%~1-%~2"
set "OUTDIR=build\%~3\%~2"
set "CFLAGS=%~4"

echo Building JsonCpp %~3 %~2...

if not exist "%OBJDIR%" mkdir "%OBJDIR%"
if errorlevel 1 (
    endlocal
    exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"
if errorlevel 1 (
    endlocal
    exit /b 1
)

cl /nologo /c /std:c++14 /EHsc %CFLAGS% /Iinclude /Fo"%OBJDIR%\json_reader.obj" src\lib_json\json_reader.cpp
if errorlevel 1 (
    endlocal
    exit /b 1
)

cl /nologo /c /std:c++14 /EHsc %CFLAGS% /Iinclude /Fo"%OBJDIR%\json_value.obj" src\lib_json\json_value.cpp
if errorlevel 1 (
    endlocal
    exit /b 1
)

cl /nologo /c /std:c++14 /EHsc %CFLAGS% /Iinclude /Fo"%OBJDIR%\json_writer.obj" src\lib_json\json_writer.cpp
if errorlevel 1 (
    endlocal
    exit /b 1
)

lib /nologo /OUT:"%OUTDIR%\jsoncpp_lib.lib" "%OBJDIR%\json_reader.obj" "%OBJDIR%\json_value.obj" "%OBJDIR%\json_writer.obj"
if errorlevel 1 (
    endlocal
    exit /b 1
)

copy /Y "%OUTDIR%\jsoncpp_lib.lib" "%OUTDIR%\json_lib.lib"
if errorlevel 1 (
    endlocal
    exit /b 1
)

endlocal
exit /b 0
