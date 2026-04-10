@echo off
setlocal EnableExtensions

if /I "%1"=="clean" (
    echo Cleaning...
    del /Q blob_loader.exe python312.dll *.obj 2>nul
    echo Done.
    goto :eof
)

echo Locating Python 3.12...

set "PY_HOME="
set "PY_LIB=python312.lib"
set "PY_DLL=python312.dll"

for /f "usebackq delims=" %%I in (`py -3.12 -c "import sys; print(sys.base_prefix)" 2^>nul`) do (
    set "PY_HOME=%%I"
)

if not defined PY_HOME (
    for /f "tokens=2,*" %%A in ('reg query "HKCU\Software\Python\PythonCore\3.12\InstallPath" /ve 2^>nul ^| find /I "REG_SZ"') do (
        set "PY_HOME=%%B"
    )
)

if not defined PY_HOME (
    for /f "tokens=2,*" %%A in ('reg query "HKLM\Software\Python\PythonCore\3.12\InstallPath" /ve 2^>nul ^| find /I "REG_SZ"') do (
        set "PY_HOME=%%B"
    )
)

if not defined PY_HOME if exist "%LocalAppData%\Programs\Python\Python312" (
    set "PY_HOME=%LocalAppData%\Programs\Python\Python312"
)

if not defined PY_HOME if exist "%ProgramFiles%\Python312" (
    set "PY_HOME=%ProgramFiles%\Python312"
)

if not defined PY_HOME if exist "%ProgramFiles(x86)%\Python312" (
    set "PY_HOME=%ProgramFiles(x86)%\Python312"
)

if not defined PY_HOME (
    echo ERROR: Python 3.12 not found.
    echo Install Python 3.12 or make sure "py -3.12" works.
    exit /b 1
)

if "%PY_HOME:~-1%"=="\" set "PY_HOME=%PY_HOME:~0,-1%"

echo Found Python 3.12 at:
echo   %PY_HOME%
echo.

if not exist "%PY_HOME%\include\Python.h" (
    echo ERROR: Missing header:
    echo   %PY_HOME%\include\Python.h
    exit /b 1
)

if not exist "%PY_HOME%\libs\%PY_LIB%" (
    echo ERROR: Missing import library:
    echo   %PY_HOME%\libs\%PY_LIB%
    exit /b 1
)

if not exist "%PY_HOME%\%PY_DLL%" (
    echo ERROR: Missing runtime DLL:
    echo   %PY_HOME%\%PY_DLL%
    exit /b 1
)

echo Building blob_loader.exe with MSVC...

cl /nologo /TC /O2 /Iinclude /I"%PY_HOME%\include" /D_CRT_SECURE_NO_WARNINGS ^
   src\main.c ^
   src\blob_loader.c ^
   src\blob_export.c ^
   src\crc32.c ^
   /Fe:blob_loader.exe ^
   /link /SUBSYSTEM:CONSOLE /LIBPATH:"%PY_HOME%\libs" %PY_LIB%

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED.
    echo Make sure you are using a Developer Command Prompt for Visual Studio.
    exit /b 1
)

echo Copying %PY_DLL%...
copy /Y "%PY_HOME%\%PY_DLL%" ".\%PY_DLL%" >nul

if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to copy %PY_DLL%.
    exit /b 1
)

echo.
echo Built: blob_loader.exe
echo Copied: %PY_DLL%
echo.

endlocal
