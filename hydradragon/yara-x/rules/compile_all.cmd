@echo off
setlocal EnableExtensions

set "YARA_X=yr.exe"

call :CompileYaraX valhalla-rules.yar valhalla-rules.yrc || exit /b %ERRORLEVEL%
call :CompileYaraX clean_rules.yar clean_rules.yrc || exit /b %ERRORLEVEL%
call :CompileYaraX machine_learning_pe.yar machine_learning_pe.yrc || exit /b %ERRORLEVEL%
call :CompileYaraX machine_learning_js.yar machine_learning_js.yrc || exit /b %ERRORLEVEL%
call :CompileYaraX yaraxtr.yar yaraxtr.yrc || exit /b %ERRORLEVEL%

endlocal
exit /b 0

:CompileYaraX
if not exist "%~1" (
    echo [ERROR] Missing input file: %~1
    exit /b 1
)
echo [YARA-X] %~1 -^> %~2
"%YARA_X%" compile "%~1" --output  "%~2"
if errorlevel 1 exit /b %ERRORLEVEL%
if not exist "%~2" (
    echo [ERROR] Missing output file after yr.exe: %~2
    exit /b 1
)
exit /b 0
