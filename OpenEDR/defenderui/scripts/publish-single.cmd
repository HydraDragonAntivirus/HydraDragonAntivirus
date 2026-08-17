@echo off
REM =====================================================================
REM  DefenderUI - Single-file publish helper
REM  Cift tiklanarak calistirilmak uzere tasarlandi.
REM  Calistirildiginda:
REM    - Release configuration ile win-x64 single-file publish yapar
REM    - Ciktilar .\publish klasorune yazilir
REM    - Bitince ciktisini Explorer'da acar
REM =====================================================================

setlocal enableextensions

REM Bu script scripts\ altinda duruyor; proje koku bir ust dizin.
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.." || (
    echo [ERROR] Proje kok dizinine gecilemedi.
    pause
    exit /b 1
)

echo.
echo === DefenderUI single-file publish ===
echo Konum : %CD%
echo Hedef : publish\DefenderUI.exe  ^(Release / win-x64 / self-contained^)
echo.

REM Onceki ciktiyi temizle (atomik / immutable deploy pratigi)
if exist "publish" (
    echo [INFO] Eski publish klasoru temizleniyor...
    rmdir /s /q "publish"
)

REM dotnet CLI mevcut mu?
where dotnet >nul 2>nul
if errorlevel 1 (
    echo [ERROR] dotnet CLI bulunamadi. .NET 9 SDK kurulu oldugundan emin olun.
    popd
    pause
    exit /b 1
)

echo [INFO] dotnet publish basliyor...
echo.

dotnet publish DefenderUI.csproj ^
    -c Release ^
    -r win-x64 ^
    -p:Platform=x64 ^
    --self-contained true ^
    -o publish

set "PUBLISH_EXIT=%ERRORLEVEL%"

echo.
if %PUBLISH_EXIT% NEQ 0 (
    echo [ERROR] Publish basarisiz. Exit code: %PUBLISH_EXIT%
    popd
    pause
    exit /b %PUBLISH_EXIT%
)

echo [OK] Publish tamamlandi.
echo.

if exist "publish\DefenderUI.exe" (
    for %%I in ("publish\DefenderUI.exe") do (
        echo [INFO] DefenderUI.exe boyutu: %%~zI bytes
    )
    echo.
    echo [INFO] publish icerigi:
    dir /b "publish"
    echo.
    echo [INFO] Explorer aciliyor...
    start "" explorer.exe "%CD%\publish"
) else (
    echo [WARN] DefenderUI.exe publish ciktisinda bulunamadi.
)

popd
echo.
pause
endlocal