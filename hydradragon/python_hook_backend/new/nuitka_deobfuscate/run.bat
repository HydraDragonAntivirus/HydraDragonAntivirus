@echo off
setlocal

cd /d "%~dp0"

echo === Building nuitka_deobfuscate C extension ===
python setup.py build_ext --inplace
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo === Build OK ===
echo.

if "%~1"=="" (
    echo Usage: run.bat ^<blob_file^> [options]
    echo.
    echo   run.bat rcdata_10_3.bin
    echo   run.bat rcdata_10_3.bin -o output_pycs
    echo   run.bat rcdata_10_3.bin --list-only
    echo   run.bat rcdata_10_3.bin -v 3.12
    echo.
    echo Options:
    echo   -o, --output DIR      Output directory for .pyc files (default: pyc_out)
    echo   -v, --version VER     CPython version for xdis magic (default: 3.12)
    echo       --list-only       List decoded section names only
    exit /b 0
)

echo === Running Extraction ===
echo.
python run_extract.py %*
exit /b %errorlevel%
