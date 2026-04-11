@echo off
setlocal

cd /d "%~dp0"

echo === Building nuitka_blob_loader C extension ===
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
    echo   run.bat rcdata_10_3.bin -v 3.12 -o out --strict
    echo.
    echo Options:
    echo   -o, --output DIR      Output directory for .pyc files (default: pyc_out)
    echo   -s, --section NAME    Blob section to extract (default: .bytecode)
    echo   -v, --version VER     CPython version for magic (default: 3.12)
    echo       --list-only       List module names without writing files
    echo       --strict          Abort on first marshal validation failure
    exit /b 0
)

echo === Running: python -m nuitka_blob_loader %* ===
echo.
python -m nuitka_blob_loader %*
exit /b %errorlevel%
