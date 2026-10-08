@echo off
setlocal
chcp 65001 >nul
rem ==== TLSH smart-whitelist training (tlsh_builder): PE + APK ====
rem Stop any time with Ctrl+C; run again and it continues where it left off (--resume).
rem Optional: limit CPU cores, e.g.  run_tlsh.bat 4
rem The old 2024 hash\tlsh_db is NOT used unless you run:  set USE_TLSH_DB=1 ^& run_tlsh.bat

set "REPO=C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus"
set "DATA=C:\Users\semae\OneDrive\Belgeler\usbdosyalar"
set "APKD=C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset"
set "TB=%REPO%\tlsh_builder\target\release\tlsh_builder.exe"
set "W=tlsh_training\work"
set "AS=%REPO%\OpenMalwareScannerPortable\tlsh_signatures"
set "J="
if not "%~1"=="" set "J=-j %~1"

echo [1/9] Building tlsh_builder...
cargo build --release --manifest-path "%REPO%\tlsh_builder\Cargo.toml" || goto :fail

cd /d "%DATA%" || goto :fail
if not exist "%W%" mkdir "%W%"
for %%L in (benign_pe mal_pe js_benign js_mal) do (
  if not exist "%W%\%%L.lst" ( echo Missing %W%\%%L.lst & goto :fail )
)

echo [2/9] Benign PE references...
"%TB%" %J% --resume refs "%W%\benign_pe.lst" -o "%W%\benign_refs.jsonl" || goto :fail
echo [3/9] Malware PE references...
"%TB%" %J% --resume refs "%W%\mal_pe.lst" -o "%W%\malware_refs.jsonl" || goto :fail
echo [4/9] JavaScript benign TLSH...
"%TB%" %J% --resume hash "%W%\js_benign.lst" --jsonl -o "%W%\js_benign.jsonl" || goto :fail
echo [5/9] JavaScript malware TLSH...
"%TB%" %J% --resume hash "%W%\js_mal.lst" --jsonl -o "%W%\js_malware.jsonl" || goto :fail

echo [6/9] APK lists...
if not exist "%APKD%" ( echo   %APKD% not found: APK steps skipped. & goto :blacklist )
if not exist "%W%\apk_benign.lst" dir /s /b "%APKD%\benign\*.apk" | findstr /v /i /c:".cache" > "%W%\apk_benign.lst"
if not exist "%W%\apk_mal.lst" dir /s /b "%APKD%\malware\*.apk" > "%W%\apk_mal.lst"
echo [7/9] APK references (DEX TLSH + signer + manifest)...
"%TB%" %J% --resume refs "%W%\apk_benign.lst" -o "%W%\apk_benign_refs.jsonl" || goto :fail
"%TB%" %J% --resume refs "%W%\apk_mal.lst" -o "%W%\apk_malware_refs.jsonl" || goto :fail

:blacklist
echo [8/9] Blacklist (similar-files display only)...
set "MERGE_DB="
if "%USE_TLSH_DB%"=="1" (
  if not exist "%W%\tlsh_db" "C:\Program Files\7-Zip\7z.exe" e "hash\tlsh_db.xz" -o"%W%" -y >nul
  if exist "%W%\tlsh_db" set "MERGE_DB=--merge %W%\tlsh_db"
) else (
  echo   tlsh_db skipped.
)
set "MERGE_APK="
if exist "%W%\apk_malware_refs.jsonl" set "MERGE_APK=--merge %W%\apk_malware_refs.jsonl"
"%TB%" blacklist --merge "%W%\malware_refs.jsonl" --merge "%W%\js_malware.jsonl" %MERGE_APK% %MERGE_DB% -o "%W%\tlsh_blacklist.txt" || goto :fail

echo [9/9] Tune (full rule: distance + injection guard, PE and APK)...
set "CLEAN_APK="
set "MAL_APK="
if exist "%W%\apk_benign_refs.jsonl" set "CLEAN_APK=--clean %W%\apk_benign_refs.jsonl"
if exist "%W%\apk_malware_refs.jsonl" set "MAL_APK=--malware %W%\apk_malware_refs.jsonl"
"%TB%" tune --clean "%W%\benign_refs.jsonl" %CLEAN_APK% --malware "%W%\malware_refs.jsonl" %MAL_APK% --report "%W%\close_calls.csv" > "%W%\tune.txt" || goto :fail
type "%W%\tune.txt"

findstr /C:"WRONGLY whitelisted: 0 of" "%W%\tune.txt" >nul
if errorlevel 1 (
  echo.
  echo NOT INSTALLED: some malware would be whitelisted.
  echo Check rows with would_be_whitelisted=true in %DATA%\%W%\close_calls.csv,
  echo remove those clean references and run again.
  goto :end
)
if not exist "%AS%" mkdir "%AS%"
if exist "%W%\apk_benign_refs.jsonl" (
  copy /y /b "%W%\benign_refs.jsonl" + "%W%\apk_benign_refs.jsonl" "%AS%\tlsh_whitelist_refs.jsonl" >nul || goto :fail
) else (
  copy /y "%W%\benign_refs.jsonl" "%AS%\tlsh_whitelist_refs.jsonl" >nul || goto :fail
)
copy /y "%W%\tlsh_blacklist.txt" "%AS%\tlsh_blacklist.txt" >nul || goto :fail
echo.
echo INSTALLED to %AS%
echo Rebuild multron_server (new fingerprint/apk code), then press "Reload engines" on the dashboard.
goto :end

:fail
echo.
echo FAILED (see the message above).
:end
pause
