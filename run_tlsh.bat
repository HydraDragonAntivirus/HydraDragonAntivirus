@echo off
setlocal
rem ==== TLSH smart-whitelist training (tlsh_builder) ====
rem Stop any time with Ctrl+C; run again and it continues where it left off (--resume).
rem Optional: limit CPU cores, e.g.  run_tlsh.bat 4

set "REPO=C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus"
set "DATA=C:\Users\semae\OneDrive\Belgeler\usbdosyalar"
set "TB=%REPO%\tlsh_builder\target\release\tlsh_builder.exe"
set "W=tlsh_training\work"
set "AS=%REPO%\OpenMalwareScannerPortable\analyst_signatures"
set "J="
if not "%~1"=="" set "J=-j %~1"

echo [1/7] Building tlsh_builder...
cargo build --release --manifest-path "%REPO%\tlsh_builder\Cargo.toml" || goto :fail

cd /d "%DATA%" || goto :fail
if not exist "%W%" mkdir "%W%"
for %%L in (benign_pe mal_pe js_benign js_mal) do (
  if not exist "%W%\%%L.lst" ( echo Missing %W%\%%L.lst & goto :fail )
)

echo [2/7] Benign PE references...
"%TB%" %J% --resume refs "%W%\benign_pe.lst" -o "%W%\benign_refs.jsonl" || goto :fail
echo [3/7] Malware PE references...
"%TB%" %J% --resume refs "%W%\mal_pe.lst" -o "%W%\malware_refs.jsonl" || goto :fail
echo [4/7] JavaScript benign TLSH...
"%TB%" %J% --resume hash "%W%\js_benign.lst" --jsonl -o "%W%\js_benign.jsonl" || goto :fail
echo [5/7] JavaScript malware TLSH...
"%TB%" %J% --resume hash "%W%\js_mal.lst" --jsonl -o "%W%\js_malware.jsonl" || goto :fail

echo [6/7] Blacklist...
set "MERGE_DB="
if exist "%W%\tlsh_db" (
  set "MERGE_DB=--merge %W%\tlsh_db"
) else if exist "C:\Program Files\7-Zip\7z.exe" (
  "C:\Program Files\7-Zip\7z.exe" e "hash\tlsh_db.xz" -o"%W%" -y >nul && set "MERGE_DB=--merge %W%\tlsh_db"
) else (
  echo   7-Zip not found: hash\tlsh_db.xz is skipped. Extract it to %W%\tlsh_db and run again to include it.
)
"%TB%" blacklist --merge "%W%\malware_refs.jsonl" --merge "%W%\js_malware.jsonl" %MERGE_DB% -o "%W%\tlsh_blacklist.txt" || goto :fail

echo [7/7] Tune (full rule: distance + injection guard)...
"%TB%" tune --clean "%W%\benign_refs.jsonl" --malware "%W%\malware_refs.jsonl" --report "%W%\close_calls.csv" > "%W%\tune.txt" || goto :fail
type "%W%\tune.txt"

findstr /C:"WRONGLY whitelisted: 0 of" "%W%\tune.txt" >nul
if errorlevel 1 (
  echo.
  echo NOT INSTALLED: some malware would be whitelisted.
  echo Check rows with would_be_whitelisted=true in %DATA%\%W%\close_calls.csv,
  echo remove those clean references from benign_refs.jsonl and run again.
  goto :end
)
if not exist "%AS%" mkdir "%AS%"
copy /y "%W%\benign_refs.jsonl"  "%AS%\tlsh_whitelist_refs.jsonl" >nul || goto :fail
copy /y "%W%\tlsh_blacklist.txt" "%AS%\tlsh_blacklist.txt" >nul || goto :fail
echo.
echo INSTALLED to %AS%
echo Now press "Reload engines" on the multron_server dashboard.
goto :end

:fail
echo.
echo FAILED (see the message above).
:end
pause
