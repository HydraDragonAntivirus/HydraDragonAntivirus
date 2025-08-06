@echo off
REM Install driver INF
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 "%~dp0hydradragon\Owlyshield\OwlyshieldRansomFilter\OwlyshieldRansomFilter.inf"

REM Create and configure service
sc create "Owlyshield Service" binPath= "\"%~dp0hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe\""
sc config "Owlyshield Service" depend= OwlyshieldRansomFilter
sc config "Owlyshield Service" start= demand

REM Optionally start the service
sc start "Owlyshield Service"

pause

REM Delete this batch file after running
del "%~f0"
