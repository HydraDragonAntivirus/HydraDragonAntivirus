bcdedit /set testsigning on
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
shutdown -r -t 2
pause