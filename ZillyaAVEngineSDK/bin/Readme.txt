This folder contains the application binaries, source code, which are part of the SDK

aveng - contains files scan engine and virus database
AVEngineService.exe - Zillya AVEngine Service binary
AVEngineClient - is simple example and ready antivirus application that uses AVEngineService

AVEngineService.exe & AVEngineClient.exe compiled with Microsoft Visual Studio 2005 using release "/MT" setting for runtime library (Multi-Threaded).


To install service run InstallAVEngineService.bat

To uninstall service tun UninstallAVEngineService.bat

To set the default path to the core run InstallPath.bat. This script used by the seaples, to find virus bases. If you not want use it, put the binaries and bases, to the application directory.