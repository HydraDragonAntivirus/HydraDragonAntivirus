TinyAntivirus
==============

[![Build status](https://ci.appveyor.com/api/projects/status/github/develbranch/TinyAntivirus?branch=master&svg=true)](https://ci.appveyor.com/project/quangnh89/TinyAntivirus/branch/master)
[![License](https://img.shields.io/badge/license-gpl2-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)

**TinyAntivirus (TinyAv)** is an open source antivirus engine designed to detect polymorphic viruses and disinfect them. Inside this repository it is kept as a specialized engine for Sality-style file infectors and advanced heuristics via **MinimalOpenHeuristics (MOH)**. The current `SalityKiller` module detects and disinfects `W32.Sality.PE`.

> [!NOTE]
> The engine is named "Tiny" and its components "Minimal" to reflect the lightweight design philosophy, but this does not imply limited capability. MinimalOpenHeuristics is a robust engine for deep file analysis.


## License

This project is released under the [GPL2](COPYING) [license](LICENSE).

## Requirements

* Visual Studio 2022 with Desktop development with C++
* Windows 10/11 SDK
* CMake 3.20 or newer
* Available source trees for `libs\googletest\googletest` and `libs\zlib`
* [zlib 1.2.8](http://www.zlib.net) or newer
* [unicorn-engine 0.9](http://www.unicorn-engine.org/)

## Build with Visual Studio 2022

* Build dependencies and the solution: `ci\\windows\\build_appveyor.bat x64 Release`
* Open `TinyAntivirus.sln` in Visual Studio 2022 if you want to debug or build manually after the dependency step
* Release output is generated under `x64\\Release\\` for `x64` builds and `Release\\` for `Win32` builds
* Additional notes for this component live in the project wiki: [TinyAntivirus wiki](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus/wiki/TinyAntivirus)
* If TinyAntivirus is used as a vendored directory inside HydraDragon, make sure `libs\\googletest\\googletest` and `libs\\zlib` contain the actual upstream sources because nested `.gitmodules` are not activated automatically by the parent repository

## Quick start

* Build `TinyAvCore`, `TinyAvConsole`, and `SalityKiller`.
* Change into the output directory and run `TinyAvConsole.exe`.

## Usage

```
TinyAvConsole.exe [options]

```
| Option   |      Meaning      |  Default value |
|----------|-------------|:------:|
| -e | plug-in directory | current directory |
| -A | Archive scan depth | -1 : any depth|
| -D | scan depth | -1 : any depth |
| -d | path to scan |  |
| -p | file pattern | \*.\* |
| -s | max file size in bytes| 10 \* 1024 \* 1024 (10 MB) |
| -m | Scan mode: Kill-virus (k) or Scan-only(s) | Kill-virus (k) |
| -h | Show usage ||

You may scan all directories and files by using default values.

**Example:** Scan for all files, including ZIP archives, to detect and disinfect virus.
ZIP files which contain virus will be deleted.
```
C:\build>TinyAvConsole.exe -d C:\sample
------------------------------------------------------
TinyAntivirus version 0.2
Copyright (C) 2026, Emirhan Ucan. All rights reserved.
------------------------------------------------------
Scanning ...
C:\sample\calc.EXE
        W32.Sality.PE Disinfected
C:\sample\container.zip                                                 OK
C:\sample\container.zip>DiskView.exe                                    OK
C:\sample\container.zip>DMON.SYS                                        OK
C:\sample\container.zip>sub_container.zip                               OK
C:\sample\container.zip>sub_container.zip>NOTEPAD.EXE
        W32.Sality.PE Deleted
C:\sample\dbgview.chm                                                   OK
C:\sample\sub\gmer.EXE
        W32.Sality.PE Disinfected

=============================================
Scanned       : 4 file(s) (10 object(s))
Detected      : 3 file(s)
Removed       : 3 file(s)
Access denied : 0 file(s)

C:\build>
```

## Contribute

If you want to contribute, please pick up something from our [Github issues](https://github.com/develbranch/TinyAntivirus/issues).

The current roadmap lives in the project wiki page for TinyAntivirus.

I have only one Sality sample to develop Sality killer module. I think there are many variant types of this file infector. Please send me samples which TinyAv can not detect or other kinds of polymorphic viruses. Thank you.

## Author

[Emirhan Ucan](https://github.com/HydraDragonAntivirus)
