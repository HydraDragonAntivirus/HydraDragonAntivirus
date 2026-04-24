TinyAntivirus
==============

[![Build status](https://ci.appveyor.com/api/projects/status/github/develbranch/TinyAntivirus?branch=master&svg=true)](https://ci.appveyor.com/project/quangnh89/TinyAntivirus/branch/master)
[![License](https://img.shields.io/badge/license-gpl2-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)

**TinyAntivirus (TinyAv)** is an open source antivirus engine designed to detect polymorphic viruses and disinfect them. Inside this repository it is kept as a specialized engine for Sality-style file infectors and conservative PE detection via **MinimalOpenSignatures (MOS)**. The current `SalityKiller` module detects and disinfects `W32.Sality.PE`, while MOS adds PE signature and heuristic coverage without treating every unusual file as malicious.

> [!NOTE]
> The engine is named "Tiny" and its components "Minimal" to reflect the lightweight design philosophy, but this does not imply limited capability. MinimalOpenSignatures is a full antivirus engine component for focused PE analysis, not a deliberately weak scanner.
> _new_instance/_set/_get/_setO not fully ported.

> [!IMPORTANT]
> Original TinyAntivirus copyright and upstream authorship remain attributed to `develbranch.com` / `quangnh89`. The HydraDragon `0.2` integration, MOS work, VS2022 updates, and later extensions are credited separately to Emirhan Ucan.


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

* Build `TinyAvCore`, `TinyAvConsole`, `SalityKiller`, and `MinimalOpenSignatures`.
* Change into the output directory and run `TinyAvConsole.exe`.

## Usage

```text
TinyAvConsole.exe -d <path> [options]
```
| Option   |      Meaning      |  Default value |
|----------|-------------|:------:|
| -e | plug-in directory | executable directory |
| -g | signature file or directory (all parseable DB containers such as `.cvd`, `.ivd`, `.rvd`, `.xmd`) | optional |
| -A | Archive scan depth | -1 : any depth|
| -D | scan depth | -1 : any depth |
| -d | path to scan | required |
| -p | file pattern | \*.\* |
| -s | max file size in bytes| 10 \* 1024 \* 1024 (10 MB) |
| -m | Scan mode: Kill-virus (k) or Scan-only(s) | Kill-virus (k) |
| -h | Show usage ||

ZIP scanning already exists in TinyAntivirus. Additional archive formats like `RAR`, `7z`, `gzip`, and `cab` are still future work.

Typical examples:

```text
TinyAvConsole.exe -d C:\sample -m s
TinyAvConsole.exe -d C:\sample -g C:\repo\TinyAntivirus\decompile -m s
TinyAvConsole.exe -d C:\sample -A 2 -D 4 -m k
```

If you want to load the reverse-engineered signature set from this repo directly, point `-g` to `TinyAntivirus\decompile`. TinyAv will now enumerate and load every parseable signature container it recognizes in that directory, not just the historical `xlmrd/orice` trio.

In the current `0.2` build, loading these databases activates MOS runtime matching as well as the conservative PE heuristics. If the Unicorn runtime is not present, `SalityKiller` quietly disables itself and MOS detection still continues.

**Example:** Scan for all files, including ZIP archives, to detect and disinfect malware.
ZIP files which contain malware can still be removed if repair is not possible.
```text
C:\build>TinyAvConsole.exe -d C:\sample -g C:\repo\TinyAntivirus\decompile
------------------------------------------------------
TinyAntivirus version 0.2
Copyright (C) 2016, develbranch.com.
Copyright (C) 2026, Emirhan Ucan.
------------------------------------------------------
[MOS] Loading signatures from C:\repo\TinyAntivirus\decompile... Success
[MOS] Loaded signature databases: 900+
[MOS]   1. xlmrd [CVD] - C:\repo\TinyAntivirus\decompile\xlmrd.cvd
[MOS]   2. xlmrd [IndexedBinary] - C:\repo\TinyAntivirus\decompile\xlmrd.ivd
[MOS]   3. orice [IndexedBinary] - C:\repo\TinyAntivirus\decompile\orice.rvd
[MOS]   4. 7zip [IndexedBinary] - C:\repo\TinyAntivirus\decompile\7zip.xmd
[MOS]   5. aitok [AVXS] - C:\repo\TinyAntivirus\decompile\aitok.cvd
[MOS]   ...
[MOS] Signature runtime matching (xlmrd/orice) is ACTIVE.
Scanning ...
C:\sample\calc.EXE
        HEUR:Win32.MOS.SectionJump (MinimalOpenSignatures)
C:\sample\virus.EXE
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

## Credits

Original upstream TinyAntivirus: [develbranch / quangnh89](https://github.com/develbranch/TinyAntivirus)

HydraDragon integration, TinyAntivirus 0.2 updates, MOS work, and VS2022 maintenance: [Emirhan Ucan](https://github.com/HydraDragonAntivirus)
