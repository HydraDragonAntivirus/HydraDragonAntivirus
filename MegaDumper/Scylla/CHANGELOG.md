## Changelog

Version 0.11.2

- Generate Python bindings for Python 3.12

Version 0.11.1

- Fix `readMemoryFromProcess` to only reprotect to `PAGE_READONLY`
- Generate Python bindings for Python 3.11

Version 0.11.0

- Update `ScyllaIatFixAutoW` and `ScyllaIatSearch` to allow dumping DLLs
- `pyscylla.dump_pe` and `pyscylla.rebuild_pe` now return None and throw
  exceptions on failure
- Generate Python bindings for Python 3.8+ (i.e., drop Python 3.7 support)

Version 0.10.0

- Update default configuration
- Add support for Windows 8.1 and Windows 10
- Switch build system to CMake
- Add bindings for Python 3
- Add a new `createNewIat` parameter to `ScyllaIatFixAutoW`
- Fix bad handling of instructions with a REX prefix in `IATReferenceScan::patchNewIat`
- Handle multiple imports that have the same address in `ApiReader::getApiByVirtualAddress`
- Add a Sphinx-generated documentation
- Update distorm to version 3.5.2
- Update WTL to version 10

Version 0.9.8

- Bugfixes for x64, IAT Search
- diStorm3 update from Jan 3rd 2015

Version 0.9.7

- Fixed bug bad allocation https://forum.tuts4you.com/topic/36458-scylla-097b-crash-on-pep-50-unpackme/
- Fixed bug https://forum.tuts4you.com/topic/35352-scylla-themida-v2180-iat-problem/
- Fixed bug with api selection https://forum.tuts4you.com/topic/35912-scylla-097-problem-acprotect/
- Included .NET binary + source, ScyllaToImprecTree to convert the api export to imprec

Version 0.9.6

- improved iat search
- fixed bug in api resolve engine
- new option: parse APIs always from disk -> slower, useful against pe header modifications

Version 0.9.5

- Fixed virtual device bug caused by QueryDosDeviceW bug
- improved process lister
- improved module lister
- improved dump name
- improved IAT parser

Version 0.9.4 Final

- direct import scanner (LEA, MOV, PUSH, CALL, JMP) + fixer with 2 fix methods
- create new iat in section
- fixed various bugs

Version 0.9.3

- new dll function: iat search
- new dll function: iat fix auto

Version 0.9.2

- Pick DLL -> Set DLL Entrypoint
- Advanced IAT Search Algorithm (Enable/Disable it in Options), thanks to ahmadmansoor
- Fixed bug in Options
- Added donate information, please feel free to donate some BTC to support this project

Version 0.9.1

- Fixed virtual device bug
- Fixed 2 minor bugs

Version 0.9

- updated to distorm v3.3
- added application exception handler
- fixed bug in dump engine
- improved "suspend process" feature, messagebox on exit

Version 0.8

- added OriginalFirstThunk support. Thanks to p0c
- fixed malformed dos header bug
- NtCreateThreadEx added infos from waliedassar, thanks!

Version 0.7 Beta

- fixed bug Overlapped Headers
- fixed bug SizeOfOptionalHeader
- added feature: suspend process for dumping, more information
- improved disassembler
- fixed various bugs

Version 0.6b

- internal code changes
- added option: fix iat and oep

Version 0.6a

- fixed buffer to small bug in dump memory

Version 0.6

- added dump memory regions
- added dump pe sections -> you can edit some values in the dialog
- improved dump engine with intelligent dumping
- improved pe rebuild engine -> removed yoda's code
- fixed various bugs

Version 0.5a:

- fixed memory leak
- improved IAT search

Version 0.5:

- added save/load import tree feature
- multi-select in tree view
- fixed black icons problem in tree view
- added keyboard shortcuts
- dll dump + dll dump fix now working
- added support for scattered IATs
- pre select target path in open file dialogs
- improved import resolving engine with api scoring
- api selection dialog
- minor bug fixes and improvements

Version 0.4:

- GUI code improvements
- bug fixes
- imports by ordinal

Version 0.3a:

- Improved import resolving
- fixed buffer overflow errors

Version 0.3:

- ImpREC plugin support
- minor bug fix
