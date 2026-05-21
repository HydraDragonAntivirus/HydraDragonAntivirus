# Zillya AVEngine SDK - VS2022

This directory contains modern Visual Studio 2022 project files for the legacy Zillya AVEngine SDK samples that originally shipped as VS2005/VS2008 `.vcproj` projects.

## Requirements

- Visual Studio 2022 or Visual Studio 2022 Build Tools
- Desktop development with C++ workload
- MSVC v143 toolset
- Windows 10 SDK
- Win32 target platform

The engine binaries under `bin\aveng` are 32-bit, so the VS2022 solution is prepared for `Win32` only. Adding an `x64` target will not work unless matching 64-bit builds of `CoreMain.DLL` and the related engine DLLs are available.

## Build

From Visual Studio:

1. Open `ZillyaAVEngineSDK-vs2022.sln`.
2. Select `Win32` and either `Release` or `Debug`.
3. Run Build Solution.

From PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\build\vs2022\Build-VS2022.ps1 -Configuration Release
```

To also create a publish folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\build\vs2022\Build-VS2022.ps1 -Configuration Release -Publish
```

Build outputs are written to `out\Win32\<Configuration>`. The `ZillyaRuntime` utility project copies the `bin\aveng` engine runtime and signature database files into the output folder's `aveng` subdirectory.

## Run

All commands below assume a `Release` build from the `ZillyaAVEngineSDK` directory:

```powershell
powershell -ExecutionPolicy Bypass -File .\build\vs2022\Build-VS2022.ps1 -Configuration Release
```

### Direct Engine Scan

`ConsoleApplication.exe` loads `CoreMain.DLL` directly from the copied `aveng` runtime directory and scans one file path.

```powershell
.\out\Win32\Release\ConsoleApplication.exe "C:\Windows\notepad.exe" /p
```

The optional `/p` argument keeps the console window open at the end of the scan.

### Service-Based Scan

The service-based path uses `AVEngineService.exe` plus a named-pipe client. Run the terminal as Administrator because the sample manifests request elevation and service install/uninstall needs admin rights.

Install the service:

```powershell
.\out\Win32\Release\AVEngineService.exe -i
```

Start it:

```powershell
Start-Service ZillyaAVEngine
```

Scan a file through the service client:

```powershell
.\out\Win32\Release\AVEngineClient.exe "C:\Windows\notepad.exe"
```

The `MyAntivirus.exe` sample uses the `zslib` wrapper and talks to the same service:

```powershell
.\out\Win32\Release\MyAntivirus.exe "C:\Windows\notepad.exe"
```

Stop and uninstall the service when finished:

```powershell
Stop-Service ZillyaAVEngine
.\out\Win32\Release\AVEngineService.exe -u
```

### Runtime Files

Keep the `aveng` directory next to the built EXE files. It contains `CoreMain.DLL`, helper engine DLLs, and the `.dat` signature databases. Moving an EXE without this directory will usually make core initialization fail.

## GitHub Actions

The `vs2022zillya-ci` workflow builds the SDK automatically when files under `ZillyaAVEngineSDK/**` or `.github/workflows/vs2022zillya.yml` change. It also supports manual runs through `workflow_dispatch`.

The workflow builds both `Debug|Win32` and `Release|Win32`. Release EXE/DLL/LIB/PDB outputs are uploaded as a workflow artifact named `zillya_vs2022_release_binaries_Win32`; the large `aveng` signature database directory is not included in the artifact.

## VS2022 Solution Projects

- `zslib`: static named-pipe client library used by the SDK.
- `zslib-test`: small test application for `zslib`.
- `AVEngineService`: service application that loads the core engine and exposes RPC scanning.
- `AVEngineClient`: native client sample that connects to the service.
- `ConsoleApplication`: native sample that loads `CoreMain.DLL` directly.
- `MyAntivirus`: simple service-based client sample using `zslib`.
- `AVEngineClientLibrary`: native DLL that managed samples can call through P/Invoke.
- `ZillyaRuntime`: utility project that copies `bin\aveng` runtime and database files into the output folder.

The legacy Java, C#, and VB project files are preserved. This modernization focuses on the native C++ SDK path and the native wrapper.

## Signature Files

For a short explanation of the `.dat` signature and database files, see [docs/dat-signatures.md](docs/dat-signatures.md).

A Turkish version is also available at [docs/dat-signatures.tr.md](docs/dat-signatures.tr.md).
