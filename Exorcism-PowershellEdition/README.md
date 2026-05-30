# Exorcism – PowerShell Edition

Small .NET Framework library that hooks Assembly.Load* at runtime and dumps loaded assemblies to disk. Useful for inspecting dynamically loaded .NET assemblies from PowerShell or other .NET hosts.

## What it does

- Uses Harmony to patch the following APIs at runtime:
	- Assembly.Load(byte[])
	- Assembly.Load(string)
	- Assembly.Load(AssemblyName)
	- Assembly.LoadFrom(string)
	- Assembly.LoadFile(string)
- After you call `Loader.Init()`, every subsequent load via the above methods will:
	- Write a copy of the raw assembly bytes to the current directory
	- Print a short log line to the console

## Requirements

- Windows
- .NET Framework 4.7.2 runtime
- Windows PowerShell 5.1 for the examples below
	- Note: This library targets .NET Framework (net472). It won’t load into PowerShell 7+ (which runs on .NET) unless you retarget the project.

## Build

- Open `Exorcism-PowershellEdition.sln` in Visual Studio and build (Debug or Release), or
- Build from a Developer Command Prompt: `msbuild Exorcism-PowershellEdition.sln /p:Configuration=Release`

The output DLL is in `Exorcism-PowershellEdition/bin/<Configuration>/Exorcism-PowershellEdition.dll`.

## Quick start (PowerShell 5.1)

Run PowerShell in the folder that contains the built DLL so dumps land where you expect.

```powershell
# Load the hook and enable patches
Add-Type -Path .\Exorcism-PowershellEdition\bin\Release\Exorcism-PowershellEdition.dll
[Exorcism_PowershellEdition.Loader]::Init()

# Any of these loads will be intercepted and dumped to the current directory
# 1) Load from bytes
$bytes = [IO.File]::ReadAllBytes('C:\Path\To\SomeLibrary.dll')
[Reflection.Assembly]::Load($bytes) | Out-Null

# 2) Load by display name
[Reflection.Assembly]::Load('System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089') | Out-Null

# 3) Load from a file path
[Reflection.Assembly]::LoadFile('C:\Path\To\ManagedAppOrLibrary.dll') | Out-Null
```

On success, you’ll see console messages like:

```
[+] Harmony patches applied: all Assembly load methods are now hooked.
[+] Dumped assembly -> C:\...\SomeLibrary_1a2b3c4d.dll
```

## Tips

- Dumps are written to the process current directory (`[Environment]::CurrentDirectory`). Start PowerShell in the folder where you want artifacts saved.
- If you don’t see dumps, ensure `Loader.Init()` was called before any assembly loads occur.
- To use with another .NET host (e.g., a managed EXE), inject and call `Exorcism_PowershellEdition.Loader.Init()` as early as possible.

## Legal / intended use

For debugging and research on assemblies you’re authorized to inspect.

