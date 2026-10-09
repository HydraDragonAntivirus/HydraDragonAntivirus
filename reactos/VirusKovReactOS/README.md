# VirusKov for ReactOS

Cloud scanner, real-time folder protection and boot sector backup for **ReactOS**,
**Windows XP SP3** and, with [dotnet9x](https://github.com/itsmattkc/dotnet9x),
**Windows 95/98/ME**. Built on **.NET Framework 3.5** (CLR 2.0): .NET 4.x is incomplete on ReactOS.

It speaks the same `wss://` protocol (version 3) as Multron Win Cleaner, so
`multron_server_rs` needs no change: hashes are checked first, only unknown files are uploaded.

## What it does

| Part | How |
|---|---|
| Cloud scan | Folder / drive / quick scan. SHA-256 per file, `check` in batches, upload only on `need_upload`. Only executables & scripts by default (same filter and EULA as Multron Win Cleaner). Folder paths are sent with the user folder replaced by `%USERPROFILE%` etc. |
| Real-time protection | `FileSystemWatcher` on Desktop, Downloads, Startup, Temp and extra folders, plus polling (every 2 min; every 30 s when there is no watcher, e.g. Windows 9x). New or changed executables are checked; malicious ones go to quarantine automatically (setting). User mode only: it detects and quarantines, it cannot block a program before it starts (that needs a kernel driver). |
| Boot sector | First 63 sectors of `\\.\PhysicalDrive0` (MBR + track 0) are backed up on first start and compared at every start. Restore writes back only the boot code and keeps the current partition table (optionally track 0 too). NT only (ReactOS, XP); not available on 9x. The backup never leaves the computer. |
| Quarantine | `data\quarantine`, XOR-scrambled, restore / delete. |

## TLS

XP, ReactOS and 9x only have SSL 3.0 / TLS 1.0 in SChannel, so TLS is done by
**BouncyCastle 1.8.9** (pure managed code, no native DLL). It is the last BouncyCastle
release with .NET 2.0 binaries and its TLS client stops at **TLS 1.2**. TLS 1.3 in
BouncyCastle C# exists only in 2.x, which needs .NET 4.6.1+, so it is not possible on 3.5
with this library. Cloudflare and the VirusKov server accept TLS 1.2.

Server certificates are checked against `roots.pem` (Mozilla CA bundle, next to the exe):
chain signatures, validity dates, CA flags and host name (SAN / CN). Replace `roots.pem`
with a newer bundle to update the trusted roots.

## Build

Visual Studio 2019/2022 or `dotnet build` (the `Microsoft.NETFramework.ReferenceAssemblies`
package provides the .NET 3.5 references, so no 3.5 targeting pack is needed):

```
dotnet build -c Release
```

Copy `VirusKovReactOS.exe`, `VirusKovReactOS.exe.config`, `BouncyCastle.Crypto.dll` and
`roots.pem` to the target machine. It keeps everything (settings, log, quarantine, boot
sector backup) in a `data` folder next to the exe, so it also runs from a USB stick.

Target machine needs .NET Framework 3.5 (ReactOS: install it from the ReactOS Applications
Manager; XP: .NET 3.5 SP1; 9x: dotnet9x). Run as administrator for the boot sector parts.

## Testing a local server

`ws://` (unencrypted) is accepted only for `localhost` / `127.0.0.1`, as in Multron Win Cleaner,
e.g. `ws://127.0.0.1:5306/ws` in Settings.

## Rules kept on purpose

- No P/Invoke except `CreateFile` for raw disk access (ReactOS is not 100 % XP compatible in kernel32/ntdll).
- No async/await, Task, ValueTuple or other .NET 4 runtime features.
- WinForms built in code, no designer, no WPF.
