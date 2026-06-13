# Python Hook Backend

C++ injection DLL that hooks `PyMarshal_ReadObjectFromString` via an `FF 25 [rip+0]` detour in the target Python process.

## Build

Run `build_dll.bat` (requires MSVC VS 2022) — produces `bin/hook64.dll` and `bin/hook32.dll`.

## Deploy

The DLL is injected at runtime by the Owlyshield Rust injector (`python_hook.rs`).  
The injector expects the DLL at:

```
C:\Program Files\HydraDragonAntivirus\hydradragon\hook64.dll   (x64)
C:\Program Files\HydraDragonAntivirus\hydradragon\hook32.dll   (x86)
```

### Path Spoofing (Anti-Analysis)

The `C:\Program Files\HydraDragonAntivirus\hydradragon\` path is intentionally used as a spoofed install directory to evade path‑based detection — the product is not actually installed under `Program Files`. The DLL must be deployed there manually after each build:

```powershell
Copy-Item bin\hook64.dll "C:\Program Files\HydraDragonAntivirus\hydradragon\hook64.dll" -Force
```

The Owlyshield service runs as `SYSTEM` and performs injection via `CreateRemoteThread` + `LoadLibraryW`, followed by calling the `HydraStartHook` export in the remote process.

## Architecture

- `hook_dll.cpp` — the injected DLL: `FF 25` detour, backwards memory scan for the Nuitka blob, module‑name extraction from blob headers, kernel32‑based `.pyc`/`.bin` file I/O.
- `bin/__hook__.py` — Python‑side marshal hooks, blob reassembly, bytecode decompilation, and module reconstruction.
- `bin/test_py_source_hook_with_gui.py` — standalone GUI for manual injection/testing.
