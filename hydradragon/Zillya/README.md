# Zillya Runtime

This directory is the preferred runtime location for the Zillya AVEngine files used by HydraDragon minimal-mode service scans.

Expected runtime layout:

```text
hydradragon/Zillya/
  AVEngineService.exe
  AVEngineClient.exe
  aveng/
    CoreMain.DLL
    *.dat
```

The Rust Owlyshield integration talks directly to the Zillya named pipe:

```text
\\.\pipe\ZSDK-{F671A1CA-7BA6-4e57-9E98-0D2AE0985A42}
```

The launcher first looks here, then falls back to `ZillyaAVEngineSDK/bin`. This avoids duplicating the large `aveng` signature database in source control while still supporting the final installed layout.

To populate this folder from the SDK checkout:

```powershell
powershell -ExecutionPolicy Bypass -File hydradragon\Zillya\sync-runtime.ps1
```
