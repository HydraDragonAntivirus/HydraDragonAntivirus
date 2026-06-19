# HydraDragonSig Native Yamdle Signature Packs

These packs are examples and are **not built in**. HydraDragonSig does not load them unless you pass them with `--rules`.

```bash
cargo run --release -- sample.exe \
  --rules examples/signatures/god_mode_iddqd_yamdle.yaml \
  --rules examples/signatures/windows_registry_sabotage_yamdle.yaml
```

## Added native modifiers

Yamdle `native_signature` atoms now support these deterministic modifiers without YARA:

- `ascii`
- `wide`
- `nocase`
- `fullword`
- `decoded`
- `xor: true` with `xor_min` / `xor_max`
- `base64: true`
- `base64wide: true`

Example:

```yaml
- id: amsi_scan_buffer_base64
  kind: text
  value: 'AmsiScanBuffer'
  base64: true
  base64wide: true

- id: reflective_loader_xor
  kind: text
  value: 'ReflectiveLoader'
  ascii: true
  wide: true
  xor: true
  fullword: true
```

## Packs

- `god_mode_iddqd_yamdle.yaml` - native conversion of the pasted God Mode static indicators plus Sigma-style command clues.
- `windows_registry_sabotage_yamdle.yaml` - destructive registry, Defender/AV tamper, IFEO debugger hijack, raw disk/PhysicalDrive, policy lockdown, and Run-key persistence signatures.
