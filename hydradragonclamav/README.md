# hydradragonclamav

Pure-Rust loader and scanner for HydraDragon's ClamAV non-hash signatures.

This project is intentionally not a libclamav wrapper. It focuses on the portable
database formats that match file bodies:

- Loads `.ndb` / `.ndu` extended body signatures.
- Loads `.ldb` / `.ldu` logical signatures.
- Skips hash databases (`.hdb`, `.hsb`, `.hdu`, `.hsu`, `.mdb`, `.msb`, `.mdu`,
  `.msu`) because HydraDragon uses Bloom filters for hashes.
- Classifies non-body formats such as `.cdb`, `.idb`, `.pdb`, `.wdb`, bytecode,
  allow/ignore lists, and config databases as unsupported metadata for now.

Supported body features include exact hex bytes, nibble wildcards, `??`, `*`,
`{n}`, `{-n}`, `{n-}`, `{n-m}`, `[x-y]`, `(B)`, `(L)`, `(W)`, alternates, negated
fixed-width alternates, logical `&` / `|`, grouped expressions, count comparisons,
and logical subsignature modifiers `i`, `w`, `a`, and `f`.

Offset support covers `*`, absolute offsets, `EOF-n`, `EP+/-n`, `Sx+/-n`, `SEx`,
and `SL+/-n` with a compact PE parser for entry point and section mapping.

## Usage

Load the portable database and print coverage:

```powershell
cargo run --manifest-path hydradragonclamav/Cargo.toml -- --database HydraDragonAVPortable/database
```

Scan a file or directory:

```powershell
cargo run --manifest-path hydradragonclamav/Cargo.toml -- --database HydraDragonAVPortable/database --scan path\to\sample.bin
```

Use `--strict-targets` to apply basic target filtering for PE, HTML, and ASCII
text signatures. By default target filtering is permissive to avoid missing
matches while HydraDragon-specific file typing is still separate.
