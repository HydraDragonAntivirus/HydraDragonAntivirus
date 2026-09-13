# hydradragonclamav

Pure-Rust loader and scanner for HydraDragon's ClamAV non-hash signatures.

This project is intentionally not a libclamav wrapper. It focuses on the portable
database formats that match file bodies:

- Loads `.ndb` / `.ndu` extended body signatures.
- Loads `.ldb` / `.ldu` logical signatures.
- Recursively scans child objects from supported archives/compression formats
  through `hydradragonextractor`: `.zip`, `.tar`, `.gz`, `.xz`, `.lzma`, and
  `.7z`.
- Scans normalized ASCII text and simple HTML views for target types 7 and 3.
- Loads `.cdb` container metadata signatures and matches the fields HydraDragon
  can observe from `hydradragonextractor` (container type/size, member real
  size, member position). Fields that need archive-member metadata we don't
  expose (filename regex, encryption, compressed size, CRC) are parsed but cause
  the signature to be skipped when constrained, so they never false-positive.
- Loads `.ftm` file-type magic (magictype `0` absolute and `1` body-pattern) and
  uses it to type files; in `--strict-targets` mode the detected `CL_TYPE_*`
  refines target filtering instead of the built-in heuristics.
- Skips hash databases (`.hdb`, `.hsb`, `.hdu`, `.hsu`, `.mdb`, `.msb`, `.mdu`,
  `.msu`) because HydraDragon uses Bloom filters for hashes.
- Classifies non-body formats such as `.idb`, `.pdb`, `.wdb`, bytecode (`.cbc`),
  allow/ignore lists, and config databases as unsupported metadata for now.

Supported body features include exact hex bytes, nibble wildcards, `??`, `*`,
`{n}`, `{-n}`, `{n-}`, `{n-m}`, `[x-y]`, `(B)`, `(L)`, `(W)`, alternates, negated
fixed-width alternates, logical `&` / `|`, grouped expressions, count comparisons,
and logical subsignature modifiers `i`, `w`, `a`, and `f`.

Logical signatures also support **PCRE subsignatures** (`Trigger/regex/flags`,
backed by the linear-time `regex` engine — patterns needing backreferences or
lookaround are flagged unsupported) and **byte-compare subsignatures**
(`trigger(offset#byte_options#comparisons)`, reading hex/decimal/auto ASCII or
little/big-endian binary integers relative to the trigger match).

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

Useful scan controls:

```powershell
cargo run --manifest-path hydradragonclamav/Cargo.toml -- --scan sample.zip --max-recursion 12 --max-child-size 256M
cargo run --manifest-path hydradragonclamav/Cargo.toml -- --scan sample.html --no-archives
cargo run --manifest-path hydradragonclamav/Cargo.toml -- --scan sample.bin --no-normalize
```

Use `--strict-targets` to apply basic target filtering for PE, HTML, and ASCII
text signatures. By default target filtering is permissive to avoid missing
matches while HydraDragon-specific file typing is still separate.

## Load-time RAM

The prefilter builds a [daachorse](https://crates.io/crates/daachorse)
double-array Aho-Corasick automaton over the signature atoms. Building that trie
over hundreds of thousands of atoms spikes a large one-time transient
(~500 MB on the full database) that drives the load-time RAM *peak*. It is built
purely in memory (no on-disk cache — serializing it only shaved that one
transient, while the launch peak is dominated by the other engines loading) and
`trim_working_set` returns the build scratch to the OS afterwards. The host
(`hydradragonav`) loads its engines **sequentially**, ClamAV first, so these
build transients don't overlap into one giant peak.

This is still not complete ClamAV parity. Phishing URL databases (`.pdb`/`.wdb`),
icon signatures (`.idb`), exact JavaScript normalization, VBA/OLE/PDF object
extraction, and fuzzy-image subsignatures remain separate follow-up pieces.
ClamAV **bytecode** (`.cbc`) is intentionally out of scope: it is compiled
programs run by ClamAV's own bytecode virtual machine, not a pattern format, so
it would require porting that whole interpreter — those records stay unsupported.
