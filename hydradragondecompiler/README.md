# hydradragondecompiler

A "decompiler-lite" string extractor for HydraDragon. Its job is to pull *more*
strings out of a binary — especially Windows PE executables — than a naive
`strings` tool would, so those strings can be fed into HydraDragon's malware
scanning.

This is an in-house implementation. It does not use radare2 or radeco; PE parsing
is done with `goblin` and disassembly with `capstone`, the same crates and
versions HydraDragon already builds with.

## Extraction modes

The extractor runs up to four passes and merges the results:

1. **ASCII** — contiguous runs of printable ASCII (`0x20..=0x7e` plus tab) of at
   least `min_len` characters, recorded with their file offset.
2. **Wide (UTF-16LE)** — runs of `printable, 0x00` pairs decoded to a `String`.
   These are invisible to a plain `strings` run without `-e l`.
3. **Code references** — for PE files, the executable sections are disassembled
   and memory operands are followed. Absolute and RIP-relative references that
   land inside a section are resolved to a file offset; if the bytes there form a
   printable ASCII or UTF-16LE string it is emitted as a `CodeRef`. This catches
   strings that are referenced only by address.
4. **Stack strings** — sequences of immediate-to-memory `mov` instructions
   (`mov byte/word/dword ptr [reg +/- disp], imm`) that assemble a string on the
   stack are reconstructed in displacement order and emitted as `StackString`.
   These never appear as a contiguous run in the file at all.

The result is deduplicated by `(kind, text)`, sorted deterministically by
`(offset, text)`, and capped at `max_strings`. Passes 3 and 4 are best-effort:
if the file is not a PE, or goblin/capstone cannot process it, those passes are
skipped and the ASCII/wide results are still returned.

Disassembly covers **x86 16/32/64**; bitness is chosen from the PE optional
header (`is_64`). Non-x86 PEs (e.g. ARM64) parse fine but yield no code-ref or
stack-string hits.

## Usage

```powershell
cargo run --manifest-path hydradragondecompiler/Cargo.toml -- sample.exe
```

Each line is printed as `KIND<TAB>offset<TAB>text` (offset is `-` for stack
strings), which is greppable:

```
ASCII   0x4012a0  MALWARE_C2_STRING
WIDE    0x418830  http://evil.example/gate.php
CODEREF 0x41a120  cmd.exe /c
STACK   -         powershell -nop -w hidden
```

Options:

```
hydradragondecompiler <FILE> [--min-len N] [--no-ascii] [--no-wide]
                             [--no-code-refs] [--no-stack-strings] [--json]
```

- `--min-len N` — minimum string length (default 4).
- `--no-ascii` / `--no-wide` / `--no-code-refs` / `--no-stack-strings` — disable
  individual passes.
- `--json` — emit a JSON array of `ExtractedString` objects instead of lines.

Exit code is 0 on success and non-zero (with a message on stderr) on error.

## Library

```rust
use hydradragondecompiler::{extract_strings, extract_from_path, ExtractOptions};

let opts = ExtractOptions::default();
let strings = extract_strings(&bytes, &opts);
let strings = extract_from_path(std::path::Path::new("sample.exe"), &opts)?;
```

## Scope

This is a standalone developer / analysis tool. It is **not** part of the
portable HydraDragon build; it exists to mine extra strings out of samples and
feed them into HydraDragon scanning. Like the sibling crates it has its own
`Cargo.toml` and is not a workspace member.
