# nuitka_blob_loader

Standalone C tool to **extract, decode, and export** Python source code from
Nuitka-compiled binaries — with no CPython dependency in the loader itself.

---

## What it does

```
Nuitka .exe / .dll
   └─ RCDATA resource #3  (rcdata_10_3.bin)
         └─ blob header     [CRC32][size]
         └─ .bytecode       → .pyc per module
         └─ __main__        → __main__.pyc
         └─ mypackage.mod   → mypackage/mod.pyc
         └─ ...
                 ↓
         output/
           __main__.pyc   + __main__.hex
           mypackage/
             mod.pyc      + mod.hex
```

Each `.pyc` is a proper Python bytecode file:
`[4B magic][4B flags=0][4B mtime=0][4B srcsize=0][marshal bytes]`

---

## Project layout

```
nuitka_blob_loader/
├── include/
│   └── blob_loader.h        ← public API + complete wire-format docs
├── src/
│   ├── main.c               ← CLI with all flags
│   ├── blob_loader.c        ← verify / find / decode constants
│   ├── blob_export.c        ← .pyc + .hex writer, hex dumper
│   └── crc32.c              ← CRC-32/ISO-HDLC
├── extract_sbox.py          ← dump cipher S-box from the .exe
├── gen_test_blob.py         ← generate a test rcdata_10_3.bin
├── verify_pyc.py            ← verify / disassemble / decompile output
├── Makefile
└── CMakeLists.txt
```

---

## Step 1 — Extract rcdata_10_3.bin

### Windows — ResourceHacker CLI
```cmd
ResourceHacker.exe -open program.exe -save rcdata_10_3.bin ^
    -action extract -mask RCDATA,3
```

### Windows — Python (no tools needed)
```python
import ctypes, struct, zlib
k = ctypes.WinDLL("kernel32")
hmod  = k.LoadLibraryExA(b"program.exe", None, 0x20)
hrsrc = k.FindResourceA(hmod, ctypes.c_int(3), ctypes.c_int(10))
hglob = k.LoadResource(hmod, hrsrc)
ptr   = k.LockResource(hglob)
size  = k.SizeofResource(hmod, hrsrc)
data  = (ctypes.c_ubyte * size).from_address(ptr)
open("rcdata_10_3.bin", "wb").write(bytes(data))
k.FreeLibrary(hmod)
```

### Linux (ELF Nuitka build)
```bash
objcopy --dump-section .nuitka_constants=rcdata_10_3.bin program
```

### macOS (Mach-O)
```bash
otool -s constant constant program | xxd -r -p > rcdata_10_3.bin
```

---

## Step 2 — Build

```bash
# Linux / macOS
make

# Windows cross-compile (MinGW)
make windows

# Windows MSVC (Developer Command Prompt)
cl /TC /O2 /Iinclude src\main.c src\blob_loader.c src\blob_export.c src\crc32.c /Fe:blob_loader.exe

# CMake
cmake -B build && cmake --build build
```

---

## Step 3 — Export .pyc files

```bash
# Auto-detect everything, export all modules
./blob_loader rcdata_10_3.bin --save-pyc ./output

# Force Python 3.11 magic (if auto-detect is wrong)
./blob_loader rcdata_10_3.bin --save-pyc ./output --pyver 0x3b0

# Print section table only
./blob_loader rcdata_10_3.bin --toc

# Decode and print constants from one section
./blob_loader rcdata_10_3.bin --section __main__

# Export + no stdout constant dump
./blob_loader rcdata_10_3.bin --save-pyc ./output --no-print
```

---

## Step 4 — Verify and disassemble

```bash
# Verify all .pyc files + disassemble
python3 verify_pyc.py output --dis

# Show constant pools too
python3 verify_pyc.py output --dis --verbose

# Decompile to Python source (requires pip install decompile3)
python3 verify_pyc.py output --decompile --save-py
```

Or directly in Python:
```python
import marshal, dis
with open("output/__main__.pyc", "rb") as f:
    f.read(16)           # skip 16-byte pyc header
    dis.dis(marshal.loads(f.read()))
```

---

## Step 5 — Decryption (if blob is encrypted)

The IDA decompilation revealed a stream cipher using a 256-byte S-box
(`byte_38B57EC20`). Extract it from the binary, then pass it to the loader.

```bash
# Extract S-box from the .exe (needs IDA address of the S-box)
python3 extract_sbox.py program.exe --addr 0x38B57EC20 --out-bin sbox.bin

# Run with decryption enabled
./blob_loader rcdata_10_3.bin --sbox sbox.bin --save-pyc ./output
```

---

## Python version magic numbers

| Version | `--pyver` | Magic (LE uint32) |
|---------|-----------|-------------------|
| 3.8     | `0x380`   | `0x0D0D550A`      |
| 3.9     | `0x390`   | `0x0D0D610A`      |
| 3.10    | `0x3a0`   | `0x0D0D6F0A`      |
| 3.11    | `0x3b0`   | `0x0D0DA70A`      |
| 3.12    | `0x3c0`   | `0x0D0DCB0A`      |
| 3.13    | `0x3d0`   | `0x0D0DF50A`      |

---

## Wire format (quick reference)

```
File:
  [uint32]  CRC32 of everything below
  [uint32]  byte count covered by CRC32
  Sections (repeated):
    [cstr]    section name  (".bytecode", "__main__", "pkg.mod", ...)
    [uint32]  section payload size
    [uint16]  constant count N
    N × constant:
      [char]  type tag
      [...]   type payload

Type tags:
  'n'  None          't'  True        'F'  False
  's'  empty str     'p'  back-ref
  'l'  +int (varint) 'q'  -int (varint)
  'G'  +bigint       'g'  -bigint
  'f'  float (8B)    'Z'  special float (sub-tag: 0=+0 1=-0 2=+nan 3=-nan 4=+inf 5=-inf)
  'j'  complex (16B) 'J'  complex via 2 child floats
  'c'  bytes (cstr)  'd'  bytes (1B)   'b'  bytes (varint+raw)
  'w'  str (1 char)  'u'  str (cstr)   'a'  interned str (cstr)  'v'  str (varint+raw)
  'T'  tuple         'L'  list         'D'  dict
  'S'  set           'P'  frozenset    ':'  slice   ';'  range
  'A'  GenericAlias  'H'  UnionType
  'M'  anon builtin  'Q'  special singleton  'O'/'E'  builtin by name
  'C'  code object   'X'  raw marshal blob  ← compiled .pyc content
```

---

## API (embed in your own code)

```c
#include "blob_loader.h"

BlobCtx *ctx;
blob_load_file("rcdata_10_3.bin", &ctx);
blob_verify(ctx);                          // CRC32 check
blob_dump_toc(ctx);                        // print section list
blob_find_section(ctx, ".bytecode", NULL); // select section
BlobVal *vals; uint32_t count;
blob_parse_constants(ctx, &vals, &count);  // decode constants
for (uint32_t i = 0; i < count; i++)
    blob_print_val(&vals[i], 0);
blob_export_all_pyc(ctx, "./output", 0);   // export .pyc + .hex
blob_free_values(vals, count);
blob_free(ctx);
```

---

## All constants tag handling

| Tag | Type | Fixed |
|-----|------|-------|
| `'X'` | raw marshal / bytecode | ✓ (was missing in v1) |
| `'C'` | code object | ✓ (field order was wrong in v1) |
| `'A'` | GenericAlias (3.9+) | ✓ (new) |
| `'H'` | UnionType (3.10+) | ✓ (new) |
| All others | fully handled | ✓ |
