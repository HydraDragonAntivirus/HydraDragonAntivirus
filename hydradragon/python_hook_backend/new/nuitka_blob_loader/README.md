# nuitka_blob_loader

Standalone C tool to load and decode the **`.bytecode`** constants section
from a Nuitka-compiled binary's `rcdata_10_3.bin` RCDATA resource.

No CPython required. No external dependencies.

---

## Project structure

```
nuitka_blob_loader/
├── include/
│   └── blob_loader.h       ← public API + full format documentation
├── src/
│   ├── main.c              ← entry point (CLI)
│   ├── blob_loader.c       ← core: verify / find-section / parse-constants
│   └── crc32.c             ← CRC-32/ISO-HDLC implementation
├── bin/                    ← put rcdata_10_3.bin here
├── Makefile
├── CMakeLists.txt
└── README.md
```

---

## Step 1 — Extract `rcdata_10_3.bin` from the Nuitka binary

### Windows (ResourceHacker GUI)
1. Open **ResourceHacker.exe** → File → Open → select the compiled `.exe`
2. Expand `RCDATA` → `3`
3. Right-click → **Save resource to BIN file** → save as `rcdata_10_3.bin`

### Windows (ResourceHacker CLI)
```cmd
ResourceHacker.exe -open program.exe -save rcdata_10_3.bin ^
    -action extract -mask RCDATA,3
```

### Windows (Python, no tools needed)
```python
import ctypes, ctypes.wintypes as wt

kernel32 = ctypes.WinDLL("kernel32")
hmod   = kernel32.LoadLibraryExA(b"program.exe", None, 0x20)  # LOAD_LIBRARY_AS_DATAFILE
hrsrc  = kernel32.FindResourceA(hmod, ctypes.c_int(3), ctypes.c_int(10))  # RT_RCDATA=10
hglob  = kernel32.LoadResource(hmod, hrsrc)
ptr    = kernel32.LockResource(hglob)
size   = kernel32.SizeofResource(hmod, hrsrc)

data   = (ctypes.c_ubyte * size).from_address(ptr)
with open("rcdata_10_3.bin", "wb") as f:
    f.write(bytes(data))

kernel32.FreeLibrary(hmod)
print("Saved", size, "bytes to rcdata_10_3.bin")
```

### Linux/macOS (objcopy for ELF/Mach-O builds)
For ELF binaries (Linux Nuitka builds), the blob is in a section, not RCDATA:
```bash
# ELF: extract the __constants section
objcopy --dump-section .nuitka_constants=rcdata_10_3.bin program

# macOS: extract the constant/constant Mach-O section
otool -s constant constant program | xxd -r -p > rcdata_10_3.bin
```

---

## Step 2 — Build

### Linux / macOS
```bash
make
# or with CMake:
cmake -B build && cmake --build build
```

### Windows (MinGW cross-compile from Linux)
```bash
make windows
```

### Windows (MSVC, from Developer Command Prompt)
```cmd
cl /TC /O2 /Iinclude src\main.c src\blob_loader.c src\crc32.c /Fe:blob_loader.exe
```

---

## Step 3 — Run

```bash
# Auto-detect rcdata_10_3.bin in current dir or bin/
./blob_loader

# Explicit path
./blob_loader /path/to/rcdata_10_3.bin
```

### Example output
```
=======================================================
  Nuitka constants blob loader  (.bytecode section)
=======================================================

[blob] Loaded 'rcdata_10_3.bin': 48392 bytes
[blob] Header: expected CRC32=0xA3F21C88  covered_size=48384 bytes
[blob] Computed CRC32=0xA3F21C88  -> OK

[blob] === Section TOC ===
  [ 0] .bytecode                                  1024 bytes  (offset=14)
  [ 1] __main__                                   4200 bytes  (offset=1042)
  [ 2] mymodule                                   8830 bytes  (offset=5246)
  ...
[blob] ===  End TOC  ===

[blob] Found section '.bytecode': 1024 bytes at payload offset 14
[main] .bytecode section: 1024 bytes

[blob] Section contains 37 top-level constants

=== Decoded .bytecode constants (37 total) ===

[   0] str[8](filename)
[   1] str[12](__main__.py)
[   2] code <code '__main__' qualname='<module>' line=1 args=0 kw=0 ...>
[   3] int(1)
[   4] None
...
```

---

## Blob wire format (quick reference)

```
File layout:
  [uint32] CRC32 of everything after this
  [uint32] size covered by CRC32
  repeated sections:
    [cstr]   section name  (e.g. ".bytecode", "__main__", "mymodule")
    [uint32] section payload size in bytes
    [bytes]  payload

Section payload:
  [uint16] number of constants N
  N × encoded constant:
    [char]   type tag
    [...]    type-specific payload
```

See `include/blob_loader.h` for the complete tag table.

---

## API (for embedding in your own code)

```c
#include "blob_loader.h"

BlobCtx *ctx;
blob_load_file("rcdata_10_3.bin", &ctx);   // 1. read file
blob_verify(ctx);                           // 2. check CRC32
blob_dump_toc(ctx);                         // 3. print section map
blob_find_section(ctx, ".bytecode", NULL);  // 4. locate section
BlobVal *vals; uint32_t count;
blob_parse_constants(ctx, &vals, &count);  // 5. decode
for (uint32_t i = 0; i < count; i++)
    blob_print_val(&vals[i], 0);            // 6. print
blob_free_values(vals, count);
blob_free(ctx);
```
