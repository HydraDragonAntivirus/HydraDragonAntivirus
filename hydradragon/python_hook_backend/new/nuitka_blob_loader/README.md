# nuitka_blob_loader

Extract `.pyc` files from a Nuitka constants blob (`rcdata_10_3.bin`)
by linking against **Nuitka's own** `HelpersConstantsBlob.c` instead of
re-implementing its parser.

## How it works

The C source `src/blob_decode.c` is Nuitka's `HelpersConstantsBlob.c`,
vendored verbatim except for a single 5-line hook in the `case 'X':`
branch that records `(pointer, size)` pairs of every raw marshal blob
the parser encounters.

A small shim header (`src/nuitka_shim.h`) is force-included before
`blob_decode.c` is compiled. It maps every Nuitka-internal symbol
(`Py_INCREF_IMMORTAL`, `Nuitka_LongFromCLong`, `MAKE_CODE_OBJECT`,
`Nuitka_PyUnion_Type`, `DECODE`, `calcCRC32`, …) onto vanilla CPython
3.12 API calls.

The Python extension (`src/module.c`) loads the blob into memory,
points the parser's `constant_bin` global at it, calls
`loadConstantsBlob(tstate, output, ".bytecode")`, then walks the
recorded X-blob list alongside the resulting `output[]` array to
match each raw marshal payload with its module-name string.

The Python side then uses **xdis** to look up the right `.pyc` magic
header for the chosen CPython version and writes one file per module.

## Build & install

```bash
pip install -e .
```

This requires CPython **3.12** (the `MAKE_CODE_OBJECT` shim is
specialised for `PyCode_NewWithPosOnlyArgs` as of 3.12). To target a
different minor version you must:

1. set `NUITKA_BLOB_LOADER_PYVER=0x3bN` etc. before `pip install`,
2. and run under that interpreter.

## Usage

```bash
# Programmatic
python -c "
from nuitka_blob_loader import load, export_all
blobs = load('rcdata_10_3.bin')           # {module_name: marshal_bytes}
export_all(blobs, './pyc_out', version='3.12')
"

# CLI
python -m nuitka_blob_loader rcdata_10_3.bin -o ./pyc_out
nuitka-blob-loader rcdata_10_3.bin -o ./pyc_out --list-only
```

Disassemble the result:

```bash
python -m dis pyc_out/__main__.pyc
```

## Layout

```
nuitka_blob_loader/
├── setup.py
├── README.md
├── src/
│   ├── blob_decode.c     # Nuitka's HelpersConstantsBlob.c (+ 1 hook)
│   ├── nuitka_shim.h    # Replaces nuitka/prelude.h
│   ├── helpers.c        # CRC32, X-blob ring, MAKE_CODE_OBJECT impl
│   └── module.c         # PyInit__core, load(), set_sbox()
└── nuitka_blob_loader/
    ├── __init__.py      # Re-exports load/export_all
    ├── __main__.py      # CLI
    └── pyc_writer.py    # Marshal-to-.pyc with xdis magic
```
