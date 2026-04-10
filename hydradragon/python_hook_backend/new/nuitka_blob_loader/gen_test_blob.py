#!/usr/bin/env python3
"""
gen_test_blob.py
Generates a valid rcdata_10_3.bin with:
  - .bytecode section: string filenames + 'X' marshal bytecode pairs
  - __main__ section:  normal constants + one 'X' bytecode blob
  - mypackage.utils:   another module section with 'X' blob
"""

import struct, zlib, marshal, types, sys

def varint(n):
    out = []
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | 0x80 if n else b)
        if not n: break
    return bytes(out)

def make_code_object(name, source):
    """Compile a tiny snippet and return its marshal bytes."""
    code = compile(source, f"{name}.py", "exec")
    return marshal.dumps(code)

# ---- Simple code objects ----
main_bytecode   = make_code_object("__main__",       "x = 1 + 2\nprint(x)")
utils_bytecode  = make_code_object("mypackage.utils","def add(a,b): return a+b")
helper_bytecode = make_code_object("helper",         "CONST = 42")

def make_section(constants_list):
    """Build section payload: uint16 count + encoded constants."""
    payload = bytearray()
    count = 0
    for tag, data in constants_list:
        payload += bytes([ord(tag)]) + data
        count += 1
    return struct.pack('<H', count) + bytes(payload)

# ---- .bytecode section: filename-str + X-blob pairs ----
def str_const(s):
    return ('u', s.encode() + b'\x00')

def x_blob(raw):
    return ('X', varint(len(raw)) + raw)

bytecode_constants = [
    str_const("__main__.py"),
    x_blob(main_bytecode),
    str_const("mypackage/utils.py"),
    x_blob(utils_bytecode),
    str_const("helper.py"),
    x_blob(helper_bytecode),
    # also some normal constants
    ('n', b''),                        # None
    ('l', varint(100)),               # int 100
    ('u', b'version\x00'),            # str "version"
]

bytecode_payload = make_section(bytecode_constants)

# ---- __main__ section: normal constants + its bytecode ----
main_constants = [
    ('n', b''),                         # None
    ('t', b''),                         # True
    ('l', varint(42)),                  # int 42
    ('u', b'Hello, World!\x00'),        # str
    ('X', varint(len(main_bytecode)) + main_bytecode),   # its bytecode
]
main_payload = make_section(main_constants)

# ---- mypackage.utils section ----
utils_constants = [
    ('u', b'add\x00'),
    ('l', varint(2)),
    ('X', varint(len(utils_bytecode)) + utils_bytecode),
]
utils_payload = make_section(utils_constants)

# ---- assemble TOC ----
def make_blob_section(name, payload):
    return name.encode() + b'\x00' + struct.pack('<I', len(payload)) + payload

sections  = make_blob_section('.bytecode',      bytes(bytecode_payload))
sections += make_blob_section('__main__',       bytes(main_payload))
sections += make_blob_section('mypackage.utils',bytes(utils_payload))

# ---- CRC header ----
crc  = zlib.crc32(sections) & 0xFFFFFFFF
blob = struct.pack('<I', crc) + struct.pack('<I', len(sections)) + sections

import os; os.makedirs("bin", exist_ok=True)
with open("bin/rcdata_10_3.bin", "wb") as f:
    f.write(blob)

print(f"Generated bin/rcdata_10_3.bin  ({len(blob)} bytes)")
print(f"  CRC32        : 0x{crc:08X}")
print(f"  Sections     : .bytecode + __main__ + mypackage.utils")
print(f"  Python       : {sys.version}")
