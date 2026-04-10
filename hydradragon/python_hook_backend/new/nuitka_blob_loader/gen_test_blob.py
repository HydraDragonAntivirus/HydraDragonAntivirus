#!/usr/bin/env python3
"""
gen_test_blob.py
Generates a minimal but valid rcdata_10_3.bin that blob_loader can parse.

Blob layout:
  [uint32] crc32
  [uint32] size_of_remaining
  section ".bytecode":
    [cstr]   ".bytecode\0"
    [uint32] payload size
    payload:
      [uint16] constant count
      constants (type-tag + data)

Constants we embed:
  None         tag 'n'
  True         tag 't'
  False        tag 'F'
  int 42       tag 'l' + varint(42)
  int -7       tag 'q' + varint(7)
  float 3.14   tag 'f' + 8-byte double
  str "hello"  tag 'u' + "hello\0"
  tuple(1,2)   tag 'T' + varint(2) + 'l'varint(1) + 'l'varint(2)
  empty str    tag 's'
  bytes b"AB"  tag 'c' + "AB\0"
"""

import struct
import zlib

def varint(n):
    """Encode unsigned n as variable-length quantity."""
    out = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

# ---- build constants payload ----
constants = bytearray()

count = 0

def add(tag, data=b""):
    global constants, count
    constants += bytes([ord(tag)]) + data
    count += 1

add('n')                                  # None
add('t')                                  # True
add('F')                                  # False
add('l', varint(42))                      # int 42
add('q', varint(7))                       # int -7
add('f', struct.pack('<d', 3.14))         # float 3.14
add('u', b"hello\x00")                   # str "hello"
add('s')                                  # empty str ""
add('c', b"AB\x00")                      # bytes b"AB"

# tuple (1, 2)  -- tag 'T' + varint(2) + 'l'1 + 'l'2
tuple_data = varint(2) + b'l' + varint(1) + b'l' + varint(2)
add('T', tuple_data)

# pack count as uint16 at front
payload = struct.pack('<H', count) + bytes(constants)

# ---- build section ----
section_name = b".bytecode\x00"
section = section_name + struct.pack('<I', len(payload)) + payload

# add a second dummy section so the TOC scan is exercised
dummy_name    = b"__main__\x00"
dummy_payload = struct.pack('<H', 1) + b'n'   # 1 constant: None
section += dummy_name + struct.pack('<I', len(dummy_payload)) + dummy_payload

# ---- CRC header ----
crc   = zlib.crc32(section) & 0xFFFFFFFF
blob  = struct.pack('<I', crc) + struct.pack('<I', len(section)) + section

with open("bin/rcdata_10_3.bin", "wb") as f:
    f.write(blob)

print(f"Generated bin/rcdata_10_3.bin  ({len(blob)} bytes)")
print(f"  CRC32       : 0x{crc:08X}")
print(f"  Section size: {len(section)} bytes")
print(f"  .bytecode   : {count} constants, payload={len(payload)} bytes")
