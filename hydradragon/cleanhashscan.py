import struct

hashes = []

with open('clean.hashes', 'rb') as f:
    while chunk := f.read(8):  # 8 bytes = 64-bit unsigned int
        (hash_val,) = struct.unpack('<Q', chunk)  # Little-endian unsigned long long
        hashes.append(hash_val)

for i, h in enumerate(hashes):
    print(f"Hash {i}: 0x{h:X}")
