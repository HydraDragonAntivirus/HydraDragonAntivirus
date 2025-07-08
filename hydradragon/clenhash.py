import struct
import pefile  # pip install pefile

def pe_hash(filename):
    pe = pefile.PE(filename)

    # Simplified example: hash some PE headers and section names
    data = b''

    # Add number of sections
    data += struct.pack('<I', pe.FILE_HEADER.NumberOfSections)

    # Add each section name
    for section in pe.sections:
        data += section.Name.rstrip(b'\x00')

    # Add entry point
    data += struct.pack('<I', pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    # Simple hash: SHA256 of all that, take first 8 bytes as 64-bit integer
    import hashlib
    h = hashlib.sha256(data).digest()
    hash_val = struct.unpack('<Q', h[:8])[0]

    return hash_val

def write_hash_to_file(hash_val, filename='clean.hashes'):
    with open(filename, 'wb') as f:
        f.write(struct.pack('<Q', hash_val))

def read_hashes(filename='clean.hashes'):
    hashes = []
    with open(filename, 'rb') as f:
        while chunk := f.read(8):
            (val,) = struct.unpack('<Q', chunk)
            hashes.append(val)
    return hashes

# Example usage:
hash_val = pe_hash('pd64.exe')
write_hash_to_file(hash_val)

hashes = read_hashes('clean.hashes')
for i, h in enumerate(hashes):
    print(f"Hash {i}: 0x{h:X}")
