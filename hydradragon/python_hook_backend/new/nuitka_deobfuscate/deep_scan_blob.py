"""
deep_scan_blob.py - Scan the raw blob for ALL marshaled code objects,
bypassing the C decoder entirely. This is a brute-force approach that
scans the entire binary for the 0xE3 marshal signature and attempts
to load each match as a Python code object.
"""
import marshal
import struct
from pathlib import Path

def main():
    blob = Path('rcdata_10_3.bin').read_bytes()
    print(f"[*] Blob size: {len(blob)} bytes")
    
    # Scan for 0xE3 (TYPE_CODE) marshal header
    found = []
    pos = 0
    attempts = 0
    
    while pos < len(blob) - 20:
        pos = blob.find(b'\xe3', pos)
        if pos == -1:
            break
        
        attempts += 1
        # Try to load from this position
        try:
            obj = marshal.loads(blob[pos:])
            if type(obj).__name__ == 'code':
                co_fn = getattr(obj, 'co_filename', '')
                co_nm = getattr(obj, 'co_name', '')
                # Estimate the size by re-marshaling
                raw = marshal.dumps(obj)
                found.append((pos, co_fn, co_nm, len(raw)))
                
                # Skip past this code object to avoid sub-matches
                pos += len(raw)
                continue
        except:
            pass
        
        pos += 1
    
    print(f"[*] Scanned {attempts} candidate positions")
    print(f"[*] Found {len(found)} valid code objects")
    
    # Show all unique co_filenames
    filenames = set()
    for offset, co_fn, co_nm, sz in found:
        filenames.add(co_fn)
    
    print(f"\n[*] Unique co_filename values ({len(filenames)}):")
    for fn in sorted(filenames):
        count = sum(1 for _, f, _, _ in found if f == fn)
        print(f"  - {fn} ({count} code objects)")
    
    # Show the top 30 largest
    print(f"\n[*] Top 30 largest code objects:")
    for offset, co_fn, co_nm, sz in sorted(found, key=lambda x: -x[3])[:30]:
        print(f"  - offset={offset:>10} size={sz:>8} co_filename={co_fn} co_name={co_nm}")
    
    # Find anything related to SinqleBoY or main app
    print(f"\n[*] Application code (non-stdlib):")
    for offset, co_fn, co_nm, sz in sorted(found, key=lambda x: -x[3]):
        lower = co_fn.lower()
        if any(x in lower for x in ['site-packages', 'lib\\python', 'lib/python', '<']):
            continue
        # Show anything that's NOT stdlib
        if co_fn and ('\\' in co_fn or '/' in co_fn):
            parts = co_fn.replace('\\', '/').split('/')
            # Skip if it looks like python stdlib or numpy etc
            if any(x in co_fn.lower() for x in ['python3', 'cpython', 'encodings', 'numpy', 'scipy', 'pycparser']):
                continue
            print(f"  - offset={offset:>10} size={sz:>8} co_filename={co_fn} co_name={co_nm}")

if __name__ == '__main__':
    main()
