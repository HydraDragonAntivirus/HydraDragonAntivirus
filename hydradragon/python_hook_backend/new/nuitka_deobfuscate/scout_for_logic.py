"""
scout_for_logic.py
------------------
This script searches the constants blob for any sequences that look like
Python bytecode (co_code) or marshaled code objects.
"""
import sys, re
import xdis.marsh as marshal
from pathlib import Path

def scout(blob_path):
    data = Path(blob_path).read_bytes()
    print(f"[*] Scouting {blob_path} ({len(data)} bytes)...")
    
    # 1. Look for \xe3 (marshal start)
    offsets = [m.start() for m in re.finditer(b'\xe3', data)]
    print(f"[*] Found {len(offsets)} possible marshal start tags (\xe3)")
    
    success_count = 0
    for i, offset in enumerate(offsets[:500]): # Limit for research
        try:
            obj = marshal.loads(data[offset:offset+10000])
            if type(obj).__name__ == 'code' or type(obj).__name__.startswith('Code'):
                print(f"  [+] Found Code Object at {offset}: {getattr(obj, 'co_name', 'unknown')}")
                success_count += 1
                if success_count > 10: break
        except:
            pass

    # 2. Look for large byte chunks that aren't strings
    # Nuitka stores bytecode as bytes.
    # We'll look for chunks of binary data (non-ascii) that exceed 100 bytes.
    binary_chunks = [m.start() for m in re.finditer(b'[\x00-\x1f\x80-\xff]{100,}', data)]
    print(f"[*] Found {len(binary_chunks)} large non-ascii binary blocks.")

    # 3. Check for specific Nuitka tags in the C code switch
    # Tags: 'c', 'a', 'u', 'b', 'A', 'v', 'X', 'Q', 'K', 'C'
    # We want to see what 'C' (Case 250) usually points to.
    c_tags = [m.start() for m in re.finditer(b'C', data)]
    print(f"[*] Found {len(c_tags)} 'C' tags in blob.")

if __name__ == "__main__":
    scout("rcdata_10_3.bin")
