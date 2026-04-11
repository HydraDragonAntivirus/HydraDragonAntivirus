"""Analyze packed items and annotation dicts in detail."""
import nuitka_deobfuscate
from pathlib import Path

def b2s(val):
    if isinstance(val, str): return val
    try: return val.decode('utf-8')
    except: return val.decode('latin-1', errors='replace')

def main():
    data = Path('rcdata_10_3.bin').read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    target = None
    for k in sections:
        if '10900998' in k: target = k; break
    
    items = sections[target]
    
    # Find ALL packed items and show what's around them
    print("=== PACKED ITEMS WITH CONTEXT ===")
    for i, item in enumerate(items):
        if isinstance(item, (bytes, bytearray)) and b'\x00' in item and len(item) > 4:
            txt = b2s(item)
            # Show context: 3 items before, the packed item, 3 items after
            print(f"\n--- Packed item at index {i} ---")
            for j in range(max(0, i-5), min(len(items), i+3)):
                val = items[j]
                marker = " >>>" if j == i else "    "
                if val is None:
                    print(f"{marker}[{j}] None")
                elif isinstance(val, (bytes, bytearray)):
                    print(f"{marker}[{j}] bytes: {b2s(val)[:100]}")
                elif isinstance(val, str):
                    print(f"{marker}[{j}] str: {val[:100]}")
                elif isinstance(val, dict):
                    keys = [b2s(k) if isinstance(k, (bytes, bytearray)) else repr(k) for k in list(val.keys())[:5]]
                    print(f"{marker}[{j}] dict({len(val)} keys): {keys}")
                elif isinstance(val, tuple):
                    decoded = [b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in val[:5]]
                    print(f"{marker}[{j}] tuple({len(val)}): {decoded}")
                elif isinstance(val, (int, float, bool)):
                    print(f"{marker}[{j}] {type(val).__name__}: {val}")
                else:
                    print(f"{marker}[{j}] {type(val).__name__}: {repr(val)[:80]}")
    
    # Now show ALL dicts and their position
    print("\n\n=== ALL DICTS WITH CONTEXT ===")
    for i, item in enumerate(items):
        if isinstance(item, dict) and len(item) <= 10:
            keys = [b2s(k) if isinstance(k, (bytes, bytearray)) else repr(k) for k in list(item.keys())]
            vals = [repr(v)[:30] for v in list(item.values())]
            
            # Show prev item
            if i > 0:
                prev = items[i-1]
                prev_str = ""
                if isinstance(prev, (bytes, bytearray)):
                    prev_str = b2s(prev)[:60]
                elif isinstance(prev, str):
                    prev_str = prev[:60]
                else:
                    prev_str = repr(prev)[:60]
                print(f"  [{i-1}] prev: {prev_str}")
            
            print(f"  [{i}] dict: keys={keys} vals={vals}")
            
            # Show next item  
            if i + 1 < len(items):
                nxt = items[i+1]
                if isinstance(nxt, (bytes, bytearray)):
                    print(f"  [{i+1}] next: {b2s(nxt)[:60]}")
                elif isinstance(nxt, str):
                    print(f"  [{i+1}] next: {nxt[:60]}")
                else:
                    print(f"  [{i+1}] next: {repr(nxt)[:60]}")
            print()

if __name__ == '__main__':
    main()
