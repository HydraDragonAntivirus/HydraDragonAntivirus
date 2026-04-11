
import nuitka_deobfuscate
from pathlib import Path
import marshal
import base64

def main():
    blob_path = Path('rcdata_10_3.bin')
    if not blob_path.exists():
        print("Blob not found.")
        return

    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    large_items = []
    
    for section_name, items in sections.items():
        if not isinstance(items, (list, tuple)): continue
        for i, item in enumerate(items):
            if isinstance(item, (bytes, bytearray)):
                if len(item) > 2000:
                    large_items.append((section_name, i, item))
            elif isinstance(item, str):
                if len(item) > 2000:
                    # Strings are already decoded by C extension
                    large_items.append((section_name, i, item.encode('utf-8')))
                    
    large_items.sort(key=lambda x: len(x[2]), reverse=True)
    
    print(f"[*] Found {len(large_items)} items > 2KB.")
    for sec, idx, val in large_items[:20]:
        print(f"  - [{sec}][{idx}] size={len(val)} bytes")
        # Try to see if it starts with marshal or something
        snippet = val[:32]
        print(f"    Hex: {snippet.hex(' ')}")
        try:
             # Try base64
             dec = base64.b64decode(val[:100], validate=True)
             print(f"    Base64 start: {dec[:16].hex(' ')}")
        except:
             pass

if __name__ == "__main__":
    main()
