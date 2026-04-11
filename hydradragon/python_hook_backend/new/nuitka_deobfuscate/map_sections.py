
import nuitka_deobfuscate
from pathlib import Path

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    
    import sys
    # We need to peek into what our decoder found
    sections = nuitka_deobfuscate.decode_blob(data)
    
    sorted_sections = []
    for k in sections:
        if 'hidden_segment_at_' in k:
            offset = int(k.split('at_')[-1])
            sorted_sections.append((offset, k))
            
    sorted_sections.sort()
    
    print(f"[*] Discovered {len(sorted_sections)} hidden segments:")
    for offset, name in sorted_sections:
        items = sections[name]
        has_code = any(type(i).__name__ == 'code' for i in items)
        print(f"  - Offset: {offset:10d} | Name: {name:40s} | Items: {len(items):5d} | Code: {has_code}")

if __name__ == "__main__":
    main()
