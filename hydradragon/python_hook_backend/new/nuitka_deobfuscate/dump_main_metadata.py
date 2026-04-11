
import nuitka_deobfuscate
from pathlib import Path

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    target = 'discovered_hidden_segment_at_10900998'
    if target not in sections:
        # Try finding it by substring
        for k in sections:
            if '10900998' in k:
                target = k
                break
    
    if target in sections:
        print(f"[*] Dumping strings from {target}...")
        items = sections[target]
        for i, item in enumerate(items):
            if isinstance(item, str):
                if len(item) > 10:
                    print(f"  [{i}] String: {item[:200]}")
            elif isinstance(item, (bytes, bytearray)):
                if len(item) > 10:
                    print(f"  [{i}] Bytes (size {len(item)}): {item[:100].hex(' ')}")
    else:
        print(f"[!] Target section not found.")

if __name__ == "__main__":
    main()
