
import nuitka_deobfuscate
from pathlib import Path
import marshal

def main():
    blob_path = Path('rcdata_10_3.bin')
    if not blob_path.exists():
        print("Blob not found.")
        return

    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    type_counts = {}
    code_examples = []
    
    for section_name, items in sections.items():
        if not isinstance(items, (list, tuple)): continue
        for item in items:
            t_name = type(item).__name__
            type_counts[t_name] = type_counts.get(t_name, 0) + 1
            if t_name == 'code' and len(code_examples) < 10:
                code_examples.append((section_name, item))
                
    print(f"[*] Found {len(sections)} sections.")
    print("[*] Type distribution:")
    for t, count in type_counts.items():
        print(f"  - {t}: {count}")
        
    if code_examples:
        print("\n[*] Sample code objects found in metadata:")
        for sec, co in code_examples:
            print(f"  - [{sec}] {co.co_name} ({getattr(co, 'co_filename', 'no-file')})")
    else:
        print("\n[!] No code objects found in constants (only bytes/strings/etc).")

if __name__ == "__main__":
    main()
