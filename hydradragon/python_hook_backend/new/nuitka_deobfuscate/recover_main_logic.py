
import nuitka_deobfuscate
from pathlib import Path
import marshal

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    target = None
    for k in sections:
        if '10900998' in k:
            target = k
            break
            
    if target and target in sections:
        print(f"[*] Analyzing section: {target}")
        items = sections[target]
        for i, item in enumerate(items):
            # Try to load as code object regardless of type
            potential_data = None
            if isinstance(item, (bytes, bytearray)):
                potential_data = item
            elif isinstance(item, str):
                try: 
                    # Maybe it's a hex or base64 string? 
                    # But if it's source code, we want it too
                    if len(item) > 100 and ('def ' in item or 'import ' in item):
                        print(f"  [{i}] Found Potential Source Code (size {len(item)})")
                        (Path('restore_deep') / f'source_{target}_{i}.py').write_text(item)
                except: pass
                
            if potential_data and len(potential_data) > 32:
                try:
                    obj = marshal.loads(potential_data)
                    if type(obj).__name__ == 'code':
                        print(f"  [{i}] DETECTED CODE OBJECT: {obj.co_name} ({getattr(obj, 'co_filename', 'no-file')})")
                        # Save it
                        out = Path('restore_deep')
                        out.mkdir(exist_ok=True)
                        header = b'\xcb\r\r\n' + b'\x00' * 12
                        (out / f'meta_{target}_{i}_{obj.co_name}.pyc').write_bytes(header + potential_data)
                except:
                    pass
    else:
        print("[!] Target section not found.")

if __name__ == "__main__":
    main()
