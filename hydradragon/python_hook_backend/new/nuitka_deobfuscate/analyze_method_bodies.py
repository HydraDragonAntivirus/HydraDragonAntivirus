"""Analyze what constants appear between consecutive method refs to understand function bodies."""
import nuitka_deobfuscate
from pathlib import Path

def b2s(val):
    if isinstance(val, str): return val
    try: return val.decode('utf-8')
    except: return val.decode('latin-1', errors='replace')

def main():
    data = Path('rcdata_10_3.bin').read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    target = [k for k in sections if '10900998' in k][0]
    items = sections[target]
    
    # Find all method ref positions
    method_positions = []
    for i, item in enumerate(items):
        name = None
        if isinstance(item, str) and '.' in item and item[0:1].isupper():
            name = item
        elif isinstance(item, (bytes, bytearray)):
            s = b2s(item)
            if '.' in s and s[0:1].isupper() and s.split('.')[0].isidentifier():
                parts = s.split('.', 1)
                if parts[1].isidentifier():
                    name = s
        if name:
            method_positions.append((i, name))
    
    print(f"Total method refs: {len(method_positions)}")
    
    # Show 5 representative methods with their full constant windows
    targets = [
        'SinqleBoYApp._set_status',
        'SinqleBoYApp._http_get_text', 
        'SinqleBoYApp._build_ui',
        'SinqleBoYApp._enforce_license_async',
        'SinqleBoYApp._verified_click',
        'SinqleBoYApp.start_listener',
        'SinqleBoYApp._run_action_direct',
        'SinqleBoYApp._init_icons',
    ]
    
    for target_name in targets:
        # Find start and end position
        start_idx = None
        end_idx = None
        for pos_idx, (i, name) in enumerate(method_positions):
            if name == target_name:
                start_idx = i
                # End is the next method ref (or end of items)
                if pos_idx + 1 < len(method_positions):
                    end_idx = method_positions[pos_idx + 1][0]
                else:
                    end_idx = min(i + 100, len(items))
                break
        
        if start_idx is None:
            print(f"\n=== {target_name}: NOT FOUND ===")
            continue
        
        print(f"\n{'='*80}")
        print(f"=== {target_name} (index {start_idx} -> {end_idx}, {end_idx-start_idx} constants) ===")
        print(f"{'='*80}")
        
        for j in range(start_idx, min(end_idx, start_idx + 80)):
            item = items[j]
            if item is None:
                print(f"  [{j}] None")
            elif isinstance(item, bool):
                print(f"  [{j}] bool: {item}")
            elif isinstance(item, int):
                print(f"  [{j}] int: {item}")
            elif isinstance(item, float):
                print(f"  [{j}] float: {item}")
            elif isinstance(item, str):
                print(f"  [{j}] str: {repr(item[:100])}")
            elif isinstance(item, (bytes, bytearray)):
                s = b2s(item)
                if '\x00' in s:
                    print(f"  [{j}] PACKED: {repr(s[:120])}")
                else:
                    print(f"  [{j}] bytes: {repr(s[:100])}")
            elif isinstance(item, tuple):
                decoded = [b2s(x) if isinstance(x, (bytes, bytearray)) else repr(x) for x in item[:8]]
                print(f"  [{j}] tuple({len(item)}): [{', '.join(decoded)}{'...' if len(item)>8 else ''}]")
            elif isinstance(item, dict):
                keys = [b2s(k) if isinstance(k, (bytes, bytearray)) else repr(k) for k in list(item.keys())[:5]]
                print(f"  [{j}] dict({len(item)}): keys={keys}")
            elif isinstance(item, (set, frozenset)):
                print(f"  [{j}] {type(item).__name__}({len(item)})")
            else:
                print(f"  [{j}] {type(item).__name__}: {repr(item)[:80]}")

if __name__ == '__main__':
    main()
