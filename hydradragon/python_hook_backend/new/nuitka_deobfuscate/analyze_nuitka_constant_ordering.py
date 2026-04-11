"""
analyze_nuitka_constant_ordering.py

Nuitka stores constants in a VERY specific order within each section.
This script analyzes the ordering to reverse-engineer the code structure.

Nuitka constant groups per module:
  - Module docstring
  - Import names  
  - Class/function names
  - For each function: arg names (tuples), local var names, string literals, defaults
  - Bytecodes of nested code objects

By analyzing the TYPE SEQUENCE of constants, we can reconstruct:
  - Function signatures (from arg name tuples)
  - Class hierarchies (from method name strings)
  - Control flow hints (from string literals like error messages)
  - API usage (from attribute access names)
"""
import nuitka_deobfuscate
from pathlib import Path
from collections import defaultdict

def classify_item(item, index):
    """Classify a constant item by its likely role in Nuitka's code."""
    if isinstance(item, str):
        if '.' in item and item[0].isupper():
            return 'METHOD_REF'  # e.g., "SinqleBoYApp._build_ui"
        if item.startswith('_') and item[1:2].islower():
            return 'PRIVATE_ATTR'  # e.g., "_banner_canvas"
        if item.startswith('__') and item.endswith('__'):
            return 'DUNDER'  # e.g., "__init__"
        if item[0:1].isupper():
            return 'CLASS_OR_CONST'  # e.g., "SinqleBoYApp", "MAXTARAMA_MS"
        if item.islower() or '_' in item:
            return 'VAR_OR_FUNC'  # e.g., "self", "delay"
        return 'STRING_LITERAL'
    elif isinstance(item, (bytes, bytearray)):
        try:
            text = item.decode('utf-8', errors='strict')
            if '\x00' in text:
                return 'NUITKA_PACKED'  # Nuitka packed names with null separators
            return 'BYTES_STRING'
        except:
            return 'RAW_BYTES'
    elif isinstance(item, tuple):
        if all(isinstance(x, str) for x in item):
            return 'NAME_TUPLE'  # Likely function arg names or import list
        return 'DATA_TUPLE'
    elif isinstance(item, dict):
        return 'DICT'
    elif isinstance(item, (int, float)):
        return 'NUMERIC'
    elif isinstance(item, bool):
        return 'BOOL'
    elif item is None:
        return 'NONE'
    elif isinstance(item, (set, frozenset)):
        return 'SET'
    elif isinstance(item, list):
        return 'LIST'
    else:
        return f'OTHER_{type(item).__name__}'

def parse_nuitka_packed(data):
    """Parse Nuitka's null-separated packed constant format.
    
    Nuitka packs related names as: tag + name\0tag + name\0...
    Tags: 'a' = argument, 'w' = keyword, 'u' = unicode string, 'D' = dict
    """
    if isinstance(data, str):
        raw = data.encode('utf-8', errors='replace')
    else:
        raw = bytes(data)
    
    segments = []
    current = b''
    for byte in raw:
        if byte == 0:
            if current:
                segments.append(current)
            current = b''
        else:
            current += bytes([byte])
    if current:
        segments.append(current)
    
    parsed = []
    for seg in segments:
        text = seg.decode('utf-8', errors='replace')
        if text.startswith('a'):
            parsed.append(('arg', text[1:]))
        elif text.startswith('w'):
            parsed.append(('kw_width', text[1:]))
        elif text.startswith('u'):
            parsed.append(('unicode', text[1:]))
        elif text.startswith('p'):
            parsed.append(('positional', text[1:]))
        elif text.startswith('T'):
            # Count prefix: T followed by number
            parsed.append(('count', text[1:]))
        elif text.startswith('D'):
            parsed.append(('dict_tag', text[1:]))
        elif text.startswith('O'):
            parsed.append(('optional', text[1:]))
        else:
            parsed.append(('raw', text))
    return parsed

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    # Focus on the SinqleBoY section
    target = None
    for k in sections:
        if '10900998' in k:
            target = k
            break
    
    if not target:
        print("[!] Target section not found")
        return
    
    items = sections[target]
    print(f"[*] Section: {target}")
    print(f"[*] Total items: {len(items)}")
    
    # Classify all items and look for patterns
    classifications = []
    for i, item in enumerate(items):
        cls = classify_item(item, i)
        classifications.append((i, cls, item))
    
    # Count classifications
    cls_counts = defaultdict(int)
    for _, cls, _ in classifications:
        cls_counts[cls] += 1
    
    print(f"\n[*] Classification distribution:")
    for cls, count in sorted(cls_counts.items(), key=lambda x: -x[1]):
        print(f"  - {cls}: {count}")
    
    # Find NUITKA_PACKED items (these contain function signatures)
    print(f"\n[*] Analyzing packed name structures (function signatures):")
    func_signatures = []
    for i, cls, item in classifications:
        if cls == 'NUITKA_PACKED':
            parsed = parse_nuitka_packed(item)
            args = [name for tag, name in parsed if tag == 'arg']
            kws = [name for tag, name in parsed if tag in ('kw_width', 'positional')]
            
            if args or kws:
                # Look backwards for the function name
                func_name = None
                for j in range(i-1, max(0, i-10), -1):
                    if classifications[j][1] == 'METHOD_REF':
                        func_name = classifications[j][2]
                        break
                    elif classifications[j][1] == 'VAR_OR_FUNC':
                        func_name = classifications[j][2]
                        break
                
                sig = {
                    'index': i,
                    'name': func_name,
                    'args': args,
                    'kws': kws,
                    'all_parsed': parsed
                }
                func_signatures.append(sig)
                
                if len(func_signatures) <= 30:
                    arg_str = ', '.join(args)
                    print(f"  [{i}] {func_name or '???'}({arg_str})")
    
    print(f"\n[*] Total function signatures found: {len(func_signatures)}")
    
    # Find NAME_TUPLE items (import lists, etc.)
    print(f"\n[*] Name tuples (imports/arg lists):")
    for i, cls, item in classifications:
        if cls == 'NAME_TUPLE' and len(item) > 1:
            print(f"  [{i}] {item[:10]}{'...' if len(item) > 10 else ''}")
    
    # Show first 200 items with their classifications for pattern analysis
    print(f"\n[*] First 200 items (type sequence):")
    for i, cls, item in classifications[:200]:
        preview = repr(item)[:80]
        print(f"  [{i:4d}] {cls:20s} | {preview}")

if __name__ == '__main__':
    main()
