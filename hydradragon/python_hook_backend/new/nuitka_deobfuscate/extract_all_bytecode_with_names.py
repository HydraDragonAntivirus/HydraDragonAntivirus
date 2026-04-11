"""
extract_all_bytecode_with_names.py

The brute-force scan found 759 code objects in the blob but NONE are from
SinqleBoY. This confirms that Nuitka compiles the main application to native C.

The blob's .bytecode section contains marshaled code for STDLIB modules only.
The metadata segment at 10900998 contains the CONSTANTS (strings, method names,
attribute names) used by the compiled SinqleBoY code.

Strategy for "converting metadata to actual pyc":
We can reconstruct a STUB .pyc that documents all method signatures, class
structure, and constant references by analyzing the metadata strings.
This is the closest we can get without a full native code decompiler.
"""
import marshal
import nuitka_deobfuscate
from pathlib import Path
import re
import types

def build_stub_code(class_name, methods, constants, filename):
    """Build a synthetic code object that documents the class structure."""
    # Collect all method names
    method_list = sorted(set(methods))
    const_list = sorted(set(constants))
    
    # Build a source-like string for documentation
    lines = []
    lines.append(f"# Reconstructed stub for {class_name}")
    lines.append(f"# Original file: {filename}")
    lines.append(f"# {len(method_list)} methods, {len(const_list)} constants")
    lines.append(f"")
    lines.append(f"class {class_name}:")
    
    for m in method_list:
        # Remove class prefix
        short = m.replace(f"{class_name}.", "")
        lines.append(f"    def {short}(self): ...")
    
    lines.append("")
    lines.append("# Constants:")
    for c in const_list[:100]:  # limit 
        lines.append(f"#   {c}")
    
    return "\n".join(lines)

def main():
    blob_path = Path('rcdata_10_3.bin')
    data = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(data)
    
    out_dir = Path('restore_deep_ultra')
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Find the main metadata section
    target = None
    for k in sections:
        if '10900998' in k:
            target = k
            break
    
    if not target:
        print("[!] Main metadata section not found")
        return
        
    items = sections[target]
    print(f"[*] Analyzing {len(items)} items from {target}")
    
    # Extract class methods and constants
    class_methods = {}  # class_name -> [method_names]
    all_strings = []
    all_bytes_items = []
    
    for i, item in enumerate(items):
        if isinstance(item, str):
            all_strings.append(item)
            # Parse "ClassName.method_name" patterns
            if '.' in item and not item.startswith('.'):
                parts = item.split('.', 1)
                cls = parts[0]
                method = parts[1]
                if cls not in class_methods:
                    class_methods[cls] = []
                class_methods[cls].append(method)
        elif isinstance(item, (bytes, bytearray)):
            try:
                text = item.decode('utf-8', errors='ignore')
                if text and len(text) > 3:
                    all_bytes_items.append(text)
                    # Also check for method patterns in bytes
                    if '.' in text and '\x00' in text:
                        for segment in text.split('\x00'):
                            segment = segment.lstrip('u')  # Nuitka prefix
                            if '.' in segment:
                                parts = segment.split('.', 1)
                                cls = parts[0]
                                method = parts[1]
                                if cls and method and cls[0].isupper():
                                    if cls not in class_methods:
                                        class_methods[cls] = []
                                    class_methods[cls].append(method)
            except:
                pass
    
    print(f"\n[*] Discovered {len(class_methods)} classes:")
    for cls, methods in sorted(class_methods.items(), key=lambda x: -len(x[1])):
        if len(methods) >= 3:  # Only significant classes
            print(f"  - {cls}: {len(methods)} methods")
            
            # Build stub source
            stub = build_stub_code(cls, 
                                   [f"{cls}.{m}" for m in methods],
                                   [], 
                                   f"{cls}.py")
            
            stub_path = out_dir / "reconstructed" / f"{cls}.py"
            stub_path.parent.mkdir(parents=True, exist_ok=True)
            stub_path.write_text(stub, encoding='utf-8')
    
    # Also extract ALL unique strings to a reference file
    ref_path = out_dir / "reconstructed" / "_all_strings.txt"
    ref_path.parent.mkdir(parents=True, exist_ok=True)
    ref_path.write_text("\n".join(sorted(set(all_strings))), encoding='utf-8')
    
    # Extract bytes items
    ref_path2 = out_dir / "reconstructed" / "_all_bytes_decoded.txt"
    ref_path2.write_text("\n".join(sorted(set(all_bytes_items))), encoding='utf-8')
    
    # Also process OTHER metadata sections for more class discoveries
    for section_name, items in sections.items():
        if section_name == target:
            continue
        if not items:
            continue
            
        for item in items:
            if isinstance(item, str) and '.' in item and not item.startswith('.'):
                parts = item.split('.', 1)
                cls = parts[0]
                method = parts[1]
                if cls and cls[0].isupper() and len(cls) > 2:
                    if cls not in class_methods:
                        class_methods[cls] = []
                    class_methods[cls].append(method)
    
    # Final summary
    total_methods = sum(len(v) for v in class_methods.values())
    print(f"\n[*] Total: {len(class_methods)} classes, {total_methods} methods")
    print(f"[*] Stubs saved to: {out_dir / 'reconstructed'}")
    
    # List the main application classes
    print(f"\n[*] Main application classes (>5 methods):")
    for cls, methods in sorted(class_methods.items(), key=lambda x: -len(x[1])):
        if len(methods) >= 5:
            # Skip garbage class names (docstrings, descriptions)
            if len(cls) > 40 or ' ' in cls or ':' in cls or '`' in cls:
                continue
            if not cls[0].isalpha() and cls[0] != '_':
                continue
                
            print(f"  - {cls}: {len(set(methods))} unique methods")
            stub = build_stub_code(cls, 
                                   [f"{cls}.{m}" for m in methods],
                                   [], 
                                   f"{cls}.py")
            # Sanitize filename
            safe_name = re.sub(r'[<>:"/\\|?*]', '_', cls)
            stub_path = out_dir / "reconstructed" / f"{safe_name}.py"
            stub_path.parent.mkdir(parents=True, exist_ok=True)
            stub_path.write_text(stub, encoding='utf-8')

if __name__ == '__main__':
    main()
