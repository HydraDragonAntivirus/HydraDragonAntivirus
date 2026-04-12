"""
run_extract.py (V14 Unified Extract & OMNI Decompile)
------------------------------------------------------
This is the master orchestrator. It extracts bytecode safely without
crashing on Python 3.12, and automatically runs the Omni Framework
to synthesize heuristic pure Python and C-API fallback representations.

Fixed: Per User instruction "only xdis no marshaol", removed standard marshal
which causes SegFaults natively on Python 3.12 with Nuitka modified blobs.
Replaced strictly with xdis.marsh for safe Python-space cross-version reading.
"""

from __future__ import annotations
import argparse
import sys
import struct
import importlib.util
from pathlib import Path
import re, json

# ============================================================================
# SAFE MARSHAL IMPORTS FOR PYTHON 3.12 (USER DIRECTIVE: ONLY XDIS)
# ============================================================================
import xdis.marsh as marshal

# ============================================================================
# PYC HEADER RESOLUTION
# ============================================================================
from xdis.magics import by_version

def get_pyc_header(version: str, timestamp: int = None, filesize: int = 0) -> bytes:
    """Generate a valid 16-byte .pyc header for Python 3.11+ using xdis."""
    magic = by_version.get(version)
    if not magic:
        # Fallback to current interpreter magic
        import importlib.util
        magic = importlib.util.MAGIC_NUMBER
    
    # 4 bytes Magic
    # 4 bytes Bitfield (0)
    # 4 bytes Timestamp
    # 4 bytes File Size
    header = bytes(magic)
    header += struct.pack("<I", 0) # Bitfield
    
    if timestamp is None:
        import time
        timestamp = int(time.time())
    header += struct.pack("<I", timestamp)
    header += struct.pack("<I", filesize & 0xFFFFFFFF)
    
    return header

def sanitize_filename(filepath: str) -> str:
    filepath = filepath.replace("\\", "/")
    if ":" in filepath: filepath = filepath.split(":", 1)[1]
    filepath = filepath.lstrip("/")
    prefixes = ["module.", "nuitka_build/"]
    for p in prefixes:
        if filepath.startswith(p): filepath = filepath[len(p):]
    return filepath

def extract_path_from_code(code_obj) -> str | None:
    try:
        if hasattr(code_obj, 'co_filename'): return str(code_obj.co_filename)
        if hasattr(code_obj, 'co_qualname'): return str(code_obj.co_qualname)
    except: pass
    return None

# OMNI SYSTEM IMPORTED FROM EXTERNAL MODULE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unified Extract & Omni Decompiler (Python 3.12 Safe)")
    parser.add_argument("blob", type=Path, help="Path to the Nuitka constants blob file")
    parser.add_argument("-o", "--output", type=Path, default=Path("./build/bytecode"), help="Output directory")
    args = parser.parse_args(argv)

    if not args.blob.is_file():
        print(f"error: blob not found: {args.blob}")
        return 2

    # Load Nuitka Deobfuscator
    try:
        import nuitka_deobfuscate
    except ImportError:
        print("[!] FATAL: 'nuitka_deobfuscate' extension missing or architecturally incompatible.")
        return 1
        
    try:
        from omni_nuitka_framework import OmniDecompiler, generate_omni_source
    except ImportError:
        print("[!] Warning: omni_nuitka_framework.py missing. Will only run bytecode extraction.")
        OmniDecompiler = None
        generate_omni_source = None

    raw = args.blob.read_bytes()
    print(f"[*] Loaded {len(raw)} bytes from {args.blob}")

    print("[*] Starting extraction sequence...")
    try:
        sections = nuitka_deobfuscate.decode_blob(raw)
    except Exception as e:
        print(f"Fatal error during C decoding: {e}")
        return 1

    print(f"[*] Discovered {len(sections)} sections/fragments.")

    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)
    
    magic_version = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    header = get_pyc_header(magic_version)

    count_pyc = 0
    count_other = 0

    def recursive_find_code(item, results, processed_ids, depth=0):
        if depth > 20: return  # Hard limit to prevent 3.12 C-stack overflows
        if id(item) in processed_ids: return
        processed_ids.add(id(item))
        
        # 1. Native code object
        if type(item).__name__ == 'code' or type(item).__name__.startswith('Code'):
            results.append(item)
            try:
                for c in getattr(item, 'co_consts', []):
                    recursive_find_code(c, results, processed_ids, depth+1)
            except: pass
                
        # 2. Marshaled bytes via xdis safely
        elif isinstance(item, (bytes, bytearray)) and len(item) > 16:
            if item.startswith(b'\xe3'):
                try:
                    # STRICTLY USING XDIS NO C-MARSHAL
                    obj = marshal.loads(item)
                    if type(obj).__name__ == 'code' or type(obj).__name__.startswith('Code'):
                        recursive_find_code(obj, results, processed_ids, depth+1)
                except: pass
                
        # 3. Containers
        elif isinstance(item, (list, tuple)):
            for x in item:
                recursive_find_code(x, results, processed_ids, depth+1)
        elif isinstance(item, dict):
            for v in item.values():
                recursive_find_code(v, results, processed_ids, depth+1)

    print("[*] Extracting Bytecode & Executing OMNI Decompilation pipeline...")
    
    sc = 0
    for section_name, items in sections.items():
        if not items: continue
        clean_section = section_name.replace("discovered_", "hidden_").replace(".", "_").strip("_")
        
        # OMNI DECOMPILATION PASS
        if OmniDecompiler:
            try:
                omp = OmniDecompiler()
                omp.run_pass_1_structural_mapping(items)
                omp.run_pass_2_ast_synthesis()
                source = generate_omni_source(omp, section_name)
                
                if 'class ' in source and 'def ' in source:
                    safe_name = re.sub(r'[<>:"/\\|?*\x00]', '_', section_name)[:80]
                    omni_out = out_dir / 'omni_reconstructed' 
                    omni_out.mkdir(parents=True, exist_ok=True)
                    (omni_out / f'{safe_name}.py').write_text(source, encoding='utf-8')
                    sc += 1
            except Exception as e:
                pass
        
        # BYTECODE EXTRACTION PASS
        for i, root_item in enumerate(items):
            discovered_code = []
            recursive_find_code(root_item, discovered_code, set())
            
            if discovered_code:
                for j, code_obj in enumerate(discovered_code):
                    try:
                        # Serialize safely back into raw bytes using xdis logic
                        # Providing cross-version compatibility without crashing the interpreter
                        raw_bytes = marshal.dumps(code_obj, python_version=sys.version_info[:2])
                        
                        path_str = extract_path_from_code(code_obj)
                        item_id = f"{i:04d}_{j:02d}"
                        
                        if path_str and "<" not in path_str:
                             recovered_path = sanitize_filename(path_str)
                             dest = out_dir / 'pyc' / recovered_path.replace('.py', '.pyc')
                        else:
                             dest = out_dir / 'pyc' / clean_section / f"bytecode_{item_id}.pyc"
                        
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(header + raw_bytes)
                        count_pyc += 1
                    except Exception:
                        pass
            
            # Save original metadata safely
            meta_dir = out_dir / "_metadata" / clean_section
            meta_dir.mkdir(parents=True, exist_ok=True)
            item_id = f"{i:04d}"
            try:
                if isinstance(root_item, (bytes, bytearray)):
                    # Check if it looks like a marshal blob (bytecode)
                    # If it starts with \xe3 (marshal tag), save as .pyc with valid header via xdis logic
                    if root_item.startswith(b'\xe3'):
                        try:
                            # Verify it's actually code via xdis
                            obj = marshal.loads(root_item)
                            if type(obj).__name__ == 'code' or type(obj).__name__.startswith('Code'):
                                (meta_dir / f"item_{item_id}.pyc").write_bytes(header + root_item)
                            else:
                                (meta_dir / f"item_{item_id}.pyc").write_bytes(root_item)
                        except:
                            (meta_dir / f"item_{item_id}.pyc").write_bytes(root_item)
                    else:
                        (meta_dir / f"item_{item_id}.pyc").write_bytes(root_item)
                else:
                    (meta_dir / f"item_{item_id}.txt").write_text(repr(root_item[:200]), encoding='utf-8', errors='replace')
                count_other += 1
            except:
                pass

    print(f"\n[!] Orchestration Success!")
    print(f"    - Extracted {count_pyc} bytecode modules (.pyc).")
    print(f"    - Extracted {count_other} metadata/constant items.")
    if OmniDecompiler: print(f"    - Generated {sc} Omni Python reconstructions.")
    print(f"    - Results saved to: {out_dir.absolute()}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
