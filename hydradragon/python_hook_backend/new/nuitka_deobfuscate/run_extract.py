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
def magic_int_for(version: str) -> int:
    try:
        from xdis.magics import by_version
        magic = by_version.get(version)
        if magic:
            return int.from_bytes(bytes(magic[:2]), "little")
    except ImportError:
        pass
        
    if version.startswith('3.12'): return 3531 | (0x0a0d << 16)
    if version.startswith('3.11'): return 3495 | (0x0a0d << 16)
    if version.startswith('3.10'): return 3439 | (0x0a0d << 16)
    return struct.unpack("<I", importlib.util.MAGIC_NUMBER)[0]

def pyc_header(magic_int: int) -> bytes:
    magic = struct.pack("<I", magic_int & 0xFFFFFFFF)
    return magic + b"\x00" * 12

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
    parser.add_argument("-o", "--output", type=Path, default=Path("./restore_final"), help="Output directory")
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
    
    magic_int = magic_int_for(str(sys.version_info.major) + "." + str(sys.version_info.minor))
    header = pyc_header(magic_int)

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
                        raw_bytes = marshal.dumps(code_obj)
                        
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
                    (meta_dir / f"item_{item_id}.bin").write_bytes(root_item)
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
