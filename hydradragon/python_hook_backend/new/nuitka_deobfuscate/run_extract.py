"""
run_extract.py -- Extract .pyc files from a Nuitka constants blob using
                  nuitka_deobfuscate (Triple Scan) + xdis/marshal validation.
"""
from __future__ import annotations

import argparse
import io
import sys
import os
import struct
import marshal
import importlib.util
from pathlib import Path

import nuitka_deobfuscate
from xdis.magics import by_version, int2magic

# Optional: if xdis is not available, we can fallback to marshal
try:
    from xdis.unmarshal import VersionIndependentUnmarshaller
except ImportError:
    VersionIndependentUnmarshaller = None


def magic_int_for(version: str) -> int:
    magic = by_version.get(version)
    if magic is None:
        # Fallback to current python version magic
        return struct.unpack("<I", importlib.util.MAGIC_NUMBER)[0]
    return int.from_bytes(bytes(magic[:2]), "little")


def pyc_header(magic_int: int) -> bytes:
    magic = int2magic(magic_int)
    # CPython 3.7+ pyc header: magic (4), flags(4), mtime(4), size(4)
    return magic + b"\x00" * 12


def sanitize_filename(filepath: str) -> str:
    """Removes platform-specific absolute paths and illegal characters."""
    # Handle Windows/Linux absolute paths
    filepath = filepath.replace("\\", "/")
    if ":" in filepath: # C:/...
        filepath = filepath.split(":", 1)[1]
    
    # Remove leading slashes
    filepath = filepath.lstrip("/")
    
    # Remove common Nuitka build prefixes
    prefixes = ["module.", "nuitka_build/"]
    for p in prefixes:
        if filepath.startswith(p):
            filepath = filepath[len(p):]
            
    return filepath


def extract_path_from_code(code_obj) -> str | None:
    """Extract co_filename from a code object."""
    try:
        # For CPython 3.x
        if hasattr(code_obj, 'co_filename'):
            return code_obj.co_filename
    except:
        pass
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract .pyc files via Nuitka Triple Scan."
    )
    parser.add_argument("blob", type=Path, help="Path to the Nuitka constants blob file")
    parser.add_argument("-o", "--output", type=Path, default=Path("./restore_final"),
                        help="Output directory (default: ./restore_final)")
    parser.add_argument("-v", "--version", default="3.12",
                        help="Target Python version (default: 3.12)")
    args = parser.parse_args(argv)

    if not args.blob.is_file():
        print(f"error: blob not found: {args.blob}")
        return 2

    raw = args.blob.read_bytes()
    print(f"[*] Loaded {len(raw)} bytes from {args.blob}")

    print("[*] Starting Triple Scan decoding (Linear + Signature + Fingerprint)...")
    try:
        sections = nuitka_deobfuscate.decode_blob(raw)
    except Exception as e:
        print(f"Fatal error during C decoding: {e}")
        return 1

    print(f"[*] Discovered {len(sections)} sections/fragments.")

    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)
    
    magic_int = magic_int_for(args.version)
    header = pyc_header(magic_int)

    count_pyc = 0
    count_other = 0

    def recursive_find_code(item, results, processed_ids):
        if id(item) in processed_ids: return
        processed_ids.add(id(item))
        
        # 1. Native code object
        if type(item).__name__ == 'code':
            results.append(item)
            # Check constants of the code object for nested functions
            for c in getattr(item, 'co_consts', []):
                recursive_find_code(c, results, processed_ids)
                
        # 2. Marshaled bytes
        elif isinstance(item, (bytes, bytearray)) and len(item) > 16:
            if item.startswith(b'\xe3'):
                try:
                    obj = marshal.loads(item)
                    recursive_find_code(obj, results, processed_ids)
                except: pass
                
        # 3. Containers
        elif isinstance(item, (list, tuple)):
            for x in item:
                recursive_find_code(x, results, processed_ids)
        elif isinstance(item, dict):
            for v in item.values():
                recursive_find_code(v, results, processed_ids)

    for section_name, items in sections.items():
        if not items: continue
        
        # Clean up section name
        clean_section = section_name.replace("discovered_", "hidden_").replace(".", "_").strip("_")
        
        for i, root_item in enumerate(items):
            discovered_code = []
            recursive_find_code(root_item, discovered_code, set())
            
            if discovered_code:
                for j, code_obj in enumerate(discovered_code):
                    try:
                        raw_bytes = marshal.dumps(code_obj)
                        path_str = extract_path_from_code(code_obj)
                        
                        item_id = f"{i:04d}_{j:02d}"
                        if path_str and "<" not in path_str:
                             recovered_path = sanitize_filename(path_str)
                             dest = out_dir / recovered_path.replace('.py', '.pyc')
                        else:
                             dest = out_dir / clean_section / f"bytecode_{item_id}.pyc"
                        
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(header + raw_bytes)
                        count_pyc += 1
                    except:
                        pass
            
            # Save original item as metadata
            meta_dir = out_dir / "_metadata" / clean_section
            meta_dir.mkdir(parents=True, exist_ok=True)
            item_id = f"{i:04d}"
            try:
                if isinstance(root_item, (bytes, bytearray)):
                    (meta_dir / f"item_{item_id}.bin").write_bytes(root_item)
                else:
                    (meta_dir / f"item_{item_id}.txt").write_text(repr(root_item), encoding='utf-8', errors='replace')
                count_other += 1
            except:
                pass


    print(f"\n[!] Success!")
    print(f"    - Extracted {count_pyc} bytecode modules (restored hierarchy where possible).")
    print(f"    - Extracted {count_other} metadata/constant items.")
    print(f"    - Results saved to: {out_dir.absolute()}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
