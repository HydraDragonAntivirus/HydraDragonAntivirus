"""
run_extract.py (V16 Unified Extract & OMNI Decompile)
------------------------------------------------------
V16 Changes:
- Added raw blob scan for marshal code objects (Nuitka constants blobs do NOT
  store bytecode as structured section items — must scan raw bytes directly).
- Added all marshal code object tags for Python 3.x (0xe3, 0x63, 0xf3).
- Added -v/--version CLI argument (was missing in V14, causing argparse rejection).
- Version propagated to get_pyc_header() and marshal.dumps() correctly.
- Auto-detection of Python version via scored marshal brute-force probe.
- py -3.12 usage in run.bat (handled externally).
"""

from __future__ import annotations
import argparse
import sys
import struct
from pathlib import Path
import re

# ============================================================================
# SAFE MARSHAL — ONLY XDIS, NO C-MARSHAL (avoids SegFaults on 3.12 blobs)
# ============================================================================
import xdis.marsh as marshal
from xdis.magics import by_version

# ============================================================================
# MARSHAL CODE OBJECT TAGS ACROSS PYTHON VERSIONS
# ============================================================================
MARSHAL_CODE_TAGS = [
    b'\xe3',   # Python 3.x  TYPE_CODE with FLAG_REF
    b'\x63',   # Python 3.x  TYPE_CODE without flag
    b'\xf3',   # Python 3.11+ TYPE_CODE with interning flag
]


# ============================================================================
# PYC HEADER
# ============================================================================

def get_pyc_header(version: str, timestamp: int = None, filesize: int = 0) -> bytes:
    """Generate a valid 16-byte .pyc header using xdis magic."""
    magic = by_version.get(version)
    if not magic:
        raise ValueError(
            f"xdis has no magic for Python {version}.\n"
            f"Known: {sorted(by_version.keys())}"
        )
    header = bytes(magic)
    header += struct.pack("<I", 0)          # Bitfield (timestamp-based)
    if timestamp is None:
        import time
        timestamp = int(time.time())
    header += struct.pack("<I", timestamp)
    header += struct.pack("<I", filesize & 0xFFFFFFFF)
    return header


# ============================================================================
# VERSION HELPERS
# ============================================================================

def parse_version(ver_str: str) -> tuple:
    try:
        parts = ver_str.split(".")
        if len(parts) != 2:
            raise ValueError
        return int(parts[0]), int(parts[1])
    except (ValueError, AttributeError):
        raise argparse.ArgumentTypeError(
            f"Invalid version '{ver_str}'. Expected MAJOR.MINOR e.g. 3.13"
        )


def detect_version_from_marshal(data: bytes) -> str | None:
    """
    Brute-force probe every xdis-known Python version.
    Scores each candidate by richness of parsed code object
    to avoid false positives from partial/corrupt matches.
    """
    candidates = sorted(by_version.keys(), reverse=True)
    scores = {}

    for ver in candidates:
        try:
            obj = marshal.loads(data)
            name = type(obj).__name__

            if name == 'code' or name.startswith('Code'):
                score = 3
                score += len(getattr(obj, 'co_consts', []))
                score += len(getattr(obj, 'co_varnames', []))
                score += int(bool(getattr(obj, 'co_filename', None)))
            elif isinstance(obj, (list, tuple, dict)):
                score = 1
            else:
                score = 0

            if score > 0:
                scores[ver] = score
        except Exception:
            continue

    if not scores:
        return None

    best = max(scores, key=lambda v: scores[v])
    top5 = sorted(scores.items(), key=lambda x: -x[1])[:5]
    print(f"[*] Version probe scores (top 5): {top5}")
    return best


# ============================================================================
# FILENAME HELPERS
# ============================================================================

def sanitize_filename(filepath: str) -> str:
    filepath = filepath.replace("\\", "/")
    if ":" in filepath:
        filepath = filepath.split(":", 1)[1]
    filepath = filepath.lstrip("/")
    for p in ["module.", "nuitka_build/"]:
        if filepath.startswith(p):
            filepath = filepath[len(p):]
    return filepath


def extract_path_from_code(code_obj) -> str | None:
    try:
        if hasattr(code_obj, 'co_filename'):
            return str(code_obj.co_filename)
        if hasattr(code_obj, 'co_qualname'):
            return str(code_obj.co_qualname)
    except Exception:
        pass
    return None


# ============================================================================
# RAW BLOB SCAN — finds bytecode embedded in Nuitka constants blobs
# ============================================================================

def raw_scan_for_code_objects(raw: bytes) -> list[tuple[int, object]]:
    """
    Brute-force scan raw blob bytes for all offsets that look like
    marshal code objects, independent of section structure.

    Nuitka constants blobs do NOT store bytecode as top-level section
    items — bytecode is embedded within the raw byte stream and must
    be found by scanning directly. The section-based recursive_find_code
    approach misses these entirely.
    """
    results = []
    processed_offsets = set()

    for tag in MARSHAL_CODE_TAGS:
        start = 0
        while True:
            offset = raw.find(tag, start)
            if offset == -1:
                break
            start = offset + 1

            # Skip if we already found a code object very nearby
            if any(abs(offset - p) < 8 for p in processed_offsets):
                continue

            chunk = raw[offset:]
            if len(chunk) < 32:
                continue

            try:
                obj = marshal.loads(chunk)
                name = type(obj).__name__
                if name == 'code' or name.startswith('Code'):
                    results.append((offset, obj))
                    processed_offsets.add(offset)
            except Exception:
                pass

    return results


# ============================================================================
# SECTION-BASED CODE FINDER — for blobs that DO embed marshal bytes as items
# ============================================================================

def recursive_find_code(item, results, processed_ids, depth=0):
    """
    Recursively search structured section items for code objects.
    Works on blobs where marshal bytes appear as list/dict/tuple items.
    Complements raw_scan_for_code_objects() which handles Nuitka blobs.
    """
    if depth > 20 or id(item) in processed_ids:
        return
    processed_ids.add(id(item))

    if type(item).__name__ == 'code' or type(item).__name__.startswith('Code'):
        results.append(item)
        try:
            for c in getattr(item, 'co_consts', []):
                recursive_find_code(c, results, processed_ids, depth + 1)
        except Exception:
            pass

    elif isinstance(item, (bytes, bytearray)) and len(item) > 16:
        for tag in MARSHAL_CODE_TAGS:
            if item.startswith(tag):
                try:
                    obj = marshal.loads(item)
                    if type(obj).__name__ == 'code' or type(obj).__name__.startswith('Code'):
                        recursive_find_code(obj, results, processed_ids, depth + 1)
                except Exception:
                    pass
                break

    elif isinstance(item, (list, tuple)):
        for x in item:
            recursive_find_code(x, results, processed_ids, depth + 1)

    elif isinstance(item, dict):
        for v in item.values():
            recursive_find_code(v, results, processed_ids, depth + 1)


# ============================================================================
# MAIN
# ============================================================================

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Unified Extract & Omni Decompiler (Python 3.12 Safe, V16)"
    )
    parser.add_argument("blob", type=Path,
                        help="Path to the Nuitka constants blob file")
    parser.add_argument("-o", "--output", type=Path, default=Path(r"C:\ProgramData\HydraDragonAntivirus\nuitka_deobfuscate"),
                        help=r"Output directory (default: C:\ProgramData\HydraDragonAntivirus\nuitka_deobfuscate)")
    parser.add_argument("-v", "--version", type=parse_version, default=None,
                        metavar="VER",
                        help="Target CPython version e.g. 3.13 (default: auto-detect)")
    parser.add_argument("--list-only", action="store_true",
                        help="List decoded section names only, do not write files")
    args = parser.parse_args(argv)

    if not args.blob.is_file():
        print(f"[!] Error: blob not found: {args.blob}")
        return 2

    # -------------------------------------------------------------------------
    # Load raw bytes first so we can auto-detect version from content
    # -------------------------------------------------------------------------
    raw = args.blob.read_bytes()
    print(f"[*] Loaded {len(raw)} bytes from {args.blob}")

    # -------------------------------------------------------------------------
    # Resolve target Python version
    # -------------------------------------------------------------------------
    if args.version is not None:
        target_ver_tuple = args.version
        target_ver_str = f"{target_ver_tuple[0]}.{target_ver_tuple[1]}"
        print(f"[*] Target Python version : {target_ver_str} (from -v flag)")
    else:
        print("[*] No -v specified, probing blob for Python version...")
        # Try to find a marshal code object in the first 64KB for version probe
        probe_detected = None
        for tag in MARSHAL_CODE_TAGS:
            offset = raw.find(tag)
            if offset != -1:
                probe_detected = detect_version_from_marshal(raw[offset:offset + 65536])
                if probe_detected:
                    break

        if probe_detected and probe_detected in by_version:
            target_ver_str = probe_detected
            target_ver_tuple = tuple(int(x) for x in probe_detected.split("."))
            print(f"[*] Auto-detected version : {target_ver_str}")
        else:
            target_ver_tuple = sys.version_info[:2]
            target_ver_str = f"{target_ver_tuple[0]}.{target_ver_tuple[1]}"
            print(f"[*] Could not detect version, falling back to running interpreter: {target_ver_str}")

    if target_ver_str not in by_version:
        print(f"[!] ERROR: xdis has no magic for Python {target_ver_str}.")
        print(f"    Known: {sorted(by_version.keys())}")
        print(f"    Fix:   pip install --upgrade xdis")
        return 1

    print(f"[*] Running Python        : {sys.version_info.major}.{sys.version_info.minor}")

    # -------------------------------------------------------------------------
    # Load extensions
    # -------------------------------------------------------------------------
    try:
        import nuitka_deobfuscate
    except ImportError:
        print("[!] FATAL: nuitka_deobfuscate extension missing or incompatible.")
        return 1

    try:
        from omni_nuitka_framework import OmniDecompiler, generate_omni_source
    except ImportError:
        print("[!] Warning: omni_nuitka_framework.py missing. Bytecode extraction only.")
        OmniDecompiler = None
        generate_omni_source = None

    # -------------------------------------------------------------------------
    # Decode sections
    # -------------------------------------------------------------------------
    print("[*] Starting extraction sequence...")
    try:
        sections = nuitka_deobfuscate.decode_blob(raw)
    except Exception as e:
        print(f"[!] Fatal error during C decoding: {e}")
        return 1

    print(f"[*] Discovered {len(sections)} sections/fragments.")

    if args.list_only:
        for name in sections:
            print(f"  {name}")
        return 0

    out_dir = args.output
    out_dir.mkdir(parents=True, exist_ok=True)
    header = get_pyc_header(target_ver_str)

    count_pyc = 0
    count_other = 0

    # =========================================================================
    # PASS 1: RAW BLOB SCAN
    # Nuitka constants blobs embed bytecode in raw bytes — NOT as section items.
    # This is the primary extraction path for Nuitka binaries.
    # =========================================================================
    print("[*] Pass 1: Raw blob scan for embedded marshal code objects...")
    raw_code_objects = raw_scan_for_code_objects(raw)
    print(f"[*] Raw scan found {len(raw_code_objects)} code object(s) in blob.")

    for offset, code_obj in raw_code_objects:
        try:
            raw_bytes = marshal.dumps(code_obj, python_version=target_ver_tuple)
            path_str = extract_path_from_code(code_obj)

            if path_str and "<" not in path_str:
                dest = out_dir / 'pyc' / sanitize_filename(path_str).replace('.py', '.pyc')
            else:
                dest = out_dir / 'pyc' / 'raw_scan' / f"at_{offset:08x}.pyc"

            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(header + raw_bytes)
            count_pyc += 1
        except Exception:
            pass

    # =========================================================================
    # PASS 2: SECTION-BASED SCAN + OMNI DECOMPILATION
    # Handles blobs that store marshal bytes as structured section items,
    # and runs the OMNI heuristic reconstruction pipeline.
    # =========================================================================
    print("[*] Pass 2: Section-based bytecode extraction & OMNI pipeline...")

    sc = 0
    for section_name, items in sections.items():
        if not items:
            continue
        clean_section = (
            section_name
            .replace("discovered_", "hidden_")
            .replace(".", "_")
            .strip("_")
        )

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
            except Exception:
                pass

        # SECTION BYTECODE PASS
        for i, root_item in enumerate(items):
            discovered_code = []
            recursive_find_code(root_item, discovered_code, set())

            if discovered_code:
                for j, code_obj in enumerate(discovered_code):
                    try:
                        raw_bytes = marshal.dumps(code_obj, python_version=target_ver_tuple)
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

            # Save raw metadata
            meta_dir = out_dir / "_metadata" / clean_section
            meta_dir.mkdir(parents=True, exist_ok=True)
            item_id = f"{i:04d}"
            try:
                if isinstance(root_item, (bytes, bytearray)):
                    is_code_tag = any(root_item.startswith(t) for t in MARSHAL_CODE_TAGS)
                    if is_code_tag:
                        try:
                            obj = marshal.loads(root_item)
                            if type(obj).__name__ == 'code' or type(obj).__name__.startswith('Code'):
                                (meta_dir / f"item_{item_id}.pyc").write_bytes(header + root_item)
                            else:
                                (meta_dir / f"item_{item_id}.pyc").write_bytes(root_item)
                        except Exception:
                            (meta_dir / f"item_{item_id}.pyc").write_bytes(root_item)
                    else:
                        (meta_dir / f"item_{item_id}.bin").write_bytes(root_item)
                else:
                    (meta_dir / f"item_{item_id}.txt").write_text(
                        repr(root_item[:200]), encoding='utf-8', errors='replace'
                    )
                count_other += 1
            except Exception:
                pass

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print(f"\n[!] Orchestration Complete!")
    print(f"    Target version  : Python {target_ver_str}")
    print(f"    Raw scan hits   : {len(raw_code_objects)} code objects found in blob")
    print(f"    Bytecode (.pyc) : {count_pyc} modules extracted")
    print(f"    Metadata items  : {count_other}")
    if OmniDecompiler:
        print(f"    OMNI recon      : {sc} Python reconstructions")
    print(f"    Output          : {out_dir.absolute()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
