"""
run_extract.py
------------------------------------------------------
- Added raw blob scan for marshal code objects (Nuitka constants blobs do NOT
  store bytecode as structured section items — must scan raw bytes directly).
- Added all marshal code object tags for Python 3.x (0xe3, 0x63, 0xf3).
- Added -v/--version CLI argument (was missing in V14, causing argparse rejection).
- Version propagated to get_pyc_header() and marshal.dumps() correctly.
- Auto-detection of Python version via scored marshal brute-force probe.
- py -3.12 usage in run.bat (handled externally).
"""

from __future__ import annotations
import os
import sys
import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re

# ============================================================================
# SAFE MARSHAL — ONLY XDIS, NO C-MARSHAL (avoids SegFaults on 3.12 blobs)
# ============================================================================
import xdis.marsh as marshal
from xdis.magics import by_version, magic2int, magic_int2tuple
from xdis.unmarshal import FLAG_REF, TYPE_CODE, TYPE_STRING, load_code as xdis_load_code

# ============================================================================
# MARSHAL CODE OBJECT TAGS ACROSS PYTHON VERSIONS
# ============================================================================
MARSHAL_CODE_TAG_VALUES = (
    ord(TYPE_CODE),
    FLAG_REF | ord(TYPE_CODE),
)
MARSHAL_CODE_TAGS = tuple(bytes((value,)) for value in MARSHAL_CODE_TAG_VALUES)
MARSHAL_CODE_TAG_PATTERN = re.compile(
    b"[" + re.escape(bytes(MARSHAL_CODE_TAG_VALUES)) + b"]"
)


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
    except (ValueError, AttributeError) as exc:
        raise ValueError(
            f"Invalid version '{ver_str}'. Expected MAJOR.MINOR e.g. 3.13"
        ) from exc


def get_magic_int(version: str | tuple[int, int]) -> int | None:
    """Resolve a stable xdis magic integer for a MAJOR.MINOR version."""
    if isinstance(version, tuple):
        version = f"{version[0]}.{version[1]}"
    magic = by_version.get(version)
    if not magic:
        return None
    return magic2int(bytes(magic))


class MemoryReader:
    """Minimal file-like reader over a bytes buffer without slicing the suffix."""

    def __init__(self, data: bytes | bytearray | memoryview, start: int = 0):
        self._data = data if isinstance(data, memoryview) else memoryview(data)
        self._pos = start

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data) - self._pos
        end = min(len(self._data), self._pos + n)
        chunk = self._data[self._pos:end].tobytes()
        self._pos = end
        return chunk


def score_code_object(code_obj) -> int:
    score = 3
    score += len(getattr(code_obj, 'co_consts', ()))
    score += len(getattr(code_obj, 'co_varnames', ()))
    score += int(bool(getattr(code_obj, 'co_filename', None)))
    return score


def try_detect_code_object(
    data: bytes | bytearray | memoryview,
    offset: int,
    magic_int: int | None,
):
    if magic_int is None or len(data) - offset < 32:
        return None

    try:
        reader = MemoryReader(data, offset)
        obj = xdis_load_code(reader, magic_int)
    except Exception:
        return None

    name = type(obj).__name__
    if name == 'code' or name.startswith('Code'):
        return obj
    return None


def looks_like_code_header(
    data: bytes | bytearray | memoryview,
    offset: int,
    magic_int: int | None,
) -> bool:
    if magic_int is None:
        return False

    version = magic_int2tuple(magic_int)
    field_count = 1  # argcount
    if version >= (3, 8):
        field_count += 1  # posonlyargcount
    if version >= (3, 0):
        field_count += 1  # kwonlyargcount
    if version < (3, 11):
        field_count += 1  # nlocals
    field_count += 2  # stacksize, flags

    header_end = offset + 1 + (field_count * 4)
    if len(data) < header_end + 1:
        return False

    fields = struct.unpack_from("<" + ("I" * field_count), data, offset + 1)
    cursor = 0

    argcount = fields[cursor]
    cursor += 1
    if argcount > 4096:
        return False

    if version >= (3, 8):
        posonlyargcount = fields[cursor]
        cursor += 1
        if posonlyargcount > 4096:
            return False

    if version >= (3, 0):
        kwonlyargcount = fields[cursor]
        cursor += 1
        if kwonlyargcount > 4096:
            return False

    if version < (3, 11):
        nlocals = fields[cursor]
        cursor += 1
        if nlocals > 65536:
            return False

    stacksize = fields[cursor]
    flags = fields[cursor + 1]
    if stacksize == 0 or stacksize > 65536:
        return False
    if flags > 0x3FFFFFFF:
        return False

    next_tag = data[header_end]
    return next_tag in (ord(TYPE_STRING), FLAG_REF | ord(TYPE_STRING))


def try_load_code_object(
    data: bytes | bytearray | memoryview,
    offset: int,
    magic_int: int | None,
):
    if not looks_like_code_header(data, offset, magic_int):
        return None

    try:
        obj = marshal._FastUnmarshaller(memoryview(data)[offset:]).load()
    except Exception:
        return None

    name = type(obj).__name__
    if name == 'code' or name.startswith('Code'):
        return obj
    return None


def detect_version_from_marshal(data: bytes) -> str | None:
    """
    Probe stable MAJOR.MINOR xdis versions against likely code-object offsets.
    Scores successful parses by richness to avoid false positives.
    """
    candidates = sorted(
        (ver for ver in by_version if re.fullmatch(r"\d+\.\d+", ver)),
        key=parse_version,
        reverse=True,
    )
    probe_offsets = [match.start() for match in MARSHAL_CODE_TAG_PATTERN.finditer(data)]
    if not probe_offsets:
        return None

    scores = {}

    for ver in candidates:
        magic_int = get_magic_int(ver)
        best_score = 0
        for offset in probe_offsets[:128]:
            obj = try_detect_code_object(data, offset, magic_int)
            if obj is None:
                continue
            best_score = max(best_score, score_code_object(obj))
            if best_score >= 4:
                break

        if best_score > 0:
            scores[ver] = best_score

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

def raw_scan_for_code_objects(
    raw: bytes,
    python_version: str | tuple[int, int],
) -> list[tuple[int, object]]:
    """
    Single-pass scan of raw blob bytes for marshal code-object tags using xdis.

    Nuitka constants blobs do NOT store bytecode as top-level section
    items — bytecode is embedded within the raw byte stream and must
    be found by scanning directly. The section-based recursive_find_code
    approach misses these entirely.
    """
    magic_int = get_magic_int(python_version)
    if magic_int is None:
        return []

    results = []
    raw_view = memoryview(raw)
    last_accepted_offset = -8

    for match in MARSHAL_CODE_TAG_PATTERN.finditer(raw):
        offset = match.start()

        # Skip if we already found a code object very nearby
        if offset - last_accepted_offset < 8:
            continue

        obj = try_load_code_object(raw_view, offset, magic_int)
        if obj is None:
            continue

        results.append((offset, obj))
        last_accepted_offset = offset

    return results


# ============================================================================
# SECTION-BASED CODE FINDER — for blobs that DO embed marshal bytes as items
# ============================================================================

def recursive_find_code(item, results, processed_ids, magic_int: int | None, depth=0):
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
                recursive_find_code(c, results, processed_ids, magic_int, depth + 1)
        except Exception:
            pass

    elif isinstance(item, (bytes, bytearray)) and len(item) > 16:
        if item[:1] in MARSHAL_CODE_TAGS:
            obj = try_load_code_object(item, 0, magic_int)
            if obj is not None:
                recursive_find_code(obj, results, processed_ids, magic_int, depth + 1)

    elif isinstance(item, (list, tuple)):
        for x in item:
            recursive_find_code(x, results, processed_ids, magic_int, depth + 1)

    elif isinstance(item, dict):
        for v in item.values():
            recursive_find_code(v, results, processed_ids, magic_int, depth + 1)


def process_section(
    section_name: str,
    items,
    out_dir: Path,
    header: bytes,
    target_ver_tuple: tuple[int, int],
    magic_int: int | None,
    OmniDecompiler,
    generate_omni_source,
) -> tuple[int, int, int, list[str]]:
    clean_section = (
        section_name
        .replace("discovered_", "hidden_")
        .replace(".", "_")
        .strip("_")
    )
    recovered_file_paths = []
    count_pyc = 0
    count_other = 0
    omni_count = 0

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
                target_py_path = omni_out / f'{safe_name}.py'
                target_py_path.write_text(source, encoding='utf-8')
                recovered_file_paths.append(str(target_py_path))
                omni_count += 1
        except Exception:
            pass

    for i, root_item in enumerate(items):
        discovered_code = []
        recursive_find_code(root_item, discovered_code, set(), magic_int)

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
                    recovered_file_paths.append(str(dest))
                    count_pyc += 1
                except Exception:
                    pass

        meta_dir = out_dir / "_metadata" / clean_section
        meta_dir.mkdir(parents=True, exist_ok=True)
        item_id = f"{i:04d}"
        try:
            if isinstance(root_item, (bytes, bytearray)):
                is_code_tag = root_item[:1] in MARSHAL_CODE_TAGS
                if is_code_tag:
                    obj = try_load_code_object(root_item, 0, magic_int)
                    if obj is not None:
                        (meta_dir / f"item_{item_id}.pyc").write_bytes(header + root_item)
                    else:
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

    return count_pyc, count_other, omni_count, recovered_file_paths


# ============================================================================
# MAIN
# ============================================================================

from dataclasses import dataclass

@dataclass
class ExtractionResult:
    pyc_count: int
    raw_scan_hits: int
    omni_recon_count: int
    metadata_count: int
    output_dir: Path
    recovered_files: list[str]

def extract_blob(blob_path: Path | str, output_dir: Path | str, target_version: str | tuple[int, int] | None = None, list_only: bool = False) -> ExtractionResult | None:
    blob_path = Path(blob_path)
    output_dir = Path(output_dir)

    if not blob_path.is_file():
        print(f"[!] Error: blob not found: {blob_path}")
        return None

    # Load raw bytes first so we can auto-detect version from content
    raw = blob_path.read_bytes()
    print(f"[*] Loaded {len(raw)} bytes from {blob_path}")

    # Resolve target Python version
    if target_version is not None:
        if isinstance(target_version, str):
            target_ver_tuple = tuple(map(int, target_version.split(".")))
            target_ver_str = target_version
        else:
            target_ver_tuple = target_version
            target_ver_str = f"{target_ver_tuple[0]}.{target_ver_tuple[1]}"
        print(f"[*] Target Python version : {target_ver_str} (from args)")
    else:
        print("[*] No target version specified, probing blob for Python version...")
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
        return None

    print(f"[*] Running Python        : {sys.version_info.major}.{sys.version_info.minor}")

    # -------------------------------------------------------------------------
    # Load extensions
    # -------------------------------------------------------------------------
    try:
        from . import nuitka_deobfuscate
    except ImportError:
        try:
            import nuitka_deobfuscate
        except ImportError:
            print("[!] FATAL: nuitka_deobfuscate extension missing or incompatible.")
            return None

    try:
        from .omni_nuitka_framework import OmniDecompiler, generate_omni_source
    except ImportError:
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
        return None

    print(f"[*] Discovered {len(sections)} sections/fragments.")

    if list_only:
        for name in sections:
            print(f"  {name}")
        return ExtractionResult(0, 0, 0, 0, output_dir, [])

    out_dir = output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    header = get_pyc_header(target_ver_str)
    magic_int = get_magic_int(target_ver_str)
    
    recovered_file_paths = []

    count_pyc = 0
    count_other = 0

    # =========================================================================
    # PASS 1: RAW BLOB SCAN
    # Nuitka constants blobs embed bytecode in raw bytes — NOT as section items.
    # This is the primary extraction path for Nuitka binaries.
    # =========================================================================
    print("[*] Pass 1: Raw blob scan for embedded marshal code objects...")
    raw_code_objects = raw_scan_for_code_objects(raw, target_ver_str)
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
            recovered_file_paths.append(str(dest))
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
    work_items = [(section_name, items) for section_name, items in sections.items() if items]
    if work_items:
        max_workers = max(1, min(len(work_items), os.cpu_count() or 1))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(
                    process_section,
                    section_name,
                    items,
                    out_dir,
                    header,
                    target_ver_tuple,
                    magic_int,
                    OmniDecompiler,
                    generate_omni_source,
                )
                for section_name, items in work_items
            ]

            for future in futures:
                section_pyc, section_other, section_sc, section_files = future.result()
                count_pyc += section_pyc
                count_other += section_other
                sc += section_sc
                recovered_file_paths.extend(section_files)

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

    return ExtractionResult(
        pyc_count=count_pyc,
        raw_scan_hits=len(raw_code_objects),
        omni_recon_count=sc if OmniDecompiler else 0,
        metadata_count=count_other,
        output_dir=out_dir,
        recovered_files=recovered_file_paths
    )
