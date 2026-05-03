"""
run_extract_cli.py
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
import argparse
import os
import sys
import struct
import json
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
MARSHAL_CODE_TAG_PATTERN = re.compile(b"[" + re.escape(bytes(MARSHAL_CODE_TAG_VALUES)) + b"]")
MARSHAL_VERSION_HINT_TAGS = (b"\xf3",) + MARSHAL_CODE_TAGS
MARSHAL_VERSION_HINT_TAG_PATTERN = re.compile(b"[" + re.escape(b"\xf3" + bytes(MARSHAL_CODE_TAG_VALUES)) + b"]")
DISCOVERED_SECTION_PATTERN = re.compile(r"^discovered_(.+?)_at_\d+$")
MARSHAL_PYC_PATH_PATTERN = re.compile(rb"([A-Za-z0-9_./\\-]{1,260}\.py)")


def _is_live_code_object(value) -> bool:
    return type(value).__name__ == "code" or type(value).__name__.startswith("Code") or hasattr(value, "co_code") or hasattr(value, "co_code_adaptive")


def _iter_marshaled_bytecode_payloads(
    value,
    magic_int: int | None = None,
    _seen=None,
    _depth: int = 0,
):
    if _depth > 20:
        return

    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
        if len(payload) >= 16 and payload[:1] in MARSHAL_VERSION_HINT_TAGS:
            if (
                guess_version_from_marshal_bytes(payload) is not None
                or payload[:1] in MARSHAL_CODE_TAGS
                or (magic_int is not None and (looks_like_code_header(payload, 0, magic_int) or try_detect_code_object(payload, 0, magic_int) is not None))
            ):
                yield payload
        return

    if _is_live_code_object(value):
        yield value
        for child in getattr(value, "co_consts", ()) or ():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )
        return

    if isinstance(value, (str, int, float, complex, bool, type(None))):
        return

    if _seen is None:
        _seen = set()
    obj_id = id(value)
    if obj_id in _seen:
        return
    _seen.add(obj_id)

    if isinstance(value, dict):
        for child in value.keys():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )
        for child in value.values():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )
        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for child in value:
            yield from _iter_marshaled_bytecode_payloads(
                child,
                magic_int=magic_int,
                _seen=_seen,
                _depth=_depth + 1,
            )


def is_marshaled_bytecode_section_items(
    section_name: str,
    items,
    magic_int: int | None = None,
) -> bool:
    if section_name.strip(".").lower() != "bytecode":
        return False
    return any(True for _ in _iter_marshaled_bytecode_payloads(items, magic_int=magic_int))


# ============================================================================
# PYC HEADER
# ============================================================================


def get_pyc_header(version: str, timestamp: int = None, filesize: int = 0) -> bytes:
    """Generate a valid 16-byte .pyc header using xdis magic."""
    magic = by_version.get(version)
    if not magic:
        raise ValueError(f"xdis has no magic for Python {version}.\nKnown: {sorted(by_version.keys())}")
    header = bytes(magic)
    header += struct.pack("<I", 0)  # Bitfield (timestamp-based)
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
        raise argparse.ArgumentTypeError(f"Invalid version '{ver_str}'. Expected MAJOR.MINOR e.g. 3.13")


def get_magic_int(version: str | tuple[int, int]) -> int | None:
    """Resolve a stable xdis magic integer for a MAJOR.MINOR version."""
    if isinstance(version, tuple):
        version = f"{version[0]}.{version[1]}"
    magic = by_version.get(version)
    if not magic:
        return None
    return magic2int(bytes(magic))


def _xdis_version_sort_key(version: str) -> tuple[int, int]:
    major, minor = version.split(".", 1)
    return int(major), int(minor)


def guess_version_from_marshal_bytes(data: bytes) -> str | None:
    """
    Guess Python version from raw marshal code object bytes
    by reading structural fields directly, without full parsing.
    """
    if not data or data[0:1] not in (b"\xe3", b"\x63", b"\xf3"):
        return None

    if data[0:1] == b"\xf3":
        return "3.11+"

    if len(data) < 25:
        return None

    try:
        argcount = struct.unpack_from("<I", data, 1)[0]
        posonlycount = struct.unpack_from("<I", data, 5)[0]
        kwonlycount = struct.unpack_from("<I", data, 9)[0]
        nlocals = struct.unpack_from("<I", data, 13)[0]
        stacksize = struct.unpack_from("<I", data, 17)[0]
        flags = struct.unpack_from("<I", data, 21)[0]

        if argcount > 255 or kwonlycount > 255 or stacksize > 65535:
            kwonlycount2 = struct.unpack_from("<I", data, 5)[0]
            nlocals2 = struct.unpack_from("<I", data, 9)[0]
            flags2 = struct.unpack_from("<I", data, 17)[0]
            if kwonlycount2 <= 255 and nlocals2 <= 65535 and flags2 >= 0:
                return "3.7"

        if flags & 0x0200:
            lower_bound = "3.6"
        else:
            lower_bound = "3.5"

        if posonlycount <= argcount and stacksize <= 65535 and nlocals <= 65535:
            if flags & 0x0100 and not (flags & 0x0200):
                return "3.8"
            return "3.8+"

        return lower_bound
    except Exception:
        return None


def _marshal_candidate_versions(version_hint: str | None) -> list[str]:
    versions = sorted(
        {version for version in by_version if re.fullmatch(r"\d+\.\d+", version) and _xdis_version_sort_key(version) >= (3, 5)},
        key=_xdis_version_sort_key,
        reverse=True,
    )

    runtime_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    if runtime_version in versions:
        runtime_key = _xdis_version_sort_key(runtime_version)
        lower_or_equal = [version for version in versions if version != runtime_version and _xdis_version_sort_key(version) <= runtime_key]
        higher = [version for version in versions if _xdis_version_sort_key(version) > runtime_key]
        versions = [runtime_version] + lower_or_equal + higher

    if version_hint is None:
        return versions

    if version_hint.endswith("+"):
        lower_bound = _xdis_version_sort_key(version_hint[:-1])
        prioritized = [version for version in versions if _xdis_version_sort_key(version) >= lower_bound]
        fallback = [version for version in versions if _xdis_version_sort_key(version) < lower_bound]
        return prioritized + fallback

    if version_hint in versions:
        return [version_hint] + [version for version in versions if version != version_hint]

    return versions


class MemoryReader:
    """Minimal file-like reader over a bytes buffer without slicing the suffix."""

    def __init__(self, data: bytes | bytearray | memoryview, start: int = 0):
        self._data = data if isinstance(data, memoryview) else memoryview(data)
        self._pos = start

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data) - self._pos
        end = min(len(self._data), self._pos + n)
        chunk = self._data[self._pos : end].tobytes()
        self._pos = end
        return chunk


def score_code_object(code_obj) -> int:
    score = 3
    score += len(getattr(code_obj, "co_consts", ()))
    score += len(getattr(code_obj, "co_varnames", ()))
    score += int(bool(getattr(code_obj, "co_filename", None)))
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
    if name == "code" or name.startswith("Code"):
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
    return try_detect_code_object(data, offset, magic_int)


def detect_version_from_marshal(data: bytes) -> str | None:
    """
    Probe stable MAJOR.MINOR xdis versions against likely code-object offsets.
    Scores successful parses by richness to avoid false positives.
    """
    version_hint = guess_version_from_marshal_bytes(data)
    candidates = _marshal_candidate_versions(version_hint)
    probe_offsets = [match.start() for match in MARSHAL_VERSION_HINT_TAG_PATTERN.finditer(data)]
    if not probe_offsets and data[:1] in MARSHAL_VERSION_HINT_TAGS:
        probe_offsets = [0]
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
        if version_hint:
            fallback_versions = _marshal_candidate_versions(version_hint)
            if fallback_versions:
                print(f"[*] Version structural hint: {version_hint} -> {fallback_versions[0]}")
                return fallback_versions[0]
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
            filepath = filepath[len(p) :]
    return filepath


def extract_path_from_code(code_obj) -> str | None:
    try:
        if hasattr(code_obj, "co_filename"):
            return str(code_obj.co_filename)
        if hasattr(code_obj, "co_qualname"):
            return str(code_obj.co_qualname)
    except Exception:
        pass
    return None


def extract_code_label(code_obj) -> str | None:
    try:
        for attr in ("co_qualname", "co_name", "co_filename"):
            value = getattr(code_obj, attr, None)
            if not value:
                continue
            label = str(value).strip().replace("\\", "/")
            if not label:
                continue
            if attr == "co_filename" and ":" in label:
                label = label.split(":", 1)[1]
            label = label.lstrip("/")
            if label == "<module>":
                label = "module"
            if attr == "co_filename":
                label = Path(label).stem or label
            label = re.sub(r'[<>:"/\\|?*\x00]+', "_", label).strip("._ ")
            if label:
                return label[:96]
    except Exception:
        pass
    return None


def extract_path_from_marshaled_bytes(data: bytes | bytearray) -> str | None:
    try:
        candidates = []
        for match in MARSHAL_PYC_PATH_PATTERN.finditer(bytes(data)[:65536]):
            candidate = match.group(1).decode("utf-8", errors="ignore").replace("\\", "/")
            candidate = candidate.lstrip("./")
            if candidate:
                candidates.append(candidate)
        if not candidates:
            return None
        return max(candidates, key=lambda value: (value.count("/"), len(value)))
    except Exception:
        return None


def _discovered_alias_matches(discovered_name: str, plain_name: str) -> bool:
    if discovered_name == plain_name:
        return True
    if len(discovered_name) > 1 and discovered_name[1:] == plain_name:
        return True
    if len(discovered_name) > 2 and discovered_name[2:] == plain_name:
        return True
    return False


def normalize_decoded_sections(sections: dict) -> dict[str, tuple]:
    discovered_names = []
    for section_name in sections:
        match = DISCOVERED_SECTION_PATTERN.fullmatch(section_name)
        if not match:
            continue
        discovered_name = match.group(1).lstrip(".")
        if discovered_name and not discovered_name.startswith("hidden_segment"):
            discovered_names.append(discovered_name)

    normalized = {}
    for section_name, items in sections.items():
        match = DISCOVERED_SECTION_PATTERN.fullmatch(section_name)
        if match:
            discovered_name = match.group(1).lstrip(".")
            if not discovered_name or discovered_name.startswith("hidden_segment"):
                normalized[section_name.replace("discovered_", "hidden_")] = items
            else:
                normalized.setdefault(discovered_name, items)
            continue

        plain_name = section_name.lstrip(".")
        if any(_discovered_alias_matches(discovered_name, plain_name) for discovered_name in discovered_names):
            continue
        normalized[plain_name] = items

    return normalized


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

    if type(item).__name__ == "code" or type(item).__name__.startswith("Code"):
        results.append(item)
        try:
            for c in getattr(item, "co_consts", []):
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
    generate_omni_nbc,
    emit_pyc: bool = False,
) -> tuple[int, int, int]:
    clean_section = section_name.replace(".", "_").strip("_")
    is_marshaled_bytecode_section = is_marshaled_bytecode_section_items(
        section_name,
        items,
        magic_int,
    )
    count_pyc = 0
    count_other = 0
    omni_count = 0

    if OmniDecompiler and not is_marshaled_bytecode_section:
        try:
            omp = OmniDecompiler()
            omp.run_pass_1_structural_mapping(items)
            omp.run_pass_2_ast_synthesis()
            source = generate_omni_source(omp, section_name, raw_constants=list(items))
            if source.strip():
                if generate_omni_nbc:
                    nbc_text = generate_omni_nbc(omp, section_name, list(items))
                    source += "\n\n" + '"""' + "\n" + nbc_text + "\n" + '"""'

                safe_name = re.sub(r'[<>:"/\\|?*\x00]', "_", section_name)[:80]
                omni_out = out_dir / "omni_reconstructed"
                omni_out.mkdir(parents=True, exist_ok=True)
                target_py_path = omni_out / f"{safe_name}.py"
                target_py_path.write_text(source, encoding="utf-8")
                omni_count += 1
        except Exception:
            pass

    section_items_metadata = []

    for i, root_item in enumerate(items):
        item_id = f"{i:04d}"
        item_info = {"id": item_id, "type": type(root_item).__name__}

        if is_marshaled_bytecode_section and isinstance(root_item, (bytes, bytearray)) and len(root_item) > 16 and root_item[:1] in MARSHAL_VERSION_HINT_TAGS:
            guessed_path = extract_path_from_marshaled_bytes(root_item)
            guessed_label = None
            if guessed_path:
                guessed_label = Path(guessed_path).stem

            item_info["detected_code_path"] = guessed_path
            if emit_pyc:
                if guessed_path:
                    dest = out_dir / "pyc" / sanitize_filename(guessed_path).replace(".py", ".pyc")
                elif guessed_label:
                    dest = out_dir / "pyc" / clean_section / f"{guessed_label}_{item_id}.pyc"
                else:
                    dest = out_dir / "pyc" / clean_section / f"bytecode_{item_id}.pyc"

                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(header + bytes(root_item))
                    count_pyc += 1
                except Exception:
                    pass
                item_info["action"] = "bytecode_extracted"
            else:
                item_info["action"] = "bytecode_detected"
            section_items_metadata.append(item_info)
            continue

        discovered_code = []
        recursive_find_code(root_item, discovered_code, set(), magic_int)

        if discovered_code:
            item_info["code_object_count"] = len(discovered_code)
            item_info["detected_code_paths"] = [path for path in (extract_path_from_code(code_obj) for code_obj in discovered_code) if path and "<" not in path][:16]
            if emit_pyc:
                for j, code_obj in enumerate(discovered_code):
                    try:
                        raw_bytes = marshal.dumps(code_obj, python_version=target_ver_tuple)
                        path_str = extract_path_from_code(code_obj)
                        sub_id = f"{i:04d}_{j:02d}"
                        code_label = extract_code_label(code_obj)

                        if path_str and "<" not in path_str:
                            recovered_path = sanitize_filename(path_str)
                            dest = out_dir / "pyc" / recovered_path.replace(".py", ".pyc")
                        elif code_label:
                            dest = out_dir / "pyc" / clean_section / f"{code_label}_{sub_id}.pyc"
                        else:
                            dest = out_dir / "pyc" / clean_section / f"bytecode_{sub_id}.pyc"

                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(header + raw_bytes)
                        count_pyc += 1
                    except Exception:
                        pass
                item_info["action"] = "code_objects_extracted"
            else:
                item_info["action"] = "code_objects_detected"
        else:
            if isinstance(root_item, (bytes, bytearray)):
                item_info["data_preview"] = root_item[:64].hex()
                item_info["size"] = len(root_item)
            else:
                item_info["repr"] = repr(root_item)[:200]
            count_other += 1

        section_items_metadata.append(item_info)

    # WRITE UNITED METADATA
    if section_items_metadata:
        meta_dir = out_dir / "_metadata"
        meta_dir.mkdir(parents=True, exist_ok=True)
        meta_file = meta_dir / f"{clean_section}_metadata.json"
        try:
            meta_file.write_text(json.dumps(section_items_metadata, indent=2), encoding="utf-8")
        except Exception:
            pass

    return count_pyc, count_other, omni_count


# ============================================================================
# MAIN
# ============================================================================


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Unified Extract & Omni Decompiler (Python 3.12 Safe, V16)")
    parser.add_argument("blob", type=Path, help="Path to the Nuitka constants blob file")
    parser.add_argument("-o", "--output", type=Path, default=Path(r"C:\ProgramData\HydraDragonAntivirus\nuitka_deobfuscate"), help=r"Output directory (default: C:\ProgramData\HydraDragonAntivirus\nuitka_deobfuscate)")
    parser.add_argument("-v", "--version", type=parse_version, default=None, metavar="VER", help="Target CPython version e.g. 3.13 (default: auto-detect)")
    parser.add_argument("--list-only", action="store_true", help="List decoded section names only, do not write files")
    parser.add_argument("--emit-pyc", action="store_true", help="Also extract marshalled code objects as .pyc files (disabled by default)")
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
        for tag in MARSHAL_VERSION_HINT_TAGS:
            offset = raw.find(tag)
            if offset != -1:
                probe_detected = detect_version_from_marshal(raw[offset : offset + 65536])
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
        print("    Fix:   pip install --upgrade xdis")
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
        from omni_nuitka_framework import OmniDecompiler, generate_omni_source, generate_omni_nbc
    except ImportError:
        print("[!] Warning: omni_nuitka_framework.py missing. Bytecode extraction only.")
        OmniDecompiler = None
        generate_omni_source = None
        generate_omni_nbc = None

    # -------------------------------------------------------------------------
    # Decode sections
    # -------------------------------------------------------------------------
    print("[*] Starting extraction sequence...")
    try:
        sections = nuitka_deobfuscate.decode_blob(raw)
    except Exception as e:
        print(f"[!] Fatal error during C decoding: {e}")
        return 1

    sections = normalize_decoded_sections(sections)

    print(f"[*] Discovered {len(sections)} sections/fragments.")

    if args.list_only:
        for name in sections:
            print(f"  {name}")
        return 0

    base_out = args.output / args.blob.stem
    out_dir = base_out
    counter = 1
    while out_dir.exists() and any(out_dir.iterdir()):
        out_dir = args.output / f"{args.blob.stem}_{counter}"
        counter += 1

    print(f"[*] Output directory      : {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    header = get_pyc_header(target_ver_str)
    magic_int = get_magic_int(target_ver_str)

    count_pyc = 0
    count_other = 0

    # =========================================================================
    # PASS 1: RAW BLOB SCAN
    # Nuitka constants blobs embed bytecode in raw bytes — NOT as section items.
    # This is the primary extraction path for Nuitka binaries.
    # =========================================================================
    raw_code_objects = []
    if args.emit_pyc:
        if is_marshaled_bytecode_section_items(
            "bytecode",
            sections.get("bytecode") or [],
            magic_int,
        ):
            print("[*] Pass 1: Raw blob scan skipped (bytecode section already provides marshalled code).")
        else:
            print("[*] Pass 1: Raw blob scan for embedded marshal code objects...")
            raw_code_objects = raw_scan_for_code_objects(raw, target_ver_str)
            print(f"[*] Raw scan found {len(raw_code_objects)} code object(s) in blob.")
    else:
        print("[*] Pass 1: Raw blob scan skipped (emit_pyc disabled; focusing on non-.pyc recovery).")

    for offset, code_obj in raw_code_objects:
        try:
            raw_bytes = marshal.dumps(code_obj, python_version=target_ver_tuple)
            path_str = extract_path_from_code(code_obj)
            code_label = extract_code_label(code_obj)

            if path_str and "<" not in path_str:
                dest = out_dir / "pyc" / sanitize_filename(path_str).replace(".py", ".pyc")
            elif code_label:
                dest = out_dir / "pyc" / "raw_scan" / f"{code_label}_at_{offset:08x}.pyc"
            else:
                dest = out_dir / "pyc" / "raw_scan" / f"at_{offset:08x}.pyc"

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
                    generate_omni_nbc,
                    args.emit_pyc,
                )
                for section_name, items in work_items
            ]

            for future in futures:
                section_pyc, section_other, section_sc = future.result()
                count_pyc += section_pyc
                count_other += section_other
                sc += section_sc

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n[!] Orchestration Complete!")
    print(f"    Target version  : Python {target_ver_str}")
    if args.emit_pyc:
        print(f"    Raw scan hits   : {len(raw_code_objects)} code objects found in blob")
        print(f"    Bytecode (.pyc) : {count_pyc} modules extracted")
    else:
        print("    Raw scan hits   : disabled by default")
        print(f"    Bytecode (.pyc) : {count_pyc} modules extracted (default disabled)")
    print(f"    Metadata items  : {count_other}")
    if OmniDecompiler:
        print(f"    OMNI recon      : {sc} Python reconstructions")
    print(f"    Output          : {out_dir.absolute()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
