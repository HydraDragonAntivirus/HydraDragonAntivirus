"""
run_extract.py
------------------------------------------------------
- Removed raw blob scan (Pass 1); section-based extraction covers all cases.
- emit_pyc enabled by default (True); Pass 2 writes .pyc files from section items.
- Added all marshal code object tags for Python 3.x (0xe3, 0x63, 0xf3).
- Added -v/--version CLI argument (was missing in V14, causing argparse rejection).
- Version propagated to get_pyc_header() and marshal.dumps() correctly.
- Auto-detection of Python version via scored marshal brute-force probe.
- py -3.12 usage in run.bat (handled externally).
"""

from __future__ import annotations
import hashlib
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
DISCOVERED_SECTION_PATTERN = re.compile(r"^discovered_(.+?)_at_(\d+)$")
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
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid version '{ver_str}'. Expected MAJOR.MINOR e.g. 3.13") from exc


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


# Characters invalid on Windows paths + non-ASCII / control characters
_INVALID_PATH_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f-\xff]')


def sanitize_filename(filepath: str) -> str:
    """
    Convert a source-path string into a valid, relative Windows-safe path.

    - Normalises backslashes to forward slashes
    - Strips drive-letter prefix (e.g. 'C:')
    - Removes known Nuitka prefixes ('module.', 'nuitka_build/')
    - Replaces all Windows-invalid characters (control, upper-ASCII, special) with '_'
    - Collapses consecutive underscores into one
    - Strips leading/trailing '_' and '.' from each path component
    """
    # If the input is bytes (binary garbage from a blob), decode safely
    if isinstance(filepath, (bytes, bytearray)):
        filepath = filepath.decode("ascii", errors="replace")

    filepath = filepath.replace("\\", "/")
    if ":" in filepath:
        filepath = filepath.split(":", 1)[1]
    filepath = filepath.lstrip("/")
    for p in ["module.", "nuitka_build/"]:
        if filepath.startswith(p):
            filepath = filepath[len(p):]

    # Replace every invalid character with underscore
    filepath = _INVALID_PATH_CHARS_RE.sub("_", filepath)
    # Collapse runs of underscores
    filepath = re.sub(r"_+", "_", filepath)
    # Clean each path component: drop empty parts and trim edge underscores/dots
    parts = []
    for part in filepath.split("/"):
        part = part.strip("_.")
        if part:
            parts.append(part)
    return "/".join(parts) if parts else "unknown"


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


def _load_module_metadata(raw: bytes) -> list[dict]:
    try:
        from . import list_modules
    except ImportError:
        try:
            import list_modules
        except ImportError:
            return []

    parser = getattr(list_modules, "parse_module_names", None)
    if parser is None:
        return []

    try:
        return list(parser(raw))
    except Exception as exc:
        print(f"[!] Warning: list_modules.parse_module_names failed: {exc}")
        return []


def _clean_module_name(name: object, *, preserve_metadata: bool = False) -> str | None:
    """Normalize a decoded/list_modules module name without dropping real modules."""
    if not isinstance(name, str):
        return None

    name = name.strip().replace("\\", "/")
    if not name:
        return None

    # list_modules may return a source path instead of a dotted module name.
    # Keep package structure, but turn it into the same dotted form used by sections.
    if name.lower().endswith(".py"):
        name = name[:-3]
    name = name.strip("./")
    name = name.replace("/", ".")
    while ".." in name:
        name = name.replace("..", ".")
    name = name.strip(".")

    if not name:
        return None

    # Only filter synthetic decoder sections. Metadata from list_modules is source of truth
    # and must not be dropped just because the decoder failed to expose a matching section.
    if not preserve_metadata:
        if name == "bytecode":
            return None
        if "hidden_segment" in name or name.startswith("hidden_"):
            return None

    return name


def _metadata_module_name(meta: dict) -> str | None:
    """Extract the module name/path reported by list_modules, preserving it."""
    for key in ("name", "module", "module_name", "fullname", "qualified_name"):
        name = _clean_module_name(meta.get(key), preserve_metadata=True)
        if name:
            return name

    for key in ("filename", "file", "path", "source", "source_path"):
        name = _clean_module_name(meta.get(key), preserve_metadata=True)
        if name:
            return name

    return None


def _metadata_name_maps(module_metadata: list[dict] | None) -> tuple[dict[int, str], list[str]]:
    by_offset: dict[int, str] = {}
    ordered_names: list[str] = []
    seen_names: set[str] = set()

    for meta in module_metadata or []:
        if not isinstance(meta, dict):
            continue
        name = _metadata_module_name(meta)
        if not name:
            continue

        if name not in seen_names:
            ordered_names.append(name)
            seen_names.add(name)

        for key in ("section_offset", "offset", "module_offset", "blob_offset", "start", "start_offset"):
            try:
                by_offset[int(meta[key])] = name
            except Exception:
                pass

    return by_offset, ordered_names


def _lookup_metadata_name(offset: int, by_offset: dict[int, str]) -> str | None:
    if offset in by_offset:
        return by_offset[offset]

    # Decoder/list_modules offsets can differ by a few bytes depending on whether the
    # marker/header or the payload start is reported. Prefer nearby metadata names, but
    # do not let a random far-away offset rename a section.
    nearest = None
    nearest_distance = 32
    for known_offset, name in by_offset.items():
        distance = abs(known_offset - offset)
        if distance < nearest_distance:
            nearest = name
            nearest_distance = distance
    return nearest


def _section_items_tuple(items) -> tuple:
    if isinstance(items, tuple):
        return items
    if isinstance(items, list):
        return tuple(items)
    if isinstance(items, (set, frozenset)):
        return tuple(items)
    return (items,)


def _merge_section_items(existing, incoming) -> tuple:
    return _section_items_tuple(existing) + _section_items_tuple(incoming)


def _add_normalized_section(normalized: dict[str, tuple], section_name: str, items) -> None:
    """Add a section without silently losing data when names collide."""
    if section_name in normalized:
        normalized[section_name] = _merge_section_items(normalized[section_name], items)
    else:
        normalized[section_name] = _section_items_tuple(items)


def normalize_decoded_sections(sections: dict, module_metadata: list[dict] | None = None) -> dict[str, tuple]:
    """
    Rename decoded sections using list_modules metadata without filtering metadata-only
    modules out of --list-only output.

    Rules:
    1. list_modules names are authoritative when an offset/ordered mapping exists.
    2. decoded/discovered names are fallback labels only.
    3. colliding section names are merged, not dropped.
    4. every module reported by list_modules is preserved, even if no decoded constants
       section was emitted for it.
    """
    metadata_by_offset, metadata_names = _metadata_name_maps(module_metadata)
    metadata_index = 0
    claimed_metadata: set[str] = set()
    normalized: dict[str, tuple] = {}

    def claim_metadata_name(name: str | None) -> str | None:
        if not name:
            return None
        claimed_metadata.add(name)
        return name

    def next_metadata_name() -> str | None:
        nonlocal metadata_index
        while metadata_index < len(metadata_names):
            name = metadata_names[metadata_index]
            metadata_index += 1
            if name not in claimed_metadata:
                claimed_metadata.add(name)
                return name
        return None

    for section_name, items in sections.items():
        match = DISCOVERED_SECTION_PATTERN.fullmatch(section_name)
        if match:
            discovered_name = match.group(1).lstrip(".")
            section_offset = int(match.group(2))

            # Prefer the name list_modules found. This fixes corrupt decoder labels like
            # "stomtkinter" when metadata knows the real module name.
            real_name = claim_metadata_name(_lookup_metadata_name(section_offset, metadata_by_offset))
            if real_name is None:
                real_name = next_metadata_name()
            if real_name is None:
                real_name = _clean_module_name(discovered_name)

            if real_name is not None:
                _add_normalized_section(normalized, real_name, items)
            continue

        plain_name = _clean_module_name(section_name.lstrip("."))
        if plain_name is not None:
            _add_normalized_section(normalized, plain_name, items)

    # Preserve metadata-only modules. They may not have decoded constants, but --list-only
    # must still show them so list_modules output is not lost/filtered.
    for name in metadata_names:
        if name not in normalized:
            normalized[name] = ()

    return normalized


# ============================================================================
# SECTION-BASED CODE FINDER — for blobs that DO embed marshal bytes as items
# ============================================================================



def _normalize_section_items(items):
    """Return section payload as an iterable of root items without splitting bytes into ints."""
    if isinstance(items, (list, tuple)):
        return items
    if isinstance(items, (set, frozenset)):
        return tuple(items)
    return (items,)


def _safe_pyc_relpath(filepath: str) -> Path:
    """Convert a source-like path into a safe relative .pyc path."""
    cleaned = sanitize_filename(filepath).replace("\\", "/")
    if cleaned.lower().endswith(".py"):
        cleaned = cleaned[:-3] + ".pyc"
    elif not cleaned.lower().endswith(".pyc"):
        cleaned += ".pyc"

    parts = [part for part in cleaned.split("/") if part not in ("", ".", "..")]
    if not parts:
        return Path("unknown.pyc")
    return Path(*parts)


def _unique_path_for_write(dest: Path) -> Path:
    """Return dest or a numbered sibling that does not exist yet."""
    if not dest.exists():
        return dest
    stem = dest.stem
    suffix = dest.suffix
    parent = dest.parent
    for counter in range(1, 10000):
        candidate = parent / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"Could not find a free output path for {dest}")


def _write_bytes_unique(dest: Path, data: bytes) -> Path:
    """Write bytes without overwriting an existing extraction result."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    for counter in range(0, 10000):
        candidate = dest if counter == 0 else dest.parent / f"{dest.stem}_{counter}{dest.suffix}"
        try:
            with candidate.open("xb") as handle:
                handle.write(data)
            return candidate
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not find a free output path for {dest}")



def _payload_dedupe_key(value):
    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
        return ("bytes", len(payload), payload[:64], payload[-64:])
    return ("object", id(value))


def _dump_code_object(code_obj, target_ver_tuple: tuple[int, int]) -> bytes:
    """Dump a live/xdis code object while keeping compatibility across xdis versions."""
    try:
        return marshal.dumps(code_obj, python_version=target_ver_tuple)
    except TypeError:
        return marshal.dumps(code_obj)


def recursive_find_code(item, results, processed_ids, magic_int: int | None, depth=0):
    """
    Recursively search structured section items for code objects.
    Works on blobs where marshal bytes appear as list/dict/tuple items.
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
        if item[:1] in MARSHAL_VERSION_HINT_TAGS:
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
    emit_pyc: bool = True,
) -> tuple[int, int, int, list[str]]:
    clean_section = sanitize_filename(section_name).replace("/", "_").replace(".", "_").strip("_") or "section"
    # Cap at 80 characters — safe ceiling for long binary-garbage section names
    clean_section = clean_section[:80]
    root_items = _normalize_section_items(items)
    recovered_file_paths = []
    count_pyc = 0
    count_other = 0
    omni_count = 0

    # ── Per-item partition: classify before acting ────────────────────────────
    # A section can be mixed: some items are marshal bytecode blobs, others are
    # plain Nuitka constants. Checking the whole section as a unit (the old
    # is_marshaled_bytecode_section gate) caused OMNI to be skipped entirely
    # whenever any item in the section contained bytecode. We now classify each
    # item individually so that bytecode items are always dumped as .pyc and
    # constant items are always passed to OMNI — nothing is lost either way.
    bytecode_item_indices: set[int] = set()

    for i, root_item in enumerate(root_items):
        if any(True for _ in _iter_marshaled_bytecode_payloads(root_item, magic_int=magic_int)):
            bytecode_item_indices.add(i)

    omni_items = tuple(
        item for i, item in enumerate(root_items) if i not in bytecode_item_indices
    )

    # ── OMNI on pure-constant items ───────────────────────────────────────────
    # Always attempted when the framework is available. Bytecode items are
    # excluded so OMNI never receives raw marshal bytes it cannot interpret.
    if OmniDecompiler and omni_items:
        try:
            omp = OmniDecompiler()
            omp.run_pass_1_structural_mapping(omni_items)
            omp.run_pass_2_ast_synthesis()
            source = generate_omni_source(
                omp,
                section_name,
                raw_constants=list(omni_items),
                python_version=target_ver_tuple,
            )
            if source.strip():
                if generate_omni_nbc:
                    nbc_text = generate_omni_nbc(
                        omp, section_name, list(omni_items), python_version=target_ver_tuple
                    )
                    source += "\n\n" + '"""' + "\n" + nbc_text + "\n" + '"""'

                _raw_sn = section_name.encode("utf-8", errors="replace") if isinstance(section_name, str) else bytes(section_name)
                _ascii_sn = re.sub(r"[^A-Za-z0-9._-]", "_", section_name if isinstance(section_name, str) else section_name.decode("ascii", errors="replace"))
                _ascii_sn = re.sub(r"_+", "_", _ascii_sn).strip("_.")[:48]
                _hash_sn = hashlib.sha1(_raw_sn).hexdigest()[:8]
                safe_name = f"{_ascii_sn}_{_hash_sn}" if _ascii_sn else f"section_{_hash_sn}"
                omni_out = out_dir / "omni_reconstructed"
                target_py_path = _write_bytes_unique(
                    omni_out / f"{safe_name}.py", source.encode("utf-8")
                )
                recovered_file_paths.append(str(target_py_path))
                omni_count += 1
        except Exception as exc:
            print(f"[!] Warning: OMNI reconstruction failed for {section_name}: {exc}")

    # ── Per-item pyc extraction ───────────────────────────────────────────────
    # Operates on ALL root_items (both bytecode and constant). Bytecode items
    # are dumped as .pyc; constant items land in count_other as before.
    section_items_metadata = []

    for i, root_item in enumerate(root_items):
        item_id = f"{i:04d}"
        item_info = {"id": item_id, "type": type(root_item).__name__}
        seen_payloads: set = set()
        raw_payloads: list[bytes] = []
        code_objects = []

        for payload in _iter_marshaled_bytecode_payloads(root_item, magic_int=magic_int):
            key = _payload_dedupe_key(payload)
            if key in seen_payloads:
                continue
            seen_payloads.add(key)
            if isinstance(payload, (bytes, bytearray)):
                raw_payloads.append(bytes(payload))
            elif _is_live_code_object(payload):
                code_objects.append(payload)

        actions = []

        if raw_payloads:
            item_info["marshal_payload_count"] = len(raw_payloads)
            item_info["detected_code_paths"] = []
            item_info["written_pyc"] = []
            item_info["errors"] = []

            for j, payload in enumerate(raw_payloads):
                guessed_path = extract_path_from_marshaled_bytes(payload)
                if guessed_path:
                    item_info["detected_code_paths"].append(guessed_path)
                    dest = out_dir / "pyc" / _safe_pyc_relpath(guessed_path)
                else:
                    dest = out_dir / "pyc" / clean_section / f"bytecode_{item_id}_{j:02d}.pyc"

                if emit_pyc:
                    try:
                        written = _write_bytes_unique(dest, header + payload)
                        item_info["written_pyc"].append(str(written))
                        recovered_file_paths.append(str(written))
                        count_pyc += 1
                    except Exception as exc:
                        item_info["errors"].append(f"raw_payload_{j}: {exc}")
                        print(
                            f"[!] Warning: failed to write pyc for {section_name} item {item_id}: {exc}"
                        )

            actions.append("bytecode_extracted" if emit_pyc else "bytecode_detected")

        if code_objects:
            item_info["code_object_count"] = len(code_objects)
            detected_paths = [
                path
                for path in (extract_path_from_code(code_obj) for code_obj in code_objects)
                if path and "<" not in path
            ][:16]
            if detected_paths:
                item_info.setdefault("detected_code_paths", []).extend(detected_paths)
            item_info.setdefault("written_pyc", [])
            item_info.setdefault("errors", [])

            if emit_pyc:
                for j, code_obj in enumerate(code_objects):
                    try:
                        raw_bytes = _dump_code_object(code_obj, target_ver_tuple)
                        path_str = extract_path_from_code(code_obj)
                        sub_id = f"{i:04d}_{j:02d}"
                        code_label = extract_code_label(code_obj)

                        if path_str and "<" not in path_str:
                            dest = out_dir / "pyc" / _safe_pyc_relpath(path_str)
                        elif code_label:
                            dest = out_dir / "pyc" / clean_section / f"{code_label}_{sub_id}.pyc"
                        else:
                            dest = out_dir / "pyc" / clean_section / f"bytecode_{sub_id}.pyc"

                        written = _write_bytes_unique(dest, header + raw_bytes)
                        item_info["written_pyc"].append(str(written))
                        recovered_file_paths.append(str(written))
                        count_pyc += 1
                    except Exception as exc:
                        item_info["errors"].append(f"code_object_{j}: {exc}")
                        print(
                            f"[!] Warning: failed to dump code object for {section_name} "
                            f"item {item_id}: {exc}"
                        )
                actions.append("code_objects_extracted")
            else:
                actions.append("code_objects_detected")

        if not raw_payloads and not code_objects:
            if isinstance(root_item, (bytes, bytearray)):
                item_info["data_preview"] = root_item[:64].hex()
                item_info["size"] = len(root_item)
            else:
                item_info["repr"] = repr(root_item)[:200]
            count_other += 1
        else:
            item_info["action"] = "+".join(actions)
            if not item_info.get("detected_code_paths"):
                item_info.pop("detected_code_paths", None)
            if not item_info.get("written_pyc"):
                item_info.pop("written_pyc", None)
            if not item_info.get("errors"):
                item_info.pop("errors", None)

        section_items_metadata.append(item_info)

    # ── Write unified metadata ────────────────────────────────────────────────
    if section_items_metadata:
        meta_dir = out_dir / "_metadata"
        meta_file = meta_dir / f"{clean_section}_metadata.json"
        try:
            written_meta = _write_bytes_unique(
                meta_file, json.dumps(section_items_metadata, indent=2).encode("utf-8")
            )
            recovered_file_paths.append(str(written_meta))
        except Exception as exc:
            print(f"[!] Warning: failed to write metadata for {section_name}: {exc}")

    return count_pyc, count_other, omni_count, recovered_file_paths

# ============================================================================
# MAIN
# ============================================================================

from dataclasses import dataclass


@dataclass
class ExtractionResult:
    pyc_count: int
    omni_recon_count: int
    metadata_count: int
    output_dir: Path
    recovered_files: list[str]


def extract_blob(
    blob_path: Path | str,
    output_dir: Path | str,
    target_version: str | tuple[int, int] | None = None,
    list_only: bool = False,
    emit_pyc: bool = True,
) -> ExtractionResult | None:
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
        from .omni_nuitka_framework import OmniDecompiler, generate_omni_source, generate_omni_nbc
    except ImportError:
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
        return None

    module_metadata = _load_module_metadata(raw)
    if module_metadata:
        print(f"[*] list_modules resolved {len(module_metadata)} module name(s).")
    sections = normalize_decoded_sections(sections, module_metadata)

    print(f"[*] Discovered {len(sections)} sections/fragments.")

    if list_only:
        for name in sections:
            print(f"  {name}")
        return ExtractionResult(0, 0, 0, output_dir, [])

    base_out = output_dir / blob_path.stem
    out_dir = base_out
    counter = 1
    while out_dir.exists() and any(out_dir.iterdir()):
        out_dir = output_dir / f"{blob_path.stem}_{counter}"
        counter += 1

    print(f"[*] Output directory      : {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    header = get_pyc_header(target_ver_str)
    magic_int = get_magic_int(target_ver_str)

    recovered_file_paths = []

    count_pyc = 0
    count_other = 0

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
                    emit_pyc,
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
    print("\n[!] Orchestration Complete!")
    print(f"    Target version  : Python {target_ver_str}")
    print(f"    Bytecode (.pyc) : {count_pyc} modules extracted")
    print(f"    Metadata items  : {count_other}")
    if OmniDecompiler:
        print(f"    OMNI recon      : {sc} Python reconstructions")
    print(f"    Output          : {out_dir.absolute()}")

    return ExtractionResult(pyc_count=count_pyc, omni_recon_count=sc if OmniDecompiler else 0, metadata_count=count_other, output_dir=out_dir, recovered_files=recovered_file_paths)
