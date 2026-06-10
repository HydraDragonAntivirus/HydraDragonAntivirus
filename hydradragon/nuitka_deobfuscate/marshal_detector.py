"""
hydradragon.nuitka_deobfuscate.marshal_detector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Library for Python version detection from marshal data and Nuitka constants-blobs.
"""

from __future__ import annotations
import struct
import sys
import re
import xdis.marsh as marshal
from xdis.magics import by_version, magic2int, magic_int2tuple
from xdis.unmarshal import load_code as xdis_load_code

# Marshal code object first-byte tags (Python 3.x)
MARSHAL_CODE_TAGS: frozenset[bytes] = frozenset({b"\xe3", b"\x63", b"\xf3"})
# Extended set: includes pyc-header-prefixed payloads (magic 4 bytes + timestamp)
MARSHAL_VERSION_HINT_TAGS: frozenset[bytes] = frozenset({b"\xe3", b"\x63", b"\xf3"})
MARSHAL_VERSION_HINT_TAG_PATTERN = re.compile(rb"[\xe3\x63\xf3]")


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
    # Strip any trailing non-digits from minor (e.g. '11a1' -> 11)
    minor_digits = "".join(c for c in minor if c.isdigit())
    return int(major), int(minor_digits) if minor_digits else 0


def _marshal_candidate_versions(version_hint: str | None) -> list[str]:
    # Robustly sort versions containing non-digits
    def sort_key(v):
        try:
            return _xdis_version_sort_key(v)
        except Exception:
            return (0, 0)

    versions = sorted(
        {
            v for v in by_version
            if re.fullmatch(r"\d+\.[a-zA-Z0-9_+]+", v)
            and sort_key(v) >= (3, 5)
        },
        key=sort_key,
        reverse=True,
    )
    return versions


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

    return True


def try_load_code_object(
    data: bytes | bytearray | memoryview,
    offset: int,
    magic_int: int | None,
):
    if not looks_like_code_header(data, offset, magic_int):
        return None
    return try_detect_code_object(data, offset, magic_int)


def guess_version_from_marshal_bytes(data: bytes) -> str | None:
    """Heuristic first-byte version hint. Returns None for \\xf3 (3.11+) so
    that the scored brute-force probe can distinguish 3.11 / 3.12 / 3.13 / 3.14 / 3.15 properly."""
    if not data or data[0:1] not in (b"\xe3", b"\x63", b"\xf3"):
        return None

    if data[0:1] == b"\xf3":
        return None

    if len(data) < 25:
        return None

    try:
        argcount = struct.unpack_from("<I", data, 1)[0]
        kwonlycount = struct.unpack_from("<I", data, 9)[0]
        stacksize = struct.unpack_from("<I", data, 17)[0]
        flags = struct.unpack_from("<I", data, 21)[0]

        if argcount > 255 or kwonlycount > 255 or stacksize > 65535:
            return "3.7"

        if flags & 0x0200:
            return "3.6"

        if flags & 0x0100 and not (flags & 0x0200):
            return "3.8"

        return "3.8+"

    except Exception:
        return None


def _extract_first_marshal_payloads_from_bytecode_chunk(
    bytecode_chunk: bytes, max_entries: int = 8
) -> list[bytes]:
    """Parse the .bytecode chunk header and return the first *max_entries*
    raw marshal payloads so we can probe the Python version against them.

    Format: [uint16 count] [('X' VLQ-size marshal_bytes) …]
    """
    if not bytecode_chunk or len(bytecode_chunk) < 4:
        return []
    pos = 2  # skip uint16 count
    payloads: list[bytes] = []
    for _ in range(max_entries):
        if pos >= len(bytecode_chunk):
            break
        if bytecode_chunk[pos] != 0x58:  # 'X'
            break
        pos += 1
        # VLQ-decode size
        marshal_size = 0
        shift = 0
        try:
            while True:
                b = bytecode_chunk[pos]
                pos += 1
                marshal_size |= (b & 0x7F) << shift
                if b < 0x80:
                    break
                shift += 7
                if shift > 63:
                    break
        except IndexError:
            break
        if marshal_size <= 0 or pos + marshal_size > len(bytecode_chunk):
            break
        payloads.append(bytecode_chunk[pos : pos + marshal_size])
        pos += marshal_size
    return payloads


def detect_version_from_marshal(data: bytes) -> str | None:
    version_hint = guess_version_from_marshal_bytes(data)

    candidates = _marshal_candidate_versions(version_hint)

    probe_offsets = [
        match.start()
        for match in MARSHAL_VERSION_HINT_TAG_PATTERN.finditer(data)
    ]

    if not probe_offsets and data[:1] in MARSHAL_VERSION_HINT_TAGS:
        probe_offsets = [0]

    if not probe_offsets:
        return version_hint  # last resort only

    scores = {}

    for ver in candidates:
        magic_int = get_magic_int(ver)
        best_score = 0

        for offset in probe_offsets[:128]:
            obj = try_detect_code_object(data, offset, magic_int)
            if obj is None:
                continue

            best_score = max(best_score, score_code_object(obj))

        if best_score > 0:
            if version_hint:
                if ver == version_hint:
                    best_score += 0.25

            scores[ver] = best_score

    if not scores:
        return version_hint

    return max(scores, key=scores.get)


def detect_version_from_bytecode_chunk(bytecode_chunk: bytes) -> str | None:
    """Detect the Python version from a Nuitka .bytecode chunk.

    Strategy:
    - Try the running Python's native marshal loader first (fast & 100% accurate if matching).
    - Extract the first few raw marshal entries (starting with 'X' + VLQ size).
    - For each entry, look at the FIRST BYTE only to determine the tag family:
        \xf3  → Python 3.11-3.15  (new-style code object)
        \xe3/\x63 → Python 3.0-3.15 (old-style code object, also used in 3.11+)
    - Pass 1: looks_like_code_header at offset 0 (lenient structural check).
    - Pass 2: full xdis parse via try_detect_code_object (strict, scored).
    - Return the highest-scoring or first structurally-matching version.
    """
    # 1. Try native marshal check first (safe, fast, and highly accurate for current runner)
    payloads = _extract_first_marshal_payloads_from_bytecode_chunk(bytecode_chunk, max_entries=1)
    if payloads:
        try:
            import marshal as builtin_marshal
            obj = builtin_marshal.loads(payloads[0])
            if type(obj).__name__ == "code":
                run_ver = f"{sys.version_info[0]}.{sys.version_info[1]}"
                if run_ver in by_version:
                    return run_ver
        except Exception:
            pass

    # 2. General probe
    _TAG_TO_VERSIONS: dict[bytes, list[str]] = {
        b"\xf3": [v for v in ("3.15", "3.14", "3.13", "3.12", "3.11")
                   if v in by_version],
        b"\xe3": [v for v in ("3.15", "3.14", "3.13", "3.12", "3.11", "3.10", "3.9", "3.8", "3.7", "3.6", "3.5")
                   if v in by_version],
        b"\x63": [v for v in ("3.15", "3.14", "3.13", "3.12", "3.11", "3.10", "3.9", "3.8", "3.7", "3.6", "3.5")
                   if v in by_version],
    }

    payloads = _extract_first_marshal_payloads_from_bytecode_chunk(bytecode_chunk)
    if not payloads:
        return None

    for payload in payloads:
        if not payload:
            continue
        tag = payload[0:1]
        candidates = _TAG_TO_VERSIONS.get(tag)
        if not candidates:
            continue

        # Pass 1: structural header check (lenient, no full parse needed).
        header_matches = []
        for ver in candidates:
            mi = get_magic_int(ver)
            if mi is None:
                continue
            if looks_like_code_header(payload, 0, mi):
                header_matches.append(ver)

        # Pass 2: full xdis parse for scoring among header matches
        # (or all candidates if no header matched, as last resort).
        probe_list = header_matches if header_matches else candidates
        scores: dict[str, int] = {}
        for ver in probe_list:
            mi = get_magic_int(ver)
            if mi is None:
                continue
            obj = try_detect_code_object(payload, 0, mi)
            if obj is not None:
                scores[ver] = score_code_object(obj)

        if scores:
            return max(scores, key=scores.get)

        # If full parse failed but structural check passed, return the
        # newest structurally-valid version (list is already newest-first).
        if header_matches:
            return header_matches[0]

    return None
