"""
hydradragon.nuitka_deobfuscate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Library API for Nuitka constants-blob extraction and version detection.

Typical usage (from antivirus.py)
----------------------------------
    from hydradragon.nuitka_deobfuscate import extract_blob, detect_nuitka_version

    result = extract_blob(blob_path="path/to/RCData.bin", output_dir="path/to/out")
    if result:
        print(result.python_version, result.recovered_files)

    ver = detect_nuitka_version("path/to/RCData.bin")   # -> "3.13" or None
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Core extraction pipeline
# ---------------------------------------------------------------------------
from .run_extract import (
    # Main entry-point used by antivirus.py
    extract_blob,

    # Version detection helpers
    detect_version_from_marshal,
    detect_version_from_bytecode_chunk,
    guess_version_from_marshal_bytes,
    _extract_first_marshal_payloads_from_bytecode_chunk,

    # CommercialBypass subsystem
    CommercialBypass,

    # Low-level utilities re-exported for convenience
    get_magic_int,
    looks_like_code_header,
    try_detect_code_object,
    score_code_object,

    # Constants
    MARSHAL_VERSION_HINT_TAGS,
    MARSHAL_CODE_TAGS,
)

# ---------------------------------------------------------------------------
# Convenience façade
# ---------------------------------------------------------------------------

def detect_nuitka_version(blob_path: str) -> str | None:
    """Return the Python version string embedded in a Nuitka constants blob.

    Uses the Strategy-0 (.bytecode chunk) probe first, then falls back to the
    raw-blob marshal scan.  Returns a string like ``"3.13"`` on success, or
    ``None`` if detection fails.

    Parameters
    ----------
    blob_path:
        Path to the raw RCDATA / constants-blob file extracted from the PE.
    """
    import struct
    from pathlib import Path
    from xdis.magics import by_version

    try:
        raw = Path(blob_path).read_bytes()
    except OSError:
        return None

    # --- Strategy 0: .bytecode chunk probe (commercial-bypass-aware) ------
    try:
        cb = CommercialBypass()
        is_commercial = cb.is_blob_encrypted(raw) or cb.has_commercial_digest(raw)

        def _find_bytecode_chunk(blob_data: bytes) -> bytes | None:
            if len(blob_data) < 8:
                return None
            size_stored = struct.unpack("<I", blob_data[4:8])[0]
            data = blob_data[8 : 8 + min(size_stored, len(blob_data) - 8)]
            offset = 0
            while offset < len(data) - 5:
                nul = data.find(b"\x00", offset, min(offset + 4096, len(data)))
                if nul == -1:
                    break
                raw_name = data[offset:nul]
                try:
                    plain = raw_name.decode("utf-8", errors="strict")
                    from .run_extract import _is_plausible_module_name
                    name = plain if _is_plausible_module_name(plain) else (
                        cb.decode_module_name(raw_name) if is_commercial
                        else raw_name.decode("utf-8", errors="replace")
                    )
                except Exception:
                    name = (
                        cb.decode_module_name(raw_name) if is_commercial
                        else raw_name.decode("utf-8", errors="replace")
                    )
                offset = nul + 1
                if offset + 4 > len(data):
                    break
                chunk_size = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
                if chunk_size > 100 * 1024 * 1024 or offset + chunk_size > len(data):
                    break
                chunk_data = data[offset : offset + chunk_size]
                offset += chunk_size
                if name == ".bytecode":
                    return chunk_data
            return None

        bc_chunk = _find_bytecode_chunk(raw)
        if bc_chunk:
            ver = detect_version_from_bytecode_chunk(bc_chunk)
            if ver and ver in by_version:
                return ver
    except Exception:
        pass

    # --- Strategy 1: raw blob marshal scan --------------------------------
    for tag in MARSHAL_VERSION_HINT_TAGS:
        off = raw.find(tag)
        if off != -1:
            ver = detect_version_from_marshal(raw[off : off + 65536])
            if ver and ver in by_version:
                return ver

    return None


__all__ = [
    # Core pipeline
    "extract_blob",
    # Version detection
    "detect_nuitka_version",
    "detect_version_from_marshal",
    "detect_version_from_bytecode_chunk",
    "guess_version_from_marshal_bytes",
    # Commercial bypass
    "CommercialBypass",
    # Low-level utils
    "get_magic_int",
    "looks_like_code_header",
    "try_detect_code_object",
    "score_code_object",
    # Constants
    "MARSHAL_VERSION_HINT_TAGS",
    "MARSHAL_CODE_TAGS",
]
