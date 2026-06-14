#!/usr/bin/env python3
"""
list_modules.py - List modules inside an authorized raw Nuitka constants blob.

Does ONLY:
  1. Raw blob loading
  2. Protected module-name normalization when present
  3. Module name parsing from blob headers

Does NOT:
  - Read PE resources or sections
  - Depend on pefile
  - Reconstruct or decompile application source
  - Extract .pyc files
  - Run the disassembler
  - Write any output files

Usage:
    python list_modules.py constants_blob.bin
    python list_modules.py constants_blob.bin --json
    python list_modules.py constants_blob.bin --filter mypackage
    python list_modules.py constants_blob.bin --filter mypackage --copy-cmd
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import zlib
from pathlib import Path
from random import Random

# ---------------------------------------------------------------------------
# Minimal standalone implementations — no dependency on nuitka_decompiler.py
# (so this script works even if you haven't set up the full tool)
# ---------------------------------------------------------------------------

# ---- Protected module-name decoding ----------------------------------------

def _build_mapping2() -> list[int]:
    """Build a module-name decoding table for supported protected layouts."""
    r = Random(27)
    fwd = list(range(1, 256))
    r.shuffle(fwd)
    fwd.insert(0, 0)
    inv = [0] * 256
    for i, v in enumerate(fwd):
        inv[v] = i
    return inv


_MAPPING2 = _build_mapping2()


def decode_module_name(raw: bytes) -> str:
    """Decode a module name from a supported protected layout."""
    return bytes(_MAPPING2[b] for b in raw).decode("utf-8", errors="replace")


# Raw blob loading ------------------------------------------------------------

def _load_blob_file(path: str) -> tuple[bytes | None, str]:
    """Load the supplied file as the constants blob, even if the CRC mismatches."""
    data = Path(path).read_bytes()
    if len(data) < 8:
        return None, "too small"
    return data, "raw blob file"


# ── Blob module-name parser ──────────────────────────────────────────────────

def _is_likely_encrypted(blob: bytes) -> bool:
    """Quick check: if CRC doesn't match, blob is encrypted."""
    if len(blob) < 8:
        return False
    stored = struct.unpack_from("<I", blob, 0)[0]
    declared = struct.unpack_from("<I", blob, 4)[0]
    if 8 + declared > len(blob):
        return True
    actual = zlib.crc32(blob[8:8 + declared]) & 0xFFFFFFFF
    return actual != stored


def _looks_like_module_name(name: str) -> bool:
    return bool(name) and all(ch == "." or ch == "_" or ch == "-" or ch.isalnum() for ch in name)


def _looks_like_utf8_module_name(raw_name: bytes) -> bool:
    try:
        name = raw_name.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return _looks_like_module_name(name)


def _decode_blob_module_name(raw_name: bytes, is_commercial: bool) -> str:
    if _looks_like_utf8_module_name(raw_name):
        return raw_name.decode("utf-8", errors="strict")
    mapped = decode_module_name(raw_name)
    if is_commercial or _looks_like_module_name(mapped):
        return mapped
    return raw_name.decode("utf-8", errors="replace")


def _valid_section_layout(data_len: int, data_start: int, size: int, count: int | None = None) -> bool:
    if size <= 0 or size > 128 * 1024 * 1024:
        return False
    if data_start < 0 or data_start + size > data_len:
        return False
    if count is None:
        return True
    return 0 < count < 65000 and size >= count


def _choose_section_layout(data: bytes, header_pos: int, is_commercial: bool) -> tuple[int, int, int | None, str] | None:
    """
    Return (data_start, section_size, item_count, layout_name).

    Modern Nuitka blobs use:
        name NUL, uint32 section_size, uint16 item_count, constants...

    Some older helpers only modeled:
        name NUL, uint32 section_size, constants...

    Prefer the size+count form because it matches the local C decoder and lets
    decode_at_offset start on the first constant tag instead of the count bytes.
    """
    if header_pos + 4 > len(data):
        return None

    section_size = struct.unpack_from("<I", data, header_pos)[0]

    def is_valid_next(next_pos: int) -> bool:
        while next_pos < len(data) and data[next_pos] == 0:
            next_pos += 1
        if next_pos == len(data):
            return True
        if next_pos < len(data):
            b = data[next_pos]
            c_plain = chr(b)
            if c_plain.isalpha() or c_plain == '_' or c_plain == '.':
                return True
            if is_commercial:
                try:
                    dec_b = _MAPPING2[b]
                    c_dec = chr(dec_b)
                    if c_dec.isalpha() or c_dec == '_' or c_dec == '.':
                        return True
                except Exception:
                    pass
        return False

    if header_pos + 6 <= len(data):
        item_count = struct.unpack_from("<H", data, header_pos + 4)[0]
        data_start = header_pos + 6
        if _valid_section_layout(len(data), data_start, section_size, item_count):
            if is_valid_next(data_start + section_size):
                return data_start, section_size, item_count, "size_count"

    data_start = header_pos + 4
    if _valid_section_layout(len(data), data_start, section_size):
        if is_valid_next(data_start + section_size):
            return data_start, section_size, None, "size_only"

    return None


def parse_module_names(blob: bytes) -> list[dict]:
    """Parse module metadata from a raw Nuitka constants blob."""
    is_commercial = _is_likely_encrypted(blob)
    declared_size = struct.unpack_from("<I", blob, 4)[0] if len(blob) >= 8 else 0
    data = blob[8:8 + declared_size] if declared_size and 8 + declared_size <= len(blob) else blob[8:]
    
    # Auto-detect if names are commercial-obfuscated by probing the first module name
    name_obfuscated = False
    if len(data) > 0:
        nul_idx = data.find(b"\x00", 0, min(1024, len(data)))
        if nul_idx > 0:
            first_raw = data[:nul_idx]
            plain_ok = False
            try:
                first_plain = first_raw.decode("utf-8")
                if first_plain.isprintable() and all(ch == "." or ch == "_" or ch == "-" or ch.isalnum() for ch in first_plain):
                    plain_ok = True
            except Exception:
                pass
            if not plain_ok:
                try:
                    first_dec = decode_module_name(first_raw)
                    if all(ch == "." or ch == "_" or ch == "-" or ch.isalnum() for ch in first_dec):
                        name_obfuscated = True
                except Exception:
                    pass
    if name_obfuscated:
        is_commercial = True

    offset = 0
    modules: list[dict] = []

    while offset < len(data) - 5:
        while offset < len(data) and data[offset] == 0:
            offset += 1

        name_end = data.find(b"\x00", offset, min(offset + 4096, len(data)))
        if name_end == -1:
            break

        raw_name = data[offset:name_end]
        header_pos = name_end + 1
        layout = _choose_section_layout(data, header_pos, is_commercial)
        if layout is None:
            offset = name_end + 1
            continue

        data_start, section_size, item_count, layout_name = layout
        name = _decode_blob_module_name(raw_name, is_commercial)
        absolute_header_pos = 8 + header_pos
        absolute_data_start = 8 + data_start

        modules.append({
            "name": name,
            "size": section_size,
            "count": item_count,
            "layout": layout_name,
            "section_offset": absolute_header_pos,
            "offset": absolute_data_start,
            "is_main": (name in ("__main__", "") or
                        (not name.startswith("_") and "." not in name and
                         not name.startswith("nuitka"))),
            "is_bytecode": name == ".bytecode",
        })

        next_offset = data_start + section_size
        best_offset = next_offset
        for back in range(1, 8):
            check_pos = next_offset - back
            if check_pos <= data_start:
                break
            if data[check_pos] == 0:
                cand_end = data.find(b"\x00", check_pos + 1, min(check_pos + 128, len(data)))
                if cand_end != -1 and cand_end > check_pos + 1:
                    cand_raw = data[check_pos + 1:cand_end]
                    cand_name = _decode_blob_module_name(cand_raw, is_commercial)
                    if cand_name and (cand_name[0].isalnum() or cand_name[0] in '._'):
                        cand_layout = _choose_section_layout(data, cand_end + 1, is_commercial)
                        if cand_layout is not None:
                            best_offset = check_pos
                            break
        offset = best_offset

    return modules


def _parse_module_names(blob: bytes, is_commercial: bool) -> list[dict]:
    """
    Parse only the module names from the blob (no constant decoding).
    Returns list of dicts: {name, size, is_main, is_bytecode}.
    """
    return parse_module_names(blob)


# ── Main ─────────────────────────────────────────────────────────────────────

def list_modules(target: str,
                 as_json: bool = False,
                 filter_str: str | None = None,
                 copy_cmd: bool = False) -> int:

    if not os.path.isfile(target):
        print(f"[ERROR] File not found: {target}", file=sys.stderr)
        return 1

    blob, source = _load_blob_file(target)
    if blob is None:
        print(f"[ERROR] Could not load constants blob from {target}: {source}", file=sys.stderr)
        return 1

    print(f"[INFO] Blob source : {source}  ({len(blob):,} bytes)", file=sys.stderr)

    is_enc = _is_likely_encrypted(blob)
    is_commercial = is_enc  # encrypted → commercial build

    if is_enc:
        print("[INFO] Blob appears encrypted (CRC mismatch) — commercial/protected build",
              file=sys.stderr)

    modules = _parse_module_names(blob, is_commercial)

    if not modules:
        crc_s  = struct.unpack_from("<I", blob, 0)[0]
        size_s = struct.unpack_from("<I", blob, 4)[0]
        print("[ERROR] Blob found but no modules parsed — format may be unsupported.",
              file=sys.stderr)
        print(f"        Blob header: CRC=0x{crc_s:08X}  declared_size={size_s:,}  "
              f"actual_blob_len={len(blob):,}", file=sys.stderr)
        print(f"        First 32 bytes (hex): {blob[:32].hex()}", file=sys.stderr)
        print("        Try running the full decompiler for deeper analysis.", file=sys.stderr)
        return 1

    # Apply filter
    if filter_str:
        f = filter_str.lower()
        modules = [m for m in modules if f in m["name"].lower()]

    # ── Output ──────────────────────────────────────────────────────────────

    if as_json:
        print(json.dumps(modules, indent=2))
        return 0

    total = len(modules)
    enc_label = "protected metadata" if is_enc else "plain metadata"
    print(f"\n  Target  : {os.path.basename(target)}")
    print(f"  Blob    : {source}")
    print(f"  Edition : {enc_label}")
    print(f"  Modules : {total}")
    if filter_str:
        print(f"  Filter  : '{filter_str}'")
    print()
    print(f"  {'#':<5}  {'MODULE NAME':<55}  {'SIZE':>9}  {'NOTE'}")
    print("  " + "─" * 80)

    for i, m in enumerate(modules, 1):
        note = ""
        if m["is_bytecode"]:
            note = "← .pyc bytecode chunk"
        elif m["is_main"]:
            note = "← likely main module"
        size_kb = m["size"] / 1024
        print(f"  {i:<5}  {m['name']:<55}  {size_kb:>7.1f} KB  {note}")

    print()

    if copy_cmd:
        names = ",".join(m["name"] for m in modules if not m["is_bytecode"])
        print("  ── Ready to use with --only: ──────────────────────────────────")
        print(f"  python nuitka_decompiler.py --source {os.path.basename(target)} --only {names}")
        print()

    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="list_modules",
        description="List modules inside an authorized raw Nuitka constants blob.",
    )
    ap.add_argument("target", help="Authorized raw Nuitka constants blob")
    ap.add_argument("--json", action="store_true",
                    help="Output as JSON (for scripting)")
    ap.add_argument("--filter", metavar="STR", default=None,
                    help="Only show modules whose name contains STR (case-insensitive)")
    ap.add_argument("--copy-cmd", action="store_true",
                    help="Print a ready-to-run --only command at the end")
    args = ap.parse_args(argv)
    return list_modules(args.target, args.json, args.filter, args.copy_cmd)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
