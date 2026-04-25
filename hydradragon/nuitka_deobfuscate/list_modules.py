#!/usr/bin/env python3
"""
list_modules.py - Nuitka binary analysis library and extractor.
Supports:
  1. Constants blob extraction (resources/sections)
  2. Onefile payload extraction (KAX/KAY markers)
  3. Module name decoding (protected commercial builds)
  4. Heuristic Python version detection (via run_extract logic)
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from pathlib import Path
from random import Random
from typing import Any, Iterator, Optional

# ---------------------------------------------------------------------------
# Dependencies & Fallbacks
# ---------------------------------------------------------------------------

try:
    import pefile  # type: ignore
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import zstandard as zstd  # type: ignore
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


# ---------------------------------------------------------------------------
# Constants & Errors
# ---------------------------------------------------------------------------

ONEFILE_MAGICS = (b"KAX", b"KAY")
class NuitkaError(Exception): pass


# ---------------------------------------------------------------------------
# Protected Module-Name Decoding
# ---------------------------------------------------------------------------

def get_nuitka_mapping(seed: int = 27) -> list[int]:
    """Build a module-name decoding table for supported protected layouts."""
    r = Random(seed)
    fwd = list(range(1, 256))
    r.shuffle(fwd)
    fwd.insert(0, 0)
    return fwd


def decode_module_name(raw: bytes, seed: int = 27) -> str:
    """Decode a module name from a supported protected layout."""
    mapping = get_nuitka_mapping(seed)
    try:
        return bytes(mapping[b] for b in raw).decode("utf-8", errors="replace")
    except Exception:
        return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# PE Utilities (Manual fallback for when pefile is missing)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class PESection:
    name: str
    raw_ptr: int
    raw_size: int
    virt_addr: int
    virt_size: int

def parse_pe_sections_manual(buf: memoryview) -> list[PESection]:
    if len(buf) < 0x100 or buf[0:2].tobytes() != b"MZ":
        return []
    try:
        e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
        if buf[e_lfanew : e_lfanew + 4].tobytes() != b"PE\x00\x00":
            return []
        coff_off = e_lfanew + 4
        num_sections = struct.unpack_from("<H", buf, coff_off + 2)[0]
        size_opt = struct.unpack_from("<H", buf, coff_off + 16)[0]
        sec_off = coff_off + 20 + size_opt
        
        sections = []
        for i in range(num_sections):
            off = sec_off + i * 40
            name = buf[off : off + 8].tobytes().split(b"\x00", 1)[0].decode("ascii", errors="replace")
            v_size, v_addr, r_size, r_ptr = struct.unpack_from("<IIII", buf, off + 8)
            sections.append(PESection(name, r_ptr, r_size, v_addr, v_size))
        return sections
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Constants Blob Extraction
# ---------------------------------------------------------------------------

def find_constants_blob(path_or_data: str | bytes | Path) -> tuple[bytes | Optional[bytes], str]:
    """
    Find and return the Nuitka constants blob and its source description.
    """
    if isinstance(path_or_data, (str, Path)):
        data = Path(path_or_data).read_bytes()
    else:
        data = path_or_data

    # Try pefile if available
    if HAS_PEFILE:
        try:
            pe = pefile.PE(data=data, fast_load=False)
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for res_id in res_type.directory.entries:
                        for res_lang in res_id.directory.entries:
                            rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            chunk = pe.get_data(rva, size)
                            if len(chunk) >= 8:
                                declared = struct.unpack_from("<I", chunk, 4)[0]
                                if 8 + declared <= size:
                                    actual_crc = zlib.crc32(chunk[8:8 + declared]) & 0xFFFFFFFF
                                    if actual_crc == struct.unpack_from("<I", chunk, 0)[0]:
                                        return chunk[:8+declared], f"PE Resource (ID {res_id.id})"
            
            for section in pe.sections:
                raw_sec = data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]
                if len(raw_sec) >= 8:
                    declared = struct.unpack_from("<I", raw_sec, 4)[0]
                    if 8 + declared <= len(raw_sec):
                        actual_crc = zlib.crc32(raw_sec[8:8 + declared]) & 0xFFFFFFFF
                        if actual_crc == struct.unpack_from("<I", raw_sec, 0)[0]:
                            return raw_sec[:8+declared], f"PE Section {section.Name.decode().strip(chr(0))}"
        except Exception:
            pass

    # Raw scan fallback
    for off in range(0, len(data) - 8, 4):
        stored_crc = struct.unpack_from("<I", data, off)[0]
        declared = struct.unpack_from("<I", data, off + 4)[0]
        if 1024 < declared < 256 * 1024 * 1024 and off + 8 + declared <= len(data):
            if zlib.crc32(data[off+8:off+8+declared]) & 0xFFFFFFFF == stored_crc:
                return data[off:off+8+declared], "Raw scan"

    return None, "Not found"


def parse_module_names(blob: bytes) -> list[dict]:
    """Parse module names from constants blob."""
    is_enc = (zlib.crc32(blob[8:]) & 0xFFFFFFFF) != struct.unpack_from("<I", blob, 0)[0]
    data = blob[8:]
    offset = 0
    modules = []

    while offset < len(data) - 5:
        name_end = data.find(b"\x00", offset, min(offset + 512, len(data)))
        if name_end == -1: break
        raw_name = data[offset:name_end]
        offset = name_end + 1
        if offset + 4 > len(data):
            break
        chunk_size = struct.unpack_from("<I", data, offset)[0]
        data_start = offset + 4
        offset = data_start + chunk_size

        if chunk_size > 128 * 1024 * 1024 or offset > len(data):
            break

        # Decode name
        try:
            name = raw_name.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            name = decode_module_name(raw_name) if is_enc else raw_name.decode("utf-8", errors="replace")

        modules.append({
            "name": name,
            "size": chunk_size,
            "offset": 8 + data_start, # absolute offset in original blob
            "is_main": (name in ("__main__", "") or
                        (not name.startswith("_") and "." not in name and
                         not name.startswith("nuitka"))),
            "is_bytecode": name == ".bytecode",
        })
    return modules


# ---------------------------------------------------------------------------
# Onefile Extraction Logic (Nuthem)
# ---------------------------------------------------------------------------

def _u16le_cstr(data: memoryview, offset: int) -> tuple[str, int]:
    end = offset
    chars = []
    while end + 2 <= len(data):
        (u,) = struct.unpack_from("<H", data, end)
        end += 2
        if u == 0: break
        chars.append(u)
    return bytes(struct.pack("<" + "H" * len(chars), *chars)).decode("utf-16le", errors="replace"), end

def _looks_like_relpath(p: str) -> bool:
    if not p or ":" in p or p.startswith(("\\", "/")): return False
    return all(ord(c) >= 32 for c in p)

def _safe_join(root: Path, rel: str) -> Path:
    rel = rel.replace("/", os.sep).replace("\\", os.sep).lstrip("\\/")
    out = (root / rel).resolve()
    if root.resolve() not in out.parents and out != root.resolve():
        raise NuitkaError(f"Path traversal detected: {rel}")
    return out

def _decompress_zstd(data: bytes, expected_size: Optional[int] = None) -> bytes:
    if not HAS_ZSTD:
        raise NuitkaError("zstandard package missing. Install with: pip install zstandard")
    dctx = zstd.ZstdDecompressor()
    try:
        if expected_size is not None:
            return dctx.decompress(data, max_output_size=expected_size)
        return dctx.decompress(data)
    except Exception as e:
        # Try stream decompression for KAY global streams
        try:
            dobj = dctx.decompressobj()
            return dobj.decompress(data)
        except:
            raise NuitkaError(f"Zstd decompression failed: {e}")

def parse_onefile_stream(stream: bytes, magic: bytes) -> list[tuple[str, bytes]]:
    data = memoryview(stream)
    off = 0
    out = []
    
    # If KAY magic and doesn't look like per-file archive, it might be global stream
    if magic == b"KAY":
        try:
            # Quick check if it's per-file archive: name -> size -> checksum? -> arch_size -> zstd
            # We try to parse a few entries. If it fails, we try global decompression.
            return parse_onefile_entries(data, is_archive=True)
        except:
            decompressed = _decompress_zstd(stream)
            return parse_onefile_entries(memoryview(decompressed), is_archive=False)
    
    return parse_onefile_entries(data, is_archive=False)

def parse_onefile_entries(data: memoryview, is_archive: bool) -> list[tuple[str, bytes]]:
    off = 0
    out = []
    while True:
        name, off = _u16le_cstr(data, off)
        if not name: break
        
        file_size = struct.unpack_from("<Q", data, off)[0]
        off += 8
        
        # Checksum detection heuristic
        # If we skip 4 bytes and the next 4 bytes are a valid archive size or MZ header...
        # Or if we just try both.
        has_checksum = False
        if is_archive:
            # In archive mode, next 4 bytes are either checksum or archive_size
            arch_size = struct.unpack_from("<I", data, off)[0]
            # Heuristic: if off+4+arch_size leads to a valid next filename or EOF
            if off + 4 + arch_size <= len(data):
                next_name_test, _ = _u16le_cstr(data, off + 4 + arch_size)
                if not next_name_test or _looks_like_relpath(next_name_test):
                    pass # Looks like no checksum
                else:
                    has_checksum = True
            else:
                has_checksum = True
        else:
            # Raw mode: checksum is optional.
            if off + 4 + file_size <= len(data):
                next_name_test, _ = _u16le_cstr(data, off + 4 + file_size)
                if next_name_test and not _looks_like_relpath(next_name_test):
                    has_checksum = True
        
        if has_checksum: off += 4
        
        if is_archive:
            arch_size = struct.unpack_from("<I", data, off)[0]
            off += 4
            content = _decompress_zstd(data[off:off+arch_size].tobytes(), expected_size=file_size)
            off += arch_size
        else:
            content = data[off:off+file_size].tobytes()
            off += file_size
        
        out.append((name, content))
    return out

def extract_onefile(path: Path, out_dir: Path) -> dict:
    blob = path.read_bytes()
    buf = memoryview(blob)
    
    sections = parse_pe_sections_manual(buf)
    if HAS_PEFILE:
        try:
            pe = pefile.PE(data=blob, fast_load=True)
            sections = [PESection(s.Name.decode().strip(chr(0)), s.PointerToRawData, s.SizeOfRawData, s.VirtualAddress, s.Misc_VirtualSize) for s in pe.sections]
        except: pass

    candidates = []
    for s in sections:
        if s.raw_ptr == 0: continue
        chunk = blob[s.raw_ptr : s.raw_ptr + s.raw_size]
        for magic in ONEFILE_MAGICS:
            pos = chunk.find(magic)
            while pos != -1:
                try:
                    stream = chunk[pos + 3:]
                    entries = parse_onefile_stream(stream, magic)
                    if entries:
                        candidates.append((len(entries), s.raw_ptr + pos, magic, entries))
                except: pass
                pos = chunk.find(magic, pos + 1)
    
    if not candidates:
        raise NuitkaError("No valid Onefile payload found.")
    
    candidates.sort(key=lambda x: x[0], reverse=True)
    count, pos, magic, entries = candidates[0]
    
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in entries:
        target = _safe_join(out_dir, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        
    return {"count": count, "magic": magic.decode(), "pos": pos}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Nuitka Module Lister & Onefile Extractor")
    parser.add_argument("target", type=Path, help="Nuitka-compiled EXE/DLL or Constants Blob")
    parser.add_argument("--list", action="store_true", help="List modules from constants blob")
    parser.add_argument("--extract", type=Path, metavar="DIR", help="Extract Onefile payload to DIR")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    results = {}

    if args.list or not args.extract:
        blob, src = find_constants_blob(args.target)
        if blob:
            modules = parse_module_names(blob)
            results["modules"] = modules
            results["constants_source"] = src
            if not args.json:
                print(f"[*] Found Constants Blob via {src}")
                for m in modules:
                    print(f"  {m['name']:<50} {m['size']/1024:>7.1f} KB {'(Bytecode)' if m['is_bytecode'] else ''}")
        else:
            if args.list:
                print("[!] Constants blob not found.")

    if args.extract:
        try:
            info = extract_onefile(args.target, args.extract)
            results["onefile"] = info
            if not args.json:
                print(f"[*] Extracted {info['count']} files from Onefile payload ({info['magic']} at 0x{info['pos']:x})")
        except Exception as e:
            print(f"[!] Onefile extraction failed: {e}")

    if args.json:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
