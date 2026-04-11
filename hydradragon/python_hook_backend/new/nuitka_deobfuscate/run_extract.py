"""
run_extract.py -- Extract .pyc files from a Nuitka constants blob using
                  xdis_blob_loader (C decoder) + xdis (marshal validation).

Usage:
    python run_extract.py <blob_file> [-o DIR] [-v 3.12] [--list-only]
"""
from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

import nuitka_deobfuscate
from xdis.magics import by_version, int2magic
from xdis.unmarshal import VersionIndependentUnmarshaller


def magic_int_for(version: str) -> int:
    magic = by_version.get(version)
    if magic is None:
        raise RuntimeError(f"xdis has no magic for Python {version}")
    return int.from_bytes(bytes(magic[:2]), "little")


def pyc_header(magic_int: int) -> bytes:
    magic = int2magic(magic_int)
    flags = (0).to_bytes(4, "little")
    mtime = (0).to_bytes(4, "little")
    src_size = (0).to_bytes(4, "little")
    return magic + flags + mtime + src_size


def validate_marshal(raw: bytes, magic_int: int) -> bool:
    try:
        stream = io.BytesIO(raw)
        um = VersionIndependentUnmarshaller(stream, magic_int, bytes_for_s=True)
        um.load()
        return True
    except Exception:
        return False


def module_to_relpath(name: str) -> Path:
    if not name:
        return Path("__unnamed__.pyc")
    parts = name.replace("/", ".").split(".")
    return Path(*parts).with_suffix(".pyc")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract .pyc files from a Nuitka constants blob (C decoder + xdis)."
    )
    parser.add_argument("blob", type=Path, help="Path to the Nuitka constants blob file")
    parser.add_argument("-o", "--output", type=Path, default=Path("./pyc_out"),
                        help="Output directory for .pyc files (default: ./pyc_out)")
    parser.add_argument("-v", "--version", default="3.12",
                        help="Target CPython version for .pyc magic (default: 3.12)")
    parser.add_argument("--list-only", action="store_true",
                        help="List decoded section names without writing files")
    args = parser.parse_args(argv)

    blob_path: Path = args.blob
    if not blob_path.is_file():
        print(f"error: blob not found: {blob_path}", file=sys.stderr)
        return 2

    raw = blob_path.read_bytes()
    print(f"[run] Loaded {len(raw)} bytes from {blob_path}")

    # Decode via C extension
    try:
        import traceback
        sections = nuitka_deobfuscate.decode_blob(raw)
    except Exception:
        traceback.print_exc()
        return 1
    except SystemError:
        import traceback
        traceback.print_exc()
        return 1

    print(f"[run] Decoded {len(sections)} section(s): {', '.join(sections.keys())}")

    out_dir: Path = args.output
    magic_int = magic_int_for(args.version)
    header = pyc_header(magic_int)

    for section_name, items in sections.items():
        if not items:
            continue
            
        # Create a subdirectory for the section
        section_dir = out_dir / section_name.replace(".", "_").strip("_")
        section_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[run] Processing section '{section_name}' ({len(items)} items) -> {section_dir}")
        
        for i, val in enumerate(items):
            # Synthetic name for the item
            item_name = f"{section_name.replace('.', '_').strip('_')}_{i}"
            
            if args.list_only:
                size_str = f"{len(val)} bytes" if isinstance(val, (bytes, bytearray)) else type(val).__name__
                print(f"  {item_name}  ({size_str})")
                continue

            if not isinstance(val, (bytes, bytearray)):
                # If it's a string, int, etc., save as repr text
                dest = section_dir / f"{item_name}.txt"
                dest.write_text(repr(val), encoding="utf-8")
                continue

            # Default to .bin
            ext = ".bin"
            content = val
            
            # Special handling for bytecode section - add pyc header
            if section_name == ".bytecode":
                ext = ".pyc"
                content = header + val
            
            dest = section_dir / f"{item_name}{ext}"
            dest.write_bytes(content)
            
            if i < 3 or i >= len(items) - 3: 
                 print(f"  [dump] {item_name} -> {dest.name} ({len(val)} bytes)")
            elif i == 3:
                 print(f"  ...")

    if not args.list_only:
        print(f"\n[run] Extraction complete. Files written to {out_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
