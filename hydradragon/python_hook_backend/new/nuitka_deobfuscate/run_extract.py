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
        sections = nuitka_deobfuscate.decode_blob(raw)
    except Exception as e:
        print(f"[run] decode_blob failed: {e}", file=sys.stderr)
        return 1

    print(f"[run] Decoded {len(sections)} section(s): {', '.join(sections.keys())}")

    # We specifically want the '.bytecode' section
    bytecode_tuple = sections.get(".bytecode")
    if not bytecode_tuple or not isinstance(bytecode_tuple, tuple):
        print("error: .bytecode section missing or not a tuple", file=sys.stderr)
        return 1
        
    # The .bytecode section ONLY contains byte payloads (count == 397 in this case)
    # The names are hardcoded in the C code, so we use synthetic names.
    blobs = {}
    for i, val in enumerate(bytecode_tuple):
        name = f".bytecode_{i}"
        blobs[name] = val

    if args.list_only:
        for name in sorted(blobs.keys(), key=lambda x: int(x.split('_')[1])):
            val = blobs[name]
            size_str = f"{len(val)} bytes" if isinstance(val, (bytes, bytearray)) else type(val).__name__
            print(f"  {name}  ({size_str})")
        return 0

    # Export .pyc files
    magic_int = magic_int_for(args.version)
    header = pyc_header(magic_int)
    out_dir: Path = args.output
    ok = 0
    bad = 0

    for name in sorted(blobs.keys(), key=lambda x: int(x.split('_')[1])):
        val = blobs[name]
        if not isinstance(val, (bytes, bytearray)):
            print(f"  [skip] {name}: not bytes ({type(val).__name__})")
            continue

        rel = module_to_relpath(name)
        dest = out_dir / rel

        valid = validate_marshal(val, magic_int)
        if not valid:
            print(f"  [warn] {name}: xdis marshal validation failed, writing anyway")

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(header + val)
        status = "OK" if valid else "WARN"
        print(f"  [{status}] {name} -> {dest} ({len(val)} bytes)")
        ok += 1

    print(f"\n[run] Wrote {ok} .pyc file(s), {bad} failed -> {out_dir}/")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
