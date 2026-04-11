"""
Command-line interface:

    python -m nuitka_blob_loader BLOB [-o OUTDIR] [-s SECTION] [-v 3.12]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import load, export_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nuitka_blob_loader",
        description="Extract .pyc files from a Nuitka constants blob.",
    )
    p.add_argument("blob", type=Path, help="path to rcdata_10_3.bin")
    p.add_argument("-o", "--output", type=Path, default=Path("./pyc_out"),
                   help="output directory for .pyc files (default: ./pyc_out)")
    p.add_argument("-s", "--section", default=".bytecode",
                   help="blob section to extract (default: .bytecode)")
    p.add_argument("-v", "--version", default="3.12",
                   help="target CPython version for .pyc magic (default: 3.12)")
    p.add_argument("--list-only", action="store_true",
                   help="list module names without writing files")
    p.add_argument("--strict", action="store_true",
                   help="abort on first marshal validation failure")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.blob.is_file():
        print(f"error: blob not found: {args.blob}", file=sys.stderr)
        return 2

    blobs = load(str(args.blob), section=args.section)
    print(f"[main] section {args.section!r}: {len(blobs)} module(s)")

    if args.list_only:
        for name in sorted(blobs):
            print(f"  {name}  ({len(blobs[name])} bytes)")
        return 0

    ok, bad = export_all(blobs, args.output, version=args.version,
                         strict=args.strict)
    print(f"[main] wrote {ok} .pyc, {bad} failed -> {args.output}/")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
