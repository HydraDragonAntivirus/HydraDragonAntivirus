#!/usr/bin/env python3
from __future__ import annotations
import argparse
import importlib.util
from pathlib import Path

def parse_magic(value: str | None) -> bytes:
    if not value:
        return importlib.util.MAGIC_NUMBER
    value = value.strip().lower().replace('0x', '').replace(' ', '')
    if len(value) != 8:
        raise SystemExit('magic must be exactly 8 hex characters, e.g. f30d0d0a')
    return bytes.fromhex(value)

def build_pyc(marshal_bytes: bytes, magic: bytes) -> bytes:
    return magic + (0).to_bytes(4, 'little') + (0).to_bytes(4, 'little') + (0).to_bytes(4, 'little') + marshal_bytes

def main() -> int:
    ap = argparse.ArgumentParser(description='Rebuild .pyc files from exported Nuitka marshal blobs')
    ap.add_argument('bundle_dir', nargs='?', default='.', help='Directory containing bytecode_*.marshal')
    ap.add_argument('--magic-hex', help='Override 4-byte MAGIC_NUMBER as 8 hex chars (e.g. f30d0d0a for Python 3.11)')
    args = ap.parse_args()

    bundle_dir = Path(args.bundle_dir)
    magic = parse_magic(args.magic_hex)
    pyc_list = []
    for path in sorted(bundle_dir.glob('bytecode_*.marshal')):
        pyc_path = path.with_suffix('.pyc')
        pyc_path.write_bytes(build_pyc(path.read_bytes(), magic))
        pyc_list.append(str(pyc_path))
        print(f'[make_pyc_list] wrote {pyc_path}')
    (bundle_dir / 'pyc_list.txt').write_text('\n'.join(pyc_list) + ('\n' if pyc_list else ''), encoding='utf-8')
    print(f'[make_pyc_list] wrote {len(pyc_list)} pyc path(s) to {bundle_dir / "pyc_list.txt"}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
