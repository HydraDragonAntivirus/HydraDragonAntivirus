"""
pyc_writer.py
=============

Turns the raw marshal blobs returned by `_core.load()` into real .pyc
files using xdis to look up the correct magic number for the desired
CPython minor version.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Mapping

from xdis.magics import by_version, int2magic
from xdis.unmarshal import VersionIndependentUnmarshaller


_DEFAULT_VERSION = "3.12"


def _magic_int_for(version: str) -> int:
    magic = by_version.get(version)
    if magic is None:
        raise RuntimeError(f"xdis has no magic for Python {version}")
    return int.from_bytes(bytes(magic[:2]), "little")


def _pyc_header(magic_int: int) -> bytes:
    magic = int2magic(magic_int)
    flags = (0).to_bytes(4, "little")
    mtime = (0).to_bytes(4, "little")
    src_size = (0).to_bytes(4, "little")
    return magic + flags + mtime + src_size


def _validate_marshal(raw: bytes, magic_int: int) -> None:
    """Make sure xdis can at least parse the marshal stream.

    We don't keep the parsed object — the .pyc just needs the bytes —
    but a successful unmarshal proves the magic + payload pair is
    coherent and not e.g. swapped versions.
    """
    stream = io.BytesIO(raw)
    um = VersionIndependentUnmarshaller(stream, magic_int, bytes_for_s=True)
    um.load()


def _module_to_relpath(name: str) -> Path:
    """Map a dotted module name to a filesystem path under the output dir."""
    if not name:
        return Path("__unnamed__.pyc")
    parts = name.split(".")
    return Path(*parts).with_suffix(".pyc")


def write_pyc(raw_marshal: bytes,
              dest: Path,
              version: str = _DEFAULT_VERSION,
              validate: bool = True) -> None:
    """Write a single .pyc file from a raw marshal blob."""
    magic_int = _magic_int_for(version)
    if validate:
        try:
            _validate_marshal(raw_marshal, magic_int)
        except Exception as e:
            raise RuntimeError(
                f"marshal validation failed for {dest} "
                f"under Python {version}: {e}"
            ) from e
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(_pyc_header(magic_int) + raw_marshal)


def export_all(blobs: Mapping[str, bytes],
               output_dir: Path,
               version: str = _DEFAULT_VERSION,
               strict: bool = False) -> tuple[int, int]:
    """Write a .pyc per (module_name, marshal_bytes) entry.

    Returns (success_count, failure_count). With strict=True, the
    first failure raises instead of being counted.
    """
    output_dir = Path(output_dir)
    ok = 0
    bad = 0
    for name, raw in blobs.items():
        rel = _module_to_relpath(name)
        dest = output_dir / rel
        try:
            write_pyc(raw, dest, version=version)
            ok += 1
        except Exception as e:
            if strict:
                raise
            print(f"[pyc_writer] FAIL {name} -> {dest}: {e}")
            bad += 1
    return ok, bad
