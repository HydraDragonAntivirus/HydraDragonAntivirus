"""
nuitka_blob_loader
==================

Standalone loader for Nuitka constants blobs (rcdata_10_3.bin and friends).

The hard work lives in a CPython extension that wraps Nuitka's own
HelpersConstantsBlob.c (vendored as src/blob_decode.c). The C parser
unpacks the requested section and hands us back the raw marshal blobs
for every Python module embedded in the binary. We then attach a
proper .pyc magic header (via xdis) and write them to disk.
"""
from ._core import load, set_sbox, PYTHON_VERSION_HEX  # noqa: F401
from .pyc_writer import write_pyc, export_all  # noqa: F401

__all__ = [
    "load",
    "set_sbox",
    "PYTHON_VERSION_HEX",
    "write_pyc",
    "export_all",
]
