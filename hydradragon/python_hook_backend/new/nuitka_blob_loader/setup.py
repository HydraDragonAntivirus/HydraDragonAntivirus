"""
setup.py
========

Builds the `nuitka_blob_loader._core` C extension.

The extension wraps Nuitka's HelpersConstantsBlob.c (vendored as
src/blob_decode.c). We force-include src/nuitka_shim.h before every
compile of blob_decode.c so that all the Nuitka-internal symbols
(Py_INCREF_IMMORTAL, Nuitka_LongFromCLong, MAKE_CODE_OBJECT, ...)
resolve to plain CPython equivalents.

Target CPython version is 3.12 (PYTHON_VERSION=0x3c0). Override
with the env var NUITKA_BLOB_LOADER_PYVER=0xNNN if you need a
different one (must match the actual interpreter you build under).
"""
from __future__ import annotations

import os
import sys
import platform
from setuptools import setup, Extension

HERE = os.path.abspath(os.path.dirname(__file__))
SRC  = os.path.join(HERE, "src")

PYVER_HEX = os.environ.get("NUITKA_BLOB_LOADER_PYVER", "0x3c0")

shim_path = os.path.join(SRC, "nuitka_shim.h")

extra_compile_args: list[str] = []
extra_link_args: list[str] = []

if platform.system() == "Windows":
    # MSVC: /FI force-includes a header
    extra_compile_args += [f"/FI{shim_path}"]
    extra_compile_args += ["/wd4244", "/wd4267", "/wd4101", "/wd4018"]
else:
    # gcc / clang
    extra_compile_args += ["-include", shim_path]
    extra_compile_args += [
        "-Wno-unused-function",
        "-Wno-unused-variable",
        "-Wno-unused-parameter",
        "-Wno-unused-but-set-variable",
        "-Wno-sign-compare",
        "-Wno-implicit-function-declaration",
        "-Wno-incompatible-pointer-types",
        "-fno-strict-aliasing",
    ]

define_macros = [
    ("PYTHON_VERSION", PYVER_HEX),
    ("_NUITKA_EXE_MODE", "0"),
]

ext = Extension(
    name="nuitka_blob_loader._core",
    sources=[
        os.path.join("src", "blob_decode.c"),
        os.path.join("src", "helpers.c"),
        os.path.join("src", "module.c"),
    ],
    include_dirs=[SRC],
    define_macros=define_macros,
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args,
)

setup(
    name="nuitka_blob_loader",
    version="0.1.0",
    description="Extract .pyc files from a Nuitka constants blob using "
                "Nuitka's own HelpersConstantsBlob.c.",
    packages=["nuitka_blob_loader"],
    ext_modules=[ext],
    python_requires=">=3.12,<3.13",
    install_requires=[
        "xdis>=6.1.1",
    ],
    entry_points={
        "console_scripts": [
            "nuitka-blob-loader=nuitka_blob_loader.__main__:main",
        ],
    },
    zip_safe=False,
)
