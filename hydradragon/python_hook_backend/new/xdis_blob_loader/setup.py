import sys

if sys.platform != "win32":
    raise RuntimeError("This extension is Windows-only.")

from setuptools import Extension, setup

ext = Extension(
    name="xdis_blob_loader",
    sources=["blob_loader.c"],
    extra_compile_args=["/O2", "/DNDEBUG", "/std:c11"],
)

setup(
    name="xdis_blob_loader",
    version="0.1.0",
    description="Windows-only C loader for Nuitka constant blobs with xdis marshal support.",
    ext_modules=[ext],
    zip_safe=False,
)
