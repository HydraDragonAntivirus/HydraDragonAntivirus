from setuptools import setup, Extension

ext = Extension(
    name="nuitka_deobfuscate",
    sources=[
        "nuitka_deobfuscate.c",
    ],
)

setup(
    name="nuitka_deobfuscate",
    version="0.1.0",
    ext_modules=[ext],
)
