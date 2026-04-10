#!/usr/bin/env python3
"""
verify_pyc.py  --  Verify, inspect, and optionally decompile exported .pyc files.

Usage:
    python3 verify_pyc.py <output_dir> [options]

Options:
    --dis           Disassemble each code object with Python's 'dis' module
    --decompile     Attempt decompilation via 'decompile3' or 'uncompyle6'
                    (install with: pip install decompile3  or  pip install uncompyle6)
    --save-py       Write decompiled .py source next to each .pyc
    --magic <hex>   Override expected pyc magic (e.g. 0x0D0DA70A for 3.11)
    --verbose       Show full constant pool for each code object

Examples:
    python3 verify_pyc.py output --dis
    python3 verify_pyc.py output --decompile --save-py
    python3 verify_pyc.py output --dis --verbose
"""

import sys
import os
import dis
import marshal
import struct
import argparse
import traceback

# ------------------------------------------------------------------ #
#  Known .pyc magic numbers                                            #
# ------------------------------------------------------------------ #
MAGIC_TABLE = {
    0x0D0D550A: (3, 8,  "Python 3.8"),
    0x0D0D610A: (3, 9,  "Python 3.9"),
    0x0D0D6F0A: (3, 10, "Python 3.10"),
    0x0D0DA70A: (3, 11, "Python 3.11"),
    0x0D0DCB0A: (3, 12, "Python 3.12"),
    0x0D0DF50A: (3, 13, "Python 3.13"),
}


def describe_magic(magic_int: int) -> str:
    if magic_int in MAGIC_TABLE:
        _, _, label = MAGIC_TABLE[magic_int]
        return label
    return f"unknown (0x{magic_int:08X})"


# ------------------------------------------------------------------ #
#  Load a .pyc file                                                    #
# ------------------------------------------------------------------ #
def load_pyc(path: str):
    """
    Returns (magic_int, code_object) or raises on failure.
    """
    with open(path, "rb") as f:
        raw = f.read()

    if len(raw) < 16:
        raise ValueError(f"File too short ({len(raw)} bytes)")

    magic_int  = struct.unpack_from("<I", raw, 0)[0]
    flags      = struct.unpack_from("<I", raw, 4)[0]
    mtime      = struct.unpack_from("<I", raw, 8)[0]
    src_size   = struct.unpack_from("<I", raw, 12)[0]
    marshal_bytes = raw[16:]

    code = marshal.loads(marshal_bytes)
    return magic_int, flags, mtime, src_size, code


# ------------------------------------------------------------------ #
#  Recursive code-object inspector                                     #
# ------------------------------------------------------------------ #
def walk_code(code, depth: int = 0, verbose: bool = False):
    indent = "  " * depth
    name = getattr(code, 'co_qualname', None) or code.co_name
    filename = code.co_filename
    firstline = code.co_firstlineno

    print(f"{indent}▶ <code '{name}'  file='{filename}'  line={firstline}"
          f"  args={code.co_argcount}"
          f"  locals={code.co_nlocals}"
          f"  consts={len(code.co_consts)}"
          f"  names={len(code.co_names)}>")

    if verbose:
        print(f"{indent}  co_flags    = 0x{code.co_flags:04X}")
        print(f"{indent}  co_consts   = {code.co_consts}")
        print(f"{indent}  co_names    = {code.co_names}")
        print(f"{indent}  co_varnames = {code.co_varnames}")
        if hasattr(code, 'co_freevars'):
            print(f"{indent}  co_freevars = {code.co_freevars}")

    # Recursively inspect nested code objects
    for const in code.co_consts:
        if hasattr(const, 'co_code'):
            walk_code(const, depth + 1, verbose)


# ------------------------------------------------------------------ #
#  Disassemble                                                          #
# ------------------------------------------------------------------ #
def disassemble_code(code, depth: int = 0):
    indent = "  " * depth
    name = getattr(code, 'co_qualname', None) or code.co_name
    print(f"\n{indent}{'─' * 60}")
    print(f"{indent}dis: <code '{name}'>")
    print(f"{indent}{'─' * 60}")
    dis.dis(code)

    for const in code.co_consts:
        if hasattr(const, 'co_code'):
            disassemble_code(const, depth + 1)


# ------------------------------------------------------------------ #
#  Decompilation                                                        #
# ------------------------------------------------------------------ #
def try_decompile(pyc_path: str, save_py: bool) -> str | None:
    """
    Try decompile3, then uncompyle6, then return source or None.
    """
    source = None

    # --- try decompile3 ---
    try:
        import decompile
        from decompile import decompile_file
        import io
        buf = io.StringIO()
        decompile_file(pyc_path, buf)
        source = buf.getvalue()
    except ImportError:
        pass
    except Exception as e:
        print(f"  [decompile3] failed: {e}")

    # --- try uncompyle6 ---
    if source is None:
        try:
            import uncompyle6
            import io
            buf = io.StringIO()
            uncompyle6.decompile_file(pyc_path, buf)
            source = buf.getvalue()
        except ImportError:
            pass
        except Exception as e:
            print(f"  [uncompyle6] failed: {e}")

    # --- fallback: bytecode_graph / pycdc ---
    if source is None:
        # Try calling pycdc as subprocess if installed
        try:
            import subprocess
            result = subprocess.run(
                ["pycdc", pyc_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                source = result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if source is None:
        print("  [decompile] No decompiler available.")
        print("  Install with:  pip install decompile3")
        print("           or:  pip install uncompyle6")
        return None

    if save_py:
        py_path = pyc_path.replace(".pyc", ".py")
        with open(py_path, "w", encoding="utf-8") as f:
            f.write(source)
        print(f"  [decompile] Saved → {py_path}")

    return source


# ------------------------------------------------------------------ #
#  Main                                                                 #
# ------------------------------------------------------------------ #
def main():
    parser = argparse.ArgumentParser(
        description="Verify and inspect exported Nuitka .pyc files"
    )
    parser.add_argument("output_dir", help="Directory containing .pyc files")
    parser.add_argument("--dis",        action="store_true", help="Disassemble bytecode")
    parser.add_argument("--decompile",  action="store_true", help="Decompile to Python source")
    parser.add_argument("--save-py",    action="store_true", help="Save decompiled .py files")
    parser.add_argument("--magic",      type=lambda x: int(x, 0), default=None,
                        help="Expected magic override (e.g. 0x0D0DA70A)")
    parser.add_argument("--verbose",    action="store_true", help="Show constant pools")
    args = parser.parse_args()

    if not os.path.isdir(args.output_dir):
        print(f"ERROR: '{args.output_dir}' is not a directory.", file=sys.stderr)
        return 1

    # Collect all .pyc files recursively
    pyc_files = []
    for root, _, files in os.walk(args.output_dir):
        for fn in sorted(files):
            if fn.endswith(".pyc"):
                pyc_files.append(os.path.join(root, fn))

    if not pyc_files:
        print(f"No .pyc files found in '{args.output_dir}'")
        return 0

    ok = 0
    fail = 0
    running_magic = sys.implementation.cache_tag  # e.g. 'cpython-312'

    print(f"\nRunning Python: {sys.version}")
    print(f"Found {len(pyc_files)} .pyc file(s) in '{args.output_dir}'\n")
    print("=" * 70)

    for pyc_path in pyc_files:
        rel = os.path.relpath(pyc_path, args.output_dir)
        print(f"\n▸ {rel}")

        try:
            magic, flags, mtime, src_size, code = load_pyc(pyc_path)
            ver_str = describe_magic(magic)
            print(f"  magic=0x{magic:08X}  ({ver_str})")
            print(f"  flags={flags}  mtime={mtime}  src_size={src_size}")
            print(f"  co_filename = {code.co_filename}")
            print(f"  co_name     = {code.co_name}")
            print(f"  co_firstlineno = {code.co_firstlineno}")

            # Magic mismatch warning
            if args.magic and magic != args.magic:
                print(f"  ⚠ magic mismatch: expected 0x{args.magic:08X}")

            # Walk code tree
            walk_code(code, depth=1, verbose=args.verbose)

            # Disassemble
            if args.dis:
                disassemble_code(code, depth=1)

            # Decompile
            if args.decompile:
                print(f"\n  [decompile] Attempting decompilation of {rel}...")
                source = try_decompile(pyc_path, args.save_py)
                if source:
                    preview = source[:500]
                    print("  " + preview.replace("\n", "\n  "))
                    if len(source) > 500:
                        print(f"  ... ({len(source)} chars total)")

            ok += 1

        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            if args.verbose:
                traceback.print_exc()
            fail += 1

    print("\n" + "=" * 70)
    print(f"\nResult: {ok} ok  /  {fail} failed  /  {len(pyc_files)} total")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
