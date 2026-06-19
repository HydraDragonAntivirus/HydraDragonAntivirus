#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fix dangling block-comment terminators in a YARA file.

YARA-X rejects an orphaned ``*/`` (a block-comment close with no matching
``/*``) with::

    error[E001]: syntax error  --> clean_rules.yar:NNNN:1
    | */  ^ expecting `global`, `private`, `rule`, `import` or `include`, found `*`

These appear in aggregated rulesets where a rule is followed by a stray ``*/``
(e.g. ``}*/`` or a lone ``*/`` after a complete rule). This tool ONLY removes
those orphaned ``*/`` markers — it does not touch anything else.

It is comment/string/regex aware: ``*/`` inside a ``/* ... */`` block comment,
a ``// line comment``, a ``"string"``, or a ``/regex/`` is left untouched; only
a ``*/`` encountered at the top level (no open ``/*``) is removed.

Usage:
    python YARA_Fix_Comments.py [INPUT.yar] [-o OUTPUT.yar] [--in-place] [--stdout]

Defaults: INPUT  = clean_rules.yar next to this script
          OUTPUT = <input>_fixed.yar   (use --in-place to overwrite, keeping a .bak)
"""

import argparse
import sys
from pathlib import Path

# Scanner states.
_NORMAL, _LINE, _BLOCK, _STRING, _REGEX = range(5)


def fix_comments(text: str):
    """Return (fixed_text, removed_count): the text with every orphaned ``*/``
    (one seen outside a comment/string/regex) removed."""
    out = []
    i = 0
    n = len(text)
    removed = 0
    state = _NORMAL

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if state == _NORMAL:
            if c == "/" and nxt == "/":
                out.append(c)
                out.append(nxt)
                i += 2
                state = _LINE
            elif c == "/" and nxt == "*":
                out.append(c)
                out.append(nxt)
                i += 2
                state = _BLOCK
            elif c == "*" and nxt == "/":
                # Orphaned block-comment close — drop both characters.
                removed += 1
                i += 2
            elif c == '"':
                out.append(c)
                i += 1
                state = _STRING
            elif c == "/":
                # Lone '/' starts a regex literal in YARA (no division operator).
                out.append(c)
                i += 1
                state = _REGEX
            else:
                out.append(c)
                i += 1

        elif state == _LINE:
            out.append(c)
            i += 1
            if c == "\n":
                state = _NORMAL

        elif state == _BLOCK:
            if c == "*" and nxt == "/":
                out.append(c)
                out.append(nxt)
                i += 2
                state = _NORMAL
            else:
                out.append(c)
                i += 1

        elif state == _STRING:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
                continue
            i += 1
            if c == '"' or c == "\n":  # strings don't span newlines; bail on newline
                state = _NORMAL

        elif state == _REGEX:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
                continue
            i += 1
            if c == "/" or c == "\n":  # regexes don't span newlines
                state = _NORMAL

    return "".join(out), removed


def main(argv=None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Remove orphaned '*/' block-comment terminators that break YARA-X compilation."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=str(here / "clean_rules.yar"),
        help="input YARA file (default: clean_rules.yar next to this script)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="output file (default: <input>_fixed.yar)",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="overwrite the input file, keeping a .bak backup first",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print the fixed text to stdout instead of writing a file",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"error: input not found: {input_path}", file=sys.stderr)
        return 2

    text = input_path.read_text(encoding="utf-8", errors="ignore")
    fixed, removed = fix_comments(text)

    if args.stdout:
        # Write UTF-8 bytes directly so a non-UTF-8 console (e.g. Windows cp1254)
        # can't fail on characters in the ruleset.
        sys.stdout.buffer.write(fixed.encode("utf-8", errors="replace"))
        print(f"removed {removed} orphaned '*/' marker(s)", file=sys.stderr)
        return 0

    if args.in_place:
        backup = input_path.with_suffix(input_path.suffix + ".bak")
        backup.write_text(text, encoding="utf-8")
        input_path.write_text(fixed, encoding="utf-8")
        out_path = input_path
        print(f"backup written to {backup}", file=sys.stderr)
    else:
        out_path = (
            Path(args.output)
            if args.output
            else input_path.with_name(input_path.stem + "_fixed" + input_path.suffix)
        )
        out_path.write_text(fixed, encoding="utf-8")

    print(
        f"removed {removed} orphaned '*/' marker(s) from {input_path} -> {out_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
