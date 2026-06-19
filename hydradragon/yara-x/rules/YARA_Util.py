#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect, extract, and remove informational (INFO) YARA rules.

A rule is treated as "informational" / non-malicious when EITHER:
  * its NAME carries an INFO marker as any underscore-delimited segment
    (``INFO_`` prefix, ``_INFO_`` infix, or ``_INFO`` suffix), OR
  * its META section marks it as info — a meta value of ``info`` or
    ``informational`` (e.g. ``severity = "info"``, ``level = "informational"``).
Matching is case-insensitive.

This both EXTRACTS the INFO rules into a separate file and (with ``--remove``)
writes the ruleset with the INFO rules stripped out — i.e. it doubles as the
"INFO remover".

The name matching mirrors the HydraDragon scan pipeline, which treats
``SUSP_``/``SUSPICIOUS`` rules as *suspicious* and ``INFO`` rules as
non-malicious (see hydradragonav/src/pipeline.rs).

Usage:
    python YARA_Util.py [INPUT.yar] [-o INFO_OUT.yar] [--remove [--clean-output CLEAN_OUT.yar]]

Defaults: INPUT    = clean_rules.yar next to this script
          INFO_OUT = info_rules.yar next to this script
          CLEAN_OUT (with --remove) = <input>_no_info.yar

This is a standalone analysis/maintenance tool; it is not part of the portable
build. The YARA parsing is brace-balanced and skips strings, regexes, and
comments, so hex strings like ``{ 4D 5A }`` and regex quantifiers like ``{2,3}``
do not confuse rule-boundary detection.
"""

import argparse
import re
import sys
from pathlib import Path

IMPORT_RE = re.compile(r'^\s*import\s+"[^"]+"\s*$', re.MULTILINE)


def info_marked(name: str) -> bool:
    """True if any underscore-delimited segment of the name is 'info' (an INFO_
    prefix, _INFO_ infix, or _INFO suffix), case-insensitive."""
    return "info" in name.lower().split("_")


def meta_info_marked(block_text: str) -> bool:
    """True if the rule's `meta:` section marks it as informational, i.e. a
    metadata value of `info` or `informational` (e.g. `severity = "info"`,
    `level = "informational"`, or an unquoted `type = info`). Matching is on the
    whole value, so a `description = "... information ..."` does NOT match."""
    in_meta = False
    for raw in block_text.splitlines():
        line = raw.strip()
        if not in_meta:
            if line == "meta:" or line.startswith("meta:"):
                in_meta = True
            continue
        # Inside meta — stop at the next section or the rule's closing brace.
        if line.startswith("strings:") or line.startswith("condition:") or line.startswith("}"):
            break
        if "=" not in line:
            continue
        value = line.split("=", 1)[1].strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        if value.strip().lower() in ("info", "informational"):
            return True
    return False


def _skip_quoted(text: str, i: int, quote: str) -> int:
    """Given text[i] == quote (opening), return the index just past the closing
    (unescaped) quote. Handles backslash escapes. Used for "strings" and /regex/."""
    n = len(text)
    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return n


def _match_block(text: str, start: int):
    """text[start] must be '{'. Return the index just past the matching '}',
    counting braces while skipping comments, "strings", and /regexes/."""
    n = len(text)
    depth = 0
    i = start
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if c == '"':
            i = _skip_quoted(text, i, '"')
            continue
        if c == "/":
            # In YARA, a lone '/' starts a regex literal (no division operator).
            i = _skip_quoted(text, i, "/")
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue
        i += 1
    return None


def _find_open_brace(text: str, i: int):
    """From i, skip whitespace, comments, and an optional ': tags' section and
    return the index of the rule body's opening '{'."""
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            return i
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        i += 1
    return None


def _read_name(text: str, i: int):
    """Skip whitespace then read an identifier; return (next_index, name)."""
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    start = i
    while i < n and (text[i].isalnum() or text[i] == "_"):
        i += 1
    return i, text[start:i]


def _backtrack_modifiers(text: str, rule_kw_start: int) -> int:
    """Extend a rule block's start backwards over 'private'/'global' modifiers
    on the same line."""
    start = rule_kw_start
    while True:
        j = start
        while j > 0 and text[j - 1] in " \t":
            j -= 1
        k = j
        while k > 0 and (text[k - 1].isalnum() or text[k - 1] == "_"):
            k -= 1
        if text[k:j] in ("private", "global"):
            start = k
        else:
            return start


def iter_rules(text: str):
    """Yield (name, block_text) for each top-level YARA rule."""
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if c == '"':
            i = _skip_quoted(text, i, '"')
            continue
        if c.isalpha() or c == "_":
            word_start = i
            while i < n and (text[i].isalnum() or text[i] == "_"):
                i += 1
            if text[word_start:i] == "rule":
                i, name = _read_name(text, i)
                brace = _find_open_brace(text, i)
                if brace is None:
                    break
                end = _match_block(text, brace)
                if end is None:
                    break
                block_start = _backtrack_modifiers(text, word_start)
                yield name, text[block_start:end]
                i = end
            continue
        i += 1


def classify_rules(text: str):
    """Partition a ruleset into INFO (non-malicious) and the rest.

    A rule is INFO when its NAME has an `info` segment OR its META section marks
    it as info. Returns (imports, info_blocks, other_blocks)."""
    imports = []
    seen = set()
    for line in IMPORT_RE.findall(text):
        line = line.strip()
        if line not in seen:
            seen.add(line)
            imports.append(line)

    info_blocks, other_blocks = [], []
    for name, block in iter_rules(text):
        if info_marked(name) or meta_info_marked(block):
            info_blocks.append(block)
        else:
            other_blocks.append(block)
    return imports, info_blocks, other_blocks


def render(imports, blocks) -> str:
    """Render imports + rule blocks back into a YARA file body."""
    parts = []
    if imports:
        parts.append("\n".join(imports))
    parts.extend(blocks)
    return ("\n\n".join(parts).rstrip() + "\n") if parts else ""


def main(argv=None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Detect INFO (non-malicious) YARA rules by rule name or "
        "metadata, then extract and/or remove them."
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
        default=str(here / "info_rules.yar"),
        help="where to write the extracted INFO rules (default: info_rules.yar)",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="also write the ruleset with INFO rules removed (the 'remover' output)",
    )
    parser.add_argument(
        "--clean-output",
        default=None,
        help="path for the INFO-removed ruleset (default: <input>_no_info.yar); implies --remove",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print the extracted INFO rules to stdout instead of writing -o",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"error: input not found: {input_path}", file=sys.stderr)
        return 2

    text = input_path.read_text(encoding="utf-8", errors="ignore")
    imports, info_blocks, other_blocks = classify_rules(text)

    info_text = render(imports, info_blocks)
    if args.stdout:
        # Write UTF-8 bytes so a non-UTF-8 console (e.g. Windows cp1254) can't
        # fail on characters in the rules.
        sys.stdout.buffer.write(info_text.encode("utf-8", errors="replace"))
    else:
        Path(args.output).write_text(info_text, encoding="utf-8")
        print(
            f"extracted {len(info_blocks)} INFO rule(s) from {input_path} -> {args.output}",
            file=sys.stderr,
        )

    if args.remove or args.clean_output:
        clean_path = (
            Path(args.clean_output)
            if args.clean_output
            else input_path.with_name(input_path.stem + "_no_info" + input_path.suffix)
        )
        clean_path.write_text(render(imports, other_blocks), encoding="utf-8")
        print(
            f"removed {len(info_blocks)} INFO rule(s); kept {len(other_blocks)} -> {clean_path}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
