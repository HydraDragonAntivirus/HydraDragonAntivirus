#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""De-duplicate YARA rules safely.

Removes only EXACT duplicates: rules that share a name AND have an identical
body (the `{...}` block). So `rule Njrat: RAT { B }` and `rule Njrat { B }`
(tag-only difference, same body) ARE duplicates and the FIRST is kept, the rest
removed.

Rules that share a name but have DIFFERENT bodies are NOT removed — they are a
genuine name collision. The tool reports them as "needs rename" so you can
rename one by hand. It NEVER renames anything itself.

Removal is surgical (the duplicate rule's byte span is cut out); everything else
is left byte-for-byte intact. The parser is brace-balanced and skips strings,
`/regex/`, and comments, so hex strings `{ 4D 5A }` and regex quantifiers
`{2,3}` don't confuse rule boundaries.

Usage:
    python YARA_Dedup.py [INPUT.yar] [--dry-run] [-o OUTPUT.yar] [--in-place]
                         [--removed-output REMOVED.yar]

Writes TWO files (input untouched unless --in-place):
  - <input>_dedup.yar   : the kept rules (duplicates removed)
  - <input>_removed.yar : the duplicate rules that were removed (a record)
"""

import argparse
import hashlib
import sys
from pathlib import Path


# --- brace-balanced, comment/string/regex-aware rule parser ---------------

def _skip_quoted(text: str, i: int, quote: str) -> int:
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
    """text[start] == '{'; return index just past the matching '}'."""
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
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    start = i
    while i < n and (text[i].isalnum() or text[i] == "_"):
        i += 1
    return i, text[start:i]


def _backtrack_modifiers(text: str, rule_kw_start: int) -> int:
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


def iter_rule_spans(text: str):
    """Yield (name, start, brace, end) for each top-level rule: byte span
    [start, end) and the index of the body's opening '{'."""
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
                yield name, block_start, brace, end
                i = end
            continue
        i += 1


# --- dedup logic ----------------------------------------------------------

def analyze(text: str):
    """Return (to_remove, conflicts).

    to_remove: byte spans (start, end) of exact-duplicate rules (a kept rule of
               the same name already has this exact body) — safe to delete.
    conflicts: list of (name, line) for rules sharing a name with an earlier
               rule but having a DIFFERENT body — must be renamed by hand.
    """
    seen_keys = set()   # (name, body_hash) already kept
    seen_names = set()  # any name kept so far
    to_remove = []
    conflicts = []
    for name, start, brace, end in iter_rule_spans(text):
        body = text[brace:end]  # the {...} block — ignores the declaration/tags
        digest = hashlib.sha1(body.encode("utf-8", "ignore")).digest()
        key = (name, digest)
        if key in seen_keys:
            to_remove.append((start, end))           # exact duplicate
        elif name in seen_names:
            seen_keys.add(key)
            line = text.count("\n", 0, start) + 1
            conflicts.append((name, line))           # same name, different body
        else:
            seen_names.add(name)
            seen_keys.add(key)
    return to_remove, conflicts


def delete_spans(text: str, spans):
    out = []
    prev = 0
    for start, end in spans:
        out.append(text[prev:start])
        prev = end
    out.append(text[prev:])
    return "".join(out)


def main(argv=None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Remove exact-duplicate YARA rules (keep first); report "
        "same-name/different-body collisions to rename."
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
        help="output file (default: <input>_dedup.yar)",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="overwrite the input file instead of writing <input>_dedup.yar",
    )
    parser.add_argument(
        "--removed-output",
        default=None,
        help="write the removed duplicate rules here (default: <input>_removed.yar)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report only; write nothing",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"error: input not found: {input_path}", file=sys.stderr)
        return 2

    text = input_path.read_text(encoding="utf-8", errors="ignore")
    to_remove, conflicts = analyze(text)

    print(
        f"exact duplicates to remove (first occurrence kept): {len(to_remove)}",
        file=sys.stderr,
    )
    print(
        f"name collisions (same name, DIFFERENT body) - NOT removed, rename one: "
        f"{len(conflicts)}",
        file=sys.stderr,
    )
    for name, line in conflicts:
        print(f"  RENAME: {name}  (line {line})", file=sys.stderr)

    if args.dry_run:
        print("\n--dry-run: nothing written.", file=sys.stderr)
        return 0
    if not to_remove:
        print("no exact duplicates to remove.", file=sys.stderr)
        return 0

    fixed = delete_spans(text, to_remove)
    out_path = (
        input_path
        if args.in_place
        else Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + "_dedup" + input_path.suffix)
    )
    out_path.write_text(fixed, encoding="utf-8")

    # Save the removed duplicate rules so nothing is lost.
    removed_path = (
        Path(args.removed_output)
        if args.removed_output
        else input_path.with_name(input_path.stem + "_removed" + input_path.suffix)
    )
    removed_text = "\n\n".join(text[start:end] for start, end in to_remove)
    removed_path.write_text(removed_text + "\n" if removed_text else "", encoding="utf-8")

    print(
        f"\nremoved {len(to_remove)} exact duplicate(s) -> {out_path}"
        f"\nremoved rules saved to {removed_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
