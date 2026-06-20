#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced YARA de-duplication: detect rules that are the same in CONTENT even
when their string variable names differ.

The plain dedup (YARA_Dedup.py) compares raw rule bodies, so two rules that are
identical except that one writes `$a0 = "x"` and the other `$a = "x"` look
"different". This tool ignores the string variable NAMES: it compares

  * the ordered list of string VALUES + modifiers (the right-hand side of each
    `$name = ...`), and
  * the CONDITION with every string reference ($name / #name / @name / !name,
    incl. a trailing `*`) rewritten to its positional index ($0, $1, ...).

Rule name, tags and metadata are ignored. Two same-named rules with the same
canonical form are true duplicates: the FIRST is kept, the rest removed (and
saved to a record file). Same-named rules whose canonical form still DIFFERS are
NOT removed — they are reported as `RENAME` (this tool never renames anything).

Scope: only rules that SHARE A NAME are compared (this is what causes YARA-X
error[E012]); it does not merge differently-named rules.

Usage:
    python YARA_Dedup_Advanced.py [INPUT.yar] [--dry-run] [-o OUT.yar]
                                  [--in-place] [--removed-output REMOVED.yar]
"""

import argparse
import re
import sys
from pathlib import Path


# --- brace-balanced, comment/string/regex-aware rule parser ---------------

def _skip_quoted(text, i, quote):
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


def _match_block(text, start):
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


def _find_open_brace(text, i):
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


def _read_name(text, i):
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    start = i
    while i < n and (text[i].isalnum() or text[i] == "_"):
        i += 1
    return i, text[start:i]


def _backtrack_modifiers(text, rule_kw_start):
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


def iter_rule_spans(text):
    """Yield (name, start, brace, end): rule byte span and the body's '{' index."""
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


# --- canonicalization (string-name-agnostic) ------------------------------

_STR_DEF = re.compile(r"^\s*\$(\w+)\s*=\s*(.+?)\s*$")
# A quoted string, a /regex/, or a string reference [$#@!]name with optional '*'.
_COND_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|/(?:\\.|[^/\\])*/|([$#@!])(\w*)(\*?)')


def _split_sections(body: str):
    """Split a rule body ('{...}') into (strings_lines, condition_text)."""
    strings_lines, cond_parts = [], []
    section = None
    for line in body.splitlines():
        t = line.strip()
        if t == "meta:" or t.startswith("meta:"):
            section = "meta"
            continue
        if t == "strings:" or t.startswith("strings:"):
            section = "strings"
            continue
        if t.startswith("condition:"):
            section = "condition"
            rest = t[len("condition:"):].strip()
            if rest:
                cond_parts.append(rest)
            continue
        if section == "strings":
            strings_lines.append(line)
        elif section == "condition":
            cond_parts.append(t)
    return strings_lines, " ".join(cond_parts)


def canonical(body: str):
    """Return a canonical (string-name-agnostic) representation of a rule body:
    (tuple of normalized string values+modifiers, normalized condition)."""
    strings_lines, cond = _split_sections(body)

    name_to_idx = {}
    values = []
    cur_name, cur_val = None, []

    def _flush():
        if cur_name is not None:
            name_to_idx[cur_name] = len(values)
            values.append(" ".join(" ".join(cur_val).split()))

    for line in strings_lines:
        m = _STR_DEF.match(line)
        if m:
            _flush()
            cur_name, cur_val = m.group(1), [m.group(2)]
        elif cur_name is not None:
            # continuation of a multi-line value (e.g. a wrapped hex string)
            cur_val.append(line.strip())
    _flush()

    def rewrite(m):
        if m.group(1) is None:  # a quoted string or /regex/ literal — leave it
            return m.group(0)
        sigil, ident, star = m.group(1), m.group(2), m.group(3)
        if ident in name_to_idx:
            return f"{sigil}{name_to_idx[ident]}{star}"
        return m.group(0)  # anonymous '$', keywords, unknown wildcard prefixes

    cond_norm = " ".join(_COND_TOKEN.sub(rewrite, cond).split())
    return tuple(values), cond_norm


# --- dedup logic ----------------------------------------------------------

def analyze(text: str):
    """Return (to_remove, conflicts): byte spans of canonical duplicates to drop
    (first kept), and (name, line) for same-name rules still differing."""
    seen_keys = set()   # (name, canonical) already kept
    seen_names = set()
    to_remove = []
    conflicts = []
    for name, start, brace, end in iter_rule_spans(text):
        key = (name, canonical(text[brace:end]))
        if key in seen_keys:
            to_remove.append((start, end))
        elif name in seen_names:
            seen_keys.add(key)
            conflicts.append((name, text.count("\n", 0, start) + 1))
        else:
            seen_names.add(name)
            seen_keys.add(key)
    return to_remove, conflicts


def delete_spans(text, spans):
    out, prev = [], 0
    for start, end in spans:
        out.append(text[prev:start])
        prev = end
    out.append(text[prev:])
    return "".join(out)


def main(argv=None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Remove content-duplicate YARA rules ignoring string variable "
        "names (keep first); report same-name/different-content collisions."
    )
    parser.add_argument("input", nargs="?", default=str(here / "clean_rules.yar"))
    parser.add_argument("-o", "--output", default=None,
                        help="output file (default: <input>_dedup.yar)")
    parser.add_argument("--in-place", action="store_true",
                        help="overwrite the input file")
    parser.add_argument("--removed-output", default=None,
                        help="write the removed duplicates here (default: <input>_removed.yar)")
    parser.add_argument("--dry-run", action="store_true",
                        help="report only; write nothing")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"error: input not found: {input_path}", file=sys.stderr)
        return 2

    text = input_path.read_text(encoding="utf-8", errors="ignore")
    to_remove, conflicts = analyze(text)

    print(f"content duplicates to remove (first kept, names ignored): {len(to_remove)}",
          file=sys.stderr)
    print(f"name collisions still differing - NOT removed, rename one: {len(conflicts)}",
          file=sys.stderr)
    for name, line in conflicts:
        print(f"  RENAME: {name}  (line {line})", file=sys.stderr)

    if args.dry_run:
        print("\n--dry-run: nothing written.", file=sys.stderr)
        return 0
    if not to_remove:
        print("no content duplicates to remove.", file=sys.stderr)
        return 0

    fixed = delete_spans(text, to_remove)
    out_path = (
        input_path if args.in_place
        else Path(args.output) if args.output
        else input_path.with_name(input_path.stem + "_dedup" + input_path.suffix)
    )
    out_path.write_text(fixed, encoding="utf-8")

    removed_path = (
        Path(args.removed_output) if args.removed_output
        else input_path.with_name(input_path.stem + "_removed" + input_path.suffix)
    )
    removed_text = "\n\n".join(text[s:e] for s, e in to_remove)
    removed_path.write_text(removed_text + "\n" if removed_text else "", encoding="utf-8")

    print(f"\nremoved {len(to_remove)} content duplicate(s) -> {out_path}"
          f"\nremoved rules saved to {removed_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
