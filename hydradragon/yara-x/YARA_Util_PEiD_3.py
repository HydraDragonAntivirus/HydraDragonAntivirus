#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA_Util_PEiD_3.py

Move every rule whose declaration carries the `PEiD` TAG — i.e. a line that
starts with `rule` and ends with `: PEiD {` (e.g. `rule ASPack_107b_DLL: PEiD {`)
— out of a source YARA file into a separate file (default `PEid_3.yar`), removing
them from the source.

This is the tag-based companion to YARA_Util_PEiD.py (which matches PEiD in the
rule NAME). Here the match is the trailing YARA tag, not the name.

The source's leading `import "..."` lines are copied to the top of the output so
the moved rules still compile. A timestamped `.bak` of the source is written
before it is rewritten.

Examples
--------
  py -3.12 YARA_Util_PEiD_3.py                      # PEiD.yar -> PEid_3.yar
  py -3.12 YARA_Util_PEiD_3.py -i clean_rules.yar -o PEid_3.yar
  py -3.12 YARA_Util_PEiD_3.py --tag PEiD --dry-run
"""

import argparse
import datetime
import os
import shutil
import sys

_DECL_PREFIXES = (
    "private global rule ",
    "global private rule ",
    "global rule ",
    "private rule ",
    "rule ",
)


def _decl_rest(line):
    """If `line` is a rule declaration, return the text after `rule ` (i.e.
    `NAME [: tag1 tag2 ...] {...`), else None."""
    s = line.lstrip()
    for prefix in _DECL_PREFIXES:
        if s.startswith(prefix):
            return s[len(prefix):]
    return None


def rule_name(line):
    """The declared rule name, or None if `line` isn't a declaration."""
    rest = _decl_rest(line)
    if rest is None:
        return None
    name = rest.split("{", 1)[0].split(":", 1)[0].strip()
    return name or None


def rule_tags(line):
    """The YARA tags on a rule declaration (the tokens between `:` and `{`)."""
    rest = _decl_rest(line)
    if rest is None:
        return []
    before_brace = rest.split("{", 1)[0]
    if ":" not in before_brace:
        return []
    return before_brace.split(":", 1)[1].split()


def split_blocks(lines):
    """Return (preamble, blocks). Preamble = lines before the first rule; each
    block is the lines from one declaration up to (but not including) the next."""
    preamble, blocks, cur = [], [], None
    for line in lines:
        if rule_name(line) is not None:
            if cur is not None:
                blocks.append(cur)
            cur = [line]
        elif cur is None:
            preamble.append(line)
        else:
            cur.append(line)
    if cur is not None:
        blocks.append(cur)
    return preamble, blocks


def import_lines(preamble):
    return [ln for ln in preamble if ln.lstrip().startswith('import "')]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        description='Move rules carrying a given YARA tag (default "PEiD") into a separate file.'
    )
    ap.add_argument("-i", "--input", default=os.path.join(here, "PEiD.yar"),
                    help="Source .yar to extract from (default: PEiD.yar)")
    ap.add_argument("-o", "--output", default=os.path.join(here, "PEid_3.yar"),
                    help="Destination .yar for the tagged rules (default: PEid_3.yar)")
    ap.add_argument("--tag", default="PEiD",
                    help='Tag a rule must carry to be moved (default: "PEiD")')
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what would move without writing any files")
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: input not found: {args.input}", file=sys.stderr)
        return 1

    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    preamble, blocks = split_blocks(lines)
    tag = args.tag

    moved, kept = [], []
    for block in blocks:
        (moved if tag in rule_tags(block[0]) else kept).append(block)

    print(f"{len(blocks)} rule(s) in {os.path.basename(args.input)}: "
          f"{len(moved)} tagged '{tag}', {len(kept)} kept.")
    if not moved:
        print("Nothing to move.")
        return 0
    if args.dry_run:
        for block in moved[:10]:
            print(f"  would move: {rule_name(block[0])}")
        if len(moved) > 10:
            print(f"  ... and {len(moved) - 10} more")
        return 0

    # Output: imports + matched rules (append if the file already exists).
    out_existing = ""
    if os.path.isfile(args.output):
        with open(args.output, "r", encoding="utf-8", errors="replace") as f:
            out_existing = f.read()
    out_parts = []
    if not out_existing:
        out_parts.extend(import_lines(preamble))
        if out_parts:
            out_parts.append("\n")
    else:
        out_parts.append(out_existing if out_existing.endswith("\n") else out_existing + "\n")
    for block in moved:
        out_parts.extend(block)
        if not out_parts[-1].endswith("\n"):
            out_parts.append("\n")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(args.input, f"{args.input}.{stamp}.bak")

    with open(args.output, "w", encoding="utf-8") as f:
        f.writelines(out_parts)

    new_src = list(preamble)
    for block in kept:
        new_src.extend(block)
    with open(args.input, "w", encoding="utf-8") as f:
        f.writelines(new_src)

    print(f"Moved {len(moved)} rule(s) -> {os.path.basename(args.output)}; "
          f"{len(kept)} remain in {os.path.basename(args.input)} "
          f"(backup: {os.path.basename(args.input)}.{stamp}.bak)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
