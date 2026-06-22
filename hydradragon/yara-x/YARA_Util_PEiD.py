#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA_Util_PEiD.py

Move every rule whose declaration contains `PEiD` (i.e. matches `rule …PEiD… {`)
out of a source YARA file into a separate file, and remove them from the source.

This is the "PEiD {" splitter: it pulls the PEiD packer/compiler identifier rules
into their own file (default `PEid_2.yar`) so the source no longer carries those
3k+ rules.

The source's leading `import "..."` lines are copied to the top of the output so
the moved rules still compile (many PEiD rules use `pe.entry_point`). A
timestamped `.bak` of the source is written before it is rewritten.

Examples
--------
  py -3.12 YARA_Util_PEiD.py                       # PEiD.yar  -> PEid_2.yar
  py -3.12 YARA_Util_PEiD.py -i clean_rules.yar -o PEid_2.yar
  py -3.12 YARA_Util_PEiD.py --match "PEiD" --dry-run
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


def rule_name(line):
    """Return the declared rule name if `line` is a rule declaration, else None."""
    s = line.lstrip()
    for prefix in _DECL_PREFIXES:
        if s.startswith(prefix):
            rest = s[len(prefix):].split("{", 1)[0].split(":", 1)[0]
            name = rest.strip().rstrip("\r").rstrip()
            return name or None
    return None


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
    """The `import "..."` lines from the source preamble (kept for the output)."""
    return [ln for ln in preamble if ln.lstrip().startswith('import "')]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        description='Move rules whose name contains "PEiD" into a separate YARA file.'
    )
    ap.add_argument(
        "-i", "--input", default=os.path.join(here, "PEiD.yar"),
        help="Source .yar to extract from (default: PEiD.yar)",
    )
    ap.add_argument(
        "-o", "--output", default=os.path.join(here, "PEid_2.yar"),
        help="Destination .yar for the matched rules (default: PEid_2.yar)",
    )
    ap.add_argument(
        "--match", default="PEiD",
        help='Substring a rule name must contain to be moved (default: "PEiD")',
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Report what would move without writing any files",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: input not found: {args.input}", file=sys.stderr)
        return 1

    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    preamble, blocks = split_blocks(lines)
    needle = args.match

    moved, kept = [], []
    for block in blocks:
        name = rule_name(block[0]) or ""
        (moved if needle in name else kept).append(block)

    print(f"{len(blocks)} rule(s) in {os.path.basename(args.input)}: "
          f"{len(moved)} match '{needle}', {len(kept)} kept.")
    if not moved:
        print("Nothing to move.")
        return 0
    if args.dry_run:
        for block in moved[:10]:
            print(f"  would move: {rule_name(block[0])}")
        if len(moved) > 10:
            print(f"  … and {len(moved) - 10} more")
        return 0

    # Build the output (imports + matched rules). Append if it already exists so
    # repeated runs accumulate rather than clobber.
    out_existing = ""
    if os.path.isfile(args.output):
        with open(args.output, "r", encoding="utf-8", errors="replace") as f:
            out_existing = f.read()
    out_parts = []
    if not out_existing:
        out_parts.extend(import_lines(preamble))
        if out_parts and not out_parts[-1].endswith("\n"):
            out_parts.append("\n")
        out_parts.append("\n")
    else:
        out_parts.append(out_existing if out_existing.endswith("\n") else out_existing + "\n")
    for block in moved:
        out_parts.extend(block)
        if not out_parts[-1].endswith("\n"):
            out_parts.append("\n")

    # Timestamped backup of the source before rewriting it.
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(args.input, f"{args.input}.{stamp}.bak")

    with open(args.output, "w", encoding="utf-8") as f:
        f.writelines(out_parts)

    # Rewrite the source with the preamble + only the kept rules.
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
