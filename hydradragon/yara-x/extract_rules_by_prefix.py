#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_rules_by_prefix.py

Move every rule whose NAME starts with a given prefix out of a YARA file into a
separate file. Default: pull all `PEiD_*` rules (packer/compiler identifiers, not
malware signatures) out of clean_rules.yar into PEiD.yar.

The leading `import "..."` lines of the source are copied to the top of the
output so the moved rules still compile (some PEiD rules use `pe.`). A timestamped
.bak of the source is written before it is rewritten.

Examples
--------
  py -3.12 extract_rules_by_prefix.py                     # PEiD_ -> rules/PEiD.yar
  py -3.12 extract_rules_by_prefix.py --prefix PEiD_ \
      -i rules/clean_rules.yar -o rules/PEiD.yar
  py -3.12 extract_rules_by_prefix.py --dry-run
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
    """Return (preamble, blocks). Preamble = lines before the first rule;
    each block is the list of lines from a declaration up to the next one."""
    preamble = []
    blocks = []
    cur = None
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


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Move rules with a name prefix into a separate YARA file.")
    ap.add_argument("--prefix", default="PEiD_", help="Rule-name prefix to extract (default: PEiD_)")
    ap.add_argument("--contains", default=None,
                    help="Instead of name prefix, extract rules whose block contains this text "
                         "(e.g. 'rule_category = \"offensive_tool_keyword\"')")
    ap.add_argument("-i", "--input", default=os.path.join(here, "rules", "clean_rules.yar"),
                    help="Source .yar file (default: rules/clean_rules.yar)")
    ap.add_argument("-o", "--output", default=os.path.join(here, "rules", "PEiD.yar"),
                    help="Destination .yar file (default: rules/PEiD.yar)")
    ap.add_argument("--dry-run", action="store_true", help="Report only; write nothing")
    ap.add_argument("--no-backup", action="store_true", help="Do not write a .bak of the source")
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] Input not found: {args.input}")
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    preamble, blocks = split_blocks(lines)
    imports = [ln for ln in preamble if ln.lstrip().startswith("import ")]

    # Match either by block content (--contains) or by rule-name prefix.
    if args.contains is not None:
        criterion = f"containing {args.contains!r}"
        match = lambda b: any(args.contains in ln for ln in b)
    else:
        criterion = f"name prefix {args.prefix!r}"
        match = lambda b: (rule_name(b[0]) or "").startswith(args.prefix)

    moved, kept = [], []
    for b in blocks:
        (moved if match(b) else kept).append(b)

    print(f"[*] Source: {args.input}")
    print(f"[*] Total rules: {len(blocks)}  |  matching {criterion}: {len(moved)}  |  staying: {len(kept)}")
    if not moved:
        print("[=] Nothing to move.")
        return
    if args.dry_run:
        print(f"[i] DRY RUN — would write {len(moved)} rule(s) to {args.output} and remove them from the source.")
        return

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Write destination: imports header + a banner + the moved blocks.
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", errors="ignore") as f:
        f.writelines(imports)
        if imports:
            f.write("\n")
        f.write(f"// {len(moved)} rule(s) ({criterion}) moved out of "
                f"{os.path.basename(args.input)} on {stamp}\n\n")
        for b in moved:
            f.writelines(b)

    # Rewrite source without the moved blocks (preamble + kept blocks).
    if not args.no_backup:
        shutil.copyfile(args.input, f"{args.input}.{stamp}.bak")
    with open(args.input, "w", encoding="utf-8", errors="ignore") as f:
        f.writelines(preamble)
        for b in kept:
            f.writelines(b)

    print(f"[+] Wrote {len(moved)} rule(s) to {args.output}")
    print(f"[+] Removed them from {args.input}" + ("" if args.no_backup else f" (backup: {args.input}.{stamp}.bak)"))


if __name__ == "__main__":
    main()
