#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dedupe_content_rules.py

Detect rules that are duplicates by CONTENT and keep the richest copy.

Two rules are duplicates when their `strings:` and `condition:` are equivalent
after normalization — IGNORING:
  * the rule name and any rule tags  (rule CPAV  ==  rule CPAV : Packer PEiD)
  * the whole `meta:` block
  * whitespace and newlines
  * hex-byte case                    ({ E8 ?? } == { e8 ?? })
  * redundant parentheses in the condition
        $a0 at (pe.entry_point)  ==  $a0 at pe.entry_point
Text inside "double-quoted strings" is compared verbatim (case + spaces kept),
so rules that only differ by an actual string literal are NOT merged.

Of each duplicate group the KEPT copy is the richest: most `meta:` lines, then
tagged over untagged, then the longest source text. The rest are reported (and,
with --remove, deleted; the removed blocks are saved to a log so nothing is lost).

This is the dedup half of YARA_Util, standalone and with a normalizer strong
enough to see the (pe.entry_point) vs pe.entry_point case as a duplicate.

Examples
--------
  # check a single file, report only
  py -3.12 dedupe_content_rules.py -f rules/clean_rules.yar

  # check a directory, report only
  py -3.12 dedupe_content_rules.py -d rules

  # actually remove the non-richest duplicates (backs up + logs first)
  py -3.12 dedupe_content_rules.py -d rules --remove
"""

import argparse
import datetime
import os
import shutil
import sys


_DECL_PREFIXES = (
    ("private global rule ", True),
    ("global private rule ", True),
    ("global rule ", False),
    ("private rule ", True),
    ("rule ", False),
)


def parse_rule_decl(line):
    """(name, is_private) if `line` declares a rule, else None."""
    s = line.lstrip()
    for prefix, is_private in _DECL_PREFIXES:
        if s.startswith(prefix):
            rest = s[len(prefix):].split("{", 1)[0].split(":", 1)[0]
            name = rest.strip().rstrip("\r").rstrip()
            return (name, is_private) if name else None
    return None


def has_tags(decl_line):
    """True if the declaration carries `: tag1 tag2` before the opening brace."""
    return ":" in decl_line.split("{", 1)[0]


def extract_blocks(lines):
    """Split a file into (preamble_lines, blocks). Each block spans its
    declaration line to the line before the next declaration; the preamble is
    everything before the first rule (imports/includes/comments)."""
    preamble = []
    blocks = []
    cur = None
    for line in lines:
        if parse_rule_decl(line) is not None:
            if cur is not None:
                blocks.append(cur)
            cur = {"lines": [line]}
        elif cur is None:
            preamble.append(line)
        else:
            cur["lines"].append(line)
    if cur is not None:
        blocks.append(cur)
    return preamble, blocks


def normalize(text, drop_parens):
    """Normalize a strings/condition fragment for comparison.

    Outside double-quoted strings: drop whitespace and comments, uppercase
    everything (so hex case and keyword/identifier case don't matter), and -- when
    `drop_parens` -- drop '(' and ')'. Inside "..." everything is copied verbatim
    so real string literals still distinguish rules."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                out.append(c)
                out.append(text[i + 1])
                i += 2
                continue
            out.append(c)
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":          # // line comment
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":          # /* block comment */
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if c.isspace():
            i += 1
            continue
        if drop_parens and c in "()":
            i += 1
            continue
        out.append(c.upper())
        i += 1
    return "".join(out)


def analyze_block(block_lines):
    """Return (meta_richness, content_key) for a rule block. `content_key` is the
    normalized strings+condition; `meta_richness` is the count of real meta lines."""
    section = None
    meta_richness = 0
    strings_parts = []
    cond_parts = []
    for line in block_lines:
        t = line.strip()
        low = t.lower()
        if low == "meta:":
            section = "meta"
            continue
        if low == "strings:":
            section = "strings"
            continue
        if low == "condition:":
            section = "condition"
            continue
        if t == "}":
            section = None
            continue
        if not t:
            continue
        if section == "meta":
            if not t.startswith("//"):
                meta_richness += 1
        elif section == "strings":
            strings_parts.append(t)
        elif section == "condition":
            # condition may share its line with the closing brace
            if t.endswith("}"):
                cond_parts.append(t[:-1])
                section = None
            else:
                cond_parts.append(t)
    # Join with newlines (NOT spaces): normalize() strips `// ...` comments to
    # the end of their line, so collapsing the lines onto one would let the first
    # inline comment swallow the entire rest of the strings/condition.
    strings_norm = normalize("\n".join(strings_parts), drop_parens=False)
    cond_norm = normalize("\n".join(cond_parts), drop_parens=True)
    return meta_richness, strings_norm + "||" + cond_norm


def find_rule_files(directory, recurse):
    out = []
    walker = os.walk(directory) if recurse else [(directory, [], os.listdir(directory))]
    for root, _dirs, files in walker:
        for name in files:
            if name.endswith(".yar") or name.endswith(".yara"):
                full = os.path.join(root, name)
                if os.path.isfile(full):
                    out.append(full)
    return sorted(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Detect content-duplicate YARA rules; keep the richest.")
    parser.add_argument("-d", "--directory", default=None, help="Directory of .yar/.yara files")
    parser.add_argument("-f", "--file", default=None, help="A single .yar/.yara file")
    parser.add_argument("--no-recurse", action="store_true", help="Do not recurse subdirectories")
    parser.add_argument("--remove", action="store_true", help="Delete the non-richest duplicates (default: report only)")
    parser.add_argument("-o", "--output", default=None, help="Write cleaned copies here instead of editing in place")
    parser.add_argument("--no-backup", action="store_true", help="When editing in place, skip the .bak")
    parser.add_argument("--removed-log", default=os.path.join(here, "removed_content_duplicates.yar"),
                        help="Where to append removed duplicate blocks")
    args = parser.parse_args()

    if args.file:
        files = [args.file]
    elif args.directory:
        files = find_rule_files(args.directory, recurse=not args.no_recurse)
    else:
        files = find_rule_files(os.path.join(here, "rules"), recurse=True)
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print("[!] No .yar/.yara files found.")
        sys.exit(1)

    print(f"[*] Scanning {len(files)} file(s){' (REMOVE mode)' if args.remove else ' (report only)'}")
    if args.output:
        os.makedirs(args.output, exist_ok=True)

    # key -> list of entries; plus per-file block cache so removal needn't re-read.
    groups = {}
    file_blocks = {}
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError as e:
            print(f"  [!] skip {fp}: {e}")
            continue
        preamble, blocks = extract_blocks(lines)
        file_blocks[fp] = (preamble, blocks)
        for idx, b in enumerate(blocks):
            name, _is_private = parse_rule_decl(b["lines"][0])
            richness, key = analyze_block(b["lines"])
            if key == "||":
                continue  # no strings and no condition parsed — nothing to compare
            text = "".join(b["lines"])
            groups.setdefault(key, []).append({
                "file": fp, "idx": idx, "name": name,
                "richness": richness, "tags": has_tags(b["lines"][0]), "len": len(text),
            })

    # Resolve winners; collect losers per file.
    dup_groups = [(k, v) for k, v in groups.items() if len(v) > 1]
    remove_by_file = {}
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if not dup_groups:
        print("[=] No content-duplicate rules found.")
        return

    print(f"[=] Found {len(dup_groups)} duplicate group(s):\n")
    for _key, entries in dup_groups:
        winner = max(entries, key=lambda e: (e["richness"], e["tags"], e["len"]))
        print(f"  KEEP  {winner['name']}  ({os.path.basename(winner['file'])}, "
              f"{winner['richness']} meta line(s){', tagged' if winner['tags'] else ''})")
        for e in entries:
            if e is winner:
                continue
            tag = "REMOVE " if args.remove else "DUP    "
            print(f"    {tag}{e['name']}  ({os.path.basename(e['file'])}, "
                  f"{e['richness']} meta line(s){', tagged' if e['tags'] else ''})")
            remove_by_file.setdefault(e["file"], set()).add(e["idx"])
        print()

    total_dups = sum(len(v) - 1 for _k, v in dup_groups)
    print(f"[=] Duplicate copies to drop: {total_dups}")

    if not args.remove:
        print("[i] Report only. Re-run with --remove to delete the duplicates.")
        return

    removed_chunks = []
    for fp, losers in remove_by_file.items():
        preamble, blocks = file_blocks[fp]
        kept = list(preamble)
        for idx, b in enumerate(blocks):
            if idx in losers:
                removed_chunks.append(f"// ===== removed from {fp} ({stamp}) =====\n" + "".join(b["lines"]) + "\n")
            else:
                kept.extend(b["lines"])
        if args.output:
            out_path = os.path.join(args.output, os.path.basename(fp))
            with open(out_path, "w", encoding="utf-8", errors="ignore") as fh:
                fh.writelines(kept)
        else:
            if not args.no_backup:
                shutil.copyfile(fp, f"{fp}.{stamp}.bak")
            with open(fp, "w", encoding="utf-8", errors="ignore") as fh:
                fh.writelines(kept)
        print(f"  [-] {fp}: removed {len(losers)} duplicate(s)")

    if removed_chunks:
        with open(args.removed_log, "a", encoding="utf-8", errors="ignore") as fh:
            fh.write("".join(removed_chunks))
        print(f"[*] Removed blocks appended to: {args.removed_log}")
        if not args.output and not args.no_backup:
            print(f"[*] Per-file backups written as *.{stamp}.bak")


if __name__ == "__main__":
    main()
