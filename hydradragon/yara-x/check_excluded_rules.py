#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_excluded_rules.py

Auto-check the YARA-X exclusion list against the rules that actually exist.

For every entry in excluded_yara_x_rules.txt it searches the scanned .yar/.yara
files for a matching rule definition (i.e. a `rule <name>` / `private rule <name>`
declaration - the "rule " tag added to the start). Entries that match a real rule
are PRESENT (the exclusion still does something); entries that match nothing are
STALE (the rule was renamed/removed, so the exclusion entry is dead weight and can
be dropped from the list).

By default this is read-only and just reports. Pass --prune to rewrite the
exclusion list, keeping only the PRESENT entries (a timestamped .bak is made first).

Examples
--------
  # report only (default), scanning the rules directory next to this script
  py -3.12 check_excluded_rules.py

  # explicit paths
  py -3.12 check_excluded_rules.py -d rules -x excluded_yara_x_rules.txt

  # remove the stale entries from the list (backs up first)
  py -3.12 check_excluded_rules.py --prune

  # also prune the mirror copy used by the portable build
  py -3.12 check_excluded_rules.py --prune \
      --also ../../HydraDragonAVPortable/excluded_yara_x_rules/excluded_yara_x_rules.txt
"""

import argparse
import datetime
import os
import sys


def find_rule_files(directory, recurse=True):
    """Return all .yar/.yara files under `directory`."""
    out = []
    if recurse:
        for root, _dirs, files in os.walk(directory):
            for name in files:
                if name.endswith(".yar") or name.endswith(".yara"):
                    out.append(os.path.join(root, name))
    else:
        for name in os.listdir(directory):
            full = os.path.join(directory, name)
            if os.path.isfile(full) and (name.endswith(".yar") or name.endswith(".yara")):
                out.append(full)
    return sorted(out)


def rule_name_from_line(line):
    """If `line` declares a rule, return (name, is_private), else None.

    Handles 'rule NAME', 'private rule NAME', 'global rule NAME', optional
    rule tags ('rule NAME : tag1 tag2') and a same-line opening brace
    ('rule NAME {'). Mirrors how YARA_Util_Exclude_Remover.py delimits rules,
    but is a touch more permissive about the 'private'/'global' prefixes.

    is_private matters because the exclusion remover only ever drops PUBLIC
    rules (YARA_Util_Exclude_Remover.py: 'if ... and not boolPrivateRule') -
    private rules can't be excluded, so an entry that only matches a private
    rule is dead weight."""
    s = line.lstrip()
    depth = 0
    is_private = False
    if s.startswith("rule "):
        depth = 5
    elif s.startswith("private rule "):
        depth, is_private = 13, True
    elif s.startswith("global rule "):
        depth = 12
    elif s.startswith("global private rule "):
        depth, is_private = 20, True
    elif s.startswith("private global rule "):
        depth, is_private = 20, True
    if depth == 0:
        return None
    name = s[depth:]
    name = name.split("{", 1)[0]   # drop same-line opening brace
    name = name.split(":", 1)[0]   # drop rule tags
    name = name.strip().rstrip("\r").rstrip()
    if not name:
        return None
    return name, is_private


def collect_rule_names(files):
    """Stream every file (these rule packs can be 100+ MB) and return
    (public_names, private_names, name_to_file). A name that appears as BOTH
    public and private anywhere lands in public_names - one public definition
    is enough for the exclusion to do something."""
    public_names = set()
    private_names = set()
    name_to_file = {}
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # cheap pre-filter before the heavier parse
                    if "rule " not in line:
                        continue
                    parsed = rule_name_from_line(line)
                    if not parsed:
                        continue
                    name, is_private = parsed
                    if is_private:
                        private_names.add(name)
                    else:
                        public_names.add(name)
                    name_to_file.setdefault(name, fp)
        except OSError as e:
            print(f"[!] Could not read {fp}: {e}")
    return public_names, private_names, name_to_file


def load_exclude_entries(filepath):
    """Return the ORDERED, de-duplicated list of exclusion entries.

    Accepts bare names ('SEH__vba') or 'rule SEH__vba' style lines (the
    'rule ' prefix is stripped), matching load_exclude_list() in
    YARA_Util_Exclude_Remover.py. Order is preserved so a pruned file stays
    readable/diff-friendly."""
    entries = []
    seen = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            name = line.strip()
            if not name:
                continue
            if name.lower().startswith("rule "):
                name = name[5:].strip()
            if name and name not in seen:
                seen.add(name)
                entries.append(name)
    return entries


def write_report(report_path, scanned_dir, exclude_path, present, private_only, absent, total):
    lines = [
        "Excluded-rules auto-check report - " + str(datetime.datetime.now()),
        f"Directory scanned: {scanned_dir}",
        f"Exclusion list:    {exclude_path}",
        f"Total entries:     {total}",
        f"Present     (matches a PUBLIC rule, exclusion is live):       {len(present)}",
        f"Private-only(matches only a PRIVATE rule, cannot be excluded): {len(private_only)}",
        f"Absent      (no matching rule at all):                        {len(absent)}",
        f"Removable   (private-only + absent):                          {len(private_only) + len(absent)}",
        "",
        "== PRESENT (keep these - public rules) ==",
    ]
    lines.extend(f"  {n}" for n in present)
    lines.append("")
    lines.append("== PRIVATE-ONLY (removable - exclusion only targets public rules) ==")
    lines.extend(f"  {n}" for n in private_only)
    lines.append("")
    lines.append("== ABSENT (removable - no such rule) ==")
    lines.extend(f"  {n}" for n in absent)
    lines.append("")
    with open(report_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("\n".join(lines))


def prune_file(filepath, keep_set):
    """Rewrite `filepath` keeping only entries whose stripped name is in
    keep_set, preserving original order. Makes a timestamped .bak first.
    Returns (kept_count, removed_count)."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        original = f.readlines()

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = f"{filepath}.{stamp}.bak"
    with open(backup, "w", encoding="utf-8", errors="ignore") as f:
        f.writelines(original)

    kept_lines = []
    kept = removed = 0
    for line in original:
        name = line.strip()
        if not name:
            continue
        if name.lower().startswith("rule "):
            name = name[5:].strip()
        if name in keep_set:
            kept_lines.append(name + "\n")
            kept += 1
        else:
            removed += 1

    with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
        f.writelines(kept_lines)
    print(f"    backup written to: {backup}")
    return kept, removed


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Auto-check the YARA-X exclusion list against existing rules.")
    parser.add_argument("-d", "--directory", default=os.path.join(here, "rules"),
                        help="Directory of .yar/.yara files to scan (default: ./rules next to this script)")
    parser.add_argument("-x", "--exclude", default=os.path.join(here, "excluded_yara_x_rules.txt"),
                        help="Path to the exclusion list (default: ./excluded_yara_x_rules.txt next to this script)")
    parser.add_argument("--no-recurse", action="store_true", help="Do not recurse into subdirectories")
    parser.add_argument("--prune", action="store_true",
                        help="Rewrite the exclusion list keeping only PRESENT entries (backs up first)")
    parser.add_argument("--also", action="append", default=[],
                        help="Additional exclusion-list copy to prune with the same result (repeatable)")
    parser.add_argument("--report", default=os.path.join(here, "check_excluded_rules_report.txt"),
                        help="Where to write the full report")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        sys.exit(1)
    if not os.path.isfile(args.exclude):
        print(f"[!] Exclusion list not found: {args.exclude}")
        sys.exit(1)

    files = find_rule_files(args.directory, recurse=not args.no_recurse)
    print(f"[*] Scanning {len(files)} rule file(s) under {args.directory}")
    for fp in files:
        print(f"      - {fp}")

    public_names, private_names, name_to_file = collect_rule_names(files)
    print(f"[*] Found {len(public_names)} public and {len(private_names)} private "
          f"distinct rule name(s) in the scanned files")

    entries = load_exclude_entries(args.exclude)
    print(f"[*] Loaded {len(entries)} exclusion entry/entries from {args.exclude}")

    # Only a PUBLIC match keeps an entry alive: the remover never excludes
    # private rules. private-only and absent entries are both removable.
    present = [e for e in entries if e in public_names]
    private_only = [e for e in entries if e not in public_names and e in private_names]
    absent = [e for e in entries if e not in public_names and e not in private_names]

    print()
    print(f"[=] PRESENT      (matches a PUBLIC rule, exclusion is live): {len(present)}")
    print(f"[=] PRIVATE-ONLY (matches only a PRIVATE rule, removable):   {len(private_only)}")
    print(f"[=] ABSENT       (no matching rule, removable):             {len(absent)}")
    print(f"[=] REMOVABLE    (private-only + absent):                   {len(private_only) + len(absent)}")

    write_report(args.report, args.directory, args.exclude, present, private_only, absent, len(entries))
    print(f"[*] Full report written to: {args.report}")

    if args.prune:
        keep_set = set(present)
        print()
        print("[*] Pruning removable entries (keeping only PUBLIC-rule matches)...")
        targets = [args.exclude] + list(args.also)
        for target in targets:
            if not os.path.isfile(target):
                print(f"    [!] skip (not found): {target}")
                continue
            kept, removed = prune_file(target, keep_set)
            print(f"    {target}: kept {kept}, removed {removed}")
        print("[*] Prune complete.")
    else:
        if private_only or absent:
            print()
            print("[i] Re-run with --prune to remove the private-only + absent entries.")


if __name__ == "__main__":
    main()
