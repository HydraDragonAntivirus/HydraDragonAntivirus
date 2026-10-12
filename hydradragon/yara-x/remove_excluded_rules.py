#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remove_excluded_rules.py

Lite excluded-rules remover. Does ONE thing: strip the rule blocks named in
exclusion lists out of the .yar/.yara files in a directory.

Exclusion lists (-x, repeatable; a directory means every list in it):
  * excluded_yara_x_rules.txt style: one rule name per line ('rule NAME' allowed),
    '#' or '//' comments.
  * ClamAV-style .ign2 / .ign ignore lists, as written by the Multron dashboard
    ("False positive: turn off a signature"): 'NAME' or 'NAME:md5' per line,
    '#' comments. The same file that turns the rule off at run time can then
    remove it from the sources for good. No
duplicate scan, no content-dedupe, no index building (that is YARA_Util's job) —
just the exclusion pass, using the same rule-block boundaries YARA_Util uses.

Like YARA_Util_Exclude_Remover.py, only PUBLIC rules are removed: a `private rule`
is never excluded (private rules don't trigger detections on their own, and other
rules may depend on them), so an exclusion entry that matches a private rule is
left in place. See its ProcessRule(): `... and not boolPrivateRule`.

A rule block runs from its `rule NAME` / `private rule NAME` declaration line up
to (not including) the next declaration; everything before the first rule
(imports/includes) is always kept.

Removed blocks are written to removed_excluded_rules.yar so nothing is lost.

Examples
--------
  # dry run: report what WOULD be removed, change nothing
  py -3.12 remove_excluded_rules.py --dry-run

  # remove in place (a timestamped .bak is written per changed file first)
  py -3.12 remove_excluded_rules.py

  # write cleaned copies to a separate dir, leave originals untouched
  py -3.12 remove_excluded_rules.py -o clean_rules

  # explicit paths
  py -3.12 remove_excluded_rules.py -d rules -x excluded_yara_x_rules.txt

  # the dashboard's FP list (.ign2), together with the txt list
  py -3.12 remove_excluded_rules.py -x multron_fp.ign2 -x excluded_yara_x_rules.txt

  # every .ign2 / .ign list in a folder (e.g. the server's yara_rules folder)
  py -3.12 remove_excluded_rules.py -x C:\\path\\to\\yara_rules
"""

import argparse
import datetime
import os
import shutil
import sys


def find_rule_files(directory, recurse=True):
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


# Declaration prefixes, longest first so 'private rule' isn't shadowed by 'rule'.
# Each maps to whether the rule is private (only public rules get excluded).
_DECL_PREFIXES = (
    ("private global rule ", True),
    ("global private rule ", True),
    ("global rule ", False),
    ("private rule ", True),
    ("rule ", False),
)


def parse_rule_decl(line):
    """If `line` declares a rule, return (name, is_private), else None. Handles
    rule tags ('rule NAME : tag') and a same-line opening brace ('rule NAME {')."""
    s = line.lstrip()
    for prefix, is_private in _DECL_PREFIXES:
        if s.startswith(prefix):
            rest = s[len(prefix):]
            rest = rest.split("{", 1)[0]   # drop same-line opening brace
            rest = rest.split(":", 1)[0]   # drop rule tags
            name = rest.strip().rstrip("\r").rstrip()
            return (name, is_private) if name else None
    return None


LIST_EXTS = (".ign2", ".ign")


def load_exclude_set(filepath):
    """Rule names to remove, accepting bare names or 'rule NAME' lines (the
    'rule ' prefix is stripped) — same as YARA_Util's load_exclude_list — and
    ClamAV ignore-list lines 'NAME:md5' (.ign2 / .ign)."""
    names = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            name = line.strip()
            if not name or name.startswith("#") or name.startswith("//"):
                continue
            if name.lower().startswith("rule "):
                name = name[5:].strip()
            # 'NAME:md5' (ign2) or 'NAME : tag' — a YARA identifier has no ':'.
            name = name.split(":", 1)[0].strip()
            if name:
                names.add(name)
    return names


def resolve_exclude_files(paths):
    """Files behind the -x arguments: a file as is, a directory as its
    .ign2 / .ign lists. Returns (files, missing)."""
    files, missing = [], []
    for p in paths:
        if os.path.isdir(p):
            found = sorted(os.path.join(p, n) for n in os.listdir(p)
                           if n.lower().endswith(LIST_EXTS) and os.path.isfile(os.path.join(p, n)))
            if not found:
                missing.append(p + " (no .ign2 / .ign list in it)")
            files.extend(found)
        elif os.path.isfile(p):
            files.append(p)
        else:
            missing.append(p)
    return files, missing


def strip_excluded(lines, excluded):
    """Stream a file's lines, dropping any PUBLIC rule block whose name is in
    `excluded`. Returns (kept_lines, removed_lines, removed_names,
    skipped_private_names)."""
    kept = []
    removed = []
    removed_names = []
    skipped_private = []
    excluding = False
    for line in lines:
        decl = parse_rule_decl(line)
        if decl is not None:
            name, is_private = decl
            if name in excluded and is_private:
                # Matches the exclusion list but is private → never removed.
                skipped_private.append(name)
            excluding = (name in excluded) and not is_private
            if excluding:
                removed_names.append(name)
        if excluding:
            removed.append(line)
        else:
            kept.append(line)
    return kept, removed, removed_names, skipped_private


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Lite remover: strip excluded rules from YARA files.")
    parser.add_argument("-d", "--directory", default=os.path.join(here, "rules"),
                        help="Directory of .yar/.yara files (default: ./rules next to this script)")
    parser.add_argument("-x", "--exclude", action="append", default=None,
                        help="Exclusion list: .txt, .ign2 / .ign, or a folder of .ign2 / .ign lists. "
                             "Repeatable. Default: ./excluded_yara_x_rules.txt next to this script")
    parser.add_argument("-o", "--output", default=None,
                        help="Write cleaned copies here instead of editing originals in place")
    parser.add_argument("--no-recurse", action="store_true", help="Do not recurse into subdirectories")
    parser.add_argument("--dry-run", action="store_true", help="Report only; write nothing")
    parser.add_argument("--no-backup", action="store_true",
                        help="When editing in place, do NOT write a .bak first (default: do)")
    parser.add_argument("--removed-log", default=os.path.join(here, "removed_excluded_rules.yar"),
                        help="Where to append the removed rule blocks")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        sys.exit(1)
    exclude_files, missing = resolve_exclude_files(args.exclude or [os.path.join(here, "excluded_yara_x_rules.txt")])
    if missing:
        for m in missing:
            print(f"[!] Exclusion list not found: {m}")
        sys.exit(1)

    excluded = set()
    for xf in exclude_files:
        names = load_exclude_set(xf)
        print(f"[*] Loaded {len(names)} exclusion entry/entries from {xf}")
        excluded |= names
    if len(exclude_files) > 1:
        print(f"[*] {len(excluded)} distinct rule name(s) in total")
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        print(f"[*] Output directory: {args.output}")
    if args.dry_run:
        print("[*] DRY RUN — nothing will be written.")

    files = find_rule_files(args.directory, recurse=not args.no_recurse)
    print(f"[*] Scanning {len(files)} rule file(s)\n")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    total_removed = 0
    total_private_skipped = 0
    removed_log_chunks = []

    for fp in files:
        try:
            # newline="" keeps CRLF / LF exactly as they are in the file.
            with open(fp, "r", encoding="utf-8", errors="ignore", newline="") as f:
                lines = f.readlines()
        except OSError as e:
            print(f"  [!] skip {fp}: {e}")
            continue

        kept, removed, removed_names, skipped_private = strip_excluded(lines, excluded)
        total_private_skipped += len(skipped_private)
        if not removed_names:
            continue
        total_removed += len(removed_names)

        uniq = sorted(set(removed_names))
        print(f"  {fp}: removing {len(removed_names)} rule(s): {', '.join(uniq)}")
        removed_log_chunks.append(
            f"// ===== removed from {fp} ({stamp}) =====\n" + "".join(removed) + "\n"
        )

        if args.dry_run:
            continue

        if args.output:
            out_path = os.path.join(args.output, os.path.basename(fp))
            with open(out_path, "w", encoding="utf-8", errors="ignore", newline="") as f:
                f.writelines(kept)
        else:
            if not args.no_backup:
                shutil.copyfile(fp, f"{fp}.{stamp}.bak")
            with open(fp, "w", encoding="utf-8", errors="ignore", newline="") as f:
                f.writelines(kept)

    # Append the removed blocks to the log (so removals are recoverable).
    if removed_log_chunks and not args.dry_run:
        with open(args.removed_log, "a", encoding="utf-8", errors="ignore") as f:
            f.write("".join(removed_log_chunks))

    print()
    print(f"[=] Public rule blocks removed : {total_removed}")
    print(f"[=] Private matches left intact: {total_private_skipped}")
    if total_removed and not args.dry_run:
        print(f"[*] Removed blocks appended to: {args.removed_log}")
        if not args.output and not args.no_backup:
            print(f"[*] Per-file backups written as *.{stamp}.bak")
    if args.dry_run and total_removed:
        print("[i] Re-run without --dry-run to apply.")


if __name__ == "__main__":
    main()
