#!/usr/bin/env python3
# YARA_Util_info_extractor.py
#
# Move every YARA rule whose NAME starts with a prefix (default "INFO_") OUT of the
# rule files and into a separate file. INFO_ rules are informational markers (not
# detections), so pulling them out keeps the main rule set detection-only while the
# moved rules stay available (and recompilable) in one place.
#
# Imports/includes before the first rule are preserved; a file left with no rules
# is deleted (so the file count drops too). Read-only by default — pass --apply to
# actually modify the files.

import os
import sys
from optparse import OptionParser


def build_cli_parser():
    parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
    parser.add_option("-d", "--dir", dest="dir", default=".",
                      help="Directory of YARA rule files to process (recursive). Default: .")
    parser.add_option("-p", "--prefix", dest="prefix", default="INFO_",
                      help='Rule-name prefix to extract. Default: "INFO_"')
    parser.add_option("", "--ext", dest="ext", default=".yar,.yara",
                      help="Comma-separated file extensions to scan. Default: .yar,.yara")
    parser.add_option("-o", "--out", dest="out", default="info_rules.yar",
                      help="File to collect the extracted rules into (relative to --dir if not "
                           "absolute). Default: info_rules.yar")
    parser.add_option("", "--case-sensitive", action="store_true", default=False,
                      help="Match the prefix case-sensitively (default: case-insensitive)")
    parser.add_option("", "--keep-empty", action="store_true", default=False,
                      help="Do NOT delete files that end up with no rules")
    parser.add_option("", "--apply", action="store_true", default=False,
                      help="Actually modify files. Without this it is a dry run (report only).")
    return parser


def split_prelude_and_blocks(lines):
    """Return (prelude_lines, blocks). A block runs from a 'rule '/'private rule '
    line up to (not including) the next such line. Prelude = lines before the first
    rule (imports/includes)."""
    prelude, blocks, current = [], [], None
    for line in lines:
        depth = 5 if line[:5] == "rule " else (13 if line[:13] == "private rule " else 0)
        if depth:
            if current is not None:
                blocks.append(current)
            current = [line]
            continue
        if current is None:
            prelude.append(line)
        else:
            current.append(line)
    if current is not None:
        blocks.append(current)
    return prelude, blocks


def rule_name(block_lines):
    """Extract the identifier from a block's first 'rule NAME ...' / 'private rule
    NAME ...' line (stops at the first non [A-Za-z0-9_] char)."""
    head = block_lines[0]
    rest = head[13:] if head.startswith("private rule ") else head[5:]
    name = []
    for ch in rest.strip():
        if ch.isalnum() or ch == "_":
            name.append(ch)
        else:
            break
    return "".join(name)


def iter_rule_files(root, exts):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.lower().endswith(exts):
                yield os.path.join(dirpath, name)


def main():
    parser = build_cli_parser()
    opts, _ = parser.parse_args()
    exts = tuple(e.strip().lower() for e in opts.ext.split(",") if e.strip())
    if not os.path.isdir(opts.dir):
        sys.exit(f"error: not a directory: {opts.dir}")

    out_path = opts.out
    if not os.path.isabs(out_path):
        out_path = os.path.normpath(os.path.join(opts.dir, out_path))
    out_real = os.path.realpath(out_path)

    prefix = opts.prefix if opts.case_sensitive else opts.prefix.lower()

    def matches(name):
        n = name if opts.case_sensitive else name.lower()
        return n.startswith(prefix)

    print(f"[extract] rules named '{opts.prefix}*' from {opts.dir} -> {out_path}  "
          f"({'APPLY' if opts.apply else 'dry-run'}, "
          f"{'case-sensitive' if opts.case_sensitive else 'case-insensitive'})")

    collected = []  # (rel_source, block_lines)
    files_scanned = files_changed = files_deleted = rules_moved = rules_total = 0

    for path in iter_rule_files(opts.dir, exts):
        # Never read or rewrite the output file itself.
        if os.path.realpath(path) == out_real:
            continue
        files_scanned += 1
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            print(f"  ! skip {path}: {e}", file=sys.stderr)
            continue

        prelude, blocks = split_prelude_and_blocks(lines)
        rules_total += len(blocks)
        kept, moved = [], []
        for b in blocks:
            (moved if matches(rule_name(b)) else kept).append(b)
        if not moved:
            continue

        rules_moved += len(moved)
        files_changed += 1
        rel = os.path.relpath(path, opts.dir)
        for b in moved:
            collected.append((rel, b))

        if not kept and not opts.keep_empty:
            files_deleted += 1
            print(f"  {rel}: moved {len(moved)}/{len(blocks)} -> file deleted (no rules left)")
            if opts.apply:
                os.remove(path)
        else:
            print(f"  {rel}: moved {len(moved)}/{len(blocks)}")
            if opts.apply:
                out = list(prelude)
                for b in kept:
                    out.extend(b)
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(out)

    # Append the collected rules to the output file.
    if collected and opts.apply:
        write_mode = "a" if os.path.exists(out_path) else "w"
        with open(out_path, write_mode, encoding="utf-8") as f:
            for rel, b in collected:
                f.write(f"\n// --- moved from {rel} ---\n")
                f.writelines(b)
                if b and not b[-1].endswith("\n"):
                    f.write("\n")
        print(f"  [wrote {len(collected)} rule(s) to {out_path}]")

    print(f"[extract] files={files_scanned} changed={files_changed} deleted={files_deleted} "
          f"rules_moved={rules_moved}/{rules_total} "
          f"({'applied' if opts.apply else 'DRY RUN — pass --apply to write'})")


if __name__ == "__main__":
    main()
