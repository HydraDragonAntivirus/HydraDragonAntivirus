#!/usr/bin/env python3
# YARA_Util_metadata_remover.py
#
# Remove YARA rules whose meta: block contains a given key = "value" pair, across
# every .yar/.yara file in a directory tree. Default target:
#     version = "icewater snowflake"
# (the auto-generated icewater/snowflake rule set — a common false-positive source,
# like ClamAV dropping its stale lists). Imports/includes before the first rule are
# preserved; a file left with no rules is deleted (so file count drops too).
#
# Read-only by default unless you pass --apply; use --dry-run style preview first.

import os
import sys
from optparse import OptionParser


def build_cli_parser():
    parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
    parser.add_option("-d", "--dir", dest="dir", default=".",
                      help="Directory of YARA rule files to process (recursive). Default: .")
    parser.add_option("-k", "--meta-key", dest="key", default="version",
                      help='Metadata key to match. Default: "version"')
    parser.add_option("-v", "--meta-value", dest="value", default="icewater snowflake",
                      help='Metadata value to match. Default: "icewater snowflake"')
    parser.add_option("", "--ext", dest="ext", default=".yar,.yara",
                      help="Comma-separated file extensions to scan. Default: .yar,.yara")
    parser.add_option("", "--case-sensitive", action="store_true", default=False,
                      help="Match the value case-sensitively (default: case-insensitive)")
    parser.add_option("", "--keep-empty", action="store_true", default=False,
                      help="Do NOT delete files that end up with no rules")
    parser.add_option("", "--apply", action="store_true", default=False,
                      help="Actually modify files. Without this it is a dry run (report only).")
    parser.add_option("", "--save-removed", dest="save_removed", default=None,
                      help="Save removed rules to this file (default: removed_metadata_rules.yar in target dir). "
                           "Pass empty string to disable.")
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


def block_matches_meta(block_lines, key, value, case_sensitive):
    """True if the block's meta: section contains `key = "value"`."""
    in_meta = False
    kl = key.lower()
    want = value if case_sensitive else value.lower()
    for line in block_lines:
        t = line.strip()
        if t == "meta:":
            in_meta = True
            continue
        if not in_meta:
            continue
        if t in ("strings:", "condition:") or t.startswith("}"):
            break  # meta section ended
        if "=" not in t or t.startswith("//"):
            continue
        k, _, val = t.partition("=")
        if k.strip().lower() != kl:
            continue
        val = val.strip().strip(",").strip()
        if len(val) >= 2 and val[0] == val[-1] == '"':
            val = val[1:-1]
        if (val if case_sensitive else val.lower()) == want:
            return True
    return False


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

    print(f"[remove] {opts.key} = \"{opts.value}\"  in {opts.dir}  "
          f"({'APPLY' if opts.apply else 'dry-run'}, "
          f"{'case-sensitive' if opts.case_sensitive else 'case-insensitive'})")

    # Resolve save path
    save_path = opts.save_removed
    if save_path is None:
        save_path = os.path.join(opts.dir, "removed_metadata_rules.yar")
    elif save_path == "":
        save_path = None  # explicitly disabled
    elif not os.path.isabs(save_path):
        save_path = os.path.normpath(os.path.join(opts.dir, save_path))

    saved_blocks = []  # (rel_source, block_lines)

    files_scanned = files_changed = files_deleted = rules_removed = rules_total = 0
    for path in iter_rule_files(opts.dir, exts):
        files_scanned += 1
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            print(f"  ! skip {path}: {e}", file=sys.stderr)
            continue

        prelude, blocks = split_prelude_and_blocks(lines)
        rules_total += len(blocks)
        kept = []
        removed_blocks = []
        for b in blocks:
            if block_matches_meta(b, opts.key, opts.value, opts.case_sensitive):
                removed_blocks.append(b)
            else:
                kept.append(b)
        removed = len(removed_blocks)
        if removed == 0:
            continue

        rules_removed += removed
        files_changed += 1
        rel = os.path.relpath(path, opts.dir)

        # Collect removed blocks for saving
        if save_path is not None and opts.apply:
            saved_blocks.append((rel, removed_blocks))

        if not kept and not opts.keep_empty:
            files_deleted += 1
            print(f"  {rel}: removed {removed}/{len(blocks)} → file deleted (no rules left)")
            if opts.apply:
                os.remove(path)
        else:
            print(f"  {rel}: removed {removed}/{len(blocks)}")
            if opts.apply:
                out = list(prelude)
                for b in kept:
                    out.extend(b)
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(out)

    # Write saved removed rules
    if save_path is not None and opts.apply and saved_blocks:
        write_mode = "a" if os.path.exists(save_path) else "w"
        with open(save_path, write_mode, encoding="utf-8") as f:
            for rel, blocks in saved_blocks:
                f.write(f"\n// --- removed from {rel} ---\n")
                for b in blocks:
                    f.writelines(b)
                    last = b[-1] if b else ""
                    if not last.endswith("\n"):
                        f.write("\n")
                    f.write("\n")
        print(f"  [saved {len(saved_blocks)} source(s) to {save_path}]")

    print(f"[remove] files={files_scanned} changed={files_changed} deleted={files_deleted} "
          f"rules_removed={rules_removed}/{rules_total} "
          f"({'applied' if opts.apply else 'DRY RUN — pass --apply to write'})")


if __name__ == "__main__":
    main()
