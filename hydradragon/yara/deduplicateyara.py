#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Split YARA file into clean / problematic based on yarac duplicated-identifier errors.
Default: keep first occurrence (file order) and move later duplicates.
If --remove-first is used: remove the first occurrence(s) and keep later ones.
"""

import os
import sys
import argparse
import subprocess
import tempfile
import re

def build_cli_parser():
    parser = argparse.ArgumentParser(
        description="Split YARA rules using yarac duplicated-identifier results."
    )
    parser.add_argument("--input-file", dest="input_rules", required=True, help="Input YARA rules file to check.")
    parser.add_argument("-y", "--yarac", dest="yarac_path", default="yarac64.exe", help="Path to yarac64.exe (default: yarac64.exe).")
    parser.add_argument("--clean-file", dest="clean_file", default="clean_rules.yar", help="Output file for clean (non-problematic) rules.")
    parser.add_argument("--problematic-file", dest="slow_file", default="bad_rules.yar", help="Output file for problematic rules (default: bad_rules.yar).")
    parser.add_argument("--compiled-output", dest="compiled_output", default=None, help="Save the compiled YARA output to this file.")
    parser.add_argument("--save-warnings", dest="save_warnings", default=None, help="Save all yarac stdout/stderr to a text file.")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Verbose output for debugging.")
    parser.add_argument("--remove-first", action="store_true", dest="remove_first",
                        help="Reverse mode: remove (move) the first occurrence(s) reported by yarac; keep later ones.")
    return parser

def run_yarac(yarac_path, input_file, compiled_output, verbose=False):
    """Run yarac and return (stdout, stderr, returncode). Exits if yarac not found."""
    tmp_created = False
    if not compiled_output:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".yrc", dir=".")
        compiled_output = tmp.name
        tmp.close()
        tmp_created = True

    cmd = [yarac_path, input_file, compiled_output]
    if verbose:
        print(f"[yarac] Running: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
    except FileNotFoundError:
        print(f"Error: yarac executable not found at '{yarac_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error running yarac: {e}")
        sys.exit(1)

    if tmp_created:
        try:
            os.remove(compiled_output)
        except Exception:
            pass

    return res.stdout or "", res.stderr or "", res.returncode

def parse_yarac_for_duplicated_identifiers(stdout, stderr, verbose=False):
    """
    Parse yarac output for duplicated identifier errors.
    Returns a set of identifier names (strings) found.
    """
    dup_set = set()
    combined = (stdout or "") + "\n" + (stderr or "")
    p_quoted = re.compile(r'duplicat(?:e|ed)\s+identifier\s*"([^"]+)"', re.IGNORECASE)
    p_unquoted = re.compile(r'duplicat(?:e|ed)\s+identifier\s+([A-Za-z_]\w*)', re.IGNORECASE)

    for line in combined.splitlines():
        if 'duplicat' not in line.lower():
            continue
        if verbose:
            print(f"[yarac parse] checking line: {line}")
        m = p_quoted.search(line)
        if m:
            ident = m.group(1).strip()
            if ident:
                dup_set.add(ident)
                if verbose:
                    print(f"[yarac parse] found duplicated identifier (quoted): {ident}")
            continue
        m2 = p_unquoted.search(line)
        if m2:
            ident = m2.group(1).strip()
            if ident:
                dup_set.add(ident)
                if verbose:
                    print(f"[yarac parse] found duplicated identifier (unquoted): {ident}")
    return dup_set

def simple_split_rules(content):
    """
    Split YARA content into header + list of (rule_name, rule_text).
    Returns (header, rules_list). rules_list items are (name_or_None, full_text).
    """
    parts = re.split(r'(\n\s*(?:private\s+|global\s+)?rule\s+)', content, flags=re.IGNORECASE)
    if len(parts) <= 1:
        return None

    header = parts[0]
    rules = []
    i = 1
    while i < len(parts):
        if i + 1 < len(parts):
            decl = parts[i]
            body = parts[i + 1]
            full = decl + body
            bn = body.lstrip()
            m = re.match(r'^([A-Za-z_]\w*)', bn)
            name = m.group(1) if m else None
            rules.append((name, full))
            i += 2
        else:
            i += 1
    return header, rules

def split_based_on_yarac(input_file, duplicated_identifiers, clean_file, problematic_file, remove_first=False, verbose=False):
    """
    Splits the input file into clean/problematic based ONLY on duplicated_identifiers (from yarac).
    - Default (remove_first=False): keep first occurrence, move later duplicates.
    - If remove_first=True: move the first occurrence(s) and keep later ones.
    """
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: input file '{input_file}' not found.")
        sys.exit(1)

    if not duplicated_identifiers:
        if verbose:
            print("[split] no duplicated identifiers from yarac; copying entire input to clean file.")
        try:
            with open(clean_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(content)
            open(problematic_file, 'w', encoding='utf-8', errors='ignore').close()
            print(f"Wrote clean file: {clean_file} (no duplicates detected)")
            print(f"Wrote problematic file (empty): {problematic_file}")
        except Exception as e:
            print(f"Error writing outputs: {e}")
        return

    parsed = simple_split_rules(content)
    if not parsed:
        if verbose:
            print("[split] no rules found; copying entire input to clean file.")
        try:
            with open(clean_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(content)
            open(problematic_file, 'w', encoding='utf-8', errors='ignore').close()
            print(f"Wrote clean file: {clean_file} (no rules found)")
            return
        except Exception as e:
            print(f"Error writing outputs: {e}")
            return

    header, rules = parsed
    if verbose:
        print(f"[split] parsed {len(rules)} rules from input.")

    clean_parts = [header]
    prob_parts = [header]
    clean_count = 0
    prob_count = 0

    # Build regex patterns only for yarac-listed identifiers
    ident_patterns = {}
    for ident in duplicated_identifiers:
        pattern = re.compile(r'(?<!\w){}\b|\${}(?=\W|$)'.format(re.escape(ident), re.escape(ident)))
        ident_patterns[ident] = pattern

    seen_rule_names = set()
    seen_identifiers = set()

    for idx, (rule_name, rule_text) in enumerate(rules, 1):
        if verbose:
            print(f"[split] processing rule #{idx}: {rule_name or '<unnamed>'}")

        # Collect which yarac-reported idents appear in this rule
        idents_found = set()
        for ident, pat in ident_patterns.items():
            if pat.search(rule_text):
                idents_found.add(ident)

        # If rule name itself is a duplicated identifier, include it
        if rule_name and rule_name in duplicated_identifiers:
            idents_found.add(rule_name)

        # Quick check: does this rule contain any relevant identifiers at all?
        has_relevant = bool(idents_found)

        name_conflict = (rule_name is not None and rule_name in seen_rule_names)
        ident_conflict = any((ident in seen_identifiers) for ident in idents_found)

        if remove_first:
            # Reverse mode: move first occurrences, keep later ones.
            # Only act if the rule contains relevant identifiers.
            if has_relevant:
                # If none of the identifiers/names have been seen yet -> this is first occurrence -> move it.
                if (not name_conflict) and (not ident_conflict):
                    prob_parts.append(rule_text)
                    prob_count += 1
                    # Mark them as seen so later ones can be kept
                    if rule_name:
                        seen_rule_names.add(rule_name)
                    if idents_found:
                        seen_identifiers.update(idents_found)
                    if verbose:
                        print(f"[split][remove-first] MOVED (first occurrence): name={rule_name}, idents={sorted(idents_found)}")
                else:
                    # At least one of them was seen -> this is a later occurrence -> keep it
                    clean_parts.append(rule_text)
                    clean_count += 1
                    if rule_name:
                        seen_rule_names.add(rule_name)
                    if idents_found:
                        seen_identifiers.update(idents_found)
                    if verbose:
                        print(f"[split][remove-first] KEEP (later occurrence): name={rule_name}, idents={sorted(idents_found)}")
            else:
                # No relevant identifiers -> keep
                clean_parts.append(rule_text)
                clean_count += 1
                if verbose:
                    print(f"[split][remove-first] KEEP (no relevant idents): {rule_name or '<unnamed>'}")
        else:
            # Default mode: keep first occurrence, move later ones
            # If rule name already seen OR any ident already seen -> move to problematic (later duplicate)
            if name_conflict or ident_conflict:
                prob_parts.append(rule_text)
                prob_count += 1
                if verbose:
                    reasons = []
                    if name_conflict:
                        reasons.append(f"rule name '{rule_name}' seen before")
                    if ident_conflict:
                        seen_list = [i for i in idents_found if i in seen_identifiers]
                        reasons.append(f"identifier(s) {seen_list} seen before")
                    print(f"[split] MOVED to problematic: {', '.join(reasons)}")
            else:
                clean_parts.append(rule_text)
                clean_count += 1
                if rule_name:
                    seen_rule_names.add(rule_name)
                if idents_found:
                    seen_identifiers.update(idents_found)
                if verbose and idents_found:
                    print(f"[split] KEEP and mark seen: {sorted(idents_found)}")

    # Write outputs
    try:
        with open(clean_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(''.join(clean_parts))
        with open(problematic_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(''.join(prob_parts))
    except Exception as e:
        print(f"Error writing output files: {e}")
        return

    print(f"Clean rules written: {clean_count}")
    print(f"Problematic rules written: {prob_count}")

def main():
    parser = build_cli_parser()
    args = parser.parse_args()

    if not os.path.exists(args.input_rules):
        print(f"Error: Input file '{args.input_rules}' not found.")
        sys.exit(1)

    mode = "remove-first (move first occurrences)" if args.remove_first else "default (keep first occurrences)"
    print(f"--- Running yarac duplicate-identifier based split ({mode}) ---")

    stdout, stderr, rc = run_yarac(args.yarac_path, args.input_rules, args.compiled_output, verbose=args.verbose)

    if args.save_warnings:
        try:
            with open(args.save_warnings, 'w', encoding='utf-8', errors='ignore') as fw:
                fw.write("--- STDOUT ---\n")
                fw.write(stdout)
                fw.write("\n--- STDERR ---\n")
                fw.write(stderr)
            if args.verbose:
                print(f"[main] saved yarac output to {args.save_warnings}")
        except Exception as e:
            print(f"Warning: could not write warnings file: {e}")

    if args.verbose:
        print(f"[main] yarac return code: {rc}")
        if stdout.strip():
            print(f"[main] yarac stdout:\n{stdout}")
        if stderr.strip():
            print(f"[main] yarac stderr:\n{stderr}")

    dup_ids = parse_yarac_for_duplicated_identifiers(stdout, stderr, verbose=args.verbose)
    print(f"Found {len(dup_ids)} duplicated identifier(s) reported by yarac.")
    if dup_ids and args.verbose:
        print("[main] duplicated identifiers:")
        for d in sorted(dup_ids):
            print(f"  - {d}")

    # Split file based ONLY on yarac results and chosen mode
    split_based_on_yarac(args.input_rules, dup_ids, args.clean_file, args.slow_file, remove_first=args.remove_first, verbose=args.verbose)

    print("\n=== SUMMARY ===")
    print(f"yarac return code: {rc}")
    print(f"Duplicated identifiers detected (from yarac): {len(dup_ids)}")
    print(f"Mode: {mode}")
    print(f"Clean file: {args.clean_file}")
    print(f"Problematic file: {args.slow_file}")
    if args.save_warnings:
        print(f"Saved yarac output: {args.save_warnings}")

if __name__ == "__main__":
    main()
