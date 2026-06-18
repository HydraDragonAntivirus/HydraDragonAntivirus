#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import sys
import subprocess
import tempfile
import re


def build_cli_parser():
    parser = argparse.ArgumentParser(
        description="Detect YARA-X 'potentially_slow_loop' warnings and extract slow rules."
    )
    slow_group = parser.add_argument_group("Slow Rule Detection")
    slow_group.add_argument(
        "--input-file",
        dest="input_rules",
        required=True,
        help="Input YARA rules file to check for slow loops.",
    )
    slow_group.add_argument(
        "-y",
        "--yr",
        dest="yr_path",
        default="yr.exe",
        help="Path to yr.exe (YARA-X CLI). Default: yr.exe",
    )
    slow_group.add_argument(
        "--clean-file",
        dest="clean_file",
        default="clean_rules_out.yar",
        help="Output file for clean (non-slow) rules.",
    )
    slow_group.add_argument(
        "--slow-file",
        dest="slow_file",
        default="hidden_slow_rules.yar",
        help="Output file for rules with potentially slow loops.",
    )
    slow_group.add_argument(
        "--save-warnings",
        dest="save_warnings",
        default=None,
        help="Save yr compile warnings to a text file.",
    )
    slow_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Verbose output.",
    )
    return parser


def run_yr_compile(yr_path, input_file, verbose):
    cmd = [yr_path, "compile", input_file]
    if verbose:
        print(f"Running: {' '.join(cmd)}")

    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
    except FileNotFoundError:
        print(f"Error: yr executable not found at '{yr_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error running yr: {e}")
        sys.exit(1)

    return res.stdout, res.stderr, res.returncode


def parse_slow_warnings(stderr, verbose):
    """
    Parse yr compile stderr for warning[potentially_slow_loop] blocks.

    YARA-X warning format:
        warning[potentially_slow_loop]: potentially slow loop
                 --> file.yar:123:45
                  |
            123 |             for any i in (1..#some_set): (
                  |                          ------- this range can be very large

    Returns a dict: {line_number: warning_message}
    """
    slow_lines = {}
    lines = stderr.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        # Look for the warning header line
        if "warning[potentially_slow_loop]" in line:
            warning_msg = line.strip()
            i += 1
            # Next line should be the --> file:line:col pointer
            if i < len(lines):
                loc_match = re.search(r"-->\s+\S+?:(\d+):(\d+)", lines[i])
                if loc_match:
                    line_num = int(loc_match.group(1))
                    slow_lines[line_num] = warning_msg
                    if verbose:
                        print(
                            f"Found slow loop at line {line_num}: {warning_msg}"
                        )
        i += 1

    return slow_lines


def get_rule_at_line(content, target_line):
    """
    Given the full YARA file content and a 1-based line number,
    find the rule name that contains that line.
    """
    lines = content.splitlines()
    current_rule = None

    for idx, line in enumerate(lines, start=1):
        # Match both `rule rule_name` and `private rule rule_name` etc.
        m = re.match(r'^\s*(private|global|)\s*(rule)\s+(\w+)', line)
        if m:
            current_rule = m.group(3)
        if idx == target_line:
            return current_rule

    return current_rule


def simple_split_rules(content):
    """Split YARA content into (header, [(rule_name, rule_body), ...])."""
    parts = re.split(r"(\n\s*(?:private\s+|global\s+)?rule\s+)", content)

    if len(parts) <= 1:
        return None, []

    header = parts[0]
    rules = []

    i = 1
    while i < len(parts):
        if i + 1 < len(parts):
            rule_decl = parts[i]
            rule_body = parts[i + 1]
            rule_name_match = re.search(r"^(\w+)", rule_body.strip())
            if rule_name_match:
                rule_name = rule_name_match.group(1)
                full_rule = rule_decl + rule_body
                rules.append((rule_name, full_rule))
            i += 2
        else:
            i += 1

    return header, rules


def build_line_to_rule_map(content):
    """Build a dict mapping 1-based line number -> rule name."""
    line_to_rule = {}
    lines = content.splitlines()
    current_rule = None

    for idx, line in enumerate(lines, start=1):
        m = re.match(r'^\s*(private\s+|global\s+)?rule\s+(\w+)', line)
        if m:
            current_rule = m.group(2)
        line_to_rule[idx] = current_rule

    return line_to_rule


def split_slow_rules(input_file, slow_lines, clean_file, slow_file, verbose):
    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return

    if verbose:
        print("Building line-to-rule map...")
    line_to_rule = build_line_to_rule_map(content)
    header, rules = simple_split_rules(content)

    if not rules:
        print("No rules found in input file.")
        return

    # Collect the set of slow rule names from warning line numbers
    slow_rule_names = set()
    for line_num in slow_lines:
        rule_name = line_to_rule.get(line_num)
        if rule_name:
            slow_rule_names.add(rule_name)
            if verbose:
                print(f"  Line {line_num} -> rule '{rule_name}'")

    if verbose:
        print(f"Slow rule names: {slow_rule_names}")

    clean_parts = [header]
    slow_parts = [header]
    clean_count = 0
    slow_count = 0

    for rule_name, rule_content in rules:
        if rule_name in slow_rule_names:
            slow_parts.append(rule_content)
            slow_count += 1
        else:
            clean_parts.append(rule_content)
            clean_count += 1

    try:
        with open(clean_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write("".join(clean_parts))

        with open(slow_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write("".join(slow_parts))

        print(f"Clean rules written: {clean_count}")
        print(f"Slow rules written to {slow_file}: {slow_count}")

    except Exception as e:
        print(f"Error writing output files: {e}")


def main():
    parser = build_cli_parser()
    args = parser.parse_args()

    if not os.path.exists(args.input_rules):
        print(f"Error: Input file '{args.input_rules}' not found.")
        sys.exit(1)

    print("--- YARA-X Potentially Slow Loop Detection ---")
    print(f"Compiling with {args.yr_path} to detect slow loops...")

    stdout, stderr, rc = run_yr_compile(
        args.yr_path, args.input_rules, args.verbose
    )

    if args.save_warnings:
        with open(args.save_warnings, "w", encoding="utf-8", errors="ignore") as f:
            f.write("--- STDOUT ---\n" + stdout + "\n--- STDERR ---\n" + stderr)
        print(f"Saved yr output to {args.save_warnings}")

    if args.verbose:
        print(f"yr return code: {rc}")
        if stderr.strip():
            print(f"yr stderr:\n{stderr}")

    slow_lines = parse_slow_warnings(stderr, args.verbose)
    print(f"Found {len(slow_lines)} potentially slow loop warning(s)")

    if not slow_lines:
        print("No slow loops detected. All rules are clean.")
        # Still write the clean output
        with open(args.clean_file, "w", encoding="utf-8", errors="ignore") as f:
            with open(args.input_rules, "r", encoding="utf-8", errors="ignore") as src:
                f.write(src.read())
        print(f"All rules written to {args.clean_file}")
        return

    print("Extracting slow rules...")
    split_slow_rules(
        args.input_rules, slow_lines, args.clean_file, args.slow_file, args.verbose
    )

    print("\n=== SUMMARY ===")
    print(f"Potentially slow loop warnings: {len(slow_lines)}")
    print(f"Clean file: {args.clean_file}")
    print(f"Slow file: {args.slow_file}")


if __name__ == "__main__":
    main()
