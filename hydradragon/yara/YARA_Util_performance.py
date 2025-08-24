#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# NOTE: This Python script is used to find and separate slow YARA rule files (.yar or .yara).
# Simple and robust version that avoids complex parsing.

import os
import argparse
import sys
import subprocess
import tempfile
import re

def build_cli_parser():
    """Builds the command-line argument parser using argparse."""
    parser = argparse.ArgumentParser(description="Find and split slow YARA rules from a single file.")
    
    # --- Group for Slow Rule Detection ---
    slow_group = parser.add_argument_group('Slow Rule Detection')
    slow_group.add_argument("--input-file", dest="input_rules", required=True, help="Input YARA rules file to check for slow rules.")
    slow_group.add_argument("-y", "--yarac", dest="yarac_path", default="yarac64.exe",
                           help="Path to yarac64.exe (default: yarac64.exe)")
    slow_group.add_argument("--clean-file", dest="clean_file", default="clean_rules.yar",
                           help="Output file for clean (non-slow) rules.")
    slow_group.add_argument("--slow-file", dest="slow_file", default="bad_rules.yar",
                           help="Output file for slow/bad rules (default: bad_rules.yar).")
    slow_group.add_argument("--compiled-output", dest="compiled_output", default=None,
                           help="Save the compiled YARA output to this file.")
    slow_group.add_argument("--save-warnings", dest="save_warnings", default=None,
                           help="Save all yarac warnings to a text file.")
    slow_group.add_argument("-v", "--verbose", action="store_true", dest="verbose_yarac", help="Verbose output for yarac operations.")

    return parser

def run_yarac(yarac_path, input_file, compiled_output, verbose):
    """Runs the yarac compiler and captures its output."""
    tmp_created = False
    if not compiled_output:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yrc", dir=".") as tmp:
            compiled_output = tmp.name
        tmp_created = True

    cmd = [yarac_path, input_file, compiled_output]
    if verbose:
        print(f"Running command: {' '.join(cmd)}")

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
    except FileNotFoundError:
        print(f"Error: yarac executable not found at '{yarac_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while running yarac: {e}")
        sys.exit(1)

    if tmp_created:
        try:
            os.remove(compiled_output)
        except OSError as e:
            if verbose:
                print(f"Could not remove temporary file {compiled_output}: {e}")

    return res.stdout, res.stderr, res.returncode

def parse_yarac_for_slow_strings(stdout, stderr):
    """Parses yarac output to find rules flagged with slow scanning warnings ONLY."""
    slow_rules = set()
    combined_output = stdout + "\n" + stderr
    
    # Simple and robust pattern - just find any quoted rule name in slow lines
    pattern = re.compile(r'"([^"]+)"')
    
    for line in combined_output.splitlines():
        # Look for both slow scanning warning types
        if 'may slow down scanning' in line.lower() or 'is slowing down scanning' in line.lower():
            print(f"DEBUG: Processing slow line: {line}")
            
            # Find all quoted strings in the line
            matches = pattern.findall(line)
            for match in matches:
                # The rule name is usually the first quoted string that looks like a rule name
                if match and not '.' in match and not '/' in match:  # Skip file paths
                    rule_name = match
                    slow_rules.add(rule_name)
                    print(f"Found SLOW rule: {rule_name}")
                    break
                
    return slow_rules

def simple_split_rules(content):
    """
    Simple rule splitting using lookahead regex.
    Much faster and more reliable than brace counting.
    """
    # Split on rule declarations but keep the delimiter
    parts = re.split(r'(\n\s*(?:private\s+|global\s+)?rule\s+)', content)
    
    if len(parts) <= 1:
        return []
    
    # The first part is the header
    header = parts[0]
    rules = []
    
    # Combine rule declarations with their bodies
    i = 1
    while i < len(parts):
        if i + 1 < len(parts):
            rule_decl = parts[i]  # e.g., "\nrule "
            rule_body = parts[i + 1]  # The actual rule content
            
            # Extract rule name from the body (first word after "rule")
            rule_name_match = re.search(r'^(\w+)', rule_body.strip())
            if rule_name_match:
                rule_name = rule_name_match.group(1)
                full_rule = rule_decl + rule_body
                rules.append((rule_name, full_rule))
            i += 2
        else:
            i += 1
    
    return header, rules

def split_slow_rules(input_file, slow_rules_set, clean_file, slow_file):
    """
    Splits a YARA file into 'clean' and 'slow' using simple regex splitting.
    """
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return

    print("Parsing rules...")
    
    try:
        result = simple_split_rules(content)
        if not result:
            print("No rules found in input file")
            return
            
        header, rules = result
        print(f"Found {len(rules)} rules")
        
    except Exception as e:
        print(f"Error parsing rules: {e}")
        return

    clean_parts = [header]
    slow_parts = [header]
    
    clean_count = 0
    slow_count = 0
    
    for rule_name, rule_content in rules:
        print(f"Processing rule: {rule_name}")
        
        if rule_name in slow_rules_set:
            print(f"  -> Moving SLOW rule to slow file")
            slow_parts.append(rule_content)
            slow_count += 1
        else:
            clean_parts.append(rule_content)
            clean_count += 1

    # Write outputs
    try:
        with open(clean_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(''.join(clean_parts))
        
        with open(slow_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(''.join(slow_parts))
            
        print(f"Clean rules written: {clean_count}")
        print(f"Slow rules written: {slow_count}")
        
    except Exception as e:
        print(f"Error writing output files: {e}")

def main():
    """Main function to execute the script."""
    parser = build_cli_parser()
    args = parser.parse_args()

    if not os.path.exists(args.input_rules):
        print(f"Error: Input file '{args.input_rules}' not found.")
        sys.exit(1)
    
    print("--- Running Slow Rule Detection ---")
    
    print("Running yarac to detect problematic rules...")
    stdout, stderr, rc = run_yarac(args.yarac_path, args.input_rules, args.compiled_output, args.verbose_yarac)

    if args.save_warnings:
        with open(args.save_warnings, 'w', encoding='utf-8', errors='ignore') as f:
            f.write("--- STDOUT ---\n" + stdout + "\n--- STDERR ---\n" + stderr)
        print(f"Saved yarac output to {args.save_warnings}")
    
    if args.verbose_yarac:
        print(f"yarac return code: {rc}")
        if stdout.strip(): 
            print(f"yarac stdout:\n{stdout}")
        if stderr.strip(): 
            print(f"yarac stderr:\n{stderr}")

    print("Parsing yarac output for SLOW rules only...")
    slow_rules_set = parse_yarac_for_slow_strings(stdout, stderr)
    print(f"Found {len(slow_rules_set)} SLOW rules (performance issues only)")

    if slow_rules_set:
        print("SLOW rules found:")
        for rule in sorted(slow_rules_set):
            print(f"  - {rule}")

    print("Splitting rules - keeping syntax errors in clean file...")
    split_slow_rules(args.input_rules, slow_rules_set, args.clean_file, args.slow_file)
    
    print("\n=== SUMMARY ===")
    print(f"yarac return code: {rc}")
    print(f"SLOW rules detected: {len(slow_rules_set)} (performance issues only)")
    print(f"Clean file: {args.clean_file} (contains rules with syntax errors - they need manual fixing)")
    print(f"Slow file: {args.slow_file} (contains only performance-slow rules)")
    if args.save_warnings:
        print(f"Warnings file: {args.save_warnings}")

if __name__ == "__main__":
    main()