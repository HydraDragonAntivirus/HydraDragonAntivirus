#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compares YARA rule names between two files and writes missing ones to result.txt.
Uses threads to parallelize file scanning and avoids ProcessPoolExecutor shutdown issues.
"""
import re
from concurrent.futures import ThreadPoolExecutor

RULE_START_REGEX = re.compile(r'\b(?:private\s+)?rule\s+([^\s{]+)', re.IGNORECASE)

def extract_rule_names(file_path):
    """
    Extracts rule names from a YARA file by matching `rule` or `private rule` keywords.
    Returns a set of rule names.
    """
    names = set()
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = RULE_START_REGEX.search(line)
            if m:
                names.add(m.group(1))
    return names


def compare_rules(new_file='compiled_rule.yar', old_file='babapro.yar'):
    """
    Compares rule names between two YARA files in parallel and returns
    a sorted list of rules present in new_file but missing in old_file.
    """
    with ThreadPoolExecutor() as executor:
        future_new = executor.submit(extract_rule_names, new_file)
        future_old = executor.submit(extract_rule_names, old_file)
        new_rules = future_new.result()
        old_rules = future_old.result()

    return sorted(new_rules - old_rules)


def main():
    import sys
    # Default file paths
    new_file = 'compiled_rule.yar'
    old_file = 'babapro.yar' #Example
    # Override via CLI
    if len(sys.argv) > 1:
        new_file = sys.argv[1]
    if len(sys.argv) > 2:
        old_file = sys.argv[2]

    missing = compare_rules(new_file, old_file)
    out_path = 'result.txt'

    with open(out_path, 'w', encoding='utf-8') as result_file:
        if missing:
            result_file.write(f"Rules in {new_file} not found in {old_file}:\n")
            for rule in missing:
                result_file.write(f"{rule}\n")
        else:
            result_file.write("All rules are present in both files.\n")

    print(f"Comparison complete. Results written to {out_path}.")

if __name__ == '__main__':
    main()