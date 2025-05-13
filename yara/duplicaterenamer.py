#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automates YARA rule compilation and resolves duplicate identifiers by renaming the first duplicate occurrence.
Handles cases where rule keywords may follow closing braces (e.g., `}rule`).
"""
import os
import re
import subprocess
import sys


def compile_yara(yarac_path, input_yar, output_rc):
    result = subprocess.run(
        [yarac_path, input_yar, output_rc],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.stdout, result.stderr


def find_duplicate_identifiers(stderr):
    dup_re = re.compile(r'duplicated identifier "([^\"]+)"')
    return list(dict.fromkeys(dup_re.findall(stderr)))  # unique preserve order


def rename_first_duplicate(yara_file, duplicates):
    # Match rule lines even if preceded by '}' or whitespace
    rule_re = re.compile(r'^([\s\}]*?(?:private|global)?\s*rule\s+)([A-Za-z0-9_]+)(.*)$', re.IGNORECASE)
    duplicates_lower = {d.lower() for d in duplicates}
    renamed = set()
    output_lines = []

    with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = rule_re.match(line)
            if m:
                prefix, name, suffix = m.groups()
                lname = name.lower()
                if lname in duplicates_lower and lname not in renamed:
                    # Mark that next time we will rename
                    renamed.add(lname)
                    output_lines.append(line)
                    continue
                if lname in renamed:
                    # First duplicate: rename
                    new_name = f"{name}0"
                    line = f"{prefix}{new_name}{suffix}\n"
                    # Remove from renamed to avoid further renaming
                    duplicates_lower.remove(lname)
                # else: original or already handled
            output_lines.append(line)

    with open(yara_file, 'w', encoding='utf-8', errors='ignore') as f:
        f.writelines(output_lines)

    return renamed


def main():
    cwd = os.getcwd()
    yarac = os.path.join(cwd, 'yarac64.exe')
    input_yara = 'babapro.yar' #Example
    output_rc = 'babapro.yrc'

    print(f"Compiling {input_yara}...")
    _, stderr = compile_yara(yarac, input_yara, output_rc)
    if 'duplicated identifier' not in stderr:
        print("No duplicates found. Compilation successful.")
        sys.exit(0)

    duplicates = find_duplicate_identifiers(stderr)
    if not duplicates:
        print("No duplicate identifiers detected.")
        sys.exit(1)

    print(f"Duplicate identifiers: {duplicates}")

    renamed = rename_first_duplicate(input_yara, duplicates)
    if renamed:
        print(f"Renamed first duplicate for: {[name+'0' for name in renamed]}")
    else:
        print("No rules renamed.")

    print("Recompiling after renaming...")
    _, stderr2 = compile_yara(yarac, input_yara, output_rc)
    if stderr2:
        print("Errors remain after renaming duplicates:")
        print(stderr2)
        sys.exit(1)
    else:
        print("Compilation succeeded after renaming duplicates.")

if __name__ == '__main__':
    main()