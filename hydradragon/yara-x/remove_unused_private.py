#!/usr/bin/env python3
"""
Detect unused private rules (not referenced by any other rule)
and move them to unused_private_rules.yar.
"""

import re
import os
import sys
from collections import defaultdict


def split_into_rules(content):
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
            full_text = decl + body
            m = re.match(r'\n\s*(?:private\s+|global\s+)?rule\s+(\w+)', full_text)
            name = m.group(1) if m else None
            rules.append((name, full_text))
            i += 2
        else:
            i += 1
    return header, rules


def is_private(rule_text):
    return bool(re.match(r'\n\s*private\s+', rule_text))


def get_condition(rule_text):
    m = re.search(r'\n\s*condition\s*:\s*(.*?)$', rule_text, re.DOTALL)
    if m:
        return m.group(1)
    return ''


def main():
    rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
    input_file = os.path.join(rules_dir, 'clean_rules.yar')
    unused_file = os.path.join(rules_dir, 'unused_private_rules.yar')

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        sys.exit(1)

    print(f"Reading {input_file}...")
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    print("Splitting into rules...")
    parsed = split_into_rules(content)
    if not parsed:
        print("Error: Could not parse rules")
        sys.exit(1)

    header, rules = parsed
    all_names = {r[0] for r in rules if r[0]}
    print(f"  {len(rules)} rules, {len(all_names)} unique names")

    # Count references to each rule name across all conditions
    ref_counts = defaultdict(int)
    for name, text in rules:
        if not name:
            continue
        cond = get_condition(text)
        if not cond:
            continue
        tokens = set(re.findall(r'[A-Za-z_]\w*', cond))
        for ref in tokens & all_names:
            if ref != name:
                ref_counts[ref] += 1

    # Find unused private rules
    unused = []
    for name, text in rules:
        if name and is_private(text) and ref_counts.get(name, 0) == 0:
            unused.append((name, text))

    if not unused:
        print("\nNo unused private rules found.")
        return

    print(f"\nFound {len(unused)} unused private rules")

    # Show some examples
    for name, _ in unused[:20]:
        print(f"  {name}")
    if len(unused) > 20:
        print(f"  ... and {len(unused)-20} more")

    # Build unused content
    unused_parts = [header]
    for name, text in unused:
        unused_parts.append(text)
    unused_content = ''.join(unused_parts)

    # Build new clean_rules.yar (without unused)
    unused_names = {n for n, _ in unused}
    clean_parts = [header]
    kept_count = 0
    for name, text in rules:
        if name not in unused_names:
            clean_parts.append(text)
            kept_count += 1
    clean_content = ''.join(clean_parts)

    # Write backup
    backup = input_file + '.bak4'
    import shutil
    shutil.copy2(input_file, backup)
    print(f"\nBackup: {backup}")

    # Write unused file
    print(f"Saving unused private rules to: {unused_file}")
    with open(unused_file, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(unused_content)

    # Write cleaned file
    print(f"Updating clean_rules.yar (removed {len(unused)} unused private rules)...")
    with open(input_file, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(clean_content)

    orig = content.count('\n')
    new = clean_content.count('\n')
    print(f"\nDone! Removed {len(unused)} unused private rules.")
    print(f"Lines: {orig} -> {new} ({orig - new} removed)")
    print(f"Unused rules saved to: {unused_file}")


if __name__ == '__main__':
    main()
