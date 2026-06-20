#!/usr/bin/env python3
"""
Detect and fix public rules that should be private (sub-rules).

A rule should be private if its condition only references other rule names
with no direct detection: no $string refs, no module calls, no uint16/32, etc.
Adds 'private' keyword to detected rules and saves modified file.
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


def is_private_rule(rule_text):
    return bool(re.match(r'\n\s*private\s+', rule_text))


def extract_condition(rule_text):
    m = re.search(r'\n\s*condition\s*:\s*(.*?)$', rule_text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return ''


DIRECT_PATTERNS = [
    r'\$[\w\d]', r'\bpe\.', r'\belf\.', r'\bmacho\.',
    r'\bconsole\.', r'\bdotnet\.', r'\bhash\.', r'\bmath\.', r'\btime\.',
    r'\buint\d+', r'\bint\d+', r'\bfilesize\b', r'\bentry_point\b',
    r'\bfor\s+(?:any|all|of)\b', r'\b(?:any|all|\d+)\s+of\b',
    r'\b(#|@)\s*\$', r'\bis\(pe\)', r'\bis\(elf\)', r'\bis\(macho\)',
]


def has_direct_detection(cond):
    for pat in DIRECT_PATTERNS:
        if re.search(pat, cond, re.IGNORECASE):
            return True
    return False


def make_private(rule_text):
    if is_private_rule(rule_text):
        return rule_text
    return re.sub(r'(\n\s*)(?:global\s+)?(rule\s+)', r'\1private \2', rule_text, count=1)


def get_rule_name_tokens(cond):
    """Extract potential rule name tokens from condition."""
    return set(re.findall(r'[A-Za-z_]\w*', cond))


def main():
    input_file = os.path.join(os.path.dirname(__file__), 'rules', 'clean_rules.yar')
    backup_file = input_file + '.bak2'

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

    # Pre-filter: find rules with no direct detection
    print("Scanning for public sub-rules...")
    candidates = []
    for name, text in rules:
        if not name or is_private_rule(text):
            continue
        cond = extract_condition(text)
        if not cond:
            continue
        if not has_direct_detection(cond):
            # Fast check: extract tokens from condition, intersect with rule names
            tokens = get_rule_name_tokens(cond)
            refs = tokens & all_names
            refs.discard(name)
            if refs:
                candidates.append((name, text, refs, cond))

    if not candidates:
        print("\nNo public sub-rules found.")
        return

    print(f"\nFound {len(candidates)} public sub-rules to make private\n")

    # Build new rules list with modifications
    name_set = {c[0] for c in candidates}
    new_rules = []
    fixed_count = 0
    for name, text in rules:
        if name in name_set:
            new_rules.append((name, make_private(text)))
            fixed_count += 1
        else:
            new_rules.append((name, text))

    # Rebuild content
    output_parts = [header]
    for _, text in new_rules:
        output_parts.append(text)
    output_content = ''.join(output_parts)

    # Show results grouped by references
    ref_groups = defaultdict(list)
    for name, _, refs, cond in candidates:
        key = frozenset(refs)
        ref_groups[key].append((name, cond[:100].replace('\n', ' ')))

    for key, members in sorted(ref_groups.items(), key=lambda x: -len(x[1])):
        print(f"  References: {', '.join(sorted(key)[:6])}")
        if len(key) > 6:
            print(f"    ... and {len(key)-6} more")
        for name, cond_preview in members:
            print(f"    -> {name}")
        print()

    # Write backup and output
    print(f"Creating backup: {backup_file}")
    import shutil
    shutil.copy2(input_file, backup_file)

    print(f"Writing modified file...")
    with open(input_file, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(output_content)

    orig_private = sum(1 for _, t in rules if is_private_rule(t))
    print(f"\nDone! Made {fixed_count} rules private (total private now: {orig_private + fixed_count})")
    print(f"Backup: {backup_file}")


if __name__ == '__main__':
    main()
