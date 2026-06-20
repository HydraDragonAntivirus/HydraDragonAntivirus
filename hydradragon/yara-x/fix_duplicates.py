#!/usr/bin/env python3
"""
Fix duplicate rule errors (E012) in clean_rules.yar.

Strategy:
1. Split YARA file at each `rule` keyword boundary
2. Identify duplicate rule names
3. For duplicates with private version: keep private, remove public
4. For true duplicates (same body): keep richest, remove rest
5. For name collisions (different body, no private): rename 2nd+ with _ren suffix
6. Save removed rules to clean_rules_removed.yar
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
            line_count = full_text.count('\n')
            rules.append((name, full_text, line_count))
            i += 2
        else:
            i += 1

    return header, rules


def is_private_rule(rule_text):
    return bool(re.match(r'\n\s*private\s+', rule_text))


def extract_meta(rule_text):
    meta = {}
    for m in re.finditer(r'^\s*(\w+)\s*=\s*"([^"]*)"', rule_text, re.MULTILINE):
        meta[m.group(1).lower()] = m.group(2)
    return meta


def count_strings(rule_text):
    return len(re.findall(r'^\s*\$[\w\d]*\s*=', rule_text, re.MULTILINE))


def has_tags(rule_text):
    m = re.match(r'\n\s*(?:private\s+|global\s+)?rule\s+\w+\s*(:\s*[^{]*)', rule_text, re.DOTALL)
    if m:
        tag_part = m.group(1).strip()
        return bool(tag_part) and tag_part != '{'
    return False


def score_rule(rule_text):
    s = 0
    s += min(count_strings(rule_text), 30)
    meta = extract_meta(rule_text)
    if meta.get('date') or meta.get('modified'):
        s += 10
    if has_tags(rule_text):
        s += 5
    s += min(len(meta), 15)
    return s


def get_normalized_body(rule_text):
    return re.sub(r'\s*meta:\s*(\n\s+\w+\s*=\s*"[^"]*"\s*)*', '', rule_text)


def rename_in_text(rule_text, new_name):
    return re.sub(
        r'(\n\s*(?:private\s+|global\s+)?rule\s+)\w+',
        r'\1' + new_name,
        rule_text,
        count=1
    )


def main():
    input_file = os.path.join(os.path.dirname(__file__), 'rules', 'clean_rules.yar')
    backup_file = input_file + '.bak'
    removed_file = os.path.join(os.path.dirname(__file__), 'rules', 'clean_rules_removed.yar')

    if not os.path.exists(input_file):
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    print(f"Reading {input_file}...")
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    size_mb = os.path.getsize(input_file) / (1024 * 1024)
    print(f"  File size: {size_mb:.1f} MB")

    print("\nSplitting into rules...")
    parsed = split_into_rules(content)
    if not parsed:
        print("Error: Could not parse rules from file.")
        sys.exit(1)

    header, rules = parsed
    print(f"  Found {len(rules)} rules")

    name_to_rules = defaultdict(list)
    for idx, (name, rule_text, line_count) in enumerate(rules):
        if name:
            name_to_rules[name].append((idx, rule_text, line_count))

    duplicates = {name: positions for name, positions in name_to_rules.items() if len(positions) > 1}
    print(f"\nFound {len(duplicates)} duplicate rule names")

    keep_indices = set(range(len(rules)))
    removed_count = 0
    renamed = {}

    for name, positions in duplicates.items():
        private_indices = [item for item in positions if is_private_rule(item[1])]

        if private_indices:
            keep_item = private_indices[0]
            for item in positions:
                if item is not keep_item:
                    keep_indices.discard(item[0])
                    removed_count += 1
            print(f"  '{name}': keeping private, removed {len(positions)-1}")
        else:
            body_groups = defaultdict(list)
            for item in positions:
                body = get_normalized_body(item[1])
                body_groups[body].append(item)

            if len(body_groups) == 1:
                scored = [(score_rule(item[1]), item) for item in positions]
                scored.sort(key=lambda x: x[0])
                keep_item = scored[-1][1]
                for item in positions:
                    if item is not keep_item:
                        keep_indices.discard(item[0])
                        removed_count += 1
                print(f"  '{name}': true duplicate, keeping richest (score={scored[-1][0]}), removed {len(positions)-1}")
            else:
                first = True
                rename_count = 0
                for item in positions:
                    if first:
                        first = False
                        continue
                    new_name = f"{name}_ren"
                    renamed[item[0]] = rename_in_text(item[1], new_name)
                    rename_count += 1
                print(f"  '{name}': name collision ({len(body_groups)} variants), renamed {rename_count}")

    # Collect removed rules
    removed_parts = [header]
    for idx in sorted(set(range(len(rules))) - keep_indices):
        removed_parts.append(rules[idx][1])
    removed_content = ''.join(removed_parts)

    # Build output
    output_parts = [header]
    kept_count = 0
    for idx in sorted(keep_indices):
        if idx in renamed:
            output_parts.append(renamed[idx])
        else:
            output_parts.append(rules[idx][1])
        kept_count += 1

    output_content = ''.join(output_parts)

    # Verify no duplicates remain
    output_rule_names = re.findall(r'(?:private\s+|global\s+)?rule\s+(\w+)', output_content)
    name_counts = defaultdict(int)
    for n in output_rule_names:
        name_counts[n] += 1
    remaining_dups = {n: c for n, c in name_counts.items() if c > 1}
    if remaining_dups:
        print(f"\nWARNING: {len(remaining_dups)} duplicate names still in output!")
        for n, c in sorted(remaining_dups.items())[:10]:
            print(f"  {n}: {c} occurrences")
        if len(remaining_dups) > 10:
            print(f"  ... and {len(remaining_dups) - 10} more")

    # Write outputs
    print(f"\nCreating backup: {backup_file}")
    import shutil
    shutil.copy2(input_file, backup_file)

    print(f"Saving removed rules to: {removed_file}")
    with open(removed_file, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(removed_content)

    print(f"Writing deduplicated file...")
    with open(input_file, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(output_content)

    orig_lines = content.count('\n')
    new_lines = output_content.count('\n')
    removed_lines = removed_content.count('\n')
    print(f"\nDone! Removed {removed_count} rule(s), kept {kept_count} rules.")
    print(f"Lines: {orig_lines} -> {new_lines} ({orig_lines - new_lines} removed)")
    print(f"Backup saved to: {backup_file}")
    print(f"Removed rules saved to: {removed_file} ({removed_lines} lines)")


if __name__ == '__main__':
    main()
