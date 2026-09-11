#!/usr/bin/env python3
"""
YARA Rule Filter for Windows (Antivirus / EDR)

Filters large YARA rule sets (e.g. signature-base, valhalla, community) to keep ONLY
Windows-relevant and generic rules, dropping all Linux, ELF, macOS, Mach-O, Android,
and Unix-specific rules.

Features:
  1. Direct signal checks (Rule name, tags, meta, modules, non-Windows magic).
  2. Cascade reference resolution (drops rules depending on dropped rules).
  3. Unused private rule pruning.
  4. Duplicate rule name deduplication (prevents YARA compile collisions).
  5. Distinction between Windows-verified (PE/MZ/Win APIs) and generic rules.
"""

import argparse
import os
import re
import sys

# Platform terms to EXCLUDE (rules specifically targeting non-Windows platforms)
DEFAULT_EXCLUDE_TERMS = {
    "linux", "lnx", "android", "apk", "osx", "macos", "darwin", "macho",
    "solaris", "aix", "bsd", "freebsd", "ios", "unix"
}

# Prefixes to drop (e.g. LNX_malware, OSX_dropper, ELF_stealer)
DEFAULT_PREFIX_ONLY_TERMS = {"lnx", "osx", "apk", "elf", "aix", "bsd"}

# Substrings in rule names that explicitly denote non-Windows targets
DEFAULT_EXCLUDE_NAME_SUBSTRINGS = {
    "_lnx_", "_linux_", "_osx_", "_macos_", "_darwin_", "_macho_",
    "_elf_", "_apk_", "_android_", "_solaris_", "_freebsd_"
}

# YARA modules that are non-Windows or unsupported in Windows YARA-X runtime
NON_WINDOWS_MODULES = {"macho", "cuckoo", "dex"}

# Terms that mark a kept rule as strongly Windows-verified
DEFAULT_VERIFY_TERMS = {
    "windows", "win32", "win64", "powershell", "cmd.exe", "system32",
    "syswow64", "ntdll", "kernel32", "advapi32", "user32", "svchost",
    "registry", "regedit", "hkey_", "mimikatz", "pe", "dotnet", ".exe",
    ".dll", ".sys", ".vbs", ".hta", ".bat", ".ps1"
}

# Splits camelCase and acronyms
_CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+|[0-9]+")

# Matches: import "pe" / import "macho"
_IMPORT_RE = re.compile(r'^\s*import\s+"(\w+)"')

# Matches module namespace usage in rule body: pe. macho. dotnet. elf.
_MODULE_USAGE_RE = re.compile(r'\b(\w+)\.')

# Any identifier token
_IDENT_RE = re.compile(r'[A-Za-z_]\w*')

# PE/DOS "MZ" magic-header check: uint16(0) == 0x5A4D
_MZ_MAGIC_RE = re.compile(
    r'uint16\s*\(\s*0\s*\)\s*==\s*0x5a4d|0x5a4d\s*==\s*uint16\s*\(\s*0\s*\)',
    re.IGNORECASE
)

# ELF magic-header detection (\x7fELF = 7f 45 4c 46)
_ELF_MAGIC_RE = re.compile(
    r'uint16\s*\(\s*0\s*\)\s*==\s*0x457f'
    r'|0x457f\s*==\s*uint16\s*\(\s*0\s*\)'
    r'|uint32\s*\(\s*0\s*\)\s*==\s*0x464c457f'
    r'|0x464c457f\s*==\s*uint32\s*\(\s*0\s*\)'
    r'|uint32be\s*\(\s*0\s*\)\s*==\s*0x7f454c46'
    r'|0x7f454c46\s*==\s*uint32be\s*\(\s*0\s*\)'
    r'|\b7f\s*45\s*4c\s*46\b'
    r'|\\x7f\s*elf'
    r'|0x464c457f'
    r'|0x7f454c46',
    re.IGNORECASE
)

# Mach-O magic header detection (0xfeedface, 0xfeedfacf)
_MACHO_MAGIC_RE = re.compile(
    r'0xfeedface|0xfeedfacf|0xcefaedfe|0xcffaedfe',
    re.IGNORECASE
)


def tokenise(text):
    """Tokenise text into lowercased tokens and underscore components."""
    tokens = set()
    raw_parts = []
    for part in text.split("_"):
        if not part:
            continue
        for t in _CAMEL_RE.findall(part):
            tokens.add(t.lower())
        tokens.add(part.lower())
        raw_parts.append(part.lower())
    return tokens, raw_parts


def matches_exclude(tokens, raw_parts, exclude_terms):
    """Return True if tokens or parts match non-Windows excluded terms."""
    if tokens & exclude_terms:
        return True
    for part in raw_parts:
        for term in exclude_terms:
            if part.startswith(term) and len(term) >= 3:
                return True
    return False


def imported_modules(lines):
    """Return imported modules."""
    modules = set()
    for line in lines:
        m = _IMPORT_RE.match(line)
        if m:
            modules.add(m.group(1).lower())
    return modules


def uses_non_windows_module(block, non_windows_modules):
    """Check if block references any non-Windows module."""
    for line in block:
        m = _IMPORT_RE.match(line)
        if m and m.group(1).lower() in non_windows_modules:
            return True
        for mod in _MODULE_USAGE_RE.findall(line):
            if mod.lower() in non_windows_modules:
                return True
    return False


def extract_comments(lines):
    """Extract comments outside quoted strings."""
    out = []
    in_block = False
    for line in lines:
        i, n = 0, len(line)
        while i < n:
            if in_block:
                end = line.find("*/", i)
                if end == -1:
                    out.append(line[i:])
                    i = n
                else:
                    out.append(line[i:end])
                    i, in_block = end + 2, False
                continue
            ch = line[i]
            if ch == '"':
                i += 1
                while i < n:
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            if ch == "/" and i + 1 < n and line[i + 1] == "/":
                out.append(line[i + 2:])
                i = n
                continue
            if ch == "/" and i + 1 < n and line[i + 1] == "*":
                in_block = True
                i += 2
                continue
            i += 1
    return " ".join(out)


def is_private_rule(header):
    return header.lstrip().startswith("private rule ")


def extract_rule_name(header):
    h = header.lstrip()
    rest = h[13:] if h.startswith("private rule ") else h[5:]
    name_chars = []
    for ch in rest.strip():
        if ch.isalnum() or ch == "_":
            name_chars.append(ch)
        else:
            break
    return "".join(name_chars)


def body_identifiers(block):
    """Extract rule identifiers from conditions outside string literals."""
    ids = set()
    for line in block[1:]:
        i, n = 0, len(line)
        while i < n:
            if line[i] == '"':
                i += 1
                while i < n:
                    if line[i] == '\\' and i + 1 < n:
                        i += 2
                        continue
                    if line[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            if line[i] == '/' and i + 1 < n and line[i + 1] == '/':
                break
            if line[i] == '/' and i + 1 < n and line[i + 1] == '*':
                end = line.find('*/', i + 2)
                i = end + 2 if end != -1 else n
                continue
            m = _IDENT_RE.match(line, i)
            if m:
                ids.add(m.group(0))
                i = m.end()
            else:
                i += 1
    ids.discard(extract_rule_name(block[0]))
    return ids


def should_keep(block, exclude_terms, prefix_only_terms, non_windows_modules,
                exclude_name_substrings=frozenset()):
    """
    Evaluate whether a YARA rule belongs to Windows / Generic threat landscape.
    Returns False if the rule explicitly targets Linux, Android, macOS or Unix.
    """
    block_raw = "".join(block)
    block_lower = block_raw.lower()

    # Drop explicit ELF binary patterns
    if _ELF_MAGIC_RE.search(block_lower):
        return False

    # Drop explicit Mach-O binary patterns
    if _MACHO_MAGIC_RE.search(block_lower):
        return False

    # Drop non-Windows module usage (macho, cuckoo, dex)
    if uses_non_windows_module(block, non_windows_modules):
        return False

    header = block[0].lstrip()
    name = extract_rule_name(header)
    name_lower = name.lower()

    # Rule name checks
    for sub in exclude_name_substrings:
        if sub in name_lower:
            return False

    first_segment = name.split("_")[0].lower() if name else ""
    if first_segment in prefix_only_terms:
        return False

    name_tokens, name_parts = tokenise(name)
    if matches_exclude(name_tokens, name_parts, exclude_terms):
        return False

    # Tags check: rule Foo : LINUX SUSP {
    tag_match = re.search(r":\s*([^{]+)\{", header)
    if tag_match:
        for tag in tag_match.group(1).strip().split():
            tag_tokens, tag_parts = tokenise(tag)
            if matches_exclude(tag_tokens, tag_parts, exclude_terms):
                return False

    # Metadata check: os = "linux", platform = "macos"
    in_meta = False
    for line in block[1:]:
        stripped = line.strip()
        if stripped in ("meta:", "strings:", "condition:"):
            in_meta = stripped == "meta:"
            continue
        if not in_meta:
            continue
        m = re.match(r'(\w+)\s*=\s*"?([^"]+)"?', stripped)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip().lower()
        if key in ("os", "platform", "target_os", "target"):
            if any(term in value for term in exclude_terms):
                return False
        for word in re.split(r'[\s,;/\\|]+', value):
            word_tokens, word_parts = tokenise(word)
            if matches_exclude(word_tokens, word_parts, exclude_terms):
                return False

    return True


def is_windows_related(block, verify_terms):
    """
    Check if a rule is strongly confirmed as Windows (PE, Windows APIs, registry, etc.)
    """
    text = "".join(block).lower()

    # PE "MZ" magic header: uint16(0) == 0x5a4d
    if _MZ_MAGIC_RE.search(text):
        return True

    # Uses PE or DotNet module
    for line in block:
        if "pe." in line or "dotnet." in line or 'import "pe"' in line or 'import "dotnet"' in line:
            return True

    # Check for Windows keywords
    if verify_terms and any(term in text for term in verify_terms):
        return True

    return False


def split_blocks(lines):
    """Split YARA file into prelude and rule blocks."""
    prelude, blocks, current = [], [], None
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("rule ") or stripped.startswith("private rule "):
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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Filter YARA rules for Windows (dropping Linux/macOS/Android/Unix).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--src",
        default="hydradragon/yara-x/rules/valhalla-rules.yar",
        help="Source .yar file (default: hydradragon/yara-x/rules/valhalla-rules.yar)",
    )
    parser.add_argument(
        "--dst",
        default=None,
        help="Destination file (default: <src>_filtered_windows.yar)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Add extra platform exclusion terms",
    )
    return parser.parse_args()


def filter_file(src_path, dst_path=None):
    if not os.path.isfile(src_path):
        print(f"Error: file '{src_path}' does not exist.")
        return False

    src_base, src_ext = os.path.splitext(src_path)
    if dst_path is None:
        dst_path = f"{src_base}_windows{src_ext}"

    print(f"Loading rules from: {src_path}")
    with open(src_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    prelude, blocks = split_blocks(lines)

    # Strip prelude imports for non-Windows modules
    dropped_prelude = imported_modules(prelude) & NON_WINDOWS_MODULES
    if dropped_prelude:
        kept_prelude = []
        for line in prelude:
            m = _IMPORT_RE.match(line)
            if m and m.group(1).lower() in NON_WINDOWS_MODULES:
                continue
            kept_prelude.append(line)
        prelude = kept_prelude

    total = len(blocks)
    names = [extract_rule_name(b[0]) for b in blocks]
    rule_names = set(n for n in names if n)

    # Pass 1: Direct signals
    keep = [
        should_keep(b, DEFAULT_EXCLUDE_TERMS, DEFAULT_PREFIX_ONLY_TERMS,
                    NON_WINDOWS_MODULES, DEFAULT_EXCLUDE_NAME_SUBSTRINGS)
        for b in blocks
    ]
    direct_removed = keep.count(False)

    # Pass 2: Cascade rule references
    dropped_names = {names[i] for i in range(total) if not keep[i] and names[i]}
    changed = True
    while changed:
        changed = False
        for i, b in enumerate(blocks):
            if not keep[i]:
                continue
            if (body_identifiers(b) & rule_names) & dropped_names:
                keep[i] = False
                if names[i]:
                    dropped_names.add(names[i])
                changed = True

    ref_removed = total - keep.count(True) - direct_removed

    # Pass 3: Drop unused private rules
    private_removed = 0
    changed = True
    while changed:
        changed = False
        referenced = set()
        for i, b in enumerate(blocks):
            if keep[i]:
                referenced |= (body_identifiers(b) & rule_names)
        for i, b in enumerate(blocks):
            if keep[i] and is_private_rule(b[0]) and names[i] not in referenced:
                keep[i] = False
                private_removed += 1
                changed = True

    # Pass 4: Deduplicate rule names
    seen_names = set()
    deduped = []
    dup_removed = 0
    for i, b in enumerate(blocks):
        if not keep[i]:
            continue
        nm = extract_rule_name(b[0])
        if nm and nm in seen_names:
            dup_removed += 1
            continue
        seen_names.add(nm)
        deduped.append(b)

    kept_blocks = deduped
    kept_count = len(kept_blocks)

    print(f"Total rules: {total}")
    print(f"Kept for Windows: {kept_count}")
    print(f"Removed non-Windows: {total - kept_count} "
          f"({direct_removed} direct, {ref_removed} cascade, "
          f"{private_removed} unused private, {dup_removed} duplicate names)")

    with open(dst_path, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in kept_blocks:
            f.writelines(b)

    print(f"Saved filtered Windows rules to: {dst_path}")
    return True


def main():
    args = parse_args()
    filter_file(args.src, args.dst)


if __name__ == "__main__":
    main()
