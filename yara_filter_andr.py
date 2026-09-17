#!/usr/bin/env python3
import argparse
import os
import re

DEFAULT_EXCLUDE_TERMS = {"win", "windows", "osx", "macho", "peid", "java", "mz", "pe",
                         "powershell", "susp", "suspicious", "lnk", "packer", "nsis",
                         "mail"}

# Terms matched ONLY against the first underscore-segment of the rule name.
# Use for short/ambiguous terms that would cause false positives elsewhere.
DEFAULT_PREFIX_ONLY_TERMS = {"ttp", "cape", "pptx", "md5", "vc6"}

# Terms matched as an exact TOKEN in the rule NAME only (any camelCase or
# underscore segment), never in tags/meta/strings/comments. Use for short words
# that are meaningful in a rule name but common elsewhere, e.g. "net" (=dotnet)
# which should drop korna_net_korna / MyNetThing but not match "internet" in a
# comment or the word "net" in a string.
DEFAULT_NAME_ONLY_TERMS = {"net", "devcpp"}

# False-positive rules to drop, matched ONLY as an exact rule-name segment
# (never in strings/meta/condition/comments). These name benign Android
# artifacts that appear in nearly every legitimate APK:
#   androidkotlindebugprobeskt -> Kotlin coroutines DebugProbesKt marker
#   androidresourcearsc        -> the resources.arsc table every APK ships
DEFAULT_NAME_FP_TERMS = {"androidkotlindebugprobeskt", "androidresourcearsc"}

# Terms matched ONLY against the rule NAME, case-aware: the lowercase form
# matches only as a full underscore segment (dll_/_dll/_dll_/dll), NOT inside a
# word like "mydllthing"; the high-case forms (Dll, DLL) match anywhere in the
# name. Never scans strings/meta/condition/comments.
DEFAULT_NAME_SEGMENTS = {"dll"}

# Case-SENSITIVE substrings matched anywhere in the WHOLE rule block (name,
# strings, meta, condition, comments). Unlike the lowercased raw checks, these
# match the literal case only — "DLL"/"Dll" fire, a lowercase "dll" does not.
CASE_SENSITIVE_RAW_TERMS = ("DLL", "Dll")

# Excluded terms allowed to match via startswith() even though they are shorter
# than the 5-char startswith guard. "susp" intentionally catches the whole
# suspicious-family (suspicious, and misspellings like suspicous/suspicoius).
PREFIX_MATCH_TERMS = {"susp"}

# Rule names CONTAINING any of these (case-insensitive, anywhere — start,
# middle or end) are dropped outright. Used for compiler/platform substrings
# that tokenisation does not otherwise catch, e.g. win32 / win64 (token
# "win32"/"win64", not "win") and borland_delphi (Windows-only Delphi binaries).
DEFAULT_EXCLUDE_NAME_SUBSTRINGS = {"borland_delphi", "win32", "win64", "windows", "exe", "anti_debug", "ps1"}

# Exact metadata values that cause a rule to be dropped, matched
# case-insensitively against the WHOLE meta value (not tokenised). Used for
# multi-word category tags whose individual words are otherwise harmless,
# e.g.  rule_category = "greyware_tool_keyword"  (greyware = legitimate tools
# that trip false positives on Android).
DEFAULT_EXCLUDE_META_VALUES = {"greyware_tool_keyword"}

# Terms that mark a KEPT rule as Android/Linux-related and therefore "verified"
# for the mobile target. Matched case-insensitively as whole words anywhere in
# the rule block (name, tags, meta, strings, condition, comments). Mirai is the
# canonical Linux/IoT/Android botnet family; Valhalla is the Nextron rule feed
# whose Linux/Android coverage we trust. Rules hitting any of these go to
# clean_rules_filtered_verified.yar; everything else kept goes to
# clean_rules_filtered_unverified.yar.
DEFAULT_VERIFY_TERMS = {"android", "linux", "mirai", "koodous", "unix", "freebsd"}

# YARA modules whose usage makes a rule non-Android-compatible.
# hash / math / time / console are portable — not listed here.
# elf is included because native .so Android rules rarely use pe/macho/dotnet
# and elf-targeting rules are usually Linux-desktop focused; remove if needed.
NON_ANDROID_MODULES = {"pe", "macho", "dotnet"}

# Splits camelCase and acronyms:
#   OSXDropper    -> ['OSX', 'Dropper']  -> {'osx', 'dropper'}
#   WindowsShell  -> ['Windows', 'Shell'] -> {'windows', 'shell'}
#   WinExec       -> ['Win', 'Exec']     -> {'win', 'exec'}
_CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+|[0-9]+")

# Matches:  import "pe"  /  import "macho"  etc.
_IMPORT_RE = re.compile(r'^\s*import\s+"(\w+)"')

# Matches module namespace usage in rule body: pe.  macho.  dotnet.  elf.
# Only triggers on word-boundary so "people." doesn't match "pe."
_MODULE_USAGE_RE = re.compile(r'\b(\w+)\.')

# Any identifier token (used to find rule references inside a condition).
_IDENT_RE = re.compile(r'[A-Za-z_]\w*')

# PE/DOS "MZ" magic-header check, e.g.  uint16(0) == 0x5A4D  (a Windows-PE
# indicator). Whitespace-insensitive (\s* matches newlines) so it still fires
# when the expression is split across multiple lines, and order-agnostic so
# 0x5A4D == uint16(0) is caught too. Matched against the lowercased block.
_MZ_MAGIC_RE = re.compile(
    r'uint16\s*\(\s*0\s*\)\s*==\s*0x5a4d|0x5a4d\s*==\s*uint16\s*\(\s*0\s*\)'
)

# ELF "\x7fELF" magic-header detection in every form a YARA rule expresses it.
# The header bytes are 0x7f 'E' 'L' 'F' == 7f 45 4c 46. A hit marks the rule as
# native/Linux-related and therefore "verified" for the Android/Linux target.
# Order-agnostic and whitespace-insensitive (\s* spans newlines); matched on the
# lowercased block, so 0x464C457F / "ELF" / "\x7FELF" all fold to lower case.
#
# Covered forms:
#   uint16(0)   == 0x457f        first two bytes 7f 45, little-endian
#   uint32(0)   == 0x464c457f    four bytes 7f 45 4c 46, little-endian
#   uint32be(0) == 0x7f454c46    big-endian read
#   hex string  { 7f 45 4c 46 } / contiguous 7f454c46 (any spacing)
#   text literal "\x7fELF"
#   bare 32-bit magic literal 0x464c457f / 0x7f454c46 (distinctive enough alone)
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
    r'|0x7f454c46'
)


def tokenise(text):
    """
    Lowercase tokens from text via camelCase + underscore splitting.
    Each underscore-part contributes both its camelCase sub-tokens AND
    its raw lowercased form, so 'PowerShell' yields both 'power'+'shell'
    and 'powershell'.
    Returns (tokens_set, raw_parts_list).
    """
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
    """
    Return True if any token exactly matches an excluded term, OR if any
    raw underscore-part starts with a long excluded term (>=5 chars).
    The length guard keeps short terms like 'pe'/'mz'/'win' from firing
    on unrelated prefixes via startswith.
    """
    if tokens & exclude_terms:
        return True
    for part in raw_parts:
        for term in exclude_terms:
            if part.startswith(term) and (len(term) >= 5 or term in PREFIX_MATCH_TERMS):
                return True
    return False


def imported_modules(lines):
    """
    Return the set of module names imported in the given lines.
    Handles both file-level prelude imports and any import lines
    inside individual rule blocks.
    """
    modules = set()
    for line in lines:
        m = _IMPORT_RE.match(line)
        if m:
            modules.add(m.group(1).lower())
    return modules


def uses_non_android_module(block, non_android_modules):
    """
    Return True if the rule block references any non-Android-compatible
    module via its namespace (e.g. pe.entry_point, macho.headers).

    Also catches import statements embedded inside the block itself.
    """
    for line in block:
        # embedded import inside block
        m = _IMPORT_RE.match(line)
        if m and m.group(1).lower() in non_android_modules:
            return True
        # namespace usage: pe.xxx  macho.xxx  dotnet.xxx  elf.xxx
        for mod in _MODULE_USAGE_RE.findall(line):
            if mod.lower() in non_android_modules:
                return True
    return False


def extract_comments(lines):
    """
    Return all comment text from the given lines as a single string,
    covering both ``// line comments`` and ``/* block comments */``.

    A small scanner tracks string-literal and block-comment state so that
    a ``//`` or ``/*`` appearing inside a quoted string (e.g. a URL like
    "http://...") is NOT mistaken for a comment.
    """
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
    """Return True if the rule header declares a private rule."""
    return header.lstrip().startswith("private rule ")


def extract_rule_name(header):
    """Return the rule identifier from a rule header line."""
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
    """
    Return the set of bare identifiers appearing in the rule body
    outside of string literals — excluding the rule's own name.

    A condition can reference other rules by name, but short words
    like ``wget`` / ``linux`` / ``net`` inside string literals
    (``$x = "wget"``) would create false-positive cascade drops.
    """
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


def should_keep(block, exclude_terms, prefix_only_terms, non_android_modules,
                exclude_meta_values=frozenset(), exclude_name_substrings=frozenset(),
                name_only_terms=frozenset(), name_fp_terms=frozenset(),
                name_segments=frozenset()):
    """
    Return False if any of these signals fires:

      0. Raw content strings — case-insensitive full-block scan for: "macos",
                               "microsoft". Catches these substrings anywhere in
                               the rule (strings, comments, meta, etc.).
      1. Rule name tokens    — camelCase + underscore split
         prefix_only_terms checked against first underscore-segment only
      2. Rule tags           — space-separated after colon on header line
      3. Metadata values     — strings inside the meta: section, plus exact
                               whole-value matches against exclude_meta_values
      4. Module usage        — pe. / macho. / dotnet. / elf. in rule body,
                               or import "pe" / import "macho" inside the block
      5. Comments            — excluded term in a // or /* */ comment, e.g.
                               a "//Windows" note above the rule body
      6. String contents     — name substring (win32/win64/...) appearing
                               anywhere in the strings: section
    """
    block_raw = "".join(block)
    # Case-sensitive whole-block substrings (e.g. high-case DLL / Dll anywhere).
    for _cs_term in CASE_SENSITIVE_RAW_TERMS:
        if _cs_term in block_raw:
            return False

    block_text = block_raw.lower()
    # Raw full-block substring checks (catch strings in literals, comments, meta)
    for _raw_term in ("macos", "microsoft", ".exe", ".dll", ".sys", "hash.md5(0,", "c# ", "autoit", "mach-o", "mimikatz", "nullsoft", "c:\\", "c:/", "guloader", "vbscript", "visual basic", ".vbs", "registry", "regedit", "frombase64", ".ps1", "heavensgate", "dotnet", "https://github.com/xen0ph0n/yaragenerator", "yargen rule generator", "upx", "system32", "installshield", "wannacry", "wannacrypt", "wcry", "remcos", "formbook", "auto-generated rule", "ntdll", "dll ", " dll", "dlls", "dllinject", '"dll"', "darkcomet", "dllname", "chaos ransomware", "chaos_ransomware", "ntkrnl"):
        if _raw_term in block_text:
            return False

    # PE/DOS "MZ" magic header check (uint16(0) == 0x5A4D), even if split
    # across multiple lines or written in reverse order.
    if _MZ_MAGIC_RE.search(block_text):
        return False

    header = block[0].lstrip()

    # ── 1. Rule name ────────────────────────────────────────────────────────
    name = extract_rule_name(header)

    name_lower = name.lower()
    for sub in exclude_name_substrings:
        if sub in name_lower:
            return False
    name_tokens, name_parts = tokenise(name)
    if matches_exclude(name_tokens, name_parts, exclude_terms):
        return False

    # Name-only segment terms (e.g. lowercase "dll"): match only as a full
    # underscore segment (dll_/_dll/_dll_/dll), never inside a word like
    # "mydllthing". High-case Dll/DLL are handled by the whole-block
    # case-sensitive check above, so they are not repeated here.
    name_us_segments = name.split("_")
    if name_segments & set(name_us_segments):
        return False

    # False-positive name terms: drop when any name segment exactly equals an FP
    # term (e.g. AndroidResourceArsc). Name-only — never inspects the body.
    if name_tokens & name_fp_terms:
        return False

    # Name-only token terms (e.g. "net" = dotnet): match any name segment but
    # never tags/meta/strings/comments.
    if name_tokens & name_only_terms:
        return False

    first_segment = name.split("_")[0].lower() if name else ""
    if first_segment in prefix_only_terms:
        return False

    # ── 2. Tags (rule Foo : tag1 tag2 {) ────────────────────────────────────
    tag_match = re.search(r":\s*([^{]+)\{", header)
    if tag_match:
        for tag in tag_match.group(1).strip().split():
            tag_tokens, tag_parts = tokenise(tag)
            if matches_exclude(tag_tokens, tag_parts, exclude_terms):
                return False

    # ── 3. Metadata values ───────────────────────────────────────────────────
    in_meta = False
    for line in block[1:]:
        stripped = line.strip()
        if stripped in ("meta:", "strings:", "condition:"):
            in_meta = stripped == "meta:"
            continue
        if not in_meta:
            continue
        m = re.match(r'\w+\s*=\s*"?([^"]+)"?', stripped)
        if not m:
            continue
        value = m.group(1).strip()
        if value.lower() in exclude_meta_values:
            return False
        for word in re.split(r'[\s,;/\\|]+', value):
            word_tokens, word_parts = tokenise(word)
            if matches_exclude(word_tokens, word_parts, exclude_terms):
                return False

    # ── 4. Non-Android module usage ──────────────────────────────────────────
    if uses_non_android_module(block, non_android_modules):
        return False

    # ── 5. Comments (// ...  and  /* ... */) ─────────────────────────────────
    for word in re.split(r'[\s,;/\\|]+', extract_comments(block)):
        if not word:
            continue
        word_tokens, word_parts = tokenise(word)
        if matches_exclude(word_tokens, word_parts, exclude_terms):
            return False

    # ── 6. String contents (name substrings, e.g. win32 / win64) ─────────────
    if exclude_name_substrings:
        in_strings = False
        for line in block[1:]:
            stripped = line.strip()
            if stripped in ("meta:", "strings:", "condition:"):
                in_strings = stripped == "strings:"
                continue
            if not in_strings:
                continue
            low = line.lower()
            if any(sub in low for sub in exclude_name_substrings):
                return False

    return True


def is_android_related(block, verify_terms):
    """
    Return True if the rule block contains any verify term (android / linux /
    mirai / valhalla, ...) as a substring anywhere in the block, case-
    insensitively. A bare substring match (not whole-word) is intentional: any
    rule mentioning these terms in any part — name, tags, meta, strings,
    condition or comments — is treated as Android/Linux-verified.
    """
    text = "".join(block).lower()
    if verify_terms and any(term in text for term in verify_terms):
        return True
    # ZIP "PK" magic (uint16(0) == 0x4b50): APKs are ZIP archives, so any rule
    # keying on this header is Android-relevant.
    if "0x4b50" in text:
        return True
    # ELF native/Linux signals: elf module usage (elf. namespace or import "elf")
    # and the ELF magic header in any form — uint16/uint32 (LE & BE), hex-string
    # bytes 7f 45 4c 46, the "\x7fELF" text literal, or the bare 32-bit magic.
    if _ELF_MAGIC_RE.search(text):
        return True
    if uses_non_android_module(block, {"elf"}):
        return True
    return False


def split_blocks(lines):
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
        description="Filter YARA rules for Android compatibility.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Default excluded terms: {sorted(DEFAULT_EXCLUDE_TERMS)}
Default non-Android modules: {sorted(NON_ANDROID_MODULES)}

Seven signals are checked per rule — if any matches, the rule is dropped:
  1. Rule name          (camelCase/underscore tokens, e.g. OSXDropper -> osx;
                         plus name substrings anywhere, e.g. win32 / win64 /
                         borland_delphi)
  2. Rule tags          (e.g.  rule Foo : windows macho {{ ... }})
  3. Metadata values    (e.g.  os = "windows",  rule_category = "greyware_tool_keyword")
  4. Module usage       (e.g.  pe.entry_point,  macho.headers,  import "dotnet")
  5. Comments           (e.g.  //Windows  or  /* PE loader */ above the body)
  6. String contents    (name substrings win32/win64/... in the strings: section)
  7. Rule references    (body mentions any rule dropped by 1-6; cascades)

Portable modules (hash, math, time, console) are NOT filtered.

Examples:
  # Use defaults
  %(prog)s

  # Add extra name/tag/meta exclusion terms
  %(prog)s --exclude linux --exclude delphi

  # Keep elf rules (e.g. if you target Android native libs)
  %(prog)s --keep-module elf

  # Drop additional modules
  %(prog)s --drop-module hash

  # Custom src/dst
  %(prog)s --src /tmp/rules.yar --dst /tmp/out.yar
""",
    )
    parser.add_argument(
        "--src",
        default=None,
        help="Source .yar file (default: clean_rules.yar next to this script)",
    )
    parser.add_argument(
        "--dst",
        default=None,
        help="Destination file (default: <src>_filtered.yar)",
    )

    def min5_term(value):
        if len(value) < 5:
            raise argparse.ArgumentTypeError(
                f"{value!r} is too short ({len(value)} chars); "
                "minimum 5 characters required to avoid false positives."
            )
        return value

    parser.add_argument(
        "--exclude",
        metavar="TERM",
        type=min5_term,
        action="append",
        default=[],
        help=(
            "Add a term to the name/tag/metadata exclusion list (repeatable). "
            "Minimum 5 characters. "
            "Added on top of defaults unless --reset-defaults is given."
        ),
    )
    parser.add_argument(
        "--reset-defaults",
        action="store_true",
        help="Start from an empty exclusion list instead of the built-in defaults.",
    )
    parser.add_argument(
        "--exclude-meta-value",
        metavar="VALUE",
        action="append",
        default=[],
        help=(
            "Drop a rule when any meta value equals VALUE exactly "
            "(case-insensitive, repeatable). Added on top of defaults unless "
            "--reset-defaults is given. Default: "
            f"{sorted(DEFAULT_EXCLUDE_META_VALUES)}"
        ),
    )
    parser.add_argument(
        "--exclude-name-substring",
        metavar="SUB",
        action="append",
        default=[],
        help=(
            "Drop a rule when its name contains SUB anywhere (start, middle or "
            "end; case-insensitive, repeatable). Added on top of defaults "
            "unless --reset-defaults is given. Default: "
            f"{sorted(DEFAULT_EXCLUDE_NAME_SUBSTRINGS)}"
        ),
    )
    parser.add_argument(
        "--verify-term",
        metavar="TERM",
        action="append",
        default=[],
        help=(
            "Add a whole-word term that marks a kept rule as Android/Linux-"
            "verified (repeatable, case-insensitive). Verified rules are written "
            "to <dst>_verified.yar, the rest to <dst>_unverified.yar. Added on "
            f"top of defaults unless --reset-defaults is given. Default: "
            f"{sorted(DEFAULT_VERIFY_TERMS)}"
        ),
    )
    parser.add_argument(
        "--drop-module",
        metavar="MODULE",
        action="append",
        default=[],
        help="Add a module to the non-Android list (repeatable, e.g. --drop-module hash).",
    )
    parser.add_argument(
        "--keep-module",
        metavar="MODULE",
        action="append",
        default=[],
        help="Remove a module from the non-Android list (repeatable, e.g. --keep-module elf).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    src = args.src or os.path.join(script_dir, "clean_rules.yar")
    src_base, src_ext = os.path.splitext(src)

    if os.path.basename(src).startswith("AndroidOS"):
        print(f"Skipping '{src}': AndroidOS files are excluded from filtering.")
        return


    exclude_terms = set() if args.reset_defaults else set(DEFAULT_EXCLUDE_TERMS)
    prefix_only_terms = set() if args.reset_defaults else set(DEFAULT_PREFIX_ONLY_TERMS)
    name_only_terms = set() if args.reset_defaults else set(DEFAULT_NAME_ONLY_TERMS)
    for t in args.exclude:
        exclude_terms.add(t.lower())

    exclude_meta_values = (
        set() if args.reset_defaults else set(DEFAULT_EXCLUDE_META_VALUES)
    )
    for v in args.exclude_meta_value:
        exclude_meta_values.add(v.lower())

    exclude_name_substrings = (
        set() if args.reset_defaults else set(DEFAULT_EXCLUDE_NAME_SUBSTRINGS)
    )
    for p in args.exclude_name_substring:
        exclude_name_substrings.add(p.lower())

    name_fp_terms = set() if args.reset_defaults else set(DEFAULT_NAME_FP_TERMS)
    name_segments = set() if args.reset_defaults else set(DEFAULT_NAME_SEGMENTS)

    verify_terms = set() if args.reset_defaults else set(DEFAULT_VERIFY_TERMS)
    for t in args.verify_term:
        verify_terms.add(t.lower())

    non_android_modules = set(NON_ANDROID_MODULES)
    for m in args.drop_module:
        non_android_modules.add(m.lower())
    for m in args.keep_module:
        non_android_modules.discard(m.lower())

    print(f"Excluded terms:       {sorted(exclude_terms)}")
    print(f"Non-Android modules:  {sorted(non_android_modules)}")
    print(f"Excluded meta values: {sorted(exclude_meta_values)}")
    print(f"Excluded name subs:   {sorted(exclude_name_substrings)}")
    print(f"Name-only terms:      {sorted(name_only_terms)}")
    print(f"Name FP terms:        {sorted(name_fp_terms)}")
    print(f"Name segments:        {sorted(name_segments)}")
    print(f"Verify terms:         {sorted(verify_terms)}")
    print(f"Reading {src}...")

    with open(src, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    prelude, blocks = split_blocks(lines)

    # Strip prelude import lines for dropped (non-Android) modules — no kept rule
    # uses them, so leaving the imports in would make YARA error on the output.
    dropped_prelude = imported_modules(prelude) & non_android_modules
    if dropped_prelude:
        kept_prelude = []
        for line in prelude:
            m = _IMPORT_RE.match(line)
            if m and m.group(1).lower() in non_android_modules:
                continue
            kept_prelude.append(line)
        prelude = kept_prelude
        print(f"Removed prelude imports for non-Android modules {sorted(dropped_prelude)}.")

    total = len(blocks)
    names = [extract_rule_name(b[0]) for b in blocks]
    rule_names = set(n for n in names if n)

    # Pass 1: direct signals (name, tags, meta, modules, comments).
    keep = [
        should_keep(b, exclude_terms, prefix_only_terms, non_android_modules,
                    exclude_meta_values, exclude_name_substrings, name_only_terms,
                    name_fp_terms, name_segments)
        for b in blocks
    ]
    direct_removed = keep.count(False)

    # Pass 2: drop every rule related to a removed rule — i.e. any rule whose
    # body references a removed rule's name (condition, strings, meta or
    # comments). Cascades to a fixpoint: if C references B and B was dropped
    # for referencing excluded A, then C is dropped too.
    # Only actual rule names are considered, not loop variables (s, seg, i, ...)
    # or YARA builtins (uint32, condition, ...) that happen to match dropped names.
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

    removed_after_refs = total - keep.count(True)
    ref_removed = removed_after_refs - direct_removed

    # Pass 3: drop unused private rules — a private rule only exists to be
    # referenced by other rules, so if no kept rule references it, it is dead
    # code. Cascades to a fixpoint: removing one private rule can leave another
    # private rule (that only the first referenced) unused in turn.
    # Only actual rule names are tracked, not YARA builtins / loop variables.
    private_removed = 0
    changed = True
    while changed:
        changed = False
        # Names referenced by any currently-kept rule.
        referenced = set()
        for i, b in enumerate(blocks):
            if keep[i]:
                referenced |= (body_identifiers(b) & rule_names)
        for i, b in enumerate(blocks):
            if keep[i] and is_private_rule(b[0]) and names[i] not in referenced:
                keep[i] = False
                private_removed += 1
                changed = True

    kept_blocks = [b for i, b in enumerate(blocks) if keep[i]]

    # Pass 4: drop duplicate rule identifiers — YARA refuses to compile two rules
    # with the same name. Keep the first occurrence, drop later duplicates.
    seen_names = set()
    deduped = []
    dup_removed = 0
    for b in kept_blocks:
        nm = extract_rule_name(b[0])
        if nm and nm in seen_names:
            dup_removed += 1
            continue
        seen_names.add(nm)
        deduped.append(b)
    kept_blocks = deduped
    kept = len(kept_blocks)

    print(f"Total rules: {total}, Kept: {kept}, Removed: {total - kept} "
          f"({direct_removed} direct, {ref_removed} related via rule references, "
          f"{private_removed} unused private, {dup_removed} duplicate names)")

    # Split kept rules: Android/Linux/Mirai/Valhalla-related -> verified,
    # everything else kept -> unverified. A verified rule's private dependencies
    # must travel with it, so private rules referenced (transitively) by any
    # verified rule are forced into the verified bucket too.
    verified_flags = [is_android_related(b, verify_terms) for b in kept_blocks]
    kept_names = [extract_rule_name(b[0]) for b in kept_blocks]
    keeplist_rule_names = set(n for n in kept_names if n)

    changed = True
    while changed:
        changed = False
        verified_refs = set()
        for i, b in enumerate(kept_blocks):
            if verified_flags[i]:
                verified_refs |= (body_identifiers(b) & keeplist_rule_names)
        for i, b in enumerate(kept_blocks):
            if (not verified_flags[i] and is_private_rule(b[0])
                    and kept_names[i] in verified_refs):
                verified_flags[i] = True
                changed = True

    verified_blocks = [b for i, b in enumerate(kept_blocks) if verified_flags[i]]
    unverified_blocks = [b for i, b in enumerate(kept_blocks) if not verified_flags[i]]

    verified_dst = f"{src_base}_filtered_verified{src_ext}"
    unverified_dst = f"{src_base}_filtered_unverified{src_ext}"

    with open(verified_dst, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in verified_blocks:
            f.writelines(b)

    with open(unverified_dst, "w", encoding="utf-8") as f:
        f.writelines(prelude)
        for b in unverified_blocks:
            f.writelines(b)

    print(f"Verified ({'/'.join(sorted(verify_terms))}/elf): {len(verified_blocks)} "
          f"-> {verified_dst}")
    print(f"Unverified: {len(unverified_blocks)} -> {unverified_dst}")


if __name__ == "__main__":
    main()
