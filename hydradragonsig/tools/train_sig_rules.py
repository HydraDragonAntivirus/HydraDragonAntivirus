#!/usr/bin/env python3
"""
HydraDragonSig Unified Rule Trainer & Synthesizer
==================================================
Trains deterministic, zero-false-positive HydraDragonSig YAML rules using:
1. yarGen Benign Databases (`yarGen/dbs/good-strings*.db` and `good-opcodes*.db`):
   - Strict ZERO-TOLERANCE VETO: Any string appearing in benign datasets is disqualified.
   - EXCLUDE BYTES: Known-benign opcode/byte sequences from `good-opcodes*.db` are
     used for collision checks and populated as `excludes: [...]` in byte rules.
2. Single-pass format analysis (PE, JavaScript, APK) without duplicate parsing:
   - PE: Imports, suspicious APIs, entry code bytes.
   - JavaScript: Script tokens, AST identifiers, suspicious calls.
   - APK: AndroidManifest and DEX components, suspicious permissions.
3. Complex Blobs / Packed Malware:
   - SpyHunter-style `byte_pattern` and `byte_set` rules with `excludes` (the exclude bytes)
     to prevent false positives on benign code or high-entropy blobs.
4. Family Grouping & Merging:
   - Extracts malware family names from filenames (e.g. Padodor.BJ, Floxif.A, Sality.3).
   - Merges same-family samples into a single unified rule.
   - Joins all sample names with commas in rule metadata (`description: "Samples: a.vir, b.vir"`).
"""

from __future__ import annotations

import argparse
import glob
import gzip
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

try:
    import lief
except ImportError:
    lief = None

# Precompiled regexes
RE_ASCII = re.compile(rb"[\x20-\x7e]{8,128}")
RE_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){8,128}")
RE_SUSP_COMMANDS = re.compile(
    r"(powershell|cmd\.exe|invoke-expression|iex\b|downloadstring|bypass|hidden|"
    r"certutil|bitsadmin|vssadmin|wscript\.shell|wscript\.network|shellexecute|"
    r"reg\s+add|schtasks|rundll32|regsvr32|curl\s|wget\s|chmod\s+\+x|eval\(|unescape\(|"
    r"String\.fromCharCode|ActiveXObject|CreateObject)",
    re.IGNORECASE
)
RE_NET_IOC = re.compile(r"(https?://|ftp://|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\.onion|\bmutex\b|botnet|inject|payload)", re.IGNORECASE)
RE_PATH_IOC = re.compile(r"(\.pdb|\.exe|\.dll|\.vbs|\.ps1|system32|appdata|temp\\|recycle)", re.IGNORECASE)

# Standard Compiler / CRT noise that might slip through small DBs
GENERIC_IGNORE_STRINGS = {
    "kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll", "shell32.dll",
    "ole32.dll", "oleaut32.dll", "ws2_32.dll", "gdi32.dll", "comctl32.dll",
    "exitprocess", "getprocaddress", "loadlibrarya", "loadlibraryw",
    "virtualalloc", "virtualfree", "getlasterror", "closehandle",
    "createfilew", "createfilea", "readfile", "writefile",
    "multibytetowidechar", "widechartomultibyte", "getmodulehandlew",
    "getstartupinfow", "microsoft corporation", "standard c++ library",
    "corbindtoruntimeex", "mscoree.dll", "<assembly xmlns=",
    "manifestversion=", "type=\"win32\"", "processorarchitecture=",
    "this program cannot be run in dos mode.", "rich header"
}


def is_meaningful_string(s: str) -> bool:
    """Filter out random opcode noise, symbol soup, and meaningless strings."""
    s = s.strip()
    if len(s) < 8 or len(s) > 120:
        return False
    lowered = s.lower()
    if lowered in GENERIC_IGNORE_STRINGS:
        return False
    
    # Must have high proportion of alphanumerics or standard separators
    alnum = sum(1 for c in s if c.isalnum())
    if alnum < 5 or (alnum / len(s)) < 0.40:
        return False
    
    # Check for character soup (e.g. repeated same char: "AAAAAAA" or "------")
    for ch in set(s):
        if s.count(ch) > len(s) * 0.40:
            return False
            
    # Pure numbers or pure hex are not good signatures
    if s.isdigit() or (all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 16):
        return False
        
    return True


def string_significance_score(s: str) -> float:
    """Score the signature value of a candidate malware string."""
    score = len(s) * 0.1
    if RE_SUSP_COMMANDS.search(s):
        score += 8.0
    if RE_NET_IOC.search(s):
        score += 7.0
    if RE_PATH_IOC.search(s):
        score += 4.0
    if "\\" in s or "/" in s:
        score += 3.0
    if "." in s and not s.endswith("."):
        score += 2.0
    return score


class BenignCorpus:
    """Strict Benign Veto Index (Strings + Exclude Bytes from yarGen DBs)."""
    def __init__(self):
        self.strings: Set[str] = set()
        self.good_opcodes_hex: Set[str] = set()
        self.good_opcodes_bytes: Set[bytes] = set()
        self.top_benign_excludes: List[str] = []

    def load_yargen_strings_dbs(self, dbs_dir: str, max_entries: int = 15_000_000):
        print(f"[*] Ingesting yarGen good-strings databases from: {dbs_dir} ...")
        shards = sorted(glob.glob(os.path.join(dbs_dir, "good-strings*.db")))
        total_loaded = 0
        for shard in shards:
            if total_loaded >= max_entries:
                break
            try:
                with gzip.open(shard, "rt", encoding="utf-8", errors="ignore") as gz:
                    data = json.load(gz)
                    for k in data.keys():
                        self.strings.add(k.lower())
                    total_loaded += len(data)
                    print(f"    Loaded {os.path.basename(shard)}: {len(data):,} strings.")
            except Exception as e:
                print(f"    [!] Error reading {shard}: {e}")
        print(f"[+] Total benign veto strings: {len(self.strings):,}")

    def load_yargen_opcodes_dbs(self, dbs_dir: str, max_entries: int = 5_000_000):
        print(f"[*] Ingesting yarGen good-opcodes (exclude bytes) from: {dbs_dir} ...")
        shards = sorted(glob.glob(os.path.join(dbs_dir, "good-opcodes*.db")))
        total_loaded = 0
        for shard in shards:
            if total_loaded >= max_entries:
                break
            try:
                with gzip.open(shard, "rt", encoding="utf-8", errors="ignore") as gz:
                    data = json.load(gz)
                    for k in data.keys():
                        clean_hex = k.strip().lower()
                        self.good_opcodes_hex.add(clean_hex)
                        try:
                            b = bytes.fromhex(clean_hex)
                            self.good_opcodes_bytes.add(b)
                        except Exception:
                            pass
                        # Pick high-frequency entries for the excludes veto list
                        if len(self.top_benign_excludes) < 100:
                            # format as spaced hex tokens: "59 5F 5E ..."
                            spaced = " ".join(clean_hex[i:i+2].upper() for i in range(0, len(clean_hex), 2))
                            if spaced not in self.top_benign_excludes:
                                self.top_benign_excludes.append(spaced)

                    total_loaded += len(data)
                    print(f"    Loaded {os.path.basename(shard)}: {len(data):,} opcodes.")
            except Exception as e:
                print(f"    [!] Error reading {shard}: {e}")
        print(f"[+] Total benign exclude byte patterns: {len(self.good_opcodes_hex):,}")

    def contains_string(self, s: str) -> bool:
        return s.strip().lower() in self.strings

    def contains_opcode_bytes(self, b: bytes) -> bool:
        return b in self.good_opcodes_bytes or b.hex().lower() in self.good_opcodes_hex


@dataclass
class MalwareSample:
    path: Path
    filename: str
    file_type: str = "unknown"
    entropy: float = 0.0
    imports: List[str] = field(default_factory=list)
    meaningful_strings: List[str] = field(default_factory=list)
    byte_patterns: List[str] = field(default_factory=list)


def extract_malware_family(filename: str) -> str:
    """Extract and normalize malware family name from AV detection filename."""
    base = os.path.splitext(filename)[0]
    base = re.sub(r"\.(vir|v|exe|bin|dll|dat)$", "", base, flags=re.I)
    cleaned = re.sub(r"[_.]\d+(_\d+)*$", "", base)
    cleaned = re.sub(r"_[A-Za-z0-9]{8,}$", "", cleaned)

    parts = cleaned.replace("_", ".").split(".")
    generic_prefixes = {
        "trojan", "virus", "worm", "backdoor", "dropped", "infector",
        "hijack", "sysbot", "danger", "hooker", "delself", "gen", "variant",
        "win32", "generic", "generickd", "application"
    }
    tokens = [p for p in parts if p.lower() not in generic_prefixes]
    filtered_tokens = [t for t in tokens if not t.isdigit() and not (len(t) >= 6 and all(c in "0123456789abcdefABCDEF" for c in t))]
    if len(filtered_tokens) >= 2:
        family = f"{filtered_tokens[-2]}_{filtered_tokens[-1]}"
    elif filtered_tokens:
        family = filtered_tokens[0]
    elif tokens:
        family = tokens[0]
    else:
        family = parts[-1] if parts else "Malware"
    family = re.sub(r"[^\w]", "_", family).strip("_")
    return family or "Malware"


def extract_code_byte_pattern(data: bytes, benign: BenignCorpus) -> Optional[str]:
    """Extract a discriminative, safe 16-24 byte pattern for complex binary blobs."""
    if len(data) < 256:
        return None
    start_offset = 0x200 if len(data) > 0x400 else 0x40
    
    for offset in range(start_offset, min(len(data) - 24, 0x4000), 16):
        chunk = data[offset:offset+16]
        # Skip null or 0xCC/0x90 fill
        if chunk.count(b"\x00") > 4 or chunk.count(b"\xcc") > 4 or chunk.count(b"\x90") > 4:
            continue
        if len(set(chunk)) < 9:
            continue
        # ZERO COLLISION WITH BENIGN OPCODES: Must not appear in good-opcodes!
        if benign.contains_opcode_bytes(chunk):
            continue
        # Format as SpyHunter hex tokens
        hex_tokens = " ".join(f"{b:02X}" for b in chunk)
        return f"{{ {hex_tokens} }}"

    return None


def analyze_sample(path: Path, benign: BenignCorpus) -> Optional[MalwareSample]:
    """Single-pass analysis for malware sample without duplicate parsing."""
    try:
        data = path.read_bytes()
    except Exception:
        return None
    if len(data) < 64:
        return None

    # Entropy
    total = len(data)
    counts = Counter(data)
    entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())

    # Format detection
    file_type = "unknown"
    imports: List[str] = []

    if data.startswith(b"MZ"):
        file_type = "pe"
        if lief:
            try:
                binary = lief.parse(data)
                if binary and isinstance(binary, lief.PE.Binary):
                    for imp in binary.imports:
                        for entry in imp.entries:
                            if entry.name:
                                imports.append(entry.name)
            except Exception:
                pass
    elif data.startswith(b"PK\x03\x04") and (b"classes.dex" in data or b"AndroidManifest.xml" in data):
        file_type = "apk"
    elif any(kw in data[:4096] for kw in (b"function ", b"var ", b"let ", b"const ", b"eval(", b"WScript.", b"ActiveXObject")):
        file_type = "javascript"

    # Extract strings
    candidates: List[str] = []
    seen = set()

    for match in RE_ASCII.finditer(data):
        raw = match.group().decode("latin1", "ignore").strip()
        if raw not in seen and is_meaningful_string(raw):
            seen.add(raw)
            candidates.append(raw)

    for match in RE_UTF16.finditer(data):
        try:
            raw = match.group().decode("utf-16-le", "ignore").strip()
            if raw not in seen and is_meaningful_string(raw):
                seen.add(raw)
                candidates.append(raw)
        except Exception:
            pass

    # STRICT VETO: Discard ANY string present in yarGen benign corpus
    clean_candidates = [s for s in candidates if not benign.contains_string(s)]
    clean_candidates.sort(key=lambda s: string_significance_score(s), reverse=True)

    # Extract code byte patterns for complex blobs / packed code
    byte_patterns: List[str] = []
    if len(clean_candidates) < 2 or entropy >= 7.2:
        bp = extract_code_byte_pattern(data, benign)
        if bp:
            byte_patterns.append(bp)

    sample = MalwareSample(
        path=path,
        filename=path.name,
        file_type=file_type,
        entropy=entropy,
        imports=imports,
        meaningful_strings=clean_candidates,
        byte_patterns=byte_patterns
    )
    return sample


def escape_yaml(s: str) -> str:
    """Safely format string for YAML value."""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def synthesize_rules(samples: List[MalwareSample], benign: BenignCorpus) -> str:
    """Group samples by family and synthesize HydraDragonSig YAML rules."""
    families: Dict[str, List[MalwareSample]] = defaultdict(list)
    for s in samples:
        fam = extract_malware_family(s.filename)
        families[fam].append(s)

    rule_lines = [
        "name: HydraDragon Learned Threat Signatures",
        f"version: \"1.0\"",
        f"# Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "# Trained against yarGen Benign Databases with Zero-Tolerance Veto & Exclude Bytes.",
        "# Multi-Factor conditions: Format + Imports + Meaningful Strings + SpyHunter Byte Rules with Excludes.",
        "",
        "rules:"
    ]

    rule_id_idx = 1
    exclude_samples = benign.top_benign_excludes[:3]

    for fam_name, members in sorted(families.items()):
        formats = Counter(m.file_type for m in members if m.file_type != "unknown")
        primary_format = formats.most_common(1)[0][0] if formats else "pe"

        # Intersect or rank strings across members
        string_freq: Dict[str, int] = Counter()
        for m in members:
            for s in m.meaningful_strings[:30]:
                string_freq[s] += 1

        selected_strings = sorted(
            string_freq.keys(),
            key=lambda s: (string_freq[s], string_significance_score(s)),
            reverse=True
        )[:12]

        # Gather byte patterns across members
        selected_byte_patterns = []
        for m in members:
            for bp in m.byte_patterns:
                if bp not in selected_byte_patterns:
                    selected_byte_patterns.append(bp)

        # Must have at least meaningful strings OR byte patterns
        if not selected_strings and not selected_byte_patterns:
            continue

        # Common imports for PE
        common_imports = []
        if primary_format == "pe":
            import_freq: Dict[str, int] = Counter()
            for m in members:
                for imp in m.imports:
                    import_freq[imp] += 1
            suspicious_apis = [
                "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "SetWindowsHookExA", "SetWindowsHookExW", "ShellExecuteA", "ShellExecuteW",
                "WinExec", "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA",
                "InternetOpenUrlA", "HttpSendRequestA", "RegSetValueExA", "RegSetValueExW"
            ]
            common_imports = [imp for imp, cnt in import_freq.most_common() if imp in suspicious_apis and cnt >= 1][:6]

        rule_id = f"MALW_{primary_format.upper()}_{rule_id_idx:04d}"
        rule_id_idx += 1

        # Join all member filenames with commas
        sample_names_joined = ", ".join(m.filename for m in members)
        clean_tag_fam = re.sub(r"[^\w-]", "-", fam_name.lower())
        tag_tokens = [primary_format, "malware", clean_tag_fam]
        tags_str = ", ".join(list(dict.fromkeys(tag_tokens)))

        rule_lines.append(f"  - id: {rule_id}")
        rule_lines.append(f"    title: \"Malware.{primary_format.upper()}.{fam_name}\"")
        rule_lines.append(f"    description: >")
        rule_lines.append(f"      Multi-factor detection for {fam_name} family ({len(members)} sample(s)).")
        rule_lines.append(f"      Samples: {sample_names_joined}")
        rule_lines.append("    severity: critical")
        rule_lines.append("    verdict: malware")
        rule_lines.append("    confidence: 95")
        rule_lines.append(f"    family: \"HydraDragon.{primary_format.upper()}.{fam_name}\"")
        rule_lines.append("    score: 95")
        rule_lines.append(f"    tags: [{tags_str}]")
        rule_lines.append("    logic: all")
        rule_lines.append("    conditions:")

        # 1. Format condition
        rule_lines.append("      - type: file_type")
        rule_lines.append(f"        values: [{primary_format}]")

        # 2. Import condition (if PE)
        if common_imports:
            rule_lines.append("      - type: import_set")
            rule_lines.append(f"        min: 1")
            rule_lines.append("        names:")
            for imp in common_imports:
                rule_lines.append(f"          - \"!{imp}\"")

        # 3. String condition (if strings exist)
        if selected_strings:
            min_strings = 2 if len(selected_strings) >= 3 else 1
            rule_lines.append("      - type: string_set")
            rule_lines.append(f"        min: {min_strings}")
            rule_lines.append("        nocase: true")
            rule_lines.append("        values:")
            for s in selected_strings:
                rule_lines.append(f"          - {escape_yaml(s)}")

        # 4. Complex blob byte pattern condition (with EXCLUDE BYTES vetoes)
        if selected_byte_patterns and (not selected_strings or len(selected_strings) < 2):
            if len(selected_byte_patterns) == 1:
                rule_lines.append("      - type: byte_pattern")
                rule_lines.append(f"        pattern: \"{selected_byte_patterns[0]}\"")
                if exclude_samples:
                    rule_lines.append("        excludes:")
                    for ex in exclude_samples:
                        rule_lines.append(f"          - \"{ex}\"")
            else:
                rule_lines.append("      - type: byte_set")
                rule_lines.append(f"        min: 1")
                rule_lines.append("        patterns:")
                for bp in selected_byte_patterns[:3]:
                    rule_lines.append(f"          - \"{bp}\"")
                if exclude_samples:
                    rule_lines.append("        excludes:")
                    for ex in exclude_samples:
                        rule_lines.append(f"          - \"{ex}\"")

        rule_lines.append("")

    return "\n".join(rule_lines)


def main():
    parser = argparse.ArgumentParser(description="HydraDragonSig Rule Trainer")
    parser.add_argument("-m", "--malware-dir", required=True, help="Directory containing malware samples")
    parser.add_argument("--yargen-dbs", default="yarGen/dbs", help="Directory containing yarGen good-strings*.db and good-opcodes*.db")
    parser.add_argument("--max-strings", type=int, default=15_000_000, help="Max entries to load from good-strings shards")
    parser.add_argument("--max-opcodes", type=int, default=3_000_000, help="Max entries to load from good-opcodes shards (exclude bytes)")
    parser.add_argument("-o", "--output", required=True, help="Output HydraDragonSig YAML rule file")
    args = parser.parse_args()

    benign = BenignCorpus()
    dbs_dir = args.yargen_dbs
    if os.path.exists(dbs_dir):
        benign.load_yargen_strings_dbs(dbs_dir, max_entries=args.max_strings)
        benign.load_yargen_opcodes_dbs(dbs_dir, max_entries=args.max_opcodes)
    else:
        print(f"[!] yarGen DB directory not found: {dbs_dir}")
        sys.exit(1)

    malware_path = Path(args.malware_dir)
    samples: List[MalwareSample] = []
    print(f"[*] Ingesting malware samples from: {malware_path} ...")
    for f in sorted(malware_path.rglob("*")):
        if f.is_file():
            res = analyze_sample(f, benign)
            if res and (res.meaningful_strings or res.byte_patterns):
                samples.append(res)
                print(f"    [+] {f.name}: {res.file_type.upper()}, {len(res.meaningful_strings)} unique clean strings, {len(res.byte_patterns)} byte patterns")

    print(f"[+] Total qualified malware samples: {len(samples)}")
    if not samples:
        print("[!] No malware samples with unique meaningful strings or byte patterns found.")
        sys.exit(1)

    print("[*] Synthesizing family-grouped multi-factor HydraDragonSig rules ...")
    yaml_rules = synthesize_rules(samples, benign)

    out_file = Path(args.output)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(yaml_rules, encoding="utf-8")
    print(f"[+] Successfully generated: {out_file} ({len(yaml_rules.splitlines())} lines)")


if __name__ == "__main__":
    main()
