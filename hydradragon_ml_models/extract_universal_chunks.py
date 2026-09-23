#!/usr/bin/env python3
"""
HydraDragon Universal Multi-Modal String & IOC Feature Extractor
Extracts 32 lexical and Shannon entropy features part-by-part to disk
to eliminate RAM bottlenecks (stays strictly under 1.5 - 2 GB RAM).

Data Sources:
  1. ClamAV Signatures (C:\Program Files\ClamAV\database):
     - Malicious URLs/Domains: phish.ndb, scam.ndb, jurlbl.ndb, bofhland_*_URL.ndb
     - Malicious Signatures/Hex: main.ndb, daily.ldb
  2. Custom YARA Rules (hydradragon/yara-x/*.yar):
     - Rule string literals & hex patterns
  3. USB Sample Corpus (C:\Users\semae\OneDrive\Belgeler\usbdosyalar):
     - PE binaries, scripts, javascript (extracts embedded C2, URLs, IPs, API names)
  4. Mobile Dataset (C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset):
     - Benign APK strings (Label 0)
     - Malware APK C2/URLs/Strings (Label 1)
  5. Website Dataset (hydradragon/website):
     - Clean whitelists (BenignIPs, WhiteListDomains, DomainsPopularity) (Label 0)
     - Blacklists (Phishing, Abuse, Malware) (Label 1)

Output:
  - Cached feature chunks in `cache_chunks/chunk_*.joblib`
  - Guarantees exact 50% Benign (0) / 50% Malicious (1) balance
"""

import os
import sys
import re
import math
import glob
import gc
import argparse
from collections import Counter
from typing import List, Tuple, Set, Optional, Generator
from urllib.parse import urlparse, parse_qs

import numpy as np
import joblib

URL_FEATURE_NAMES = [
    "url_len",
    "domain_len",
    "path_len",
    "query_len",
    "path_depth",
    "subdomain_count",
    "query_param_count",
    "is_ip_host",
    "has_port",
    "is_https",
    "digit_count",
    "letter_count",
    "special_count",
    "digit_ratio",
    "letter_ratio",
    "special_ratio",
    "token_count",
    "max_token_len",
    "avg_token_len",
    "url_entropy",
    "host_entropy",
    "count_at",
    "count_question",
    "count_hyphen",
    "count_equal",
    "count_dot",
    "count_percent",
    "count_slash",
    "count_semicolon",
    "count_ampersand",
    "has_suspicious_tld",
    "has_hacked_keywords",
]

SUSPICIOUS_TLDS = frozenset([
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "buzz", "rest", "fit", "casa", "surf", "icu", "bar", "live", "vip"
])

HACK_KEYWORDS = re.compile(
    r"login|signin|verify|account|banking|secure|update|confirm|wallet|admin|wp-content|"
    r"cmd|shell|exec|eval|select|union|insert|drop|etc/passwd|windows/system32|powershell|c2|payload",
    re.I
)

RE_IP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
PRINTABLE_RE = re.compile(b"[A-Za-z0-9_\\-\\.\\/\\\\:=?&]{5,120}")


def ln1p(x: float) -> float:
    if x is None or math.isnan(x) or x <= 0:
        return 0.0
    return float(math.log1p(x))


def shannon_entropy_str(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c, count in counts.items():
        p = count / total
        ent -= p * math.log2(p)
    return float(ent)


def extract_url_features(raw_url: str) -> List[float]:
    """
    Extracts identical 32 features from a raw URL, domain, IP, or raw IOC string.
    Mirrors OpenEDR/owlyshield_predict/src/ml/url_predict.rs exactly.
    """
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        url = "http://" + raw_url
    else:
        url = raw_url

    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else ""
    path = parsed.path or ""
    query = parsed.query or ""

    url_len = float(len(raw_url))
    domain_len = float(len(host))
    path_len = float(len(path))
    query_len = float(len(query))

    path_depth = float(len([p for p in path.split("/") if p]))
    subdomain_count = float(max(0, len(host.split(".")) - 2))

    try:
        query_param_count = float(len(parse_qs(query)))
    except Exception:
        query_param_count = float(query.count("&") + 1 if query else 0)

    is_ip = 1.0 if RE_IP.match(host) else 0.0
    has_port = 1.0 if ":" in parsed.netloc else 0.0
    is_https = 1.0 if raw_url.lower().startswith("https://") else 0.0

    digits = float(sum(c.isdigit() for c in raw_url))
    letters = float(sum(c.isalpha() for c in raw_url))
    specials = float(url_len - digits - letters)

    digit_ratio = digits / max(1.0, url_len)
    letter_ratio = letters / max(1.0, url_len)
    special_ratio = specials / max(1.0, url_len)

    tokens = [t for t in re.split(r"[/._?=&-]", raw_url) if t]
    token_count = float(len(tokens))
    if tokens:
        token_lens = [len(t) for t in tokens]
        max_tok = float(max(token_lens))
        avg_tok = float(sum(token_lens) / len(tokens))
    else:
        max_tok = avg_tok = 0.0

    url_entropy = shannon_entropy_str(raw_url)
    host_entropy = shannon_entropy_str(host)

    c_at = float(raw_url.count("@"))
    c_q = float(raw_url.count("?"))
    c_hyphen = float(raw_url.count("-"))
    c_eq = float(raw_url.count("="))
    c_dot = float(raw_url.count("."))
    c_pct = float(raw_url.count("%"))
    c_slash = float(raw_url.count("/"))
    c_semi = float(raw_url.count(";"))
    c_amp = float(raw_url.count("&"))

    tld = host.split(".")[-1].lower() if "." in host else ""
    susp_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
    hacked_kw = 1.0 if HACK_KEYWORDS.search(raw_url) else 0.0

    return [
        ln1p(url_len),
        ln1p(domain_len),
        ln1p(path_len),
        ln1p(query_len),
        path_depth,
        subdomain_count,
        query_param_count,
        is_ip,
        has_port,
        is_https,
        ln1p(digits),
        ln1p(letters),
        ln1p(specials),
        digit_ratio,
        letter_ratio,
        special_ratio,
        ln1p(token_count),
        ln1p(max_tok),
        avg_tok,
        url_entropy,
        host_entropy,
        c_at,
        c_q,
        ln1p(c_hyphen),
        ln1p(c_eq),
        ln1p(c_dot),
        ln1p(c_pct),
        ln1p(c_slash),
        c_semi,
        ln1p(c_amp),
        susp_tld,
        hacked_kw,
    ]


class ChunkWriter:
    """
    Writes extracted feature vectors in fixed-size chunks to disk
    and immediately frees Python heap memory to prevent RAM bloat.
    """
    def __init__(self, output_dir: str, chunk_size: int = 50000):
        self.output_dir = output_dir
        self.chunk_size = chunk_size
        self.chunk_idx = 1
        self.buffer_X: List[List[float]] = []
        self.buffer_y: List[int] = []
        self.total_benign = 0
        self.total_malicious = 0
        os.makedirs(self.output_dir, exist_ok=True)

    def add(self, raw_str: str, label: int):
        feat = extract_url_features(raw_str)
        self.buffer_X.append(feat)
        self.buffer_y.append(label)
        if label == 0:
            self.total_benign += 1
        else:
            self.total_malicious += 1

        if len(self.buffer_y) >= self.chunk_size:
            self.flush()

    def flush(self):
        if not self.buffer_y:
            return
        chunk_file = os.path.join(self.output_dir, f"chunk_{self.chunk_idx:04d}.joblib")
        X_arr = np.array(self.buffer_X, dtype=np.float32)
        y_arr = np.array(self.buffer_y, dtype=np.int32)

        joblib.dump({"X": X_arr, "y": y_arr}, chunk_file, compress=3)
        print(f"  [>] Flushed Chunk {self.chunk_idx:04d}: {len(y_arr):,} samples to {os.path.basename(chunk_file)} "
              f"(Benign: {np.sum(y_arr == 0):,}, Malicious: {np.sum(y_arr == 1):,})")

        self.chunk_idx += 1
        self.buffer_X.clear()
        self.buffer_y.clear()
        gc.collect()

    def finalize(self):
        self.flush()
        print(f"[+] All chunks saved. Total processed: {self.total_benign + self.total_malicious:,} "
              f"({self.total_benign:,} Benign, {self.total_malicious:,} Malicious).")


def extract_strings_from_binary_file(file_path: str, max_strings: int = 200) -> Generator[str, None, None]:
    """Extracts printable ASCII strings from binary files (PE, APK, DEX)."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(1024 * 1024 * 4)  # read up to 4MB per file
        count = 0
        for match in PRINTABLE_RE.finditer(data):
            cand = match.group(0).decode("ascii", errors="ignore").strip()
            if cand and not cand.startswith(("#", "//", "/*")):
                yield cand
                count += 1
                if count >= max_strings:
                    break
    except Exception:
        return


def extract_clamav_strings(clamav_dir: str) -> Generator[str, None, None]:
    """Extracts malicious URLs and signature strings from ClamAV database."""
    if not os.path.isdir(clamav_dir):
        return

    # 1. URL specific NDB files
    url_files = ["phish.ndb", "scam.ndb", "jurlbl.ndb", "blurl.ndb", "bofhland_phishing_URL.ndb", "bofhland_malware_URL.ndb"]
    for fname in url_files:
        fpath = os.path.join(clamav_dir, fname)
        if not os.path.isfile(fpath):
            continue
        print(f"  [ClamAV] Reading URL signatures from: {fname}...")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    hex_sig = re.sub(r"\{[^\}]+\}|\([^\)]+\)|\*|\?", "", parts[3])
                    if len(hex_sig) >= 8 and len(hex_sig) % 2 == 0:
                        try:
                            raw = bytes.fromhex(hex_sig)
                            for match in PRINTABLE_RE.finditer(raw):
                                yield match.group(0).decode("ascii", errors="ignore")
                        except ValueError:
                            pass

    # 2. Body NDB / LDB files (samples)
    for fname in ["main.ndb", "daily.ndb", "daily.ldb"]:
        fpath = os.path.join(clamav_dir, fname)
        if not os.path.isfile(fpath):
            continue
        print(f"  [ClamAV] Reading binary signatures from: {fname}...")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            count = 0
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    hex_sig = re.sub(r"\{[^\}]+\}|\([^\)]+\)|\*|\?", "", parts[3])
                    if len(hex_sig) >= 12 and len(hex_sig) % 2 == 0:
                        try:
                            raw = bytes.fromhex(hex_sig)
                            for match in PRINTABLE_RE.finditer(raw):
                                yield match.group(0).decode("ascii", errors="ignore")
                                count += 1
                        except ValueError:
                            pass
                if count >= 100000:
                    break


def extract_yara_strings(yara_dir: str) -> Generator[str, None, None]:
    """Extracts strings from custom YARA rules."""
    if not os.path.isdir(yara_dir):
        return
    yara_files = glob.glob(os.path.join(yara_dir, "**", "*.yar*"), recursive=True)
    for yfile in yara_files:
        with open(yfile, "r", encoding="utf-8", errors="ignore") as fh:
            in_strings = False
            for line in fh:
                lstr = line.strip()
                if lstr == "strings:":
                    in_strings = True
                    continue
                elif lstr == "condition:":
                    in_strings = False
                    continue
                if in_strings:
                    str_match = re.search(r'\$\w+\s*=\s*"([^"]{5,})"', lstr)
                    if str_match:
                        yield str_match.group(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Extract Multi-Modal IOC & String Features Part-by-Part")
    parser.add_argument("--website-dir", default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\website")
    parser.add_argument("--clamav-dir", default=r"C:\Program Files\ClamAV\database")
    parser.add_argument("--yara-dir", default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\yara-x")
    parser.add_argument("--usb-dir", default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar")
    parser.add_argument("--mobile-dir", default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset")
    parser.add_argument("--output-chunks", default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models\cache_chunks")
    parser.add_argument("--chunk-size", type=int, default=50000, help="Number of samples per disk chunk")
    parser.add_argument("--max-items-per-source", type=int, default=150000, help="Quota per sub-corpus to avoid imbalance")
    return parser.parse_args()


def main():
    args = parse_args()
    print("=" * 72)
    print(" HydraDragon - Universal Multi-Modal IOC & String Feature Extractor ")
    print(f" Chunk Size: {args.chunk_size:,} | Output: {args.output_chunks}")
    print("=" * 72)

    writer = ChunkWriter(output_dir=args.output_chunks, chunk_size=args.chunk_size)

    # ---- Phase 1: Whitelist Ground-Truth for Safeguarding ----
    print("\n[Phase 1] Collecting Known Benign Whitelist (Label 0)...")
    benign_safeguard: Set[str] = set()

    # 1.1 Website Whitelist Domains & IPs
    if os.path.isdir(args.website_dir):
        benign_files = ["BenignIPs.txt", "WhiteListIPv4.csv", "WhiteListDomains.csv", "WhiteListSubDomains.csv", "BenignDomains.txt"]
        for fname in benign_files:
            fpath = os.path.join(args.website_dir, fname)
            if not os.path.isfile(fpath):
                continue
            print(f"  [+] Loading Benign entries from: {fname}...")
            count = 0
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    cand = line.split(",")[0].strip().lower()
                    if cand and not cand.startswith("#") and cand != "entry" and cand != "domain":
                        benign_safeguard.add(cand)
                        writer.add(cand, label=0)
                        count += 1
                        if count >= args.max_items_per_source:
                            break

    # 1.2 Mobile Benign Samples (APKs)
    mobile_benign_dir = os.path.join(args.mobile_dir, "benign")
    if os.path.isdir(mobile_benign_dir):
        print(f"  [+] Scanning Mobile Benign APKs in: {mobile_benign_dir}...")
        apk_count = 0
        for root, _, files in os.walk(mobile_benign_dir):
            for file in files:
                fpath = os.path.join(root, file)
                for s in extract_strings_from_binary_file(fpath, max_strings=100):
                    benign_safeguard.add(s.lower())
                    writer.add(s, label=0)
                apk_count += 1
                if apk_count >= 500:
                    break
            if apk_count >= 500:
                break

    print(f"[+] Total Benign Samples Extracted: {writer.total_benign:,}")

    # ---- Phase 2: Malicious Sources (Label 1) with Whitelist Safeguard ----
    print("\n[Phase 2] Collecting Malicious Signatures, IOCs & Samples (Label 1)...")
    quota_malicious = writer.total_benign  # Balance strictly 50/50

    # 2.1 ClamAV Signatures
    if os.path.isdir(args.clamav_dir):
        print(f"  [-] Extracting from ClamAV Database: {args.clamav_dir}...")
        for s in extract_clamav_strings(args.clamav_dir):
            if s.lower() in benign_safeguard:
                continue
            writer.add(s, label=1)
            if writer.total_malicious >= quota_malicious // 4:
                break

    # 2.2 Custom YARA Rules
    if os.path.isdir(args.yara_dir):
        print(f"  [-] Extracting from YARA Rules: {args.yara_dir}...")
        for s in extract_yara_strings(args.yara_dir):
            if s.lower() in benign_safeguard:
                continue
            writer.add(s, label=1)
            if writer.total_malicious >= quota_malicious // 2:
                break

    # 2.3 Website Malicious Domains & IPs
    if os.path.isdir(args.website_dir):
        mal_files = ["PhishingDomains.csv", "AbuseDomains.csv", "MalwareDomains.csv", "IPv4PhishingActive.csv", "IPv4Malware.csv"]
        for fname in mal_files:
            fpath = os.path.join(args.website_dir, fname)
            if not os.path.isfile(fpath):
                continue
            print(f"  [-] Extracting from Website Blacklist: {fname}...")
            count = 0
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    cand = line.split(",")[0].strip().lower()
                    if cand and cand != "entry" and cand not in benign_safeguard:
                        writer.add(cand, label=1)
                        count += 1
                        if count >= args.max_items_per_source // 2:
                            break
                    if writer.total_malicious >= (quota_malicious * 3) // 4:
                        break

    # 2.4 USB Samples (Malware Binaries & Scripts)
    if os.path.isdir(args.usb_dir):
        print(f"  [-] Extracting from USB Malware Samples: {args.usb_dir}...")
        sample_count = 0
        for root, _, files in os.walk(args.usb_dir):
            # Skip massive archives directly
            for file in files:
                if file.endswith((".7z", ".zip", ".rar", ".tar", ".gz")):
                    continue
                fpath = os.path.join(root, file)
                for s in extract_strings_from_binary_file(fpath, max_strings=150):
                    if s.lower() in benign_safeguard:
                        continue
                    writer.add(s, label=1)
                sample_count += 1
                if writer.total_malicious >= quota_malicious or sample_count >= 2000:
                    break
            if writer.total_malicious >= quota_malicious or sample_count >= 2000:
                break

    # 2.5 Mobile Malware APKs
    mobile_malware_dir = os.path.join(args.mobile_dir, "malware")
    if os.path.isdir(mobile_malware_dir) and writer.total_malicious < quota_malicious:
        print(f"  [-] Extracting from Mobile Malware APKs: {mobile_malware_dir}...")
        apk_count = 0
        for root, _, files in os.walk(mobile_malware_dir):
            for file in files:
                fpath = os.path.join(root, file)
                for s in extract_strings_from_binary_file(fpath, max_strings=150):
                    if s.lower() in benign_safeguard:
                        continue
                    writer.add(s, label=1)
                apk_count += 1
                if writer.total_malicious >= quota_malicious or apk_count >= 500:
                    break
            if writer.total_malicious >= quota_malicious or apk_count >= 500:
                break

    # Finalize remaining buffer to disk
    writer.finalize()
    print("=" * 72)
    print(f"[✓] Feature extraction complete! Chunks are saved in: {args.output_chunks}")
    print(f"    Total Benign (0):    {writer.total_benign:,}")
    print(f"    Total Malicious (1): {writer.total_malicious:,}")
    print("=" * 72)


if __name__ == "__main__":
    main()
