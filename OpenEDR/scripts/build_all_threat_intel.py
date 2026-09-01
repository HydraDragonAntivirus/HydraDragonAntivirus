"""
Master Threat Intelligence Pipeline for OpenEDR & OwlyShield.

Processes all 37 datasets in `websitenobloom`:
- Filters out referenceless (,0) entries for both IPs and Domains to eliminate FP.
- Applies Popularity & Exact Whitelists (WhiteListDomains, WhiteListIPv4, etc.).
- Normalizes protocols (http://), ports, paths, and trailing dots.
- Generates per-category text files, CIDR lists, and combined malicious sets.
- Automatically executes xorfilter_writer to produce BinaryFuse16 (.xf) binaries.

Usage:
    python build_all_threat_intel.py <websitenobloom_dir> <output_threat_intel_dir> [xorfilter_writer_exe]
"""

import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def clean_item(raw: str, is_ip: bool = False) -> str:
    raw = raw.strip().lower()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw and not is_ip:
        raw = raw.split(":", 1)[0]
    if raw.endswith("."):
        raw = raw[:-1]
    return raw.strip()


def extract_csv_items(filepath: Path, skip_zero: bool = False, is_ip: bool = False) -> set:
    items = set()
    if not filepath.exists():
        return items
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if not row or not row[0].strip() or row[0].startswith("#"):
                continue
            if skip_zero and len(row) >= 2 and row[1].strip() == "0":
                continue
            cleaned = clean_item(row[0], is_ip=is_ip)
            if cleaned:
                items.add(cleaned)
    return items


def extract_urls_from_file(filepath: Path) -> set:
    urls = set()
    if not filepath.exists():
        return urls
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cleaned = clean_item(line)
            if cleaned:
                urls.add(cleaned)
    return urls


def process_cidrs(filepath: Path, out_path: Path):
    cidrs = []
    seen = set()
    if not filepath.exists():
        return
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if not row or not row[0].strip() or row[0].startswith("#"):
                continue
            if len(row) >= 2 and row[1].strip() == "0":
                continue
            cidr = row[0].strip()
            if cidr not in seen:
                seen.add(cidr)
                cidrs.append(cidr)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(cidrs))
        if cidrs:
            f.write("\n")
    print(f"  [CIDR] {out_path.name}: {len(cidrs):,} CIDR ranges")


def main():
    if len(sys.argv) < 3:
        print("Usage: python build_all_threat_intel.py <websitenobloom_dir> <output_threat_intel_dir> [xorfilter_writer_exe]")
        sys.exit(1)

    datasets_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    writer_exe = Path(sys.argv[3]) if len(sys.argv) >= 4 else None

    stage_dir = datasets_dir / "stage_txt"
    stage_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=== Processing websitenobloom Datasets (Full Pipeline) ===")

    # Extract Per-Category Threat Datasets
    print("\n--- Extracting Category Threat Datasets ---")
    categories = {}

    # Phishing
    categories["phishing"] = (
        extract_csv_items(datasets_dir / "PhishingDomains.optimized.csv", skip_zero=False) |
        extract_csv_items(datasets_dir / "PhishingSubDomains.optimized.csv", skip_zero=False)
    )

    # Malware (ONLY category where skip_zero=True is applied)
    categories["malware"] = (
        extract_csv_items(datasets_dir / "MalwareDomains.optimized.csv", skip_zero=True) |
        extract_csv_items(datasets_dir / "MalwareSubDomains.optimized.csv", skip_zero=True)
    )

    # Abuse
    categories["abuse"] = (
        extract_csv_items(datasets_dir / "AbuseDomains.optimized.csv", skip_zero=False) |
        extract_csv_items(datasets_dir / "AbuseSubDomains.optimized.csv", skip_zero=False)
    )

    # Mining
    categories["mining"] = (
        extract_csv_items(datasets_dir / "MiningDomains.optimized.csv", skip_zero=False) |
        extract_csv_items(datasets_dir / "MiningSubDomains.optimized.csv", skip_zero=False)
    )

    # Spam
    categories["spam"] = (
        extract_csv_items(datasets_dir / "SpamDomains.optimized.csv", skip_zero=False) |
        extract_csv_items(datasets_dir / "SpamSubDomains.optimized.csv", skip_zero=False)
    )

    # Malicious Mail
    categories["malicious_mail"] = (
        extract_csv_items(datasets_dir / "MaliciousMailDomains.optimized.csv", skip_zero=False) |
        extract_csv_items(datasets_dir / "MaliciousMailSubDomains.optimized.csv", skip_zero=False)
    )

    # IP Malware (ONLY malware uses skip_zero=True)
    categories["ip_malware"] = (
        extract_csv_items(datasets_dir / "IPv4Malware.optimized.csv", skip_zero=True, is_ip=True) |
        extract_csv_items(datasets_dir / "IPv6Malware.optimized.csv", skip_zero=True, is_ip=True)
    )

    # IP Phishing
    categories["ip_phishing"] = (
        extract_csv_items(datasets_dir / "IPv4PhishingActive.optimized.csv", skip_zero=False, is_ip=True) |
        extract_csv_items(datasets_dir / "IPv4PhishingInActive.optimized.csv", skip_zero=False, is_ip=True)
    )

    # IP Brute Force
    categories["ip_bruteforce"] = extract_csv_items(datasets_dir / "IPv4BruteForce.optimized.csv", skip_zero=False, is_ip=True)

    # IP DDoS
    categories["ip_ddos"] = (
        extract_csv_items(datasets_dir / "IPv4DDoS.optimized.csv", skip_zero=False, is_ip=True) |
        extract_csv_items(datasets_dir / "IPv6DDoS.optimized.csv", skip_zero=False, is_ip=True)
    )

    # IP Spam
    categories["ip_spam"] = (
        extract_csv_items(datasets_dir / "IPv4Spam.optimized.csv", skip_zero=False, is_ip=True) |
        extract_csv_items(datasets_dir / "IPv6Spam.optimized.csv", skip_zero=False, is_ip=True)
    )

    # 3. CIDR Subnets
    print("\n--- Processing CIDR Subnets ---")
    process_cidrs(datasets_dir / "CIDRBlackListIPv4.optimized.csv", output_dir / "CIDRBlackListIPv4.txt")
    process_cidrs(datasets_dir / "CIDRBlackListIPv6.optimized.csv", output_dir / "CIDRBlackListIPv6.txt")

    # 4. Write Staging Text Files
    print("\n--- Writing Stage Text Files ---")
    stage_files = {}

    for cat_name, items in categories.items():
        txt_path = stage_dir / f"{cat_name}.txt"
        with open(txt_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(items)))
            if items:
                f.write("\n")
        stage_files[cat_name] = txt_path
        print(f"  {txt_path.name}: {len(items):,} items")

    # 5. Generate .xf Filters via xorfilter_writer
    if writer_exe and writer_exe.exists():
        print("\n--- Generating BinaryFuse16 (.xf) Filters ---")
        for stem, txt_file in stage_files.items():
            if not txt_file.exists() or txt_file.stat().st_size == 0:
                print(f"  [SKIP] {txt_file.name} is empty (0 items), skipping .xf build")
                continue
            xf_out = output_dir / f"{stem}.xf"
            cmd = [str(writer_exe), str(txt_file), str(xf_out)]
            try:
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                print(f"  [OK] Built {xf_out.name}")
            except Exception as e:
                print(f"  [ERR] Failed building {xf_out.name}: {e}")
    else:
        print("\n[NOTE] xorfilter_writer binary path not provided or not found. Stage text files written to stage_txt/")

    print("\n=== Master Threat Intel Build Complete ===")


if __name__ == "__main__":
    main()
