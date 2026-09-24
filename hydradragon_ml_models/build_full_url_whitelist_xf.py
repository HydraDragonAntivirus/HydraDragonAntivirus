#!/usr/bin/env python3
"""
HydraDragon Master BinaryFuse16 (.xf) Whitelist Builder
Consolidates ALL whitelists from hydradragon/website/ and compiles an updated,
ultra-fast BinaryFuse16 (.xf) filter using xorfilter_writer.exe.

Features:
  - Aggregates Domains and IPs (IPv4 & IPv6).
  - Normalizes keys (lowercase, strips protocols, ports, trailing dots).
  - Builds BinaryFuse16 filter via Rust binary (~2.16 bytes/key, 0% FN, O(1) lookup).
  - Synchronizes the updated .xf filter to all engine folders across the repo.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Set

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_DIR = REPO_ROOT / "hydradragon" / "website"
WRITER_EXE = REPO_ROOT / "xorfilter_writer" / "target" / "release" / "xorfilter_writer.exe"

DEST_DIRS = [
    REPO_ROOT / "OpenEDR" / "owlyshield_predict" / "xorfilter_rules",
    REPO_ROOT / "OpenEDR" / "openedr_web" / "www" / "xorfilter_rules",
    REPO_ROOT / "OpenMalwareScannerPortable" / "models",
    REPO_ROOT / "OpenMalwareScannerPortable" / "xorfilter_rules",
    REPO_ROOT / "docs" / "xorfilter_rules",
]

def clean_key(raw: str) -> str:
    raw = raw.strip().lower()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw and not ("." not in raw and ":" in raw): # Strip port unless it's pure IPv6
        raw = raw.split(":", 1)[0]
    if raw.endswith("."):
        raw = raw[:-1]
    return raw.strip()

def collect_all_whitelists(website_dir: Path) -> Set[str]:
    # User instruction: ONLY CSV whitelist files
    whitelist_files = [
        "WhiteListDomains.csv",
        "WhiteListSubDomains.csv",
        "BenignMailDomains.csv",
        "BenignMailSubDomains.csv",
        "DomainsPopularityWhiteList.csv",
        "WhiteListIPv4.csv",
        "WhiteListIPv6.csv",
    ]

    all_keys: Set[str] = set()
    print("=" * 65)
    print(f"[*] Aggregating Whitelists (ONLY CSV) from: {website_dir}")
    print("=" * 65)

    for fname in whitelist_files:
        fpath = website_dir / fname
        if not fpath.is_file():
            continue

        count_before = len(all_keys)
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line or line.startswith("#"):
                    continue
                first_col = line.split(",")[0].strip()
                if not first_col or first_col in ("entry", "domain", "ip"):
                    continue
                k = clean_key(first_col)
                if len(k) >= 2 and not k.startswith("#"):
                    all_keys.add(k)

        added = len(all_keys) - count_before
        print(f"  [+] {fname:32}: added {added:,} entries (Total: {len(all_keys):,})")

    print("=" * 65)
    print(f"[+] Total Distinct Whitelist Keys Collected: {len(all_keys):,}")
    print("=" * 65)
    return all_keys

def main():
    if not WEBSITE_DIR.is_dir():
        print(f"[!] Error: Website directory not found at: {WEBSITE_DIR}")
        sys.exit(1)

    if not WRITER_EXE.is_file():
        print(f"[!] Error: xorfilter_writer binary not found at: {WRITER_EXE}")
        print("[*] Building xorfilter_writer via cargo...")
        subprocess.check_call(["cargo", "build", "--release"], cwd=str(REPO_ROOT / "xorfilter_writer"))

    # 1. Collect and deduplicate
    keys = collect_all_whitelists(WEBSITE_DIR)
    if not keys:
        print("[!] No whitelist keys found.")
        sys.exit(1)

    # 2. Stage to text file
    stage_txt = REPO_ROOT / "hydradragon_ml_models" / "staged_whitelist_all.txt"
    print(f"[*] Writing {len(keys):,} sorted keys to staging file: {stage_txt}...")
    with open(stage_txt, "w", encoding="utf-8", newline="\n") as f:
        for k in sorted(keys):
            f.write(k + "\n")
    print(f"[+] Staged file written successfully ({stage_txt.stat().st_size / (1024*1024):.2f} MB).")

    # 3. Build BinaryFuse16 (.xf) filter via xorfilter_writer
    out_xf = REPO_ROOT / "hydradragon_ml_models" / "url_whitelist.xf"
    print(f"[*] Running xorfilter_writer to generate BinaryFuse16 (.xf)...")
    cmd = [str(WRITER_EXE), str(stage_txt), str(out_xf)]
    subprocess.check_call(cmd)

    xf_size_mb = out_xf.stat().st_size / (1024 * 1024)
    print(f"\n[+] BinaryFuse16 filter created: {out_xf} ({xf_size_mb:.2f} MB)")

    # 4. Synchronize to all engine directories
    print("\n[*] Synchronizing updated url_whitelist.xf to all engine directories:")
    for dest_dir in DEST_DIRS:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / "url_whitelist.xf"
        shutil.copy2(out_xf, dest_file)
        print(f"  [>] Updated: {dest_file}")

    # 5. Clean up staging text file
    if stage_txt.exists():
        stage_txt.unlink()
        print(f"[+] Cleaned up temporary staging file.")

    # 6. Verification check on sample items
    print("\n[*] Verifying compiled filter with round-trip checks:")
    sample_tests = ["google.com", "8.8.8.8", "1.1.1.1", "nic.in", "cloudflare.com"]
    for sample in sample_tests:
        res = subprocess.run([str(WRITER_EXE), "--check", str(out_xf), sample],
                             capture_output=True, text=True)
        output_line = res.stdout.strip() or res.stderr.strip()
        print(f"  -> {output_line}")

    print("\n" + "=" * 65)
    print(" [+] MASTER BINARYFUSE16 WHITELIST BUILD COMPLETE! ")
    print("=" * 65)

if __name__ == "__main__":
    main()
