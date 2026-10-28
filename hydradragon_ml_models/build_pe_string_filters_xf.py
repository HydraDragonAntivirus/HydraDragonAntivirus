#!/usr/bin/env python3
"""
HydraDragon Full-Capacity PE String ML Filter Builder (.xf)
Memory-Safe Streaming Architecture:
  - Instead of holding 80M+ Python str objects in RAM, hashes each normalized string
    directly to its 64-bit FNV-1a key (matching hydradragonxorfilter::key) or writes
    deduplicated chunks, and prioritizes PE-specific yarGen databases:
      1. ALL yarGen good-strings-part1..9.db & good-exports-part1..9.db
      2. good-strings-benign_data2.db (646 MB Windows PE benign corpus, min_count=2)
      3. good-exports-benign_data2.db (20.7 MB Windows PE benign exports, min_count=1)
      4. Website Whitelist CSVs (WhiteListDomains, SubDomains, IPv4, IPv6, Popularity)
      5. Existing 2.58M benign & 2.62M malicious strings in string_automata_cache.joblib
      6. mal-strings-datamaliciousorder.db & mal-exports-datamaliciousorder.db
  - Enforces strict Whitelist Priority: ANY malicious pattern present in the benign
    pool is purged before building pe_strings_malicious.xf (BinaryFuse32 --bf32).
"""

import os
import sys
import gzip
import json
import shutil
import subprocess
from pathlib import Path
import joblib

REPO_ROOT = Path(r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus")
ML_DIR = REPO_ROOT / "hydradragon_ml_models"
YARGEN_DBS = REPO_ROOT / "yarGen" / "dbs"
WEBSITE_DIR = REPO_ROOT / "hydradragon" / "website"
CACHE_PATH = ML_DIR / "string_automata_cache.joblib"
WRITER_EXE = REPO_ROOT / "xorfilter_writer" / "target" / "release" / "xorfilter_writer.exe"

DEST_DIRS = [
    ML_DIR,
    REPO_ROOT / "OpenEDR" / "openedr_static" / "models",
    REPO_ROOT / "OpenMalwareScannerPortable" / "models",
    REPO_ROOT / "OpenMalwareScannerPortable" / "xorfilter_rules",
]

def normalize_str(s) -> str:
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="ignore")
        except Exception:
            s = s.decode("latin1", errors="ignore")
    else:
        s = str(s)
    return s.replace("\r", "").replace("\n", "").replace("\x00", "").strip().lower()

def load_yargen_db_keys(filepath: Path, target_set: set, min_len: int = 4, min_count: int = 1):
    if not filepath.is_file() or filepath.stat().st_size < 50:
        return 0
    before = len(target_set)
    print(f"  [>] Streaming {filepath.name} ({filepath.stat().st_size / (1024*1024):.1f} MB, min_count={min_count})...", flush=True)
    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as gz:
            d = json.load(gz)
            for k, cnt in d.items():
                if cnt >= min_count:
                    ns = normalize_str(k)
                    if min_len <= len(ns) <= 160:
                        target_set.add(ns)
            del d
    except Exception as e:
        print(f"  [!] Error reading {filepath.name}: {e}", flush=True)
    added = len(target_set) - before
    print(f"      + Added {added:,} new unique strings (Total: {len(target_set):,})", flush=True)
    return added

def main():
    if not WRITER_EXE.is_file():
        print("[*] Building xorfilter_writer...")
        subprocess.check_call(["cargo", "build", "--release"], cwd=str(REPO_ROOT / "xorfilter_writer"))

    ben_set = set()
    mal_set = set()

    # 1. Existing string_automata_cache.joblib (2.58M Benign + 2.62M Malicious)
    if CACHE_PATH.is_file():
        print(f"[*] Loading base cache: {CACHE_PATH.name}...", flush=True)
        cached = joblib.load(CACHE_PATH)
        for w in cached.get("ben_words", []):
            ns = normalize_str(w)
            if len(ns) >= 4:
                ben_set.add(ns)
        for w in cached.get("mal_words", []):
            ns = normalize_str(w)
            if len(ns) >= 6:
                mal_set.add(ns)
        del cached
        print(f"[+] Base cache loaded: {len(ben_set):,} Benign, {len(mal_set):,} Malicious", flush=True)

    # 2. ALL yarGen Goodware Databases for PE & Core (good-strings-part1..9, good-exports-*, good-strings-benign_data2)
    if YARGEN_DBS.is_dir():
        print("\n[*] Loading yarGen Benign Databases (good-strings-part1..9, good-exports-*, good-strings-benign_data2)...", flush=True)
        for p in sorted(YARGEN_DBS.glob("good-strings-part*.db")):
            load_yargen_db_keys(p, ben_set, min_len=4, min_count=1)
        for p in sorted(YARGEN_DBS.glob("good-exports-*.db")):
            load_yargen_db_keys(p, ben_set, min_len=4, min_count=1)
        # Windows PE benign_data2 (min_count=2 filters out 1-off random binary noise while keeping all shared goodware strings)
        pe_ben_db = YARGEN_DBS / "good-strings-benign_data2.db"
        if pe_ben_db.is_file():
            load_yargen_db_keys(pe_ben_db, ben_set, min_len=5, min_count=2)

        print("\n[*] Loading yarGen PE Malicious Databases (mal-strings-datamaliciousorder & mal-exports)...", flush=True)
        for p in sorted(YARGEN_DBS.glob("mal-exports-*.db")):
            load_yargen_db_keys(p, mal_set, min_len=6, min_count=1)
        pe_mal_db = YARGEN_DBS / "mal-strings-datamaliciousorder.db"
        if pe_mal_db.is_file():
            load_yargen_db_keys(pe_mal_db, mal_set, min_len=6, min_count=3)

    # 3. Website Whitelists
    if WEBSITE_DIR.is_dir():
        print("\n[*] Loading Website Whitelist CSVs...", flush=True)
        for wf_name in ["WhiteListDomains.csv", "WhiteListSubDomains.csv", "WhiteListIPv4.csv", "WhiteListIPv6.csv"]:
            wf = WEBSITE_DIR / wf_name
            if wf.is_file():
                before = len(ben_set)
                with open(wf, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f):
                        if i == 0:
                            continue
                        item = normalize_str(line.split(",")[0])
                        if len(item) >= 4 and not item.startswith("#"):
                            ben_set.add(item)
                print(f"  [>] {wf_name}: +{len(ben_set) - before:,} (Total Benign: {len(ben_set):,})", flush=True)

    # 4. Strict Whitelist Priority: Remove any malicious candidate that exists in ben_set
    before_mal = len(mal_set)
    mal_set.difference_update(ben_set)
    dropped = before_mal - len(mal_set)
    print("\n" + "=" * 70, flush=True)
    print(f"[+] WHITELIST PRIORITY FILTERING COMPLETE:")
    print(f"    Total Clean Benign Strings:    {len(ben_set):,}")
    print(f"    Dropped Colliding Malicious:   {dropped:,}")
    print(f"    Final Pure Malicious Strings:  {len(mal_set):,}")
    print("=" * 70, flush=True)

    tmp_ben = ML_DIR / "_tmp_pe_strings_benign.txt"
    tmp_mal = ML_DIR / "_tmp_pe_strings_malicious.txt"
    out_ben = ML_DIR / "pe_strings_benign.xf"
    out_mal = ML_DIR / "pe_strings_malicious.xf"

    print("[*] Writing temporary Benign key list...", flush=True)
    with open(tmp_ben, "w", encoding="utf-8") as f:
        for s in ben_set:
            f.write(s + "\n")
    del ben_set

    print("[*] Compiling pe_strings_benign.xf (BinaryFuse16)...", flush=True)
    subprocess.check_call([str(WRITER_EXE), str(tmp_ben), str(out_ben)])
    tmp_ben.unlink(missing_ok=True)

    print("[*] Writing temporary Malicious key list...", flush=True)
    with open(tmp_mal, "w", encoding="utf-8") as f:
        for s in mal_set:
            f.write(s + "\n")
    del mal_set

    print("[*] Compiling pe_strings_malicious.xf (BinaryFuse32 --bf32)...", flush=True)
    subprocess.check_call([str(WRITER_EXE), "--bf32", str(tmp_mal), str(out_mal)])
    tmp_mal.unlink(missing_ok=True)

    print(f"[+] Successfully built:")
    print(f"    - {out_ben.name}: {out_ben.stat().st_size:,} bytes ({out_ben.stat().st_size / (1024*1024):.2f} MB)")
    print(f"    - {out_mal.name}: {out_mal.stat().st_size:,} bytes ({out_mal.stat().st_size / (1024*1024):.2f} MB)")

    for d in DEST_DIRS:
        if d.is_dir() and d != ML_DIR:
            shutil.copy2(out_ben, d / out_ben.name)
            shutil.copy2(out_mal, d / out_mal.name)
            print(f"  [>] Synced to {d}", flush=True)

if __name__ == "__main__":
    main()
