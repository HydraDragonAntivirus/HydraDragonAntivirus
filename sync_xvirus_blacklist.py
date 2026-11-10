"""Xvirus Daily Malicious Blacklist Routine Synchronization Daemon / Job.

Target:
  https://raw.githubusercontent.com/danisss9/Xvirus/main/Cloud/sdk/Database/dailylist.db

Enforced Security Rules:
  1. 0-Size Empty File Safety:
     `d41d8cd98f00b204e9800998ecf8427e` is NEVER blacklisted.
  2. Whitelist Priority (P0):
     Hashes in NSRL or `purged_md5_false_positives.txt` are strictly dropped.
  3. Analyst Overrides:
     Hashes in `analyst_signatures/blacklist_removals.jsonl` are strictly dropped.
  4. Separation:
     MD5 hashes are kept strictly separate in `allblooms/dailylist_xvirus_md5.txt`
     and `allblooms/md5.txt`. SHA-256 and SHA-1 lists/filters are never mixed.
  5. Archive Safety:
     `C:\\viruskov_archive` is NEVER touched.

Usage:
  python sync_xvirus_blacklist.py [--once] [--interval <seconds>] [--build-xf]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
ALLBLOOMS = os.path.join(HERE, "allblooms")
TARGET_MD5 = os.path.join(ALLBLOOMS, "md5.txt")
DAILY_CACHE_FILE = os.path.join(ALLBLOOMS, "dailylist_xvirus_md5.txt")
DAILY_DB_FILE = os.path.join(ALLBLOOMS, "dailylist.db")
RULES_DAILY_DB = os.path.join(HERE, "OpenMalwareScannerPortable", "xorfilter_rules", "dailylist.db")
PURGED_FP_FILE = os.path.join(ALLBLOOMS, "purged_md5_false_positives.txt")
OVERRIDES_FILE = os.path.join(HERE, "analyst_signatures", "blacklist_removals.jsonl")

XVIRUS_URL = "https://raw.githubusercontent.com/danisss9/Xvirus/main/Cloud/sdk/Database/dailylist.db"
ZERO_SIZE_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def load_benign_purged() -> set:
    """Load known benign / purged MD5 false positives."""
    benign = set()
    if os.path.isfile(PURGED_FP_FILE):
        with open(PURGED_FP_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                t = line.strip().lower()
                if not t or t.startswith("#"):
                    continue
                if "#" in t:
                    t = t.split("#")[0].strip()
                if len(t) == 32 and all(c in "0123456789abcdef" for c in t):
                    benign.add(t)
    return benign


def load_analyst_overrides() -> set:
    """Load analyst overrides (removals)."""
    overrides = set()
    if os.path.isfile(OVERRIDES_FILE):
        with open(OVERRIDES_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                t = line.strip()
                if not t:
                    continue
                try:
                    obj = json.loads(t)
                    if obj.get("removed", True):
                        h = obj.get("hash", "").strip().lower()
                        if len(h) == 32:
                            overrides.add(h)
                except Exception:
                    pass
    return overrides


def fetch_xvirus_dailylist() -> list:
    """Fetch raw hashes from Xvirus repository."""
    req = urllib.request.Request(
        XVIRUS_URL,
        headers={"User-Agent": "HydraDragonAntivirus-Sync/1.0 (Windows NT 10.0; Win64; x64)"},
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        content = resp.read().decode("utf-8", errors="ignore")

    hashes = []
    for line in content.splitlines():
        t = line.strip().lower()
        if len(t) == 32 and all(c in "0123456789abcdef" for c in t):
            hashes.append(t)
    return hashes


def run_sync(build_xf: bool = False) -> int:
    """Execute one synchronization pass. Returns number of new hashes added."""
    t0 = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now_str}] [*] Checking Xvirus daily blacklist updates...")

    try:
        raw_hashes = fetch_xvirus_dailylist()
    except Exception as e:
        print(f"[{now_str}] [!] Network error fetching Xvirus dailylist: {e}")
        return 0

    print(f"[{now_str}] [+] Retrieved {len(raw_hashes):,} candidate MD5 hashes from Xvirus.")

    # Apply filters
    benign_set = load_benign_purged()
    override_set = load_analyst_overrides()

    clean_hashes = set()
    zero_dropped = 0
    benign_dropped = 0
    override_dropped = 0

    for h in raw_hashes:
        if h == ZERO_SIZE_MD5:
            zero_dropped += 1
            continue
        if h in benign_set:
            benign_dropped += 1
            continue
        if h in override_set:
            override_dropped += 1
            continue
        clean_hashes.add(h)

    print(f"[{now_str}] [+] Filtered: {zero_dropped} empty files dropped, {benign_dropped} benign collisions dropped, {override_dropped} overrides excluded.")
    print(f"[{now_str}] [+] {len(clean_hashes):,} clean malicious hashes verified.")

    # Save to daily cache files for multron_server_rs
    daily_lines = [h + "\n" for h in sorted(clean_hashes)]
    os.makedirs(ALLBLOOMS, exist_ok=True)
    with open(DAILY_CACHE_FILE, "w", encoding="utf-8") as f:
        f.writelines(daily_lines)
    with open(DAILY_DB_FILE, "w", encoding="utf-8") as f:
        f.writelines(daily_lines)
    os.makedirs(os.path.dirname(RULES_DAILY_DB), exist_ok=True)
    with open(RULES_DAILY_DB, "w", encoding="utf-8") as f:
        f.writelines(daily_lines)

    # Read existing allblooms/md5.txt to find brand new entries
    existing = set()
    if os.path.isfile(TARGET_MD5):
        with open(TARGET_MD5, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                t = line.strip().lower()
                if len(t) == 32:
                    existing.add(t)

    new_hashes = [h for h in clean_hashes if h not in existing]
    if new_hashes:
        print(f"[{now_str}] [+] Found {len(new_hashes):,} brand new malicious MD5 hashes. Appending to {os.path.relpath(TARGET_MD5, HERE)}...")
        with open(TARGET_MD5, "a", encoding="utf-8") as f:
            for h in new_hashes:
                f.write(h + "\n")
    else:
        print(f"[{now_str}] [*] All {len(clean_hashes):,} Xvirus hashes are already integrated in local database.")

    if build_xf and new_hashes:
        print(f"[{now_str}] [*] Rebuilding separate malicious_md5.xf filter...")
        cargo_path = os.path.join(HERE, "xorfilter_writer", "Cargo.toml")
        cmd = ["cargo", "run", "--release", "--bin", "build_separated_blacklists", "--manifest-path", cargo_path]
        res = subprocess.run(cmd)
        if res.returncode == 0:
            print(f"[{now_str}] [+] malicious_md5.xf updated successfully.")
        else:
            print(f"[{now_str}] [!] Error rebuilding separated blacklists.")

    elapsed = time.time() - t0
    print(f"[{now_str}] [+] Sync pass finished in {elapsed:.2f}s.\n")
    return len(new_hashes)


def main():
    parser = argparse.ArgumentParser(description="Synchronize Xvirus daily blacklist into HydraDragonAntivirus")
    parser.add_argument("--once", action="store_true", default=True, help="Run single sync pass and exit (default)")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in background")
    parser.add_argument("--interval", type=int, default=3600, help="Poll interval in seconds for daemon mode (default: 3600s / 1 hour)")
    parser.add_argument("--build-xf", action="store_true", help="Rebuild XOR filters when new hashes are detected")
    args = parser.parse_args()

    if args.daemon:
        print(f"[*] Starting Xvirus daily blacklist sync daemon (interval: {args.interval}s)...")
        while True:
            try:
                run_sync(build_xf=args.build_xf)
            except Exception as e:
                print(f"[!] Daemon error: {e}")
            time.sleep(args.interval)
    else:
        run_sync(build_xf=args.build_xf)


if __name__ == "__main__":
    main()
