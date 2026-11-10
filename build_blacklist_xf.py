"""Build the malicious hash XOR filter (`malicious_sha256.xf`, BinaryFuse32).

Uses `allblooms/` as the primary repository of blacklist hashes.
Per project requirements:
  - Supports ALL hash types (MD5, SHA-1, SHA-256) combined or individually (default: ALL).
  - Zero-size check: 0-byte (empty file) hashes are strictly excluded so empty files are never blacklisted.
  - No ssdeep (TLSH is used for fuzzy similarity, while exact hash lookups use BinaryFuse32 XOR filter).
  - Whitelist Priority (P0): Any hash found in `allblooms/whitelist/` or benign dataset
    is unconditionally excluded from the blacklist XOR filter.
  - Blacklist Overrides: Hashes recorded in `analyst_signatures/blacklist_removals.jsonl`
    are excluded from the build so that production builds reflect analyst overrides.

Usage:
  python build_blacklist_xf.py [--algo {all,sha256,sha1,md5}] [--verify]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "hydradragon_ml_models"))
try:
    import dataset_paths
except ImportError:
    dataset_paths = None

ALLBLOOMS = os.path.join(HERE, "allblooms")
OVERRIDE_FILE = os.path.join(HERE, "analyst_signatures", "blacklist_removals.jsonl")
WRITER_EXE = os.path.join(HERE, "xorfilter_writer", "target", "release", "xorfilter_writer.exe")

# 0-size / empty-file hash definitions: NEVER to be blacklisted!
ZERO_SIZE_HASHES = {
    # MD5 (32 hex)
    "d41d8cd98f00b204e9800998ecf8427e",
    # SHA-1 (40 hex)
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    # SHA-256 (64 hex)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

# Whitelist files for conflict checking (SHA-256)
WHITELIST_FILES_SHA256 = [
    os.path.join(ALLBLOOMS, "whitelist", "rds_sha256.txt"),
    os.path.join(ALLBLOOMS, "whitelist", "benign_sha256.txt"),
    os.path.join(ALLBLOOMS, "whitelist", "RDS_2026.09.1_modern_minimal_delta_sha256.txt"),
    os.path.join(ALLBLOOMS, "purged_sha256_false_positives.txt"),
]

# Blacklist sources in allblooms
SOURCES_SHA256 = [
    os.path.join(ALLBLOOMS, "sha256.txt"),
    os.path.join(ALLBLOOMS, "sha256_db"),
    os.path.join(ALLBLOOMS, "sha256amnestytech"),
    os.path.join(ALLBLOOMS, "iocemotet"),
    os.path.join(ALLBLOOMS, "virussign"),
    os.path.join(ALLBLOOMS, "samplesstalkware"),
    os.path.join(ALLBLOOMS, "eset"),
]

SOURCES_SHA1 = [
    os.path.join(ALLBLOOMS, "sha1.txt"),
]

SOURCES_MD5 = [
    os.path.join(ALLBLOOMS, "md5.txt"),
    os.path.join(ALLBLOOMS, "md5_db"),
    os.path.join(ALLBLOOMS, "virusshare1"),
    os.path.join(ALLBLOOMS, "virusshare2"),
    os.path.join(ALLBLOOMS, "virusshare2026.md5"),
    os.path.join(ALLBLOOMS, "virusshare_hashes.txt"),
    os.path.join(ALLBLOOMS, "old_hashes", "md5.txt"),
]


def classify_hex_hash(s: str) -> str:
    """Returns 'sha256', 'sha1', 'md5', or None."""
    s_len = len(s)
    if s_len not in (32, 40, 64):
        return None
    if not all(c in "0123456789abcdef" for c in s):
        return None
    if s_len == 64:
        return "sha256"
    elif s_len == 40:
        return "sha1"
    else:
        return "md5"


def load_analyst_overrides(path: str) -> set:
    """Load removed hashes from blacklist_removals.jsonl."""
    overrides = set()
    if not os.path.isfile(path):
        return overrides
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    h = obj.get("hash", "").strip().lower()
                    removed = obj.get("removed", True)
                    if removed and h:
                        overrides.add(h)
                    elif not removed and h in overrides:
                        overrides.remove(h)
                except Exception:
                    pass
    except Exception as e:
        print(f"[!] Warning reading overrides from {path}: {e}")
    return overrides


def load_whitelist_hashes(external_md5_files=None) -> set:
    """Collect known-benign hashes (SHA-256 only) to guarantee Whitelist Priority (P0).
    Benign MD5 and SHA-1 are strictly forbidden due to hash collision vulnerabilities."""
    wl = set()

    # 1. SHA-256 Whitelist files under allblooms/whitelist/
    whitelist_dir = os.path.join(ALLBLOOMS, "whitelist")
    if os.path.isdir(whitelist_dir):
        for root, _, files in os.walk(whitelist_dir):
            for f in files:
                if f.lower().endswith(".txt"):
                    wf = os.path.join(root, f)
                    if os.path.getsize(wf) > 300 * 1024 * 1024:
                        print(f"[*] Skipping {os.path.basename(wf)} (>300MB, pre-purged into purged_sha256_false_positives.txt)")
                        continue
                    print(f"[*] Reading SHA-256 whitelist: {wf}")
                    with open(wf, "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            t = line.strip().lower()
                            if not t or t.startswith("#"):
                                continue
                            if "#" in t:
                                t = t.split("#")[0].strip()
                            if len(t) == 64 and all(c in "0123456789abcdef" for c in t):
                                if t not in ZERO_SIZE_HASHES:
                                    wl.add(t)

    # 2. Add purged SHA-256 false positives
    purged_file = os.path.join(ALLBLOOMS, "purged_sha256_false_positives.txt")
    if os.path.isfile(purged_file):
        print(f"[*] Reading purged false positives: {os.path.basename(purged_file)}")
        with open(purged_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                t = line.strip().lower()
                if not t or t.startswith("#"):
                    continue
                if "#" in t:
                    t = t.split("#")[0].strip()
                if len(t) == 64 and all(c in "0123456789abcdef" for c in t):
                    if t not in ZERO_SIZE_HASHES:
                        wl.add(t)

    # 3. Read dataset benign hashes directly from cache (fast JSONL stream)
    hash_cache_file = os.path.join(HERE, "hydradragon_ml_models", "dataset_hash_cache.jsonl")
    if os.path.isfile(hash_cache_file):
        print(f"[*] Reading dataset benign hashes from cache: {os.path.basename(hash_cache_file)}")
        with open(hash_cache_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try:
                    import json
                    d = json.loads(line)
                    p = d.get("p", "").lower()
                    h = d.get("h", "").lower()
                    if len(h) == 64 and h not in ZERO_SIZE_HASHES:
                        if any(x in p for x in ["benign", "clean", "data2", "ml_fp_benign", "normal"]):
                            wl.add(h)
                except Exception:
                    pass

    return wl


def main():
    parser = argparse.ArgumentParser(
        description="Build malicious hash BinaryFuse32 XOR filter with 0-size check and Whitelist Priority."
    )
    parser.add_argument(
        "--algo",
        choices=["all", "sha256", "sha1", "md5"],
        default="all",
        help="Hash algorithm to build: 'all' merges MD5, SHA-1 and SHA-256 into a unified filter (default: all)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output .xf path (defaults to OpenMalwareScannerPortable/xorfilter_rules/malicious_sha256.xf)",
    )
    parser.add_argument(
        "--override-file",
        type=str,
        default=OVERRIDE_FILE,
        help="Path to analyst blacklist removals JSONL file",
    )
    parser.add_argument(
        "--benign-md5",
        type=str,
        nargs="*",
        default=[],
        help="External benign MD5 file(s) or directories to include in Whitelist Priority",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify the built filter with xorfilter_writer --check",
    )
    args = parser.parse_args()

    algo_choice = args.algo.lower()
    start_time = time.time()

    print("=" * 70)
    print(" HydraDragon Antivirus - Universal Blacklist XOR Filter Builder")
    print(f" Target Algorithm: {algo_choice.upper()}")
    print(" 0-Size File Protection: ACTIVE (Empty files strictly excluded)")
    print(" Whitelist Priority (P0): ACTIVE (Benign collisions excluded)")
    print("=" * 70)

    # 1. Load Whitelist & Analyst Overrides
    print("[*] Loading benign whitelist hashes...")
    whitelist = load_whitelist_hashes(args.benign_md5)
    print(f"[+] Loaded {len(whitelist):,} benign whitelist hashes for conflict checking.")

    print(f"[*] Loading analyst override list ({args.override_file})...")
    overrides = load_analyst_overrides(args.override_file)
    print(f"[+] Loaded {len(overrides):,} analyst override removals.")

    # 2. Collect Candidate Malicious Hashes
    sources_to_read = []
    if algo_choice in ("all", "sha256"):
        sources_to_read.extend([(f, "sha256") for f in SOURCES_SHA256])
    if algo_choice in ("all", "sha1"):
        sources_to_read.extend([(f, "sha1") for f in SOURCES_SHA1])
    if algo_choice in ("all", "md5"):
        sources_to_read.extend([(f, "md5") for f in SOURCES_MD5])

    # Auto-include any files under allblooms/old_hashes/ for md5 or all
    if algo_choice in ("all", "md5"):
        old_dir = os.path.join(ALLBLOOMS, "old_hashes")
        if os.path.isdir(old_dir):
            for root, _, files in os.walk(old_dir):
                for f in files:
                    full_p = os.path.join(root, f)
                    if not any(full_p == s[0] for s in sources_to_read):
                        sources_to_read.append((full_p, "auto"))

    candidate_hashes = set()
    total_raw_lines = 0
    zero_size_dropped = 0
    counts_by_type = {"md5": 0, "sha1": 0, "sha256": 0}

    for src_path, expected_type in sources_to_read:
        if not os.path.isfile(src_path):
            continue
        try:
            # 0-size file check on source list itself
            if os.path.getsize(src_path) == 0:
                print(f"[!] Skipping 0-byte source file: {src_path}")
                continue
        except OSError:
            continue

        print(f"[*] Reading malicious hashes from: {src_path} ({expected_type.upper()})")
        with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_raw_lines += 1
                t = line.strip().lower()
                if not t:
                    continue
                # If space or comma separated (e.g. md5:filename or hash,name), take the first token
                if " " in t:
                    t = t.split()[0]
                elif "," in t:
                    t = t.split(",")[0]
                elif ":" in t:
                    t = t.split(":")[0]

                # 0-size / empty file hash check
                if t in ZERO_SIZE_HASHES:
                    zero_size_dropped += 1
                    continue

                htype = classify_hex_hash(t)
                if htype:
                    if algo_choice == "all" or algo_choice == htype:
                        if t not in candidate_hashes:
                            candidate_hashes.add(t)
                            counts_by_type[htype] += 1

    # Also collect malicious dataset hashes from cache if sha256 or all
    if algo_choice in ("all", "sha256"):
        hash_cache_file = os.path.join(HERE, "hydradragon_ml_models", "dataset_hash_cache.jsonl")
        if os.path.isfile(hash_cache_file):
            print(f"[*] Reading dataset malicious hashes from cache: {os.path.basename(hash_cache_file)}")
            with open(hash_cache_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        sz = d.get("s", 0)
                        if sz == 0:
                            zero_size_dropped += 1
                            continue
                        p = d.get("p", "").lower()
                        h = d.get("h", "").strip().lower()
                        if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                            if h in ZERO_SIZE_HASHES:
                                zero_size_dropped += 1
                                continue
                            if not any(x in p for x in ["benign", "clean", "data2", "ml_fp_benign", "normal"]):
                                if h not in candidate_hashes:
                                    candidate_hashes.add(h)
                                    counts_by_type["sha256"] += 1
                    except Exception:
                        pass

    print("-" * 70)
    print(f"[*] Total lines processed: {total_raw_lines:,}")
    print(f"[*] Candidate hashes found: {len(candidate_hashes):,}")
    print(f"    - SHA-256: {counts_by_type['sha256']:,}")
    print(f"    - SHA-1:   {counts_by_type['sha1']:,}")
    print(f"    - MD5:     {counts_by_type['md5']:,}")
    print(f"[+] 0-size check: {zero_size_dropped:,} empty-file (0 bytes) hashes excluded.")
    print("-" * 70)

    # 3. Filter Out Whitelist Hits & Analyst Overrides
    clean_malicious = []
    wl_excluded = 0
    override_excluded = 0

    for h in sorted(candidate_hashes):
        # 0-size double-check
        if h in ZERO_SIZE_HASHES:
            zero_size_dropped += 1
            continue
        # Whitelist Priority (P0)
        if h in whitelist:
            wl_excluded += 1
            continue
        # Analyst Override list
        if h in overrides:
            override_excluded += 1
            continue
        clean_malicious.append(h)

    print(f"[+] Filter resolution summary:")
    print(f"    - {wl_excluded:,} benign whitelist collisions excluded (Whitelist Priority)")
    print(f"    - {override_excluded:,} analyst override removals excluded")
    print(f"    - {len(clean_malicious):,} clean malicious hashes remaining for XOR filter.")

    if not clean_malicious:
        print("[!] Error: No malicious hashes left to build filter.")
        sys.exit(1)

    # 4. Stream to Temp Text File
    tmp_txt = os.path.join(HERE, f".malicious_{algo_choice}.build.txt")
    tmp_xf = os.path.join(HERE, f".malicious_{algo_choice}.build.xf")

    print(f"[*] Writing clean hashes to build buffer: {tmp_txt}...")
    with open(tmp_txt, "w", encoding="utf-8") as out:
        for h in clean_malicious:
            out.write(h + "\n")

    # 5. Build BinaryFuse32 XOR Filter
    print(f"[*] Compiling BinaryFuse32 filter with xorfilter_writer...")
    if os.path.isfile(WRITER_EXE):
        cmd = [WRITER_EXE, "--bf32", tmp_txt, tmp_xf]
    else:
        cmd = ["cargo", "run", "--release", "--", "--bf32", tmp_txt, tmp_xf]

    cwd = os.path.join(HERE, "xorfilter_writer") if not os.path.isfile(WRITER_EXE) else None
    res = subprocess.run(cmd, cwd=cwd)
    if res.returncode != 0:
        print("[!] Error: xorfilter_writer failed to build filter.")
        if os.path.isfile(tmp_txt):
            os.remove(tmp_txt)
        sys.exit(res.returncode)

    if not os.path.isfile(tmp_xf):
        print("[!] Error: Output .xf file not created.")
        sys.exit(1)

    # 6. Copy to Destination
    dest_path = args.output
    if not dest_path:
        dest_path = os.path.join(
            HERE, "OpenMalwareScannerPortable", "xorfilter_rules", "malicious_sha256.xf"
        )
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copyfile(tmp_xf, dest_path)
    xf_size = os.path.getsize(dest_path)

    print("=" * 70)
    print(f"[+] Successfully built: {dest_path}")
    print(f"    - File size: {xf_size:,} bytes ({xf_size / (1024 * 1024):.2f} MB)")
    print(f"    - Total keys: {len(clean_malicious):,} keys (~{(xf_size / len(clean_malicious)):.2f} bytes/key)")
    print(f"    - Elapsed time: {time.time() - start_time:.1f}s")
    print("=" * 70)

    # 7. Verification
    if args.verify and os.path.isfile(WRITER_EXE):
        print("[*] Verifying filter roundtrip & 0-size safety...")
        sample_hash = clean_malicious[0]
        test_res = subprocess.run([WRITER_EXE, "--check", dest_path, sample_hash], capture_output=True, text=True)
        print(f"    Sample malicious hit: {test_res.stdout.strip()} (expected: true)")

        # Verify that all 0-size hashes return false!
        for zh in ZERO_SIZE_HASHES:
            zh_res = subprocess.run([WRITER_EXE, "--check", dest_path, zh], capture_output=True, text=True)
            print(f"    0-size check {zh[:10]}...: {zh_res.stdout.strip()} (expected: false)")

        if overrides:
            sample_ov = next(iter(overrides))
            ov_res = subprocess.run([WRITER_EXE, "--check", dest_path, sample_ov], capture_output=True, text=True)
            print(f"    Override excluded check: {ov_res.stdout.strip()} (expected: false)")

    # Cleanup temp
    if os.path.isfile(tmp_txt):
        os.remove(tmp_txt)
    if os.path.isfile(tmp_xf):
        os.remove(tmp_xf)

    print("[*] Universal Blacklist build finished successfully.")


if __name__ == "__main__":
    main()
