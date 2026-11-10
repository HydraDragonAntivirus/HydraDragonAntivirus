"""Build the SHA-256 benign whitelist (`benign_sha256.xf`, BinaryFuse32).

Sources, all merged:
  - allblooms/whitelist/rds_sha256.txt  (NSRL RDS, ~74M hashes)
  - allblooms/whitelist/benign_sha256.txt
  - every benign file of every training folder: Windows (PE), Android and JavaScript,
    from the same dataset_paths.json the trainers and multron_server use (new folders
    included, archived clean uploads too; files under both labels are left out).

Never whitelisted: the known-malicious SHA-256 list (allblooms/sha256.txt) and every
malicious training file. A whitelist hit skips the content scan, so a malware hash in
a public benign set (NSRL carries some hacking tools) must not get in.

The .txt is ONE bare lowercase SHA-256 hex digest per line - no signer prefix.
That is what makes the same .xf usable by both consumers, which each fold the
key the same way (FNV-1a-64 over the ASCII-lowercased bytes):
  - openedr_web   -> web_load_benign_whitelist -> is_benign(sha256_hex)
  - openedr_static-> SignerDb::is_benign(sha256_hex), loaded from
                     xorfilter_rules/benign_sha256.xf at init

Both read BinaryFuse32 (tag 32, version 2) only, so one build serves both. The
writer de-duplicates, so the merged list is streamed to the .txt as it is.

`xorfilter_rules/` is the ONLY home for a .xf. The old hash_rules/ and
database/ destinations were removed with the hash-only layouts they served.
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "hydradragon_ml_models"))
import dataset_paths  # noqa: E402  (the trainers' folder list and hash cache)

ALLBLOOMS = os.path.join(HERE, "allblooms")
LIST_FILES = [
    os.path.join(ALLBLOOMS, "whitelist", "rds_sha256.txt"),
    os.path.join(ALLBLOOMS, "whitelist", "benign_sha256.txt"),
    # NSRL RDS 2026.09.1 modern minimal delta (files added since the previous modern release).
    os.path.join(ALLBLOOMS, "whitelist", "RDS_2026.09.1_modern_minimal_delta_sha256.txt"),
]
MALICIOUS_LISTS = [os.path.join(ALLBLOOMS, "sha256.txt")]
WRITER_EXE = os.path.join(HERE, "xorfilter_writer", "target", "release", "xorfilter_writer.exe")

# Local temp source (gitignored, never committed).
TMP_TXT = os.path.join(HERE, ".benign_sha256.build.txt")
TMP_XF = os.path.join(HERE, ".benign_sha256.build.xf")

# Tracked .xf destinations. Every one of these is under xorfilter_rules/.
XF_OUTPUT_FILES = [
    os.path.join(HERE, "OpenMalwareScannerPortable", "xorfilter_rules", "benign_sha256.xf"),
]

for out_f in XF_OUTPUT_FILES:
    os.makedirs(os.path.dirname(out_f), exist_ok=True)


EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def is_sha256(t):
    return len(t) == 64 and all(c in "0123456789abcdef" for c in t)


start_time = time.time()

# 1. Training files from cache: benign hashes, and the malicious ones to keep out.
hash_cache_file = os.path.join(HERE, "hydradragon_ml_models", "dataset_hash_cache.jsonl")
dataset_benign = set()
malicious = set()
if os.path.isfile(hash_cache_file):
    print(f"[*] Reading dataset hashes from cache: {os.path.basename(hash_cache_file)}")
    import json
    with open(hash_cache_file, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            try:
                d = json.loads(line)
                if d.get("s", 0) == 0:
                    continue
                p = d.get("p", "").lower()
                h = d.get("h", "").strip().lower()
                if is_sha256(h) and h != EMPTY_SHA256:
                    if any(x in p for x in ["benign", "clean", "data2", "ml_fp_benign", "normal"]):
                        dataset_benign.add(h)
                    else:
                        malicious.add(h)
            except Exception:
                pass

# 2. Known-malicious hash lists.
for f in MALICIOUS_LISTS:
    if os.path.isfile(f):
        with open(f, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                t = line.strip().lower()
                if is_sha256(t):
                    malicious.add(t)
print(f"[*] {len(dataset_benign):,} benign training hashes; {len(malicious):,} malicious hashes kept out")

# 3. Stream the merged list (the writer de-duplicates).
written = dropped = 0
with open(TMP_TXT, "w", encoding="utf-8") as out:
    def put(t):
        global written, dropped
        # 0-size empty file check: never whitelist empty files
        if t in malicious or t == EMPTY_SHA256:
            dropped += 1
        else:
            out.write(t + "\n")
            written += 1
    for f in LIST_FILES:
        if not os.path.isfile(f):
            print(f"[!] Missing list: {f}")
            continue
        print(f"[*] Reading {f}")
        with open(f, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                t = line.strip().lower()
                if is_sha256(t):
                    put(t)
    for t in sorted(dataset_benign):
        put(t)
print(f"[+] {written:,} lines written ({dropped:,} malicious hashes left out) in {time.time() - start_time:.0f}s: {TMP_TXT}")

# 4. Build .xf with the shared builder (BinaryFuse32).
print("[*] Building BinaryFuse32 filter (.xf)...")
if os.path.isfile(WRITER_EXE):
    subprocess.run([WRITER_EXE, TMP_TXT, TMP_XF], check=True)
else:
    subprocess.run(["cargo", "run", "--release", "--", TMP_TXT, TMP_XF], cwd=os.path.join(HERE, "xorfilter_writer"), check=True)
print(f"[+] Temp xf built: {TMP_XF} ({os.path.getsize(TMP_XF)} bytes)")
os.remove(TMP_TXT)

for out_f in XF_OUTPUT_FILES:
    shutil.copyfile(TMP_XF, out_f)
    print(f"[+] Copied xf to: {out_f}")
os.remove(TMP_XF)
print("[*] Done.")
