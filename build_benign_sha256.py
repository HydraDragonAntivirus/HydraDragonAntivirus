"""Build the SHA-256 benign whitelist.

New workflow (txt is gitignored, .xf is tracked):
  1. This script hashes the benign corpora into a LOCAL temp .txt
     (never committed — see **/benign_sha256.txt in .gitignore).
  2. Build the BinaryFuse16 filter (~29x smaller: 17 MB txt -> 0.6 MB xf):
       cargo run -p xorfilter_writer --release -- benign_sha256.txt benign_sha256.xf
  3. Copy the .xf to every tracked location (see XF_OUTPUT_FILES below)
     and `git add` them. The desktop engine (openedr_static) and the web
     demo (openedr_web) both load the .xf — no .txt path remains.

Legacy: the old script wrote benign_sha256.txt into 4 tracked locations
(68 MB total). Those files are deleted; the engine keeps a transient
.txt->xf in-memory fallback only so old installs don't break.
"""
import os
import hashlib
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

DIRS = [
    r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2",
    r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\data2",
]

HERE = os.path.dirname(os.path.abspath(__file__))

# Local temp source (gitignored, never committed).
TMP_TXT = os.path.join(HERE, ".benign_sha256.build.txt")
TMP_XF = os.path.join(HERE, ".benign_sha256.build.xf")

# Tracked .xf destinations (web demo + portable runtime; NOTE: openedr_static
# does NOT use a benign whitelist — no static destinations here).
XF_OUTPUT_FILES = [
    os.path.join(HERE, "OpenEDR", "openedr_web", "www", "xorfilter_rules", "benign_sha256.xf"),
    os.path.join(HERE, "OpenEDR", "openedr_web", "www", "hash_rules", "benign_sha256.xf"),
    os.path.join(HERE, "OpenMalwareScannerPortable", "hash_rules", "benign_sha256.xf"),
    os.path.join(HERE, "OpenMalwareScannerPortable", "database", "benign_sha256.xf"),
    os.path.join(HERE, "OpenMalwareScannerPortable", "xorfilter_rules", "benign_sha256.xf"),
    os.path.join(HERE, "docs", "xorfilter_rules", "benign_sha256.xf"),
]

for out_f in XF_OUTPUT_FILES:
    os.makedirs(os.path.dirname(out_f), exist_ok=True)


def hash_file(fpath):
    try:
        h = hashlib.sha256()
        with open(fpath, "rb") as fp:
            while chunk := fp.read(131072):
                h.update(chunk)
        return h.hexdigest().lower()
    except Exception:
        return None


all_paths = []
print("[*] Collecting files...")
for d in DIRS:
    if not os.path.exists(d):
        print(f"[!] Directory not found: {d}")
        continue
    for root, _, files in os.walk(d):
        for f in files:
            all_paths.append(os.path.join(root, f))

print(f"[*] Found {len(all_paths)} files. Calculating SHA-256 in parallel...")
start_time = time.time()

unique_hashes = set()
count = 0

with ThreadPoolExecutor(max_workers=16) as executor:
    for sha in executor.map(hash_file, all_paths):
        count += 1
        if sha:
            unique_hashes.add(sha)
        if count % 10000 == 0:
            print(f"    Processed {count}/{len(all_paths)} files ({len(unique_hashes)} unique SHA-256)...")

elapsed = time.time() - start_time
print(f"[*] Done in {elapsed:.2f}s! Total files: {count}, Unique SHA-256: {len(unique_hashes)}")

# Sort and save to LOCAL temp txt (gitignored).
sorted_hashes = sorted(unique_hashes)
with open(TMP_TXT, "w", encoding="utf-8") as fp:
    for h in sorted_hashes:
        fp.write(h + "\n")
print(f"[+] Temp txt saved to: {TMP_TXT} ({os.path.getsize(TMP_TXT)} bytes)")

# Build .xf via the shared builder (same key/format as every filter in repo).
print("[*] Building BinaryFuse16 filter (.xf)...")
subprocess.run(
    ["cargo", "run", "-p", "xorfilter_writer", "--release", "--", TMP_TXT, TMP_XF],
    cwd=HERE,
    check=True,
)
print(f"[+] Temp xf built: {TMP_XF} ({os.path.getsize(TMP_XF)} bytes)")

for out_f in XF_OUTPUT_FILES:
    shutil.copyfile(TMP_XF, out_f)
    print(f"[+] Copied xf to: {out_f}")

print("[*] Done. `git add` the .xf files above; the .txt stays local (gitignored).")
