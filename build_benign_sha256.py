import os
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor

DIRS = [
    r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2",
    r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\data2",
]

OUTPUT_FILES = [
    r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenMalwareScannerPortable\hash_rules\benign_sha256.txt",
    r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenMalwareScannerPortable\database\benign_sha256.txt",
    r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenEDR\openedr_static\database\benign_sha256.txt",
]

for out_f in OUTPUT_FILES:
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

# Sort and save
sorted_hashes = sorted(unique_hashes)
for out_f in OUTPUT_FILES:
    with open(out_f, "w", encoding="utf-8") as fp:
        for h in sorted_hashes:
            fp.write(h + "\n")
    print(f"[+] Saved to: {out_f}")
