# build_blacklist.py
import json
import msgpack
from cuckoopy import CuckooFilter
from tqdm import tqdm

INPUT_FILE = "blacklist.txt"       # domain|category lines
FILTER_FILE = "blacklist.cuckoo"
INDEX_FILE = "categories.msgpack"
META_FILE = "metadata.json"

# Estimate capacity based on input size
def count_lines(path):
    with open(path, "rb") as f:
        return sum(1 for _ in f)

def build_filter():
    total = count_lines(INPUT_FILE)
    print(f"[+] Detected ~{total} lines")

    cuckoo = CuckooFilter(capacity=total * 2, bucket_size=4, fingerprint_size=16)
    categories = {}

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in tqdm(f, total=total, desc="Building filter"):
            line = line.strip()
            if not line or "|" not in line:
                continue
            domain, cat = line.split("|", 1)
            domain = domain.lower()
            cuckoo.insert(domain)
            categories[domain] = cat

    # Save filter
    cuckoo.save(FILTER_FILE)

    # Save compact index
    with open(INDEX_FILE, "wb") as f:
        msgpack.pack(categories, f)

    # Save metadata
    meta = {
        "entries": len(categories),
        "filter_bits": cuckoo.num_buckets * 4 * cuckoo.fingerprint_size,
    }
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Done: {len(categories)} entries saved")

if __name__ == "__main__":
    build_filter()
