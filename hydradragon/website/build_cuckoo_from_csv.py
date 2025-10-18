# build_cuckoo_from_csvs.py
import os
import time
import json
import pickle
from pathlib import Path
from cuckoopy import CuckooFilter
from tqdm import tqdm

DATA_DIR = Path(".")
OUT_DIR = Path("blacklists")
OUT_DIR.mkdir(exist_ok=True)

# Tune these
BUCKET_SIZE = 4
FINGERPRINT_SIZE = 16    # bits (8..16)
SHARD_LINES = 10_000_000 # create shard after this many lines (adjust to RAM)

def guess_type(name: str):
    n = name.lower()
    if "ipv4" in n: return "ipv4"
    if "ipv6" in n: return "ipv6"
    if "subdomain" in n or "subdomains" in n: return "subdomain"
    return "domain"

def normalize_token(line: str):
    if not line: return None
    # accept CSV with extra columns — take first cell
    token = line.split(",", 1)[0].split(";", 1)[0].strip().strip('"').strip("'")
    if not token: return None
    return token.lower()

def build_shard(shard_index:int, basename:str, ftype:str, items_count:int, cf:CuckooFilter):
    out_base = OUT_DIR / f"{basename}-{shard_index:03d}"
    cuckoo_path = str(out_base) + ".cuckoo"
    meta_path = str(out_base) + ".meta.json"

    # Save filter — use pickle (works for most Python objects). fallback to cf.save()
    try:
        with open(cuckoo_path, "wb") as fh:
            pickle.dump(cf, fh, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as ex:
        if hasattr(cf, "save"):
            cf.save(cuckoo_path)
        else:
            raise RuntimeError(f"Can't serialize filter to {cuckoo_path}: {ex}")

    meta = {
        "basename": basename,
        "shard": shard_index,
        "type": ftype,
        "inserted": items_count,
        "bucket_size": BUCKET_SIZE,
        "fingerprint_size": FINGERPRINT_SIZE,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
    }
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)
    print(f"Saved {cuckoo_path} ({items_count} items)")

def build_for_file(path:Path):
    print(f"\nProcessing {path.name}")
    ftype = guess_type(path.name)
    total_lines = 0
    # fast count lines
    with open(path, "rb") as f:
        for _ in f:
            total_lines += 1
    print(f" lines ~{total_lines:,} detected type={ftype}")

    shard_idx = 0
    shard_items = 0
    # capacity: approximate lines per shard * 1.3
    capacity = max(1000, int(min(SHARD_LINES, total_lines) * 1.3))
    cf = CuckooFilter(capacity=capacity, bucket_size=BUCKET_SIZE, fingerprint_size=FINGERPRINT_SIZE)

    def make_key(ftype, token):
        if ftype == "ipv4": return "ipv4:" + token
        if ftype == "ipv6": return "ipv6:" + token
        if ftype == "subdomain": return "sub:" + token
        return "dom:" + token

    inserted_total = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        pbar = tqdm(f, total=total_lines, desc=f" Inserting {path.name}", unit="lines")
        for line in pbar:
            token = normalize_token(line)
            if not token: 
                continue
            key = make_key(ftype, token)
            try:
                cf.insert(key)
                shard_items += 1
                inserted_total += 1
            except Exception:
                # if insert fails, finalize shard and start larger shard
                if shard_items == 0:
                    # extremely full even on empty shard: increase capacity and retry
                    capacity = int(capacity * 1.6) + 1000
                    cf = CuckooFilter(capacity=capacity, bucket_size=BUCKET_SIZE, fingerprint_size=FINGERPRINT_SIZE)
                    print(f"  Increased capacity to {capacity} and retrying insert for {key}")
                    try:
                        cf.insert(key)
                        shard_items += 1
                        inserted_total += 1
                        continue
                    except Exception as e:
                        print("  FATAL: can't insert even after increasing capacity:", e)
                        break
                # finalize current shard
                build_shard(shard_idx, path.stem, ftype, shard_items, cf)
                shard_idx += 1
                shard_items = 0
                # decide new capacity: base on remaining lines or SHARD_LINES
                remaining = total_lines - pbar.n
                cap = max(1000, int(min(SHARD_LINES, remaining) * 1.3))
                cf = CuckooFilter(capacity=cap, bucket_size=BUCKET_SIZE, fingerprint_size=FINGERPRINT_SIZE)
                # now try inserting again
                try:
                    cf.insert(key)
                    shard_items += 1
                    inserted_total += 1
                except Exception as e:
                    print("  ERROR inserting after shard rotate:", e)
                    break

            # rotate shard on line count threshold
            if shard_items >= SHARD_LINES:
                build_shard(shard_idx, path.stem, ftype, shard_items, cf)
                shard_idx += 1
                shard_items = 0
                cf = CuckooFilter(capacity=capacity, bucket_size=BUCKET_SIZE, fingerprint_size=FINGERPRINT_SIZE)

    # finalize last shard
    if shard_items > 0:
        build_shard(shard_idx, path.stem, ftype, shard_items, cf)

    print(f"Done {path.name}: total inserted={inserted_total:,}")

def main():
    csvs = sorted([p for p in DATA_DIR.iterdir() if p.is_file() and p.suffix.lower()==".csv"])
    if not csvs:
        print("No .csv files found.")
        return
    for p in csvs:
        try:
            build_for_file(p)
        except Exception as e:
            print(f"Failed {p.name}: {e}")

if __name__ == "__main__":
    main()
