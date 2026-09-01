"""
Dataset Generator for OpenEDR & OwlyShield Threat Intel XorFilters.

Extracts domain and IP lists from datasets, stripping protocol/port/path formatting
and EXCLUDING referenceless (,0) entries for both IPs and domains to prevent False Positives (FP).

Usage:
    python gen_intel_xfilters.py <input_dir> <output_dir>
"""

import csv
import sys
from pathlib import Path


def process_dataset(input_file: Path, output_file: Path, is_ip: bool = False):
    items = set()
    skipped_zero_ref = 0

    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if not row or not row[0].strip() or row[0].startswith("#"):
                continue

            # Drop referenceless (,0) entries for both IPs and domains (FP Prevention)
            if len(row) >= 2 and row[1].strip() == "0":
                skipped_zero_ref += 1
                continue

            raw_item = row[0].strip().lower()

            # Clean formatting
            if "://" in raw_item:
                raw_item = raw_item.split("://", 1)[1]
            if "/" in raw_item:
                raw_item = raw_item.split("/", 1)[0]
            if ":" in raw_item and not is_ip:
                raw_item = raw_item.split(":", 1)[0]
            if raw_item.ends_with("."):
                raw_item = raw_item[:-1]

            raw_item = raw_item.strip()
            if not raw_item:
                continue

            if is_ip and "/" in raw_item:
                continue  # Skip CIDR ranges for XorFilter text generator

            items.add(raw_item)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sorted(items)))
        if items:
            f.write("\n")

    print(f"Processed {input_file.name} -> {output_file.name}: {len(items):,} items (skipped {skipped_zero_ref:,} zero-ref entries)")


def main():
    if len(sys.argv) < 3:
        print("Usage: python gen_intel_xfilters.py <input_dir> <output_dir>")
        sys.exit(1)

    input_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])

    for csv_path in sorted(input_dir.glob("*.csv")):
        is_ip = "ip" in csv_path.name.lower()
        out_name = csv_path.name.replace(".optimized.csv", ".txt").replace(".csv", ".txt")
        process_dataset(csv_path, output_dir / out_name, is_ip=is_ip)


if __name__ == "__main__":
    main()
