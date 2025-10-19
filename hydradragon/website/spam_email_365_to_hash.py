#!/usr/bin/env python3
# listed_email_365_to_hash.py
"""
Convert listed_email_365.txt -> MMH3 64-bit hashes

Outputs:
 - listed_email_365.hash.txt  : one hex hash (8 bytes -> 16 hex chars) per line
 - listed_email_365.hash.bin  : binary file containing 8 bytes per entry

Rules:
 - Ignores blank lines and lines starting with '#'
 - Strips whitespace
 - Uses mmh3.hash_bytes(...) and takes first 8 bytes (consistent 64-bit fingerprint)
"""

from pathlib import Path
import mmh3
from tqdm import tqdm

INPUT = Path("listed_email_365.txt")
OUT_HEX = Path("listed_email_365.hash.txt")
OUT_BIN = Path("listed_email_365.hash.bin")

def normalize_line(line: str) -> str:
    return line.strip()

def is_ignored(line: str) -> bool:
    s = line.strip()
    return (not s) or s.startswith("#")

def hash64_bytes(s: str) -> bytes:
    # mmh3.hash_bytes returns a bytes digest; take first 8 bytes for 64-bit fingerprint
    return mmh3.hash_bytes(s.encode("utf-8"))[:8]

def main():
    if not INPUT.exists():
        print(f"Input file not found: {INPUT}")
        return

    # Count usable lines first for progress bar
    usable_lines = []
    with INPUT.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            if not is_ignored(raw):
                usable_lines.append(normalize_line(raw))

    if not usable_lines:
        print("No entries found (all lines empty or commented).")
        return

    # Write hex text and binary file
    with OUT_HEX.open("w", encoding="utf-8") as fh_hex, OUT_BIN.open("wb") as fh_bin:
        for entry in tqdm(usable_lines, desc="Hashing", unit="lines"):
            fp = hash64_bytes(entry)           # 8 bytes
            hexstr = fp.hex()                 # 16 hex chars
            fh_hex.write(hexstr + "\n")
            fh_bin.write(fp)

    print(f"\nWrote {len(usable_lines):,} hashes")
    print(f"Hex file : {OUT_HEX} ({OUT_HEX.stat().st_size:,} bytes)")
    print(f"Bin file : {OUT_BIN} ({OUT_BIN.stat().st_size:,} bytes)")

if __name__ == "__main__":
    main()
