#!/usr/bin/env python3
# reference_optimizer.py
"""
Reference optimizer / registry builder

- Scans CSV/TXT files in a directory (default: current dir)
- Skips urlhaus.txt and liste_email_365.txt (and listed_email_365.txt)
- Extracts reference strings, assigns integer IDs (0,1,2,...)
- Writes:
    - references.txt   (human readable: id TAB reference)
    - references.hrf   (binary HREF format)
    - For each input CSV/TXT: <basename>.optimized.csv with references replaced by IDs
Usage:
    python reference_optimizer.py --dir path/to/rules
"""

import argparse
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SKIP_NAMES = {"urlhaus.txt", "listed_email_365.txt"}

# -----------------------
# ReferenceRegistry (same format as before)
# -----------------------
class ReferenceRegistry:
    """Map reference strings -> small integer IDs; save/load to binary HREF format."""

    VERSION = 1

    def __init__(self):
        self.ref_to_id: Dict[str, int] = {}
        self.id_to_ref: Dict[int, str] = {}
        self.next_id = 0

    def register(self, ref: str) -> Optional[int]:
        key = ref.strip()
        if not key:
            return None
        if key not in self.ref_to_id:
            rid = self.next_id
            self.ref_to_id[key] = rid
            self.id_to_ref[rid] = key
            self.next_id += 1
            return rid
        return self.ref_to_id[key]

    def save_text(self, path: Path):
        with path.open("w", encoding="utf-8") as f:
            for rid in sorted(self.id_to_ref.keys()):
                f.write(f"{rid}\t{self.id_to_ref[rid]}\n")

    def save(self, path: Path):
        with path.open("wb") as f:
            f.write(b'HREF')
            f.write(struct.pack('B', self.VERSION))
            f.write(struct.pack('I', len(self.id_to_ref)))
            for ref_id in sorted(self.id_to_ref.keys()):
                ref_str = self.id_to_ref[ref_id].encode('utf-8')
                f.write(struct.pack('I', ref_id))
                f.write(struct.pack('I', len(ref_str)))
                f.write(ref_str)

# -----------------------
# CSV parsing helpers
# -----------------------
def parse_threat_line(line: str) -> Tuple[Optional[str], List[str]]:
    """
    Parse a line like:
      domain,ref1 | ref2 | ref3
    Return (domain or None, [reference strings...])
    """
    if not line:
        return None, []
    s = line.strip()
    if not s or s.startswith("#"):
        return None, []
    parts = s.split(",", 1)
    domain = parts[0].strip().lower()
    refs: List[str] = []
    if len(parts) > 1:
        refs_part = parts[1]
        # split by '|' and strip
        for r in refs_part.split("|"):
            rr = r.strip()
            if rr:
                refs.append(rr)
    return domain, refs

def rewrite_line_with_ids(domain: str, ref_ids: List[int]) -> str:
    # Format: domain,id1 | id2 | id3
    if not ref_ids:
        return f"{domain}\n"
    ids_part = " | ".join(str(i) for i in ref_ids)
    return f"{domain},{ids_part}\n"

# -----------------------
# Main optimizer
# -----------------------
def build_registry_and_rewrite(input_dir: Path, out_dir: Path):
    registry = ReferenceRegistry()
    input_dir = Path(input_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Collect input files: csv or txt, skip defined names
    files = sorted([p for p in input_dir.iterdir()
                    if p.is_file() and p.suffix.lower() in {'.csv', '.txt'}
                    and p.name.lower() not in SKIP_NAMES])

    if not files:
        print("No CSV/TXT files to process (after skipping).")
        return

    # First pass: collect references and register
    print(f"Scanning {len(files)} file(s) for references...")
    for p in files:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                domain, refs = parse_threat_line(raw)
                if not domain:
                    continue
                for r in refs:
                    registry.register(r)

    total_refs = len(registry.id_to_ref)
    print(f"Collected {total_refs} unique references.")

    # Save references list (human readable) and binary hrff
    refs_txt = out_dir / "references.txt"
    refs_hrf = out_dir / "references.hrf"
    registry.save_text(refs_txt)
    registry.save(refs_hrf)
    print(f"Wrote {refs_txt} and {refs_hrf}")

    # Second pass: rewrite files to .optimized.csv replacing refs with IDs
    print("Rewriting files with reference IDs...")
    for p in files:
        outp = out_dir / (p.stem + ".optimized.csv")
        with p.open("r", encoding="utf-8", errors="ignore") as fin, \
             outp.open("w", encoding="utf-8") as fout:
            for raw in fin:
                domain, refs = parse_threat_line(raw)
                if not domain:
                    fout.write("\n")  # preserve blank/comment lines as blank
                    continue
                ref_ids = []
                for r in refs:
                    rid = registry.register(r)  # should exist already
                    if rid is not None:
                        ref_ids.append(rid)
                fout.write(rewrite_line_with_ids(domain, ref_ids))
        print(f"  {p.name} -> {outp.name}")

    print("Done.")

# -----------------------
# CLI
# -----------------------
def main():
    ap = argparse = __import__('argparse').ArgumentParser(description="Reference optimizer")
    ap.add_argument("--dir", "-d", type=str, default=".", help="Directory with CSV/TXT rule files")
    ap.add_argument("--out", "-o", type=str, default="ref_out", help="Output directory for references + optimized files")
    args = ap.parse_args()

    build_registry_and_rewrite(Path(args.dir), Path(args.out))

if __name__ == "__main__":
    main()
