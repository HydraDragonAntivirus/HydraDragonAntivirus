#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# reference_optimizer.py
"""
Reference optimizer / registry builder

- Scans ONLY .csv files in a directory (default: current dir)
- Skips ALLOW*.csv files
- Does NOT skip WhiteList*/whitelist CSV files
- Skips:
    - generated optimizer outputs: *.optimized.csv
    - ALLOW*.csv
    - huge ranking/source lists that are not reference rule files:
      top-1m.csv, builtwith-top1m-20250121.csv, tranco_PL9GJ.csv
- Extracts reference strings, assigns integer IDs (0,1,2,...)
- Writes:
    - references.txt
    - For each input CSV: <basename>.optimized.csv with references replaced by IDs

Usage:
    python reference_optimizer.py
    python reference_optimizer.py --dir path\to\rules --out path\to\ref_out
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Exact CSV names that should NOT be optimized.
# IMPORTANT: WhiteList*/whitelist CSV files are intentionally NOT listed here.
# ALLOW*.csv is skipped by prefix rule below.
SKIP_NAMES = {
    "top-1m.csv",
    "builtwith-top1m-20250121.csv",
    "tranco_pl9gj.csv",
    "tranco_pl9gj_old.csv",
}


# -----------------------
# File selection
# -----------------------
def should_process_file(path: Path) -> bool:
    """Return True only for CSV source files that should be optimized."""
    name = path.name.lower()

    if not path.is_file():
        return False
    if path.suffix.lower() != ".csv":
        return False

    # Never re-optimize output files from previous runs.
    if name.endswith(".optimized.csv"):
        return False

    # Skip generated/temporary allow lists.
    # Requested behavior: ALLOW*.csv should NOT be optimized.
    if name.startswith("allow"):
        return False

    # Skip CIDR whitelist files — they store raw CIDR notation (e.g. 1.2.3.0/24)
    # and have no reference column, so reference optimization must not touch them.
    if name.startswith("cidrwhitelist"):
        return False

    # Skip known huge ranking/source lists, not whitelist/rule files.
    if name in SKIP_NAMES:
        return False

    return True


def file_size_mb(path: Path) -> float:
    try:
        return path.stat().st_size / (1024 * 1024)
    except OSError:
        return 0.0


# -----------------------
# ReferenceRegistry
# -----------------------
class ReferenceRegistry:
    """Map reference strings -> small integer IDs."""

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
        with path.open("w", encoding="utf-8", newline="") as f:
            for rid in sorted(self.id_to_ref.keys()):
                f.write(f"{rid}\t{self.id_to_ref[rid]}\n")


# -----------------------
# CSV parsing helpers
# -----------------------
def split_csv_line(line: str) -> List[str]:
    """
    Fast CSV line splitter.
    Most rule files are simple comma-separated rows without quoting; use a fast path.
    If quoting is present, fall back to Python's csv module.
    """
    stripped = line.rstrip("\r\n")
    if not stripped:
        return []

    if '"' not in stripped:
        return [part.strip() for part in stripped.split(",")]

    try:
        return [part.strip() for part in next(csv.reader([stripped]))]
    except csv.Error:
        # Badly quoted line: use a conservative fallback instead of crashing.
        return [part.strip() for part in stripped.split(",")]


def parse_threat_line(
    line: str,
    is_first_line: bool = False,
) -> Tuple[Optional[str], List[str], str, str, str]:
    """
    Parse rows like:
      domain,ref1 | ref2 | ref3
      domain,ref1 | ref2,123
      domain,sub1 | sub2,ref1 | ref2,123
      rank,domain,ref1 | ref2

    Return:
      (domain or None, [reference strings...], format_name, subdomains, popularity)
    """
    if not line:
        return None, [], "skip", "", ""

    s = line.strip()
    if not s or s.startswith("#"):
        return None, [], "skip", "", ""

    parts = split_csv_line(line)
    if not parts:
        return None, [], "skip", "", ""

    first_col = parts[0].lower()
    second_col = parts[1].lower() if len(parts) > 1 else ""
    third_col = parts[2].lower() if len(parts) > 2 else ""
    fourth_col = parts[3].lower() if len(parts) > 3 else ""

    if is_first_line:
        if (
            first_col in {"entry", "domain", "threat", "indicator", "ip", "address", "subdomain"}
            or second_col in {"reference", "references", "source", "description"}
            or (first_col in {"domain", "entry"} and second_col == "subdomains" and third_col in {"reference", "references", "source"})
            or (first_col == "popularity" and second_col in {"domain", "entry"})
            or (third_col in {"reference", "references"} and fourth_col == "popularity")
        ):
            return None, [], "skip", "", ""

    refs: List[str] = []

    # domain,subdomains,refs,popularity
    if len(parts) >= 4 and parts[3].strip().isdigit():
        domain = parts[0].strip().lower()
        subdomains = parts[1].strip()
        refs_part = parts[2].strip()
        popularity = parts[3].strip()
        for r in refs_part.split("|"):
            rr = r.strip()
            if rr:
                refs.append(rr)
        return domain, refs, "popularity", subdomains, popularity

    # domain,refs,popularity
    if len(parts) >= 3 and parts[2].strip().isdigit():
        domain = parts[0].strip().lower()
        refs_part = parts[1].strip()
        popularity = parts[2].strip()
        for r in refs_part.split("|"):
            rr = r.strip()
            if rr:
                refs.append(rr)
        return domain, refs, "popularity_simple", "", popularity

    # rank,domain,refs
    if len(parts) >= 3 and parts[0].strip().isdigit():
        domain = parts[1].strip().lower()
        refs_part = parts[2].strip()
        for r in refs_part.split("|"):
            rr = r.strip()
            if rr:
                refs.append(rr)
        return domain, refs, "ranked", "", parts[0].strip()

    # domain,refs
    domain = parts[0].strip().lower()
    refs_part = parts[1].strip() if len(parts) > 1 else ""
    for r in refs_part.split("|"):
        rr = r.strip()
        if rr:
            refs.append(rr)
    return domain, refs, "standard", "", ""


def rewrite_line_with_ids(
    domain: str,
    ref_ids: List[int],
    format_name: str,
    subdomains: str = "",
    popularity: str = "",
) -> str:
    ids_part = " | ".join(str(i) for i in ref_ids)

    if format_name == "popularity":
        return f"{domain},{subdomains},{ids_part},{popularity}\n"
    if format_name == "popularity_simple":
        return f"{domain},{ids_part},{popularity}\n"
    if format_name == "ranked":
        # Keep the original rank/popularity in the first column.
        return f"{popularity},{domain},{ids_part}\n" if ref_ids else f"{popularity},{domain}\n"
    if not ref_ids:
        return f"{domain}\n"
    return f"{domain},{ids_part}\n"


# -----------------------
# Main optimizer
# -----------------------
def build_registry_and_rewrite(input_dir: Path, out_dir: Path, progress_every: int = 500_000):
    registry = ReferenceRegistry()
    input_dir = Path(input_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_csv_files = sorted(p for p in input_dir.iterdir() if p.is_file() and p.suffix.lower() == ".csv")
    files = [p for p in all_csv_files if should_process_file(p)]
    skipped_files = [p for p in all_csv_files if not should_process_file(p)]

    if skipped_files:
        print(f"Skipped {len(skipped_files)} CSV file(s) from skip rules:", flush=True)
        for p in skipped_files:
            print(f"  {p.name}", flush=True)

    if not files:
        print("No CSV files to process after skip rules.", flush=True)
        return

    print(f"Processing {len(files)} CSV file(s). WhiteList/whitelist and benign CSV files are included; ALLOW*.csv files are skipped.", flush=True)

    # First pass: collect references and register.
    print("Scanning references...", flush=True)
    for idx, p in enumerate(files, start=1):
        print(f"[{idx}/{len(files)}] Scanning {p.name} ({file_size_mb(p):.1f} MB)", flush=True)
        with p.open("r", encoding="utf-8-sig", errors="ignore", newline="") as f:
            for line_num, raw in enumerate(f, start=1):
                if progress_every > 0 and line_num % progress_every == 0:
                    print(f"    {p.name}: {line_num:,} lines scanned", flush=True)

                domain, refs, _, _, _ = parse_threat_line(raw, is_first_line=(line_num == 1))
                if not domain:
                    continue
                for r in refs:
                    registry.register(r)

    total_refs = len(registry.id_to_ref)
    print(f"Collected {total_refs} unique references.", flush=True)

    refs_txt = out_dir / "references.txt"
    registry.save_text(refs_txt)
    print(f"Wrote {refs_txt}", flush=True)

    # Second pass: rewrite files to .optimized.csv replacing refs with IDs.
    print("Rewriting CSV files with reference IDs...", flush=True)
    for idx, p in enumerate(files, start=1):
        outp = out_dir / (p.stem + ".optimized.csv")
        print(f"[{idx}/{len(files)}] Rewriting {p.name} -> {outp.name}", flush=True)

        with p.open("r", encoding="utf-8-sig", errors="ignore", newline="") as fin, outp.open("w", encoding="utf-8", newline="") as fout:
            for line_num, raw in enumerate(fin, start=1):
                if progress_every > 0 and line_num % progress_every == 0:
                    print(f"    {p.name}: {line_num:,} lines rewritten", flush=True)

                domain, refs, format_name, subdomains, popularity = parse_threat_line(
                    raw,
                    is_first_line=(line_num == 1),
                )
                if not domain:
                    # Preserve comments/headers/blanks as blank lines, matching the old behavior.
                    fout.write("\n")
                    continue

                ref_ids = []
                for r in refs:
                    rid = registry.register(r)
                    if rid is not None:
                        ref_ids.append(rid)

                fout.write(rewrite_line_with_ids(domain, ref_ids, format_name, subdomains, popularity))

    print("Done.", flush=True)


# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Reference optimizer - CSV only; skips ALLOW*.csv; keeps whitelist CSVs")
    parser.add_argument("--dir", "-d", type=str, default=".", help="Directory with CSV rule files")
    parser.add_argument("--out", "-o", type=str, default="ref_out", help="Output directory for references + optimized files")
    parser.add_argument(
        "--progress-every",
        type=int,
        default=500_000,
        help="Print progress every N lines per file. Use 0 to disable line progress.",
    )
    args = parser.parse_args()

    try:
        build_registry_and_rewrite(Path(args.dir), Path(args.out), progress_every=args.progress_every)
    except KeyboardInterrupt:
        print("\nStopped by user with Ctrl+C.", file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
