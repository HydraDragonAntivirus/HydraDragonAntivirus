#!/usr/bin/env python3
"""
virusshare_md5.py — Download & export VirusShare MD5 hash sets for bloom_builder.

Pipeline:
    download  → fetch VirusShare_00000.md5 .. VirusShare_NNNNN.md5
    build     → extract every unique MD5, write a clean hashes-only list (one
                per line, no virus names, no sizes). Pass this file to
                `bloom_builder` to create the allblooms.
    filter    → given a hash-signature DB directory, remove explicit sigs that
                are now redundant because their MD5 is in the VirusShare set
                (the bloom built by bloom_builder detects them at runtime).

The bloom filters (blacklist.bloom, whitelist.bloom, …) are produced by the
separate Rust tool `bloom_builder` — this script only prepares the clean hash
data and can optionally slim an older explicit-hash DB of redundant entries.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import re
import sys
import time
import urllib.request

BASE_URL = "https://virusshare.com/hashfiles/VirusShare_{:05d}.md5"
MD5_LINE = re.compile(rb"^[0-9a-fA-F]{32}$")
MD5_ANY = re.compile(rb"[0-9a-fA-F]{32}")


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #
def download_one(idx: int, out_dir: str, retries: int = 4) -> tuple[int, str]:
    path = os.path.join(out_dir, f"VirusShare_{idx:05d}.md5")
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return idx, "skip"
    url = BASE_URL.format(idx)
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hydradragon-md5/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            tmp = path + ".part"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
            return idx, "ok"
        except Exception as e:
            if attempt == retries - 1:
                return idx, f"FAIL {e}"
            time.sleep(2 * (attempt + 1))
    return idx, "FAIL"


def cmd_download(args) -> None:
    os.makedirs(args.hashes_dir, exist_ok=True)
    idxs = list(range(args.start, args.end + 1))
    print(f"[download] {len(idxs)} files ({args.start}..{args.end}) → {args.hashes_dir}")
    ok = skip = fail = 0
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for idx, status in ex.map(lambda i: download_one(i, args.hashes_dir), idxs):
            if status == "ok":
                ok += 1
            elif status == "skip":
                skip += 1
            else:
                fail += 1
                print(f"  [{idx:05d}] {status}", file=sys.stderr)
    print(f"[download] ok={ok} skip={skip} fail={fail}")


# --------------------------------------------------------------------------- #
# Build — write a clean hashes-only file for bloom_builder
# --------------------------------------------------------------------------- #
def iter_md5s(hashes_dir: str):
    files = sorted(f for f in os.listdir(hashes_dir) if f.lower().endswith(".md5"))
    for name in files:
        path = os.path.join(hashes_dir, name)
        with open(path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(b"#"):
                    continue
                if MD5_LINE.match(line):
                    yield line.decode("ascii").lower()
                else:
                    mo = MD5_ANY.search(line)
                    if mo:
                        yield mo.group(0).decode("ascii").lower()


def cmd_build(args) -> None:
    out = args.output
    print(f"[build] extracting MD5s from {args.hashes_dir} → {out}")
    seen = set() if args.dedup else None
    total = written = 0
    t0 = time.time()
    with open(out, "w", encoding="ascii") as w:
        for h in iter_md5s(args.hashes_dir):
            total += 1
            if seen is not None:
                key = bytes.fromhex(h)
                if key in seen:
                    continue
                seen.add(key)
            w.write(h + "\n")
            written += 1
            if total % 1_000_000 == 0:
                print(f"  …{total:,} read, {written:,} unique ({total/(time.time()-t0):,.0f}/s)")
    sz = os.path.getsize(out) / 1e6
    print(f"[build] {written:,} unique hashes ({total:,} read) → {out}  ({sz:.1f} MB)")
    print("[build] feed this file to `bloom_builder <dir>` to create the allblooms.")


# --------------------------------------------------------------------------- #
# Filter — remove redundant explicit sigs from a hash-DB dir
# --------------------------------------------------------------------------- #
HASH_EXTS = (".hdb", ".hsb", ".hdu", ".hsu", ".mdb", ".msb", ".md5", ".txt")


def load_virusshare_set(path: str) -> set[bytes]:
    """Load a hashes-only file (one hex MD5 per line) into a bytes set."""
    out: set[bytes] = set()
    with open(path, "r", encoding="ascii") as f:
        for line in f:
            h = line.strip()
            if len(h) == 32 and all(c in "0123456789abcdef" for c in h):
                out.add(bytes.fromhex(h))
    return out


def line_md5(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    head = line.split(":", 1)[0].split()[0] if line else ""
    head = head.lower()
    return head if len(head) == 32 and all(c in "0123456789abcdef" for c in head) else None


def cmd_filter(args) -> None:
    print(f"[filter] loading VirusShare set from {args.vs_list} …")
    vs_set = load_virusshare_set(args.vs_list)
    print(f"[filter] {len(vs_set):,} hashes loaded.  DB={args.filter_db}")

    total_in = total_kept = total_dropped = 0
    for root, dirs, files in os.walk(args.filter_db):
        if not args.recursive and root != args.filter_db:
            dirs[:] = []
        for name in files:
            if not name.lower().endswith(HASH_EXTS):
                continue
            path = os.path.join(root, name)
            kept: list[str] = []
            dropped = 0
            lines = 0
            changed = False
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    lines += 1
                    md5 = line_md5(line)
                    if md5 is None:
                        if args.hashes_only:
                            changed = True
                        else:
                            kept.append(line)
                        continue
                    in_vs = bytes.fromhex(md5) in vs_set
                    if in_vs:
                        dropped += 1
                        changed = True
                    elif args.hashes_only:
                        kept.append(md5 + "\n")
                        changed = changed or (md5 + "\n" != line)
                    else:
                        kept.append(line)
            total_in += lines
            total_kept += len(kept)
            total_dropped += dropped
            if changed and not args.dry_run:
                if kept:
                    with open(path, "w", encoding="utf-8") as f:
                        f.writelines(kept)
                else:
                    os.remove(path)
            if dropped:
                tag = "WOULD drop" if args.dry_run else "dropped"
                print(f"  {os.path.relpath(path, args.filter_db)}: {tag} {dropped}/{lines}"
                      f"{' (file removed)' if not kept and not args.dry_run else ''}")
    print(f"[filter] lines={total_in:,} kept={total_kept:,} "
          f"dropped={total_dropped:,}  ({'dry-run' if args.dry_run else 'applied'})")
    print("[filter] removed explicit sigs that VirusShare allbloom now covers at runtime.")


# --------------------------------------------------------------------------- #
def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hashes-dir", default="virusshare_hashes", help="dir for downloaded .md5 files")
    p.add_argument("--start", type=int, default=0, help="first VirusShare index")
    p.add_argument("--end", type=int, default=148, help="last VirusShare index (inclusive)")
    p.add_argument("--jobs", type=int, default=8, help="parallel downloads")
    # build
    p.add_argument("--output", default="virusshare_hashes.txt", help="build: output hashes-only file")
    p.add_argument("--no-dedup", dest="dedup", action="store_false", help="build: skip dedup (lower RAM)")
    p.set_defaults(dedup=True)
    # filter
    p.add_argument("--filter-db", default=None, help="filter: hash-DB dir to slim")
    p.add_argument("--recursive", action="store_true", help="filter: recurse into DB subfolders")
    p.add_argument("--hashes-only", action="store_true", help="filter: rewrite kept sigs as bare MD5s")
    p.add_argument("--dry-run", action="store_true", help="filter: report without modifying files")
    # subtle: --vs-list used by filter; exposed top-level for convenience
    p.add_argument("--vs-list", default=None,
                   help="filter: VirusShare hashes file (default: same as --output)")
    p.add_argument("cmd", choices=["download", "build", "filter"])
    args = p.parse_args()

    if args.cmd == "download":
        cmd_download(args)
    elif args.cmd == "build":
        cmd_build(args)
    elif args.cmd == "filter":
        vs_list = args.vs_list or args.output
        if not os.path.isfile(vs_list):
            sys.exit(f"[filter] VirusShare hash list not found: {vs_list}  (run `build` first, or set --vs-list)")
        if not args.filter_db:
            sys.exit("[filter] --filter-db is required")
        cmd_filter(args)


if __name__ == "__main__":
    main()
