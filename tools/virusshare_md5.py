#!/usr/bin/env python3
"""
virusshare_md5.py — Download VirusShare MD5 hash files & build a clean hash list
for bloom_builder.

Commands:
    download  → fetch VirusShare_00000.md5 .. VirusShare_NNNNN.md5
    build     → extract every unique MD5, write a hashes-only file. This file is
                consumed by `bloom_builder filter` to slim a hash DB and produce
                type-sorted hash lists.
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
    seen: set[str] = set() if args.dedup else None
    total = written = 0
    t0 = time.time()
    with open(out, "w", encoding="ascii") as w:
        for h in iter_md5s(args.hashes_dir):
            total += 1
            if seen is not None:
                if h in seen:
                    continue
                seen.add(h)
            w.write(h + "\n")
            written += 1
            if total % 1_000_000 == 0:
                print(f"  …{total:,} read, {written:,} unique ({total/(time.time()-t0):,.0f}/s)")
    sz = os.path.getsize(out) / 1e6
    print(f"[build] {written:,} unique hashes ({total:,} read) → {out}  ({sz:.1f} MB)")
    print("[build] feed this file to `bloom_builder filter` to slim a hash DB.")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hashes-dir", default="virusshare_hashes", help="dir for downloaded .md5 files")
    p.add_argument("--start", type=int, default=0, help="first VirusShare index")
    p.add_argument("--end", type=int, default=148, help="last VirusShare index (inclusive)")
    p.add_argument("--jobs", type=int, default=8, help="parallel downloads")
    p.add_argument("--output", default="virusshare_hashes.txt", help="build: output hashes-only file")
    p.add_argument("--no-dedup", dest="dedup", action="store_false", help="build: skip dedup (lower RAM)")
    p.set_defaults(dedup=True)
    p.add_argument("cmd", choices=["download", "build"])
    args = p.parse_args()

    if args.cmd == "download":
        cmd_download(args)
    elif args.cmd == "build":
        cmd_build(args)


if __name__ == "__main__":
    main()
