"""
Removes CDN address space from the CIDR blacklists (cidr_blacklist_ipv4.bin / ipv6.bin).

A CDN IP serves thousands of sites. When one of them is malicious, the IP lands on a
few blocklists and gets 2-4 VirusTotal hits, while the same IP keeps serving every
clean site behind it. The engine checks the CIDR blacklist before the whitelist
(engine.rs check_whitelist_blacklist), so whitelisting such an IP does not help: it has
to leave the blacklist. A threat on a CDN is caught by its domain / URL, not its IP.

CDN ranges, as the providers publish them (kept in cdn_ranges/, refreshed with
--download):
  - Cloudflare     ips-v4 / ips-v6
  - AWS CloudFront ip-ranges.json, services CLOUDFRONT and CLOUDFRONT_ORIGIN_FACING
  - Fastly         public-ip-list
  - Google         goog.json minus cloud.json: Google's own services; Google Cloud
                   customer machines stay blockable
  - Bunny CDN      edgeserverlist (IPv4 / IPv6)
Akamai and Azure Front Door publish no stable list and are not covered.

Every blacklist range is cut by the CDN ranges (a range partly inside a CDN keeps the
rest). Without --apply only the report is printed.

Usage:
    python strip_cdn_from_cidr_blacklist.py [--download] [--apply] [bin_dir ...]
    (default bin dirs: the four copies of the tables in this repository)
"""

import argparse
import ipaddress
import json
import struct
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RANGES_DIR = HERE / "cdn_ranges"
DEFAULT_BIN_DIRS = [
    REPO / "OpenEDR" / "openedr_static" / "src",
    REPO / "OpenEDR" / "owlyshield_predict" / "src",
    REPO / "OpenEDR" / "openedr_web" / "src",
    REPO / "OpenMalwareScannerPortable" / "cidr_rules",
]

SOURCES = {
    "cloudflare-v4.txt": "https://www.cloudflare.com/ips-v4",
    "cloudflare-v6.txt": "https://www.cloudflare.com/ips-v6",
    "aws.json": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "fastly.json": "https://api.fastly.com/public-ip-list",
    "goog.json": "https://www.gstatic.com/ipranges/goog.json",
    "gcloud.json": "https://www.gstatic.com/ipranges/cloud.json",
    "bunny-v4.json": "https://bunnycdn.com/api/system/edgeserverlist",
    "bunny-v6.json": "https://bunnycdn.com/api/system/edgeserverlist/IPv6",
}
AWS_CDN_SERVICES = {"CLOUDFRONT", "CLOUDFRONT_ORIGIN_FACING"}


def download():
    RANGES_DIR.mkdir(exist_ok=True)
    for name, url in SOURCES.items():
        req = urllib.request.Request(url, headers={"Accept": "application/json, text/plain", "User-Agent": "HydraDragon-cidr-builder"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        (RANGES_DIR / name).write_bytes(data)
        print(f"  [download] {name}: {len(data):,} bytes")


def net_range(text):
    """(version, first, last) of an address or network; None when it does not parse."""
    try:
        n = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    return n.version, int(n.network_address), int(n.broadcast_address)


def load_cdn_ranges():
    """{provider: [(version, first, last)]} from cdn_ranges/."""
    def read(name):
        p = RANGES_DIR / name
        if not p.exists():
            sys.exit(f"{p} missing: run with --download first")
        return p.read_text(encoding="utf-8")

    out = {}
    out["cloudflare"] = [r for t in (read("cloudflare-v4.txt") + "\n" + read("cloudflare-v6.txt")).split() if (r := net_range(t))]

    aws = json.loads(read("aws.json"))
    out["aws-cloudfront"] = [
        r
        for p in aws.get("prefixes", []) + aws.get("ipv6_prefixes", [])
        if p.get("service") in AWS_CDN_SERVICES and (r := net_range(p.get("ip_prefix") or p.get("ipv6_prefix") or ""))
    ]

    fastly = json.loads(read("fastly.json"))
    out["fastly"] = [r for t in fastly.get("addresses", []) + fastly.get("ipv6_addresses", []) if (r := net_range(t))]

    def google(name):
        return [r for p in json.loads(read(name)).get("prefixes", []) if (r := net_range(p.get("ipv4Prefix") or p.get("ipv6Prefix") or ""))]
    out["google"] = subtract_all(google("goog.json"), google("gcloud.json"))

    out["bunny"] = [r for name in ("bunny-v4.json", "bunny-v6.json") for t in json.loads(read(name)) if (r := net_range(t))]
    return out


def merge(ranges):
    """Sorted, overlapping / adjacent ranges joined (per version)."""
    out = []
    for v, a, b in sorted(ranges):
        if out and out[-1][0] == v and a <= out[-1][2] + 1:
            out[-1] = (v, out[-1][1], max(out[-1][2], b))
        else:
            out.append((v, a, b))
    return out


def subtract_all(ranges, cut):
    """`ranges` minus `cut`: a range partly covered keeps its uncovered pieces."""
    cut = merge(cut)
    out = []
    for v, a, b in ranges:
        pieces = [(a, b)]
        for cv, ca, cb in cut:
            if cv != v or cb < a or ca > b:
                continue
            nxt = []
            for pa, pb in pieces:
                if cb < pa or ca > pb:
                    nxt.append((pa, pb))
                    continue
                if pa < ca:
                    nxt.append((pa, ca - 1))
                if cb < pb:
                    nxt.append((cb + 1, pb))
            pieces = nxt
            if not pieces:
                break
        out.extend((v, pa, pb) for pa, pb in pieces)
    return out


def read_bin(path, version):
    data = path.read_bytes()
    if version == 4:
        return [(4, s, e) for s, e in struct.iter_unpack("<II", data)]
    out = []
    for i in range(0, len(data) - len(data) % 32, 32):
        out.append((6, int.from_bytes(data[i:i + 16], "little"), int.from_bytes(data[i + 16:i + 32], "little")))
    return out


def write_bin(path, ranges, version):
    # The engine binary-searches the table: sorted by start, no overlaps.
    ranges = merge(ranges)
    with open(path, "wb") as f:
        for _, a, b in ranges:
            if version == 4:
                f.write(struct.pack("<II", a, b))
            else:
                f.write(a.to_bytes(16, "little") + b.to_bytes(16, "little"))


def size(ranges):
    return sum(b - a + 1 for _, a, b in ranges)


def show(v, a, b):
    lo, hi = ipaddress.ip_address(a), ipaddress.ip_address(b)
    return str(lo) if a == b else f"{lo} - {hi}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--download", action="store_true", help="refresh cdn_ranges/ from the providers first")
    ap.add_argument("--apply", action="store_true", help="write the cleaned tables (default: report only)")
    ap.add_argument("bin_dirs", nargs="*", type=Path, default=DEFAULT_BIN_DIRS)
    args = ap.parse_args()

    if args.download:
        download()
    cdn = load_cdn_ranges()
    all_cdn = merge(r for rs in cdn.values() for r in rs)
    for name, rs in cdn.items():
        print(f"  [cdn] {name}: {len(rs):,} ranges")

    for d in args.bin_dirs:
        print(f"\n=== {d} ===")
        for version in (4, 6):
            path = d / f"cidr_blacklist_ipv{version}.bin"
            if not path.exists():
                print(f"  {path.name}: missing, skipped")
                continue
            old = read_bin(path, version)
            new = subtract_all(old, all_cdn)
            removed = size(old) - size(new)
            hit = [r for r in old if subtract_all([r], all_cdn) != [r]]
            print(f"  {path.name}: {len(old):,} ranges -> {len(merge(new)):,}; {len(hit):,} touched a CDN, {removed:,} addresses removed")
            for v, a, b in hit[:15]:
                owners = [n for n, rs in cdn.items() if subtract_all([(v, a, b)], rs) != [(v, a, b)]]
                print(f"      {show(v, a, b):<40} {', '.join(owners)}")
            if len(hit) > 15:
                print(f"      ... {len(hit) - 15:,} more")
            if args.apply and hit:
                write_bin(path, new, version)
                print(f"  {path.name}: written")
    if not args.apply:
        print("\nReport only; run with --apply to write the tables.")


if __name__ == "__main__":
    main()
