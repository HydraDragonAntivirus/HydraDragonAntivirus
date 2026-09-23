"""Split a domain universe (default: top10milliondomains.csv) into
popular / malicious / unknown buckets.

Pipeline (offline, streaming pass over the input):
  1. IP literals          -> <base>_skipped_ips.csv   (IP threats skipped:
                             too many FPs, out of scope for now)
  2. Public suffix rows   -> <base>_new.csv (category=dead_unknown, matched_in=public-suffix, wl_hit=""),
                             <base>_unknown.csv (domain, category=dead_unknown)
  3. Invalid hostnames    -> <base>_new.csv (category=dead_unknown, matched_in="", wl_hit=""),
                             <base>_unknown.csv (domain, category=dead_unknown)
  4. Hit in a known-malicious list (exact or PSL-gated parent walk)
                          -> <base>_malicious.csv (domain, matched_in, wl_hit),
                             <base>_new.csv (category=malicious, matched_in, wl_hit)
  5. Hit in popularity whitelist or other whitelists (exact or parent walk)
                          -> <base>_popular.csv (domain, matched_in) (dropped from _new)
  6. Everything else      -> <base>_unknown.csv (domain, category=unknown),
                             <base>_new.csv (category=unknown, matched_in="", wl_hit="")

Malicious wins ties: every domain is checked against malicious lists.
If listed in both malicious and whitelist, malicious wins (whitelist is noted in wl_hit,
never shields).

Memory: ~13M whitelist + ~9M malicious entries as sets (~2-3 GB).
Use --light to skip SubDomainsPopularityWhiteList (7.8M rows) on small RAM,
--sample N for a quick logic check.

Usage (run inside hydradragon/website):
  python popular_unknown_malicious.py
  python popular_unknown_malicious.py --sample 20000
  python popular_unknown_malicious.py --input top10milliondomains.csv --sample 20000
"""

import argparse
import csv
import ipaddress
import os
import re
import sys
import time
import publicsuffix2

HERE = os.path.dirname(os.path.abspath(__file__))

# column names recognised (case-insensitive) when a header row is present
DOMAIN_COLS = ("domain", "entry", "subdomain", "host", "hostname")
HEADER_WORDS = DOMAIN_COLS + ("rank", "reference", "popularity", "extension")

# (set_label, filename) — order matters, first hit wins the label
WL_FILES = [
    ("popularity", "DomainsPopularityWhiteList.csv"),
    ("sub-popularity", "SubDomainsPopularityWhiteList.csv"),
    ("other-whitelist", "WhiteListDomains.csv"),
    ("other-whitelist", "WhiteListSubDomains.csv"),
]

BL_FILES = [
    "MalwareDomains.csv",
    "MalwareSubDomains.csv",
    "PhishingDomains.csv",
    "PhishingSubDomains.csv",
    "AbuseDomains.csv",
    "AbuseSubDomains.csv",
    "MiningDomains.csv",
    "MiningSubDomains.csv",
    "SpamDomains.csv",
    "SpamSubDomains.csv",
]

HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z0-9-]{2,63}$"
)


def label_walk(d, limit=5):
    """Plain parent walk, no PSL (fallback for --no-psl)."""
    cand = d
    for _ in range(limit + 1):
        if not cand or "." not in cand:
            return
        yield cand
        _, dot, rest = cand.partition(".")
        if not dot:
            return
        cand = rest


def psl_walk(d, limit=5):
    """Parent walk that never yields a public suffix itself."""
    cand = d
    for _ in range(limit + 1):
        if not cand or "." not in cand:
            return
        tld = publicsuffix2.get_tld(cand)
        if cand == tld:
            return
        yield cand
        _, dot, rest = cand.partition(".")
        if not dot:
            return
        cand = rest


def log(msg):
    print(msg, flush=True)


def normalize(raw):
    s = (raw or "").strip().lower()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if s.endswith("."):
        s = s[:-1]
    return s


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def classify(d, wl_sets, bl_sets, walk):
    """-> (bucket, matched_in, wl_hit).
    Malicious wins ties: every domain is checked against malicious lists first.
    If malicious matches, bucket=malicious, and wl_hit is recorded if also in whitelist.
    If malicious does not match, then whitelist is checked -> bucket=popular.
    Otherwise -> bucket=unknown.
    """
    candidates = list(walk(d))

    mal_hit = ""
    for cand in candidates:
        for s, fname in bl_sets:
            if cand in s:
                mal_hit = fname
                break
        if mal_hit:
            break

    if mal_hit:
        # Check if also in whitelist to record wl_hit
        wl_hit = ""
        for cand in candidates:
            for s, label in wl_sets:
                if cand in s:
                    wl_hit = label
                    break
            if wl_hit:
                break
        return "malicious", mal_hit, wl_hit

    # Check whitelist
    for cand in candidates:
        for s, label in wl_sets:
            if cand in s:
                return "popular", label, label

    return "unknown", "", ""


def is_header_row(cells):
    joined = ",".join(cells).lower()
    return any(w in joined for w in HEADER_WORDS)


def domain_column(cells):
    for i, c in enumerate(cells):
        if c.strip().lower() in DOMAIN_COLS:
            return i
    return 0


def load_set(path):
    """Load normalised domains from a .csv (domain/entry column) or .txt."""
    out = set()
    if not os.path.isfile(path):
        log(f"  [!] missing, skipped: {os.path.basename(path)}")
        return out
    t0 = time.time()
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if path.lower().endswith(".csv"):
            reader = csv.reader(fh)
            try:
                first = next(reader)
            except StopIteration:
                return out
            if is_header_row(first):
                col = domain_column(first)
                rows = reader
            else:
                # headerless: first row is data, domain in col 0
                col = 0
                fh.seek(0)
                rows = csv.reader(fh)
            for row in rows:
                if not row or col >= len(row):
                    continue
                d = normalize(row[col])
                if d:
                    out.add(d)
                    n += 1
        else:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                d = normalize(s.split()[0])
                if d:
                    out.add(d)
                    n += 1
    log(f"  loaded {n:,} entries from {os.path.basename(path)} "
        f"({time.time() - t0:.1f}s)")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", default="top10milliondomains.csv")
    ap.add_argument("--outdir", default=HERE)
    ap.add_argument("--sample", type=int, default=0,
                    help="process only first N input rows (0 = all)")
    ap.add_argument("--light", action="store_true",
                    help="skip SubDomainsPopularityWhiteList (7.8M rows)")
    ap.add_argument("--no-parent", action="store_true",
                    help="exact matches only, no parent-domain walk")
    ap.add_argument("--no-psl", action="store_true",
                    help="skip Mozilla PSL gating (plain parent walk)")
    args = ap.parse_args()

    if args.no_parent:
        walk = lambda d: [d]  # noqa: E731
    elif args.no_psl:
        walk = label_walk
    else:
        walk = psl_walk

    inp = args.input if os.path.isabs(args.input) else os.path.join(HERE, args.input)
    if not os.path.isfile(inp):
        log(f"input not found: {inp}")
        return 1
    base = os.path.splitext(os.path.basename(inp))[0]
    os.makedirs(args.outdir, exist_ok=True)
    out = lambda name: os.path.join(args.outdir, f"{base}_{name}")  # noqa: E731

    t_all = time.time()
    # ---- phase 1: whitelists ----
    log("[1/3] loading whitelists...")
    wl_sets = []
    for label, fname in WL_FILES:
        if args.light and fname == "SubDomainsPopularityWhiteList.csv":
            log("  [--light] skipped: SubDomainsPopularityWhiteList.csv")
            continue
        s = load_set(os.path.join(HERE, fname))
        wl_sets.append((s, fname if label != "other-whitelist" else label))
    # merge small "other" sets into one to keep lookup loop short
    merged = set()
    final_wl = []
    for s, label in wl_sets:
        if label == "other-whitelist":
            merged |= s
        else:
            final_wl.append((s, label))
    if merged:
        final_wl.append((merged, "other-whitelist"))
    wl_sets = final_wl

    # ---- phase 2: malicious lists ----
    log("[2/3] loading malicious lists...")
    bl_sets = []
    for fname in BL_FILES:
        s = load_set(os.path.join(HERE, fname))
        if s:
            bl_sets.append((s, fname))

    # ---- phase 3: stream input ----
    log("[3/3] classifying input (streaming)...")
    f_new = open(out("new.csv"), "w", encoding="utf-8", newline="")
    f_pop = open(out("popular.csv"), "w", encoding="utf-8", newline="")
    f_mal = open(out("malicious.csv"), "w", encoding="utf-8", newline="")
    f_unk = open(out("unknown.csv"), "w", encoding="utf-8", newline="")
    f_ip = open(out("skipped_ips.csv"), "w", encoding="utf-8", newline="")
    f_act = open(out("active_sites.txt"), "w", encoding="utf-8")
    w_new = csv.writer(f_new)
    w_pop = csv.writer(f_pop)
    w_mal = csv.writer(f_mal)
    w_unk = csv.writer(f_unk)
    w_ip = csv.writer(f_ip)

    counts = {"popular": 0, "malicious": 0, "unknown": 0,
              "dead_unknown": 0, "skipped_ip": 0, "bad_row": 0}
    t0 = time.time()
    with open(inp, "r", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            log("empty input")
            return 1
        if is_header_row(header):
            try:
                dcol = [c.strip().lower() for c in header].index("domain")
            except ValueError:
                dcol = domain_column(header)
            w_new.writerow(header + ["category", "matched_in", "wl_hit"])
        else:
            # headerless: assume domain in col 0, fabricate header
            dcol = 0
            w_new.writerow(["domain", "category", "matched_in", "wl_hit"])
            fh.seek(0)
            reader = csv.reader(fh)
        w_pop.writerow(["domain", "matched_in"])
        w_mal.writerow(["domain", "matched_in", "wl_hit"])
        w_unk.writerow(["domain", "category"])
        w_ip.writerow(["raw", "reason"])

        for i, row in enumerate(reader):
            if args.sample and i >= args.sample:
                break
            if not row or dcol >= len(row):
                counts["bad_row"] += 1
                continue
            d = normalize(row[dcol])
            if not d:
                counts["bad_row"] += 1
                continue
            if is_ip(d):
                counts["skipped_ip"] += 1
                w_ip.writerow([row[dcol].strip(), "ip-literal"])
                continue
            if not args.no_psl and not args.no_parent and d == publicsuffix2.get_tld(d):
                # the row IS a public suffix (e.g. co.uk): cannot be an
                # active site -> dead_unknown, never matched as a domain
                counts["dead_unknown"] += 1
                w_new.writerow(row + ["dead_unknown", "public-suffix", ""])
                w_unk.writerow([d, "dead_unknown"])
                continue
            if not HOST_RE.match(d):
                counts["dead_unknown"] += 1
                w_new.writerow(row + ["dead_unknown", "", ""])
                w_unk.writerow([d, "dead_unknown"])
                continue
            bucket, matched, wl_hit = classify(d, wl_sets, bl_sets, walk)
            if bucket == "popular":
                counts["popular"] += 1
                w_pop.writerow([d, matched])
                f_act.write(d + "\n")
            elif bucket == "malicious":
                counts["malicious"] += 1
                w_new.writerow(row + ["malicious", matched, wl_hit])
                w_mal.writerow([d, matched, wl_hit])
            else:
                counts["unknown"] += 1
                w_new.writerow(row + ["unknown", "", ""])
                w_unk.writerow([d, "unknown"])
            if (i + 1) % 1000000 == 0:
                log(f"  ...{(i + 1):,} rows "
                    f"({(i + 1) / (time.time() - t0):,.0f} rows/s)")

    for f in (f_new, f_pop, f_mal, f_unk, f_ip, f_act):
        f.close()

    elapsed = time.time() - t_all
    summary = (
        f"input: {os.path.basename(inp)}\n"
        f"rows: popular={counts['popular']:,} malicious={counts['malicious']:,} "
        f"unknown={counts['unknown']:,} dead_unknown={counts['dead_unknown']:,} "
        f"skipped_ip={counts['skipped_ip']:,} bad_row={counts['bad_row']:,}\n"
        f"elapsed: {elapsed:.1f}s  sample={args.sample} light={args.light} "
        f"no_parent={args.no_parent}\n"
    )
    log("---- summary ----\n" + summary)
    with open(out("new.stats.txt"), "w", encoding="utf-8") as fh:
        fh.write(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
