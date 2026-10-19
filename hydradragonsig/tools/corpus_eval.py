#!/usr/bin/env python3
"""Run HydraDragonSig rules over the Multron benign corpus and labelled positives.

Uses the hydradragonsig CLI (no second scanner): the file lists are built here,
scanned in small batches with `--path-list` (the CLI keeps every report of a run
in memory), and the findings are summarised per rule.

Sets, all read-only:
  benign    every `windows_clean` root of <archive>/dataset_paths.json (the
            verified benign reference corpus + analyst-checked ML false
            positives) and the files under <archive>/multron_incoming whose
            latest human verdict is `clean`.
  positive  files of the `windows_malware` root whose name carries a stealer or
            ransomware family label, and multron_incoming files whose human
            verdict is malicious with a Stealer / Ransom threat name.

Nothing is written outside --out; no verdict, queue or archive file is touched.

  python3 corpus_eval.py --bin ./hydradragonsig --rules probe.yaml \
      --archive /mnt/viruskov_archive --out eval \
      --map 'C:\\Users\\me\\usbdosyalar=/mnt/usbdosyalar' scan
  python3 corpus_eval.py --out eval summary

`scan` resumes where it stopped (batches already in eval/done.txt are skipped).
Rule ids starting with `OLD-` are a renamed copy of the previous rule version, so
old and new can be compared in one pass.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from collections import Counter, defaultdict

STEALER_RE = re.compile(
    r"stealer|trojan-?psw|\bpsw\b|\bpws\b|passwordstealer|credstealer|redline|lumma|vidar|raccoon|"
    r"azorult|agenttesla|stealc|risepro|metastealer|lokibot|\bpony\b|formbook|snakekeylogger|"
    r"discord.?grab|tokengrab|growtopia", re.I)
RANSOM_RE = re.compile(
    r"ransom|lockbit|\bconti\b|\bdjvu\b|filecoder|crypmod|blackcat|babuk|phobos|wannacry|wcry|"
    r"gandcrab|sodinokibi|revil|\bryuk\b|chaos|filecryptor|cryptolocker", re.I)
SHA_PREFIX = re.compile(r"^([0-9A-Fa-f]{64})_")
MAX_BATCH_FILES = 300
MAX_BATCH_BYTES = 256 * 1024 * 1024
UNKNOWN_SIZE = 2 * 1024 * 1024  # budget for a file missing from dataset_index.jsonl


def label_of(name):
    if RANSOM_RE.search(name):
        return "ransom"
    if STEALER_RE.search(name):
        return "stealer"
    return None


def map_path(win_path, maps):
    for src, dst in maps:
        if win_path.lower().startswith(src.lower()):
            rest = win_path[len(src):].replace("\\", "/").lstrip("/")
            return os.path.join(dst, rest)
    return win_path


def walk(root):
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            yield os.path.join(dirpath, f)


def latest_human_verdicts(archive):
    """sha -> (verdict, threat_name) of the latest completed review."""
    path = os.path.join(archive, "analyst_signatures", "human_verdicts.jsonl")
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                j = json.loads(line)
            except ValueError:
                continue
            sha = j.get("sha256", "").lower()
            if not sha:
                continue
            if j.get("deleted"):
                out.pop(sha, None)
            elif j.get("status") == "completed" and j.get("verdict"):
                out[sha] = (j["verdict"], j.get("threat_name") or "")
    return out


def build_lists(args):
    maps = [tuple(m.split("=", 1)) for m in args.map]
    paths = json.load(open(os.path.join(args.archive, "dataset_paths.json"), encoding="utf-8"))
    benign, positive = [], []
    for root in paths.get("windows_clean", []):
        local = map_path(root["path"], maps)
        if not os.path.isdir(local):
            print(f"[skip] benign root not reachable: {root['path']} -> {local}", file=sys.stderr)
            continue
        benign += [("benign", root.get("name", "corpus"), p) for p in walk(local)]
    mal = paths.get("windows_malware")
    for root in mal if isinstance(mal, list) else [mal] if mal else []:
        local = map_path(root["path"], maps)
        if not os.path.isdir(local):
            print(f"[skip] malware root not reachable: {root['path']} -> {local}", file=sys.stderr)
            continue
        for p in walk(local):
            lab = label_of(os.path.basename(p))
            if lab:
                positive.append(("positive", lab, p))
    verdicts = latest_human_verdicts(args.archive)
    for p in walk(os.path.join(args.archive, "multron_incoming")):
        m = SHA_PREFIX.match(os.path.basename(p))
        if not m:
            continue
        v = verdicts.get(m.group(1).lower())
        if not v:
            continue
        if v[0] == "clean":
            benign.append(("benign", "human_clean", p))
        elif v[0] == "malicious":
            lab = label_of(v[1])
            if lab:
                positive.append(("positive", lab, p))
    return benign, positive


def with_size(items, args):
    """Add sizes from <archive>/dataset_index.jsonl (a stat per file is slow on network
    or virtual mounts); -1 when the file is not in the index."""
    maps = [tuple(m.split("=", 1)) for m in args.map]
    sizes = {}
    index = os.path.join(args.archive or "", "dataset_index.jsonl")
    if os.path.exists(index):
        with open(index, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    j = json.loads(line)
                    sizes[map_path(j["p"], maps)] = int(j["s"])
                except (ValueError, KeyError):
                    continue
    return [(it[0], it[1], it[2], sizes.get(it[2], -1)) for it in items]


def batches(items, max_files=MAX_BATCH_FILES, max_bytes=MAX_BATCH_BYTES):
    """(set, label, path, size) items -> batches of one set, bounded in count and bytes."""
    cur, size = [], 0
    for it in items:
        sz = it[3] if it[3] >= 0 else UNKNOWN_SIZE
        if cur and (len(cur) >= max_files or size + sz > max_bytes or cur[0][0] != it[0]):
            yield cur
            cur, size = [], 0
        cur.append(it)
        size += sz
    if cur:
        yield cur


def summarize_report(r):
    pe = r.get("pe") or {}
    dirs = pe.get("data_directories") or []
    return {
        "type": (r.get("file_type") or {}).get("primary"),
        "dotnet": bool(len(dirs) > 14 and dirs[14][0]),
        "packed": pe.get("likely_packed"),
        "imports": len(pe.get("imports") or []),
        "rules": sorted({f["rule_id"] for f in r.get("findings", [])}),
    }


def cmd_scan(args):
    os.makedirs(args.out, exist_ok=True)
    manifest = os.path.join(args.out, "manifest.json")
    if os.path.exists(manifest):
        lists = json.load(open(manifest, encoding="utf-8"))
        benign, positive = [tuple(x) for x in lists["benign"]], [tuple(x) for x in lists["positive"]]
    else:
        benign, positive = build_lists(args)
    if any(len(x) < 4 for x in benign + positive):
        benign = sorted(with_size(benign, args), key=lambda x: x[2])
        positive = sorted(with_size(positive, args), key=lambda x: x[2])
        json.dump({"benign": benign, "positive": positive}, open(manifest, "w", encoding="utf-8"))
    if args.prefilter:
        # Second stage: only the files a cheap literal pre-scan (another --out dir) flagged.
        hits = set()
        with open(os.path.join(args.prefilter, "results.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                hits.add(json.loads(line)["path"])
        benign = [x for x in benign if x[2] in hits]
        positive = [x for x in positive if x[2] in hits]
    print(f"benign={len(benign)} positive={len(positive)}", flush=True)
    done_path = os.path.join(args.out, "done.txt")
    done = set(open(done_path).read().split()) if os.path.exists(done_path) else set()
    order = {"benign": benign, "positive": positive}.get(args.only, benign + positive)
    results = open(os.path.join(args.out, "results.jsonl"), "a", encoding="utf-8")
    lock = threading.Lock()
    t0 = time.time()

    def run(i, batch):
        meta = {it[2]: (it[0], it[1]) for it in batch}
        cmd = [args.bin, "--rules", args.rules, "-o", "jsonl", "--no-progress", "--hash",
               "--max-mib", str(args.max_mib)]
        if batch[0][0] == "positive":
            cmd.append("--include-clean")
        cmd += ["--"] + list(meta)
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        recs = []
        for line in proc.stdout.splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            s, lab = meta.get(r.get("path"), ("?", "?"))
            recs.append({"set": s, "label": lab, "path": r.get("path"),
                         "sha256": (r.get("hashes") or {}).get("sha256"), **summarize_report(r)})
        with lock:
            for rec in recs:
                results.write(json.dumps(rec) + "\n")
            results.flush()
            with open(done_path, "a") as fh:
                fh.write(f"{batch[0][0]}:{i}\n")
            print(f"[{time.time() - t0:7.0f}s] batch {i} {batch[0][0]} files={len(batch)} rc={proc.returncode}", flush=True)

    todo = ((i, b) for i, b in enumerate(batches(order, args.batch_files, args.batch_mib << 20)) if f"{b[0][0]}:{i}" not in done)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        running = set()
        for i, b in todo:
            if args.time_limit and time.time() - t0 > args.time_limit:
                break
            running.add(pool.submit(run, i, b))
            if len(running) >= args.jobs:
                finished, running = wait(running, return_when=FIRST_COMPLETED)
                for f in finished:
                    f.result()
    remaining = sum(1 for i, b in enumerate(batches(order, args.batch_files, args.batch_mib << 20)) if f"{b[0][0]}:{i}" not in
                    set(open(done_path).read().split()))
    print(f"remaining batches: {remaining}", flush=True)


def is_verdict_rule(rule_id):
    base = rule_id[4:] if rule_id.startswith("OLD-") else rule_id
    return not base.startswith("HG-")


def cmd_summary(args):
    lists = json.load(open(os.path.join(args.out, "manifest.json"), encoding="utf-8"))
    if args.only:
        lists = {k: (v if k == args.only else []) for k, v in lists.items()}
    totals = Counter((x[0], x[1]) for x in lists["benign"] + lists["positive"])
    seen = {}
    for line in open(os.path.join(args.out, "results.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        seen[r["path"]] = r  # a batch interrupted after writing is scanned again
    benign_hits = defaultdict(list)
    pos = {}
    for r in seen.values():
        if r["set"] == "benign":
            for rule in r["rules"]:
                benign_hits[rule].append(r)
        else:
            pos[r["path"]] = r
    out = [f"# Corpus evaluation ({args.out})", ""]
    out.append("## Sets")
    for (s, lab), n in sorted(totals.items()):
        out.append(f"- {s}/{lab}: {n} files")
    out += ["", "## Benign matches per rule (verdict rules first)"]
    for rule in sorted(benign_hits, key=lambda r: (not is_verdict_rule(r), r)):
        hits = benign_hits[rule]
        out.append(f"- **{rule}**: {len(hits)}")
        if is_verdict_rule(rule) and not rule.startswith("OLD-"):
            for h in hits[: args.list_max]:
                out.append(f"  - `{h['path']}` sha256={h['sha256']} type={h['type']}")
    out += ["", "## Positive recall"]
    for lab, rules in (("stealer", ["HDS-GEN-STEALER-001", "OLD-HDS-GEN-STEALER-001"]),
                       ("ransom", ["RANSOM_0001", "RANSOM_0002", "OLD-RANSOM_0001", "OLD-HDS-GEN-RANSOM-001"])):
        rs = [r for r in pos.values() if r["label"] == lab]
        out.append(f"### {lab}: {len(rs)} scanned")
        for rule in rules:
            n = sum(rule in r["rules"] for r in rs)
            out.append(f"- {rule}: {n} ({100.0 * n / max(1, len(rs)):.1f}%)")
        main = rules[0]
        missed = [r for r in rs if main not in r["rules"]]
        why = Counter()
        for r in missed:
            if r["type"] not in ("pe32", "pe64"):
                why[f"not a PE ({r['type']})"] += 1
            elif r["dotnet"]:
                why[".NET (IL strings only)"] += 1
            elif r["packed"] or "HG-OBF-PACKED" in r["rules"]:
                why["packed / protected"] += 1
            elif r["imports"] <= 10:
                why["thin import table (dynamic resolution / shell)"] += 1
            else:
                why["native, steps not all visible statically"] += 1
        out.append(f"- missed by {main}: {len(missed)}")
        for k, n in why.most_common():
            out.append(f"  - {k}: {n}")
        comp = Counter(rule for r in missed for rule in r["rules"] if rule.startswith("HG-") or rule.startswith("HG"))
        if comp:
            out.append("  - steps seen in missed files: " + ", ".join(f"{k}={v}" for k, v in comp.most_common(12)))
        out.append("")
    text = "\n".join(out)
    open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8").write(text)
    print(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default="hydradragonsig")
    ap.add_argument("--rules")
    ap.add_argument("--archive")
    ap.add_argument("--out", required=True)
    ap.add_argument("--map", action="append", default=[], help="WINDOWS_PREFIX=LOCAL_PREFIX")
    ap.add_argument("--max-mib", type=int, default=256)
    ap.add_argument("--batch-files", type=int, default=MAX_BATCH_FILES,
                    help="files per CLI run (raise for a literal-only pre-scan rule pack)")
    ap.add_argument("--batch-mib", type=int, default=MAX_BATCH_BYTES >> 20, help="bytes per CLI run")
    ap.add_argument("--prefilter", metavar="DIR",
                    help="scan only files listed in DIR/results.jsonl (a pre-scan with a "
                         "literal superset of the rules' strings, much cheaper than the full rules)")
    ap.add_argument("--only", choices=["benign", "positive"], help="scan one set only")
    ap.add_argument("--jobs", type=int, default=2, help="CLI processes run at the same time")
    ap.add_argument("--time-limit", type=float, default=0,
                    help="seconds; start no new batch after this (resume with the same command)")
    ap.add_argument("--list-max", type=int, default=200)
    ap.add_argument("command", choices=["scan", "summary"])
    args = ap.parse_args()
    if args.command == "scan":
        if not (args.rules and args.archive):
            ap.error("scan needs --rules and --archive")
        cmd_scan(args)
    else:
        cmd_summary(args)


if __name__ == "__main__":
    main()
