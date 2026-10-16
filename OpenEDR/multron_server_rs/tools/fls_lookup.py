"""Look up files in Comodo FLS (File Lookup Service) and write the answers to a CSV.

Manual verifier only: it never saves a verdict on the server. The CSV is for an
analyst to read next to the queue.

    python tools/fls_lookup.py --queue                          # whole human-analysis queue
    python tools/fls_lookup.py --queue --ext exe,dll --limit 500
    python tools/fls_lookup.py --queue --folder \\downloads\\ --not-folder found.000
    python tools/fls_lookup.py --hashes hashes.txt              # SHA-1 or SHA-256, one per line
    python tools/fls_lookup.py --files C:\\samples              # hash local files (recursive)
    python tools/fls_lookup.py ... --out fls_results.csv

Protocol: FLS v4 over UDP, the same one the OpenEDR agent uses
(OpenEDR/edrav2/iprj/libcloud/src/flsproto4.cpp; host fls.security.comodo.com:4447,
SimpleRequest, SHA-1 hashes, up to 49 per packet, 2-byte answers whose first byte is
the verdict: 0 absent, 1 safe, 2 malicious, 3 unknown, 4 fail).

FLS only takes SHA-1. Queue items carry SHA-256, so for --queue (and SHA-256 lines in
--hashes) the script finds the kept copy through the dashboard (/api/kept/info/<sha256>)
and hashes it here, so run it on the server computer. Files that are not kept get
fls_verdict "no_sha1". GET calls only: the dashboard needs no analyst key for them.
"""
import argparse
import csv
import hashlib
import json
import lzma
import os
import random
import socket
import struct
import sys
import time
import urllib.parse
import urllib.request

FLS_HOST = "fls.security.comodo.com"
FLS_PORT = 4447
DASHBOARD = "http://127.0.0.1:9440"

REQUEST_SIMPLE = 0
HASH_SHA1 = 0
PROTOCOL = 3
APP_CLOUD_AV = 10
CALLER_ON_ACCESS = 1
MAX_PER_PACKET = 49
ANSWER_SIZE = 2
VERDICTS = {0: "absent", 1: "safe", 2: "malicious", 3: "unknown", 4: "fail"}


def fls_query(sock, addr, sha1s, timeout, retries):
    """One FLS v4 SimpleRequest for up to 49 SHA-1 hex strings -> {sha1: verdict name}."""
    req_id = random.getrandbits(32)
    head = struct.pack("<BIBBBB16sB", REQUEST_SIMPLE, req_id, len(sha1s), HASH_SHA1,
                       PROTOCOL, APP_CLOUD_AV, b"\0" * 16, CALLER_ON_ACCESS)
    packet = head + b"".join(bytes.fromhex(h) for h in sha1s)
    sock.settimeout(timeout)
    for _ in range(retries + 1):
        sock.sendto(packet, addr)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _src = sock.recvfrom(2048)
            except socket.timeout:
                break
            if len(data) < 5:
                continue
            rid, n = struct.unpack_from("<IB", data, 0)
            if rid != req_id:
                continue  # late answer to an earlier packet
            if n != len(sha1s) or len(data) < 5 + n * ANSWER_SIZE:
                return {h: "bad_response" for h in sha1s}
            return {h: VERDICTS.get(data[5 + i * ANSWER_SIZE], f"code_{data[5 + i * ANSWER_SIZE]}")
                    for i, h in enumerate(sha1s)}
    return {h: "timeout" for h in sha1s}


def get_json(path):
    with urllib.request.urlopen(DASHBOARD + path, timeout=120) as r:
        return json.load(r)


def sha1_of(path, compressed):
    h = hashlib.sha1()
    opener = lzma.open if compressed or path.lower().endswith(".xz") else open
    with opener(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def kept_sha1(sha256):
    try:
        k = get_json("/api/kept/info/" + sha256)
    except Exception as e:
        return "", f"kept/info: {e}"
    if not k.get("kept"):
        return "", "not kept on the server"
    try:
        return sha1_of(k["path"], k.get("compressed")), ""
    except Exception as e:
        return "", f"read {k.get('path')}: {e}"


def queue_rows(args):
    params = {"recent": "0", "limit": "5000", "offset": "0"}
    for key, val in (("ext", args.ext), ("not_ext", args.not_ext), ("engine_verdict", args.engine_verdict),
                     ("folder", args.folder), ("not_folder", args.not_folder)):
        if val:
            params[key] = val
    rows = []
    while True:
        page = get_json("/api/reviews?" + urllib.parse.urlencode(params))
        for it in page.get("pending", []):
            ips = sorted({s.get("ip", "") for s in it.get("sightings") or [] if s.get("ip")})
            rows.append({
                "sha256": it["sha256"].lower(),
                "file_name": " | ".join(it.get("file_names") or []),
                "folder": " | ".join((it.get("folders") or [])[:3]),
                "ext": it.get("ext", ""),
                "size": it.get("file_size", ""),
                "engine_verdict": it.get("engine_verdict", ""),
                "detections": " | ".join(f"{d.get('layer')}:{d.get('name')}" for d in it.get("detections") or []),
                "signer": (it.get("signer") or {}).get("name", ""),
                "seen_count": it.get("seen_count", ""),
                "ips": " ".join(ips),
            })
            if args.limit and len(rows) >= args.limit:
                return rows
        if page.get("next_offset") is None:
            return rows
        params["offset"] = str(page["next_offset"])


def hash_file_rows(path):
    rows = []
    for line in open(path, encoding="utf-8-sig"):
        h = line.strip().split()[0].lower() if line.strip() else ""
        if len(h) == 40:
            rows.append({"sha1": h})
        elif len(h) == 64:
            rows.append({"sha256": h})
    return rows


def local_rows(root):
    rows = []
    paths = [root] if os.path.isfile(root) else [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs]
    for p in paths:
        try:
            data_sha1, data_sha256 = hashlib.sha1(), hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    data_sha1.update(chunk)
                    data_sha256.update(chunk)
            rows.append({"sha1": data_sha1.hexdigest(), "sha256": data_sha256.hexdigest(),
                         "file_name": os.path.basename(p), "folder": os.path.dirname(p),
                         "size": os.path.getsize(p)})
        except OSError as e:
            rows.append({"file_name": os.path.basename(p), "folder": os.path.dirname(p), "note": str(e)})
    return rows


def main():
    global DASHBOARD
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--queue", action="store_true", help="pending files of the human-analysis queue")
    src.add_argument("--hashes", help="text file with SHA-1 or SHA-256 hashes, one per line")
    src.add_argument("--files", help="a file or folder on this computer (recursive)")
    ap.add_argument("--ext", help="queue filter: extensions, e.g. exe,dll")
    ap.add_argument("--not-ext", dest="not_ext")
    ap.add_argument("--engine-verdict", dest="engine_verdict", help="e.g. unknown,possible_clean")
    ap.add_argument("--folder")
    ap.add_argument("--not-folder", dest="not_folder")
    ap.add_argument("--limit", type=int, default=0, help="at most this many queue files")
    ap.add_argument("--out", default="fls_results.csv")
    ap.add_argument("--dashboard", default=DASHBOARD)
    ap.add_argument("--host", default=FLS_HOST)
    ap.add_argument("--port", type=int, default=FLS_PORT)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between FLS packets")
    args = ap.parse_args()
    DASHBOARD = args.dashboard.rstrip("/")

    if args.queue:
        rows = queue_rows(args)
    elif args.hashes:
        rows = hash_file_rows(args.hashes)
    else:
        rows = local_rows(args.files)
    print(f"{len(rows)} files")

    for i, r in enumerate(rows, 1):
        if not r.get("sha1") and r.get("sha256"):
            r["sha1"], why = kept_sha1(r["sha256"])
            if why:
                r["note"] = why
        if i % 500 == 0:
            print(f"  sha1 {i}/{len(rows)}")

    addr = (socket.gethostbyname(args.host), args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    todo = sorted({r["sha1"] for r in rows if r.get("sha1")})
    answers = {}
    for i in range(0, len(todo), MAX_PER_PACKET):
        answers.update(fls_query(sock, addr, todo[i:i + MAX_PER_PACKET], args.timeout, args.retries))
        if (i // MAX_PER_PACKET) % 20 == 0:
            print(f"  fls {min(i + MAX_PER_PACKET, len(todo))}/{len(todo)}")
        time.sleep(args.delay)
    sock.close()

    cols = ["fls_verdict", "sha256", "sha1", "file_name", "folder", "ext", "size", "engine_verdict",
            "detections", "signer", "seen_count", "ips", "note"]
    counts = {}
    with open(args.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            r["fls_verdict"] = answers.get(r.get("sha1"), "no_sha1")
            counts[r["fls_verdict"]] = counts.get(r["fls_verdict"], 0) + 1
            w.writerow(r)
    print(f"wrote {args.out}")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {k:12} {v}")


if __name__ == "__main__":
    sys.exit(main())
