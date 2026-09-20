#!/usr/bin/env python3
"""Train OUR OWN APK tree model for openedr_web — Python trains, Rust reads.

Same pattern as the PE/JS trees: this script extracts a fixed 24-float
feature vector per APK, trains a boosted forest, and emits `apk_trees.bin`
in the exact 25-byte/node bundle format that
`openedr_web/src/ml/tree_model.rs` parses. Rust never trains — it only
`web_load_model(kind=3)` + `predict_probability` (sigmoid of summed leaf
weights), exactly like `pe_trees.bin` / `js_trees.bin`.

Feature extraction here mirrors `openedr_web/src/apk.rs::apk_tree_features`
byte-for-byte (central-directory ZIP walk, capped inflation, AXML port,
f32 rounding). Verify parity any time with:

    python tools/apk_train.py --parity suspicious.apk
    # compare against: cargo run -p openedr_web --bin apk-feats -- suspicious.apk

Usage:
    pip install lightgbm numpy            # preferred
    # or: pip install scikit-learn numpy  # fallback (--algo sklearn-gb/rf)
    python tools/apk_train.py \\
        --benign  ../HydraDragonAV-Mobile/dataset/benign \\
        --malware "../HydraDragonAV-Mobile/dataset/malware/MalwareBazaar/27.06.2026 - 203930_212345/apk" \\
        --output www/models/apk_trees.bin

Outputs next to the bundle: `apk_trees.meta.json` (threshold, validation
stats, feature names). Bake the threshold into
`openedr_web/src/engine.rs::APK_TREE_THRESHOLD`.
"""

import argparse
import json
import math
import os
import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# Feature extraction (stdlib only) — mirrors src/apk.rs
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "dex_classes", "dex_strings", "dex_methods", "dex_files",
    "elf_so_count", "perm_total", "activities", "services",
    "receivers", "min_sdk", "target_sdk", "entropy",
    "entry_count", "file_size_log", "manifest_size_log", "dex_size_log",
    "so_size_log", "dangerous_perm_count", "sms_trio", "has_manifest",
    "multidex", "compression_ratio", "avg_entry_size_log",
    "native_with_perms",
]
N_FEATURES = len(FEATURE_NAMES)
assert N_FEATURES == 24

MAX_ENTRY_SCAN = 8 * 1024 * 1024
PROFILE_MANIFEST_CAP = 2 * 1024 * 1024
PROFILE_TOTAL_CAP = 8 * 1024 * 1024
PROFILE_DEX_PREFIX = 4096
PROFILE_MAX_DEX = 32
MAX_ENTRIES = 8192

DANGEROUS_PERMS = [
    "android.permission.send_sms", "android.permission.read_sms",
    "android.permission.receive_sms", "android.permission.read_contacts",
    "android.permission.read_call_log", "android.permission.record_audio",
    "android.permission.camera", "android.permission.access_fine_location",
    "android.permission.receive_boot_completed",
    "android.permission.system_alert_window",
    "android.permission.request_install_packages",
    "android.permission.bind_device_admin",
]

ATTR_MIN_SDK = 0x0101020C
ATTR_TARGET_SDK = 0x01010270


def f32(x):
    return struct.unpack("<f", struct.pack("<f", float(x)))[0]


def ln1p(x):
    if not math.isfinite(x) or x <= 0.0:
        return 0.0
    return math.log(x + 1.0)


def ascii_lower(b: bytes) -> bytes:
    return bytes(((b - 32) if 65 <= b <= 90 else b) for b in b)


class AxmlError(Exception):
    pass


def u16(b, off):
    if off + 2 > len(b):
        raise AxmlError("oob")
    return struct.unpack_from("<H", b, off)[0]


def u32(b, off):
    if off + 4 > len(b):
        raise AxmlError("oob")
    return struct.unpack_from("<I", b, off)[0]


def i32(b, off):
    if off + 4 > len(b):
        raise AxmlError("oob")
    return struct.unpack_from("<i", b, off)[0]


def parse_central_dir(data: bytes):
    """-> list of dicts or None (mirrors Rust parse_central_dir)."""
    if len(data) < 22 or data[0:2] != b"PK":
        return None
    search_start = max(0, len(data) - (64 * 1024 + 22))
    eocd = None
    i = len(data) - 22
    while True:
        if i < search_start:
            break
        if data[i:i + 4] == b"PK\x05\x06":
            eocd = i
            break
        if i == 0 or i == search_start:
            break
        i -= 1
    if eocd is None:
        return None
    total = struct.unpack_from("<H", data, eocd + 10)[0]
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    if total == 0 or total > MAX_ENTRIES or cd_off >= len(data):
        return None
    entries = []
    off = cd_off
    for _ in range(min(total, MAX_ENTRIES)):
        if off + 46 > len(data) or u32(data, off) != 0x02014B50:
            break
        method = u16(data, off + 10)
        comp = u32(data, off + 20)
        uncomp = u32(data, off + 24)
        fn_len = u16(data, off + 28)
        ex_len = u16(data, off + 30)
        co_len = u16(data, off + 32)
        local = u32(data, off + 42)
        name_off = off + 46
        name_end = name_off + fn_len
        if name_end > len(data) or fn_len > 2048:
            break
        entries.append({
            "name": data[name_off:name_end].decode("utf-8", "replace"),
            "method": method, "comp": comp, "uncomp": uncomp,
            "local": local,
        })
        off = name_end + ex_len + co_len
        if off >= len(data):
            break
    return entries or None


def local_data_offset(data: bytes, local_off: int):
    if local_off + 30 > len(data) or u32(data, local_off) != 0x04034B50:
        return None
    fn_len, ex_len = u16(data, local_off + 26), u16(data, local_off + 28)
    if fn_len > 4096 or ex_len > 65536:
        return None
    return local_off + 30 + fn_len + ex_len


def inflate_entry(data: bytes, entry, limit: int):
    """Decompress up to `limit` uncompressed bytes (None on failure/empty)."""
    if entry["comp"] == 0xFFFFFFFF or entry["uncomp"] == 0xFFFFFFFF:
        return None
    doff = local_data_offset(data, entry["local"])
    if doff is None:
        return None
    comp = data[doff:doff + entry["comp"]]
    if len(comp) != entry["comp"]:
        return None
    if entry["method"] == 0:
        out = comp[:limit]
        return bytes(out) or None
    if entry["method"] != 8 or not comp:
        return None
    try:
        dec = zlib.decompressobj(-15)
        out = dec.decompress(comp, limit)
        return bytes(out) or None
    except Exception:
        return None


def dex_counts(buf: bytes):
    if len(buf) < 0x70 or buf[0:4] != b"dex\n":
        return None
    s_ids = struct.unpack_from("<I", buf, 0x38)[0]
    m_ids = struct.unpack_from("<I", buf, 0x58)[0]
    c_ids = struct.unpack_from("<I", buf, 0x60)[0]
    if s_ids > 10_000_000 or m_ids > 10_000_000 or c_ids > 5_000_000:
        return None
    return c_ids, s_ids, m_ids


def parse_axml_pool(b: bytes, start: int, size: int):
    header = u16(b, start + 2)
    count = u32(b, start + 8)
    if count > 100_000:
        return None
    flags = u32(b, start + 16)
    sstart = u32(b, start + 20)
    is_utf8 = bool(flags & 0x100)
    strings = []
    off_base = start + header
    for i in range(count):
        rel = u32(b, off_base + i * 4)
        soff = start + sstart + rel
        if soff >= start + size or soff >= len(b):
            strings.append("")
            continue
        if is_utf8:
            q = soff
            for _ in range(2):  # skip utf16-len, utf8-len prefixes
                if q >= len(b):
                    raise AxmlError("oob")
                q += 2 if b[q] & 0x80 else 1
            if q - 1 >= len(b):
                strings.append("")
                continue
            # re-derive from second prefix (mirrors Rust)
            q2 = soff
            q2 += 2 if b[q2] & 0x80 else 1
            if q2 >= len(b):
                strings.append("")
                continue
            b0 = b[q2]
            if b0 & 0x80:
                if q2 + 1 >= len(b):
                    strings.append("")
                    continue
                blen = ((b0 & 0x7F) << 8) | b[q2 + 1]
                st = q2 + 2
            else:
                blen = b0
                st = q2 + 1
            if blen > 1_000_000:
                strings.append("")
                continue
            st = min(st, len(b))
            en = min(st + blen, len(b))
            strings.append(b[st:en].decode("utf-8", "replace"))
        else:
            ln = u16(b, soff)
            if ln > 100_000:
                strings.append("")
                continue
            units = [u16(b, soff + 2 + j * 2) for j in range(ln)]
            strings.append(b"".join(u.to_bytes(2, "little") for u in units).decode(
                "utf-16-le", "replace"))
        if len(strings) >= 100_000:
            break
    return strings


def analyze_manifest(buf: bytes):
    if len(buf) < 8:
        return None
    pool, rmap = [], []
    feats = {"perm": 0, "act": 0, "srv": 0, "rcv": 0, "min": 0, "tgt": 0}
    seen = False
    off, chunks = 0, 0
    try:
        while off + 8 <= len(buf) and chunks < 50_000:
            chunks += 1
            ctype = u16(buf, off)
            hsize = u16(buf, off + 2)
            csize = u32(buf, off + 4)
            if csize < hsize or hsize < 8 or csize == 0 or off + csize > len(buf):
                break
            if ctype == 0x0001:
                p = parse_axml_pool(buf, off, csize)
                if p is not None:
                    pool = p
            elif ctype == 0x0180:
                p = off + hsize
                while p + 4 <= off + csize and len(rmap) < 10_000:
                    rmap.append(u32(buf, p))
                    p += 4
            elif ctype == 0x0102:
                seen = True
                node = off + 8
                nn = node + 8
                name_idx = i32(buf, nn + 4)
                ename = pool[name_idx] if 0 <= name_idx < len(pool) else ""
                aso = nn + 8
                if aso + 8 > len(buf):
                    break
                astart = u16(buf, aso)
                asize = u16(buf, aso + 2)
                acount = u16(buf, aso + 4)
                if asize == 0 or acount > 256:
                    off += hsize if ctype == 0x0003 else csize
                    continue
                base = nn + astart
                if ename in ("activity", "activity-alias"):
                    feats["act"] += 1
                elif ename == "service":
                    feats["srv"] += 1
                elif ename == "receiver":
                    feats["rcv"] += 1
                elif ename in ("uses-permission", "uses-permission-sdk-23",
                               "permission"):
                    feats["perm"] += 1
                elif ename == "uses-sdk":
                    for k in range(acount):
                        ao = base + k * asize
                        if ao + 20 > len(buf):
                            break
                        aname = i32(buf, ao + 4)
                        dval = u32(buf, ao + 16)
                        rid = rmap[aname] if 0 <= aname < len(rmap) else 0
                        if rid == ATTR_MIN_SDK:
                            feats["min"] = dval
                        elif rid == ATTR_TARGET_SDK:
                            feats["tgt"] = dval
            if ctype == 0x0003:
                if hsize == 0 or off + hsize > len(buf):
                    break
                off += hsize
            else:
                off += csize
    except AxmlError:
        return None
    return feats if seen else None


def harvest_manifest_text(buf: bytes) -> str:
    out = []
    total = 0

    def flush(run: bytearray):
        nonlocal total
        if 4 <= len(run) <= 256:
            try:
                s = bytes(run).decode("ascii")
            except Exception:
                run.clear()
                return
            if s:
                out.append(" " + s)
                total += len(s) + 1
        run.clear()

    run = bytearray()
    for b in buf[:2 * 1024 * 1024]:
        if 0x20 <= b < 0x7F:
            run.append(b)
            if len(run) > 256:
                flush(run)
        else:
            flush(run)
        if total > 256 * 1024:
            break
    flush(run)
    u16r = bytearray()
    lim = min(len(buf), 2 * 1024 * 1024)
    j = 0
    while j + 1 < lim:
        lo, hi = buf[j], buf[j + 1]
        if hi == 0 and 0x20 <= lo < 0x7F:
            u16r.append(lo)
        elif u16r:
            flush(u16r)
        j += 2
        if total > 256 * 1024:
            break
    flush(u16r)
    return "".join(out)


def shannon_entropy(hist, total):
    if total == 0:
        return 0.0
    e = 0.0
    for c in hist:
        if c:
            p = c / total
            e -= p * math.log2(p)
    return f32(e)


def profile_apk(data: bytes):
    entries = parse_central_dir(data)
    if entries is None:
        return None
    p = {"has_manifest": False, "dex_files": 0, "so_files": 0,
         "entry_count": len(entries), "comp": 0, "uncomp": 0,
         "classes": 0, "strings": 0, "methods": 0,
         "dex_size": 0, "so_size": 0, "manifest_size": 0,
         "perm": 0, "act": 0, "srv": 0, "rcv": 0, "min": 0, "tgt": 0,
         "entropy": 0.0, "dangerous": 0, "trio": False}
    manifest_e, dex_es = None, []
    for e in entries:
        if e["comp"] == 0xFFFFFFFF or e["uncomp"] == 0xFFFFFFFF:
            continue
        p["comp"] += e["comp"]
        p["uncomp"] += e["uncomp"]
        ln = e["name"].lower()
        if ln == "androidmanifest.xml":
            p["has_manifest"] = True
            p["manifest_size"] = e["uncomp"]
            if manifest_e is None:
                manifest_e = e
        elif ln.endswith(".dex"):
            p["dex_files"] += 1
            p["dex_size"] += e["uncomp"]
            if len(dex_es) < PROFILE_MAX_DEX:
                dex_es.append(e)
        elif ln.startswith("lib/") and ln.endswith(".so"):
            p["so_files"] += 1
            p["so_size"] += e["uncomp"]
    if not p["has_manifest"] and p["dex_files"] == 0:
        return None

    hist, htot, spent = [0] * 256, 0, 0
    if manifest_e is not None:
        buf = inflate_entry(data, manifest_e, MAX_ENTRY_SCAN)
        if buf:
            buf = buf[:PROFILE_MANIFEST_CAP]
            spent += len(buf)
            for b in buf:
                hist[b] += 1
            htot += len(buf)
            low = ascii_lower(harvest_manifest_text(buf).encode(
                "ascii", "ignore")).decode("ascii")
            dg = sum(1 for x in DANGEROUS_PERMS if x in low)
            p["dangerous"] = dg
            p["trio"] = ("android.permission.send_sms" in low
                         and "android.permission.read_sms" in low
                         and "android.permission.receive_sms" in low)
            m = analyze_manifest(buf)
            if m:
                p.update({"perm": m["perm"], "act": m["act"],
                          "srv": m["srv"], "rcv": m["rcv"],
                          "min": m["min"], "tgt": m["tgt"]})
    for de in dex_es:
        if spent >= PROFILE_TOTAL_CAP:
            break
        pre = inflate_entry(data, de, PROFILE_DEX_PREFIX)
        if not pre:
            continue
        spent += len(pre)
        for b in pre:
            hist[b] += 1
        htot += len(pre)
        if len(pre) >= 0x70:
            c = dex_counts(pre)
            if c:
                p["classes"] += c[0]
                p["strings"] += c[1]
                p["methods"] += c[2]
    p["entropy"] = shannon_entropy(hist, htot)
    return p


def apk_features(data: bytes):
    """24 floats in APK_TREE_FEATURE_NAMES order (f32-rounded like Rust)."""
    p = profile_apk(data)
    if p is None:
        return None
    ratio = (p["comp"] / p["uncomp"] if p["uncomp"] else 0.0)
    ratio = min(1.0, max(0.0, ratio))
    avg = p["uncomp"] / p["entry_count"] if p["entry_count"] else 0.0
    feats = [
        float(p["classes"]), float(p["strings"]), float(p["methods"]),
        float(p["dex_files"]), float(p["so_files"]), float(p["perm"]),
        float(p["act"]), float(p["srv"]), float(p["rcv"]),
        float(p["min"]), float(p["tgt"]), p["entropy"],
        float(p["entry_count"]), ln1p(len(data)),
        ln1p(p["manifest_size"]), ln1p(p["dex_size"]), ln1p(p["so_size"]),
        float(p["dangerous"]), 1.0 if p["trio"] else 0.0,
        1.0 if p["has_manifest"] else 0.0,
        1.0 if p["dex_files"] >= 2 else 0.0, ratio, ln1p(avg),
        1.0 if (p["so_files"] >= 1 and p["dangerous"] >= 5) else 0.0,
    ]
    return [f32(x) for x in feats]


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

def walk_apks(root):
    out = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if fn.lower().endswith((".apk", ".zip")):
                out.append(os.path.join(dp, fn))
    return sorted(out)


def label_of(path):
    parts = path.lower().replace("\\", "/").split("/")
    if "malware" in parts:
        return 1
    if "benign" in parts:
        return 0
    return None


def load_dataset(benign_dir, malware_dir, limit=0):
    import numpy as np
    X, y, skipped = [], [], 0
    for root, lab in ((benign_dir, 0), (malware_dir, 1)):
        files = walk_apks(root)
        if limit:
            files = files[:limit]
        for i, fp in enumerate(files):
            if i % 500 == 0:
                print(f"  {root}: {i}/{len(files)}", flush=True)
            try:
                with open(fp, "rb") as f:
                    data = f.read()
            except OSError:
                skipped += 1
                continue
            f = apk_features(data)
            if f is None:
                skipped += 1
                continue
            X.append(f)
            y.append(lab)
    print(f"  usable={len(y)} skipped={skipped}", flush=True)
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


# ---------------------------------------------------------------------------
# Trees: intermediate repr, evaluation, .bin emission (matches tree_model.rs)
# ---------------------------------------------------------------------------

class Tree:
    def __init__(self):
        self.nodes = []  # (id, feat, thr, left, right, is_leaf, weight)

    def emit(self):
        out = [struct.pack("<I", len(self.nodes))]
        for (i, f, t, l, r, leaf, w) in self.nodes:
            out.append(struct.pack("<IIfIIBf", i, f, t, l, r,
                                   1 if leaf else 0, w))
        return b"".join(out)

    def score(self, x):
        by_id = {n[0]: n for n in self.nodes}
        cur = 0
        for _ in range(len(self.nodes) + 1):
            n = by_id.get(cur)
            if n is None:
                return 0.0
            _, f, t, l, r, leaf, w = n
            if leaf:
                return w
            cur = l if x[f] <= t else r
        return 0.0


def forest_proba(trees, X):
    import numpy as np
    s = np.zeros(len(X))
    for t in trees:
        s += np.array([t.score(x) for x in X])
    return 1.0 / (1.0 + np.exp(-np.clip(s, -30, 30)))


def convert_lightgbm(dump):
    trees = []
    for info in dump["tree_info"]:
        t, nxt = Tree(), [0]

        def new_id():
            nxt[0] += 1
            return nxt[0]

        queue = [(info["tree_structure"], 0)]
        nodes = {}
        while queue:
            node, nid = queue.pop(0)
            if "leaf_value" in node:
                nodes[nid] = (nid, 0, 0.0, 0, 0, True,
                              float(node["leaf_value"]))
            else:
                l, r = new_id(), new_id()
                nodes[nid] = (nid, int(node["split_feature"]),
                              float(node["threshold"]), l, r, False, 0.0)
                queue.append((node["left_child"], l))
                queue.append((node["right_child"], r))
        t.nodes = [nodes[k] for k in sorted(nodes)]
        trees.append(t)
    return trees


def convert_sklearn_gb(est_list, lr, prior_logit):
    import numpy as np
    trees = []
    stump = Tree()
    stump.nodes = [(0, 0, 0.0, 0, 0, True, float(prior_logit))]
    trees.append(stump)
    for est in est_list:
        tr = est[0].tree_
        t = Tree()
        left, right = tr.children_left, tr.children_right
        feat = tr.feature
        thr = tr.threshold
        val = tr.value[:, 0, 0] * lr
        nxt = [0]

        def new_id():
            nxt[0] += 1
            return nxt[0]

        queue = [(0, 0)]
        nodes = {}
        while queue:
            src, nid = queue.pop(0)
            if left[src] == -1:
                nodes[nid] = (nid, 0, 0.0, 0, 0, True, float(val[src]))
            else:
                l, r = new_id(), new_id()
                nodes[nid] = (nid, int(feat[src]), float(thr[src]),
                              l, r, False, 0.0)
                queue.append((int(left[src]), l))
                queue.append((int(right[src]), r))
        t.nodes = [nodes[k] for k in sorted(nodes)]
        trees.append(t)
    return trees


def convert_sklearn_rf(forest):
    import numpy as np
    T = len(forest.estimators_)
    trees = []
    for est in forest.estimators_:
        tr = est.tree_
        t = Tree()
        left, right = tr.children_left, tr.children_right
        feat = tr.feature
        thr = tr.threshold
        val = tr.value[:, 0, :]
        nxt = [0]

        def new_id():
            nxt[0] += 1
            return nxt[0]

        def logit_p(counts):
            tot = counts.sum()
            p = min(1.0 - 1e-6, max(1e-6, counts[1] / tot if tot else 0.5))
            return math.log(p / (1.0 - p)) / T

        queue = [(0, 0)]
        nodes = {}
        while queue:
            src, nid = queue.pop(0)
            if left[src] == -1:
                nodes[nid] = (nid, 0, 0.0, 0, 0, True,
                              float(logit_p(val[src])))
            else:
                l, r = new_id(), new_id()
                nodes[nid] = (nid, int(feat[src]), float(thr[src]),
                              l, r, False, 0.0)
                queue.append((int(left[src]), l))
                queue.append((int(right[src]), r))
        t.nodes = [nodes[k] for k in sorted(nodes)]
        trees.append(t)
    return trees


def write_bin(path, trees):
    with open(path, "wb") as f:
        f.write(struct.pack("<I", len(trees)))
        for t in trees:
            f.write(t.emit())
    print(f"wrote {path}: {len(trees)} trees, "
          f"{os.path.getsize(path)} bytes")


# ---------------------------------------------------------------------------
# Metrics / threshold
# ---------------------------------------------------------------------------

def metrics_at(y_true, proba, thr):
    import numpy as np
    pred = (proba >= thr).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    acc = (tp + tn) / max(1, len(y_true))
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    fpr = fp / max(1, fp + tn)
    return dict(thr=thr, tp=tp, fp=fp, tn=tn, fn=fn, acc=acc,
                prec=prec, rec=rec, f1=f1, fpr=fpr)


def pick_threshold(y_true, proba):
    rows = [metrics_at(y_true, proba, t)
            for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9)]
    print("\n thr | acc | prec | rec | f1 | fpr | tp fp tn fn", flush=True)
    for r in rows:
        print(f" {r['thr']:.2f} | {r['acc']:.3f} | {r['prec']:.3f} | "
              f"{r['rec']:.3f} | {r['f1']:.3f} | {r['fpr']:.4f} | "
              f"{r['tp']} {r['fp']} {r['tn']} {r['fn']}", flush=True)
    feas = [r for r in rows if r["fpr"] <= 0.02]
    best = max(feas or rows, key=lambda r: r["f1"])
    print(f"\nchosen threshold={best['thr']} "
          f"(f1={best['f1']:.3f} fpr={best['fpr']:.4f})", flush=True)
    return best


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Train our own APK tree model (Python trains, Rust reads)")
    ap.add_argument("--benign", required=False)
    ap.add_argument("--malware", required=False)
    ap.add_argument("--output", default="apk_trees.bin")
    ap.add_argument("--algo", default="auto",
                    choices=["auto", "lightgbm", "sklearn-gb", "sklearn-rf"])
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--leaves", type=int, default=31)
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--valid-frac", type=float, default=0.2)
    ap.add_argument("--limit", type=int, default=0,
                    help="files per class cap (smoke test)")
    ap.add_argument("--parity", default=None,
                    help="print 24 features for one APK and exit")
    ap.add_argument("--score-dir", default=None,
                    help="score a directory with an existing bundle")
    ap.add_argument("--bundle", default=None,
                    help=".bin bundle for --score-dir")
    args = ap.parse_args()

    if args.parity:
        with open(args.parity, "rb") as f:
            feats = apk_features(f.read())
        print(json.dumps({"features": feats, "names": FEATURE_NAMES}))
        return

    if args.score_dir:
        if not args.bundle:
            ap.error("--score-dir needs --bundle")
        with open(args.bundle, "rb") as f:
            blob = f.read()
        ntrees = struct.unpack_from("<I", blob, 0)[0]
        print(f"bundle trees={ntrees}")
        files = walk_apks(args.score_dir)
        for fp in files[:50]:
            with open(fp, "rb") as f:
                feats = apk_features(f.read())
            print(f"{'SKIP' if feats is None else 'OK  '} {fp}")
        return

    if not args.benign or not args.malware:
        ap.error("--benign and --malware are required (or use --parity)")

    import numpy as np
    print("loading dataset...", flush=True)
    X, y = load_dataset(args.benign, args.malware, args.limit)
    if len(y) < 10 or len(set(y.tolist())) < 2:
        sys.exit("need benign AND malware samples")

    rng = np.random.RandomState(args.seed)
    idx = np.arange(len(y))
    rng.shuffle(idx)
    cut = int(len(y) * (1.0 - args.valid_frac))
    tr, va = idx[:cut], idx[cut:]
    Xtr, ytr, Xva, yva = X[tr], y[tr], X[va], y[va]
    n_pos = int((ytr == 1).sum())
    n_neg = int((ytr == 0).sum())
    print(f"train={len(tr)} (mal={n_pos} ben={n_neg}) "
          f"valid={len(va)}", flush=True)

    algo = args.algo
    if algo == "auto":
        try:
            import lightgbm  # noqa
            algo = "lightgbm"
        except ImportError:
            algo = "sklearn-gb"
    print(f"algo={algo}", flush=True)

    if algo == "lightgbm":
        import lightgbm as lgb
        dtrain = lgb.Dataset(Xtr, label=ytr)
        params = {"objective": "binary", "num_leaves": args.leaves,
                  "min_data_in_leaf": 20, "feature_fraction": 0.8,
                  "bagging_fraction": 0.8, "bagging_freq": 1,
                  "scale_pos_weight": n_neg / max(1, n_pos),
                  "verbosity": -1, "seed": args.seed,
                  "num_threads": max(1, (os.cpu_count() or 4) - 1)}
        bst = lgb.train(params, dtrain, num_boost_round=args.trees)
        trees = convert_lightgbm(bst.dump_model())
    elif algo == "sklearn-gb":
        from sklearn.ensemble import GradientBoostingClassifier
        sw = np.where(ytr == 1, n_neg / max(1, n_pos), 1.0)
        clf = GradientBoostingClassifier(
            n_estimators=args.trees, max_depth=args.depth,
            learning_rate=args.lr, subsample=0.8,
            min_samples_leaf=20, random_state=args.seed)
        clf.fit(Xtr, ytr, sample_weight=sw)
        prior = math.log(n_pos / max(1, n_neg))  # weighted log-odds stump
        trees = convert_sklearn_gb(clf.estimators_, args.lr, prior)
    elif algo == "sklearn-rf":
        from sklearn.ensemble import RandomForestClassifier
        clf = RandomForestClassifier(
            n_estimators=args.trees, max_depth=None,
            min_samples_leaf=5, max_features="sqrt",
            class_weight="balanced_subsample",
            n_jobs=max(1, (os.cpu_count() or 4) - 1),
            random_state=args.seed)
        clf.fit(Xtr, ytr)
        trees = convert_sklearn_rf(clf)
    else:
        ap.error(f"unknown algo {algo}")

    print(f"converted {len(trees)} trees, scoring validation...",
          flush=True)
    proba = forest_proba(trees, Xva)
    best = pick_threshold(yva, proba)

    write_bin(args.output, trees)
    meta = {
        "threshold": best["thr"],
        "algo": algo,
        "n_trees": len(trees),
        "n_features": N_FEATURES,
        "feature_names": FEATURE_NAMES,
        "seed": args.seed,
        "train": {"total": len(tr), "malware": n_pos, "benign": n_neg},
        "valid": {"total": len(va), **{k: v for k, v in best.items()
                                       if k != "thr"}},
    }
    meta_path = os.path.splitext(args.output)[0] + ".meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"wrote {meta_path}", flush=True)
    print(f"\nBAKE THIS INTO src/engine.rs: "
          f"pub const APK_TREE_THRESHOLD: f32 = {best['thr']};", flush=True)


if __name__ == "__main__":
    main()