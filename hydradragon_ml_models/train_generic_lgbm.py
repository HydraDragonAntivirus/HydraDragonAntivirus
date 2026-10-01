#!/usr/bin/env python3
r"""
HydraDragon Generic Whole-Buffer Pure Byte, Padding & Entropy ML Trainer
Category-based 50% / 50% Balanced Training (NO SAMPLE LIMITS, NO DOWNLOADS):

Categories:
  1. PE / Windows:
     - Benign:    C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2
     - Malicious: C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder
     -> Balanced 50% / 50% internally.
  2. JavaScript:
     - Benign:    C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\data2
     - Malicious: C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\datamaliciousorder
     -> Balanced 50% / 50% internally.
  3. Mobile / Android:
     - Benign:    C:\Users\semae\OneDrive\Belgeler\Github\HydraDragonAV-Mobile\dataset\benign
     - Malicious: C:\Users\semae\OneDrive\Belgeler\Github\HydraDragonAV-Mobile\dataset\malware
     -> Balanced 50% / 50% internally.

ZERO keyword lists, ZERO string regexes.
Features match generic_features.rs EXACTLY (20 features).
"""

import os
import math
import struct
import gc
import random
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import joblib
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

FEATURE_NAMES = [
    "len_log",
    "content_len_log",
    "whole_entropy",
    "content_entropy",
    "entropy_delta",
    "padding_ratio",
    "trailing_pad_ratio",
    "lead_pad_ratio",
    "stripped_zero_ratio",
    "mean_byte_norm",
    "std_byte_norm",
    "printable_ratio",
    "high_byte_ratio",
    "control_byte_ratio",
    "chunk_entropy_var",
    "max_chunk_entropy",
    "min_chunk_entropy",
    "has_mz",
    "has_pe_sig",
    "has_zip_magic",
]
N_FEATS = len(FEATURE_NAMES)
assert N_FEATS == 20

CAP = 8 * 1024 * 1024  # 8 MiB inspect cap
CHUNK_SIZE = 4096


def _ln1p(x: float) -> float:
    return float(math.log1p(x)) if x > 0 else 0.0


def _shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    n = len(buf)
    counts = Counter(buf)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
    return ent if math.isfinite(ent) else 0.0


def featurize_buffer(data: bytes) -> list:
    """Exact parity with Rust extract_generic_features() in generic_features.rs"""
    if not data or len(data) < 2:
        return [0.0] * N_FEATS

    total_len = len(data)
    buf = data[:CAP]
    n = len(buf)

    # 1. Whole buffer stats
    counts = Counter(buf)
    zero_count = counts.get(0, 0)
    padding_ratio = zero_count / n

    # Trailing null run
    trailing = 0
    for i in range(len(data) - 1, -1, -1):
        if data[i] == 0:
            trailing += 1
        else:
            break
    trailing_pad_ratio = trailing / total_len

    # Leading null run
    leading = 0
    for b in data[:min(total_len, 65536)]:
        if b == 0:
            leading += 1
        else:
            break
    lead_pad_ratio = leading / total_len

    # Byte dispersion (mean and std dev)
    byte_sum = sum(b * c for b, c in counts.items())
    mean_b = byte_sum / n
    mean_byte_norm = mean_b / 255.0
    var_b = sum(((b - mean_b) ** 2) * c for b, c in counts.items()) / n
    std_byte_norm = math.sqrt(var_b) / 128.0

    whole_entropy = _shannon_entropy(buf)

    # 2. Stripped buffer stats (strip trailing null padding)
    real_end = n
    while real_end > 0 and buf[real_end - 1] == 0:
        real_end -= 1
    stripped = buf[:real_end] if real_end > 0 else buf[:min(n, 64)]
    sn = len(stripped)

    content_entropy = _shannon_entropy(stripped)
    entropy_delta = max(0.0, whole_entropy - content_entropy)

    s_counts = Counter(stripped)
    stripped_zeros = s_counts.get(0, 0)
    stripped_zero_ratio = stripped_zeros / sn if sn > 0 else 0.0

    printable = sum(s_counts.get(b, 0) for b in list(range(0x20, 0x7F)) + [9, 10, 13])
    high_bytes = sum(s_counts.get(b, 0) for b in range(0x80, 0x100))
    ctrl_bytes = sum(s_counts.get(b, 0) for b in range(1, 0x20) if b not in (9, 10, 13))

    printable_ratio = printable / sn if sn > 0 else 0.0
    high_byte_ratio = high_bytes / sn if sn > 0 else 0.0
    control_byte_ratio = ctrl_bytes / sn if sn > 0 else 0.0

    # 3. Chunk-level entropy profiling (4KB chunks across stripped content)
    chunk_ents = []
    for offset in range(0, sn, CHUNK_SIZE):
        chunk = stripped[offset:offset + CHUNK_SIZE]
        if len(chunk) >= 256:
            chunk_ents.append(_shannon_entropy(chunk))

    if chunk_ents:
        avg_chunk_ent = sum(chunk_ents) / len(chunk_ents)
        chunk_entropy_var = sum((ce - avg_chunk_ent) ** 2 for ce in chunk_ents) / len(chunk_ents)
        max_chunk_entropy = max(chunk_ents)
        min_chunk_entropy = min(chunk_ents)
    else:
        chunk_entropy_var = 0.0
        max_chunk_entropy = content_entropy
        min_chunk_entropy = content_entropy

    # 4. Binary format markers (cheap, no strings)
    has_mz = 1.0 if len(data) >= 2 and data[:2] == b"MZ" else 0.0
    has_pe = 0.0
    if has_mz and len(data) >= 64:
        try:
            e = int.from_bytes(data[0x3C:0x40], "little")
            if e + 6 <= len(data) and data[e:e + 4] == b"PE\0\0":
                nsec = int.from_bytes(data[e + 4:e + 6], "little")
                if nsec <= 96:
                    has_pe = 1.0
        except Exception:
            pass

    has_zip = 1.0 if len(data) >= 4 and data[:4] == b"PK\x03\x04" else 0.0

    return [
        _ln1p(total_len),
        _ln1p(sn),
        whole_entropy,
        content_entropy,
        entropy_delta,
        padding_ratio,
        trailing_pad_ratio,
        lead_pad_ratio,
        stripped_zero_ratio,
        mean_byte_norm,
        std_byte_norm,
        printable_ratio,
        high_byte_ratio,
        control_byte_ratio,
        chunk_entropy_var,
        max_chunk_entropy,
        min_chunk_entropy,
        has_mz,
        has_pe,
        has_zip,
    ]


def _read_and_featurize_file(path: str):
    try:
        with open(path, "rb") as fh:
            data = fh.read(CAP)
        if len(data) < 8:
            return None
        return featurize_buffer(data)
    except Exception:
        return None


def collect_all_files(dir_path: str):
    paths = []
    if not os.path.exists(dir_path):
        print(f"[!] Path not found: {dir_path}", flush=True)
        return paths
    print(f"[*] Scanning all files in: {dir_path} ...", flush=True)
    for root, _, files in os.walk(dir_path):
        for f in files:
            paths.append(os.path.join(root, f))
    print(f"[+] Found {len(paths):,} total files in: {dir_path}", flush=True)
    return paths


def export_bin(clf, out_path: str):
    dump = clf.booster_.dump_model()
    chunks = [struct.pack("<I", len(dump["tree_info"]))]
    for info in dump["tree_info"]:
        nodes = {}
        nxt = [0]

        def new_id():
            nxt[0] += 1
            return nxt[0]

        queue = [(info["tree_structure"], 0)]
        while queue:
            node, nid = queue.pop(0)
            if "leaf_value" in node:
                nodes[nid] = (nid, 0, 0.0, 0, 0, True, float(node["leaf_value"]))
            else:
                left, right = new_id(), new_id()
                nodes[nid] = (nid, int(node["split_feature"]), float(node["threshold"]),
                              left, right, False, 0.0)
                queue.append((node["left_child"], left))
                queue.append((node["right_child"], right))
        ordered = [nodes[k] for k in sorted(nodes)]
        chunks.append(struct.pack("<I", len(ordered)))
        for (i, f, t, left, right, leaf, w) in ordered:
            chunks.append(struct.pack("<IIfIIBf", i, f, t, left, right, 1 if leaf else 0, w))
    raw = b"".join(chunks)
    with open(out_path, "wb") as fh:
        fh.write(raw)
    print(f"[+] Exported bin: {out_path} ({len(raw):,} bytes)", flush=True)


def main():
    print("=== HydraDragon Pure Byte/Evasion Category-Wise ML Trainer ===", flush=True)

    categories = [
        {
            "name": "PE / Windows Binaries",
            "benign": r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2",
            "malicious": r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder",
        },
        {
            "name": "JavaScript Scripts",
            "benign": r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\data2",
            "malicious": r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\datamaliciousorder",
        },
        {
            "name": "Mobile / Android APKs",
            "benign": r"C:\Users\semae\OneDrive\Belgeler\Github\HydraDragonAV-Mobile\dataset\benign",
            "malicious": r"C:\Users\semae\OneDrive\Belgeler\Github\HydraDragonAV-Mobile\dataset\malware",
        },
    ]

    workers = max(1, (os.cpu_count() or 4) - 1)
    print(f"[*] Running with {workers} parallel worker processes\n", flush=True)

    all_X_list = []
    all_y_list = []

    for cat in categories:
        cname = cat["name"]
        print(f"--- Processing Category: {cname} ---", flush=True)
        ben_files = collect_all_files(cat["benign"])
        mal_files = collect_all_files(cat["malicious"])

        if not ben_files or not mal_files:
            print(f"[!] Skipping {cname}: empty benign ({len(ben_files)}) or malicious ({len(mal_files)})", flush=True)
            continue

        min_cat = min(len(ben_files), len(mal_files))
        print(f"[*] Category {cname} internally balanced to 50%/50%: {min_cat:,} Benign vs {min_cat:,} Malicious", flush=True)

        random.seed(42)
        random.shuffle(ben_files)
        random.shuffle(mal_files)
        ben_files = ben_files[:min_cat]
        mal_files = mal_files[:min_cat]

        def featurize_list(flist, label, desc):
            feats = []
            done = 0
            total = len(flist)
            with ProcessPoolExecutor(max_workers=workers) as ex:
                for r in ex.map(_read_and_featurize_file, flist, chunksize=64):
                    if r is not None:
                        feats.append(r)
                    done += 1
                    if done % 10000 == 0 or done == total:
                        print(f"    [{desc}] {done:,} / {total:,} ({len(feats):,} valid vectors)", flush=True)
            X = np.array(feats, dtype=np.float32)
            y = np.full(len(feats), label, dtype=np.int8)
            return X, y

        print(f"[*] Extracting {cname} Benign...", flush=True)
        Xb, yb = featurize_list(ben_files, 0, f"{cname} Benign")

        print(f"[*] Extracting {cname} Malicious...", flush=True)
        Xm, ym = featurize_list(mal_files, 1, f"{cname} Malicious")

        m_valid = min(len(Xb), len(Xm))
        all_X_list.append(Xb[:m_valid])
        all_X_list.append(Xm[:m_valid])
        all_y_list.append(yb[:m_valid])
        all_y_list.append(ym[:m_valid])
        print(f"[+] Category {cname} contributed {m_valid * 2:,} vectors ({m_valid:,} Benign + {m_valid:,} Malicious)\n", flush=True)

    X = np.vstack(all_X_list)
    y = np.concatenate(all_y_list)
    del all_X_list, all_y_list
    gc.collect()

    shuff_idx = np.arange(len(y))
    np.random.RandomState(42).shuffle(shuff_idx)
    X = X[shuff_idx]
    y = y[shuff_idx]

    b_count = int(np.sum(y == 0))
    m_count = int(np.sum(y == 1))
    print(f"\n=======================================================", flush=True)
    print(f"[+] TOTAL BALANCED MATRIX: {X.shape}", flush=True)
    print(f"[+] Benign: {b_count:,} ({b_count/len(y)*100:.1f}%) | Malicious: {m_count:,} ({m_count/len(y)*100:.1f}%)", flush=True)
    print(f"=======================================================\n", flush=True)

    output_joblib = os.path.join(BASE_DIR, "generic_features.joblib")
    joblib.dump({"X": X, "y": y, "features": FEATURE_NAMES}, output_joblib, compress=3)
    print(f"[+] Saved dataset matrix to: {output_joblib}", flush=True)

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    del X, y
    gc.collect()

    print(f"[*] Training LightGBM on pure evasion features (train={len(Xtr):,}, test={len(Xte):,})...", flush=True)
    clf = lgb.LGBMClassifier(
        n_estimators=500,
        learning_rate=0.03,
        num_leaves=127,
        max_depth=10,
        min_child_samples=40,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    clf.fit(Xtr, ytr)
    yp = clf.predict(Xte)

    print("\n--- Test Set Evaluation ---", flush=True)
    print(classification_report(yte, yp, target_names=["Benign", "Malicious"], digits=4), flush=True)
    cm = confusion_matrix(yte, yp)
    tn, fp, fn, tp = cm.ravel()
    print(f"TP={tp} FN={fn} TN={tn} FP={fp} | Recall={tp / max(1, tp + fn) * 100:.2f}% | FPR={fp / max(1, fp + tn) * 100:.2f}%\n", flush=True)

    imp = clf.feature_importances_
    print("--- Top Feature Importance ---", flush=True)
    for idx in np.argsort(imp)[::-1]:
        print(f"  {FEATURE_NAMES[idx]:<22}: {imp[idx]}", flush=True)

    output_bin = os.path.join(BASE_DIR, "generic_trees.bin")
    export_bin(clf, output_bin)

    # Sync
    import shutil
    for dest in (
        os.path.join(REPO_ROOT, "OpenEDR", "openedr_static", "models"),
        os.path.join(REPO_ROOT, "OpenMalwareScannerPortable", "models"),
    ):
        if os.path.isdir(dest):
            shutil.copy2(output_bin, os.path.join(dest, "generic_trees.bin"))
            print(f"[+] Synced generic_trees.bin -> {dest}", flush=True)


if __name__ == "__main__":
    main()
