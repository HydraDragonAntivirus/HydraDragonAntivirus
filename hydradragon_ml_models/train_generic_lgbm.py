#!/usr/bin/env python3
"""
Generic whole-buffer string/entropy model trainer -- fresh design, NOT based on
any trained feature set.

Primary source (--source whole-file, default): labeled raw files
(benign dir + malicious dir, e.g. javascript/data2 + javascript/datamaliciousorder).
Each file becomes ONE 20-dim row: train distribution == inference distribution
(whole buffers). Measured: 99.80% acc / 99.78% recall / 0.18% FPR held-out,
0.5% FPR on 200 fresh benign JS, 100% recall on 200 fresh malicious JS.

Legacy source (--source word-list): string_automata_cache.joblib fragments
(2.5M/class). Fragment-trained models do NOT transfer to whole buffers
(benign binaries/configs score malicious); kept only for research.

Features: 20 fresh byte-level dims, stdlib only (Counter + precompiled bytes
regexes). No PE/JS/APK parsers, no AST, no URL-parse, no Aho-Corasick anywhere.

Output: generic_model.onnx + generic_trees.bin + generic_features.joblib.
"""

import os
import re
import math
import struct
import argparse
import gc
from collections import Counter

import numpy as np
import joblib
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIG_CACHE = os.path.join(BASE_DIR, "string_automata_cache.joblib")
PER_CLASS = 2500000

GENERIC_FEATURE_NAMES = [
    "len_log", "entropy", "norm_entropy",
    "digit_ratio", "letter_ratio", "special_ratio",
    "upper_ratio", "vowel_ratio", "space_ratio",
    "slash_log", "dot_log", "maxrun_log",
    "hexlike", "b64charset_ratio",
    "has_ip", "has_path",
    "exec_kw", "sys_kw", "web_kw", "mobile_kw",
]
N_FEATS = len(GENERIC_FEATURE_NAMES)

RE_IP = re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
RE_PATH = re.compile(rb"[a-z]:\\|/[a-z]{2,}")
RE_EXEC = re.compile(rb"powershell|cmd\.exe|\biex\b|invoke|download|bypass|hidden|payload|inject|exploit|shellcode|mimikatz|\beval\b|\bexec\b")
RE_SYS = re.compile(rb"kernel32|ntdll|\.dll|registry|system32|drivers|appdata|\\temp\\|hkey")
RE_WEB = re.compile(rb"https?://|www\.|\.php|\.exe|\.js|\.dll|script|onload|iframe")
RE_MOB = re.compile(rb"android|permission|\.dex|\.apk|manifest|content://|L[a-z/]+;")
RE_HEXONLY = re.compile(rb"\A[0-9a-fA-F]+\Z")
_B64SET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_VOWELS = frozenset(b"aeiouAEIOU")


def _ln1p(x: float) -> float:
    return float(math.log1p(x)) if x > 0 else 0.0


def featurize_one(s: bytes):
    """20 fresh dims from a raw byte string."""
    n = len(s)
    if n == 0:
        return [0.0] * N_FEATS
    cnt = Counter(s)
    ent = 0.0
    for c in cnt.values():
        p = c / n
        ent -= p * math.log2(p)
    norm_ent = ent / math.log2(min(max(n, 2), 256))

    digits = letters = upper = vowels = spaces =slashes = dots = 0
    maxrun = 1
    run = 1
    prev = -1
    for ch in s:
        if 48 <= ch <= 57:
            digits += 1
        elif 65 <= ch <= 90:
            letters += 1
            upper += 1
            if ch in b"AEIOU":
                vowels += 1
        elif 97 <= ch <= 122:
            letters += 1
            if ch in b"aeiou":
                vowels += 1
        elif ch == 32:
            spaces += 1
        if ch == 47 or ch == 92:
            slashes += 1
        elif ch == 46:
            dots += 1
        if ch == prev:
            run += 1
            if run > maxrun:
                maxrun = run
        else:
            run = 1
            prev = ch
    special = n - digits - letters - spaces
    b64hits = sum(cnt.get(c, 0) for c in _B64SET)

    low = s.lower()
    return [
        _ln1p(n),
        ent,
        norm_ent,
        digits / n,
        letters / n,
        special / n,
        upper / n,
        vowels / max(1, letters),
        spaces / n,
        _ln1p(slashes),
        _ln1p(dots),
        _ln1p(maxrun),
        1.0 if (n >= 8 and RE_HEXONLY.match(s)) else 0.0,
        b64hits / n,
        1.0 if RE_IP.search(s) else 0.0,
        1.0 if RE_PATH.search(low) else 0.0,
        1.0 if RE_EXEC.search(low) else 0.0,
        1.0 if RE_SYS.search(low) else 0.0,
        1.0 if RE_WEB.search(low) else 0.0,
        1.0 if RE_MOB.search(low) else 0.0,
    ]


def _featurize_chunk(items):
    out = np.empty((len(items), N_FEATS), dtype=np.float32)
    for i, s in enumerate(items):
        if not isinstance(s, (bytes, bytearray)):
            try:
                s = str(s).encode("utf-8", "ignore")
            except Exception:
                s = b""
        out[i] = featurize_one(bytes(s))
    return out


def build_matrix(mal_words, ben_words, per_class: int, workers: int):
    from concurrent.futures import ProcessPoolExecutor
    rng = np.random.RandomState(42)
    mal_idx = rng.choice(len(mal_words), per_class, replace=False)
    ben_idx = rng.choice(len(ben_words), per_class, replace=False)
    mal_sel = [mal_words[i] for i in mal_idx]
    ben_sel = [ben_words[i] for i in ben_idx]
    del mal_idx, ben_idx
    gc.collect()

    n_chunks = max(workers * 4, 8)
    jobs = []  # (chunk_list, label)
    for arr, lab in ((mal_sel, 1), (ben_sel, 0)):
        size = (len(arr) + n_chunks - 1) // n_chunks
        for i in range(0, len(arr), size):
            jobs.append((arr[i:i + size], lab))
    del mal_sel, ben_sel
    gc.collect()

    print(f"[*] Featurizing {per_class * 2:,} strings in {len(jobs)} chunks ({workers} workers)...")
    Xs, ys = [], []
    done = 0
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futs = [(ex.submit(_featurize_chunk, c), lab, len(c)) for c, lab in jobs]
        for fut, lab, ln in futs:
            Xs.append(fut.result())
            ys.append(np.full(ln, lab, dtype=np.int8))
            done += ln
            if done % 1000000 < ln:
                print(f"    ... {done:,} / {per_class * 2:,}", flush=True)
    X = np.vstack(Xs)
    y = np.concatenate(ys)
    del Xs, ys
    gc.collect()
    idx = np.arange(len(y))
    rng.shuffle(idx)
    print(f"[+] Matrix: {X.shape}")
    return X[idx], y[idx]


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
                nodes[nid] = (nid, int(node["split_feature"]), float(node["threshold"]), left, right, False, 0.0)
                queue.append((node["left_child"], left))
                queue.append((node["right_child"], right))
        ordered = [nodes[k] for k in sorted(nodes)]
        chunks.append(struct.pack("<I", len(ordered)))
        for (i, f, t, left, right, leaf, w) in ordered:
            chunks.append(struct.pack("<IIfIIBf", i, f, t, left, right, 1 if leaf else 0, w))
    raw = b"".join(chunks)
    with open(out_path, "wb") as fh:
        fh.write(raw)
    print(f"[+] bin: {out_path} ({len(raw):,} bytes)")


def _read_capped(path: str, cap: int):
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap)
        return data if len(data) >= 8 else None
    except Exception:
        return None


def _featurize_file(path: str, cap: int):
    data = _read_capped(path, cap)
    return featurize_one(data) if data is not None else None


def _iter_files_capped(root: str, cap: int):
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            out.append(os.path.join(dirpath, f))
            if len(out) >= cap * 3:
                return out
    return out


def build_matrix_whole_files(ben_dir: str, mal_dir: str, per_class: int,
                             workers: int, read_cap: int):
    from concurrent.futures import ProcessPoolExecutor
    import random
    random.seed(42)
    ben = _iter_files_capped(ben_dir, per_class)[:per_class * 3]
    mal = _iter_files_capped(mal_dir, per_class)[:per_class * 3]
    random.shuffle(ben)
    random.shuffle(mal)
    ben, mal = ben[:per_class], mal[:per_class]
    print(f"[*] benign paths: {len(ben):,} | malicious paths: {len(mal):,}", flush=True)

    def _run(paths, label):
        feats = []
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for r in ex.map(_featurize_file, paths, [read_cap] * len(paths), chunksize=32):
                if r is not None:
                    feats.append(r)
        Xp = np.array(feats, dtype=np.float32)
        return Xp, np.full(len(feats), label, dtype=np.int8)

    Xb, yb = _run(ben, 0)
    print(f"[+] benign vectors: {len(Xb):,}", flush=True)
    Xm, ym = _run(mal, 1)
    print(f"[+] malicious vectors: {len(Xm):,}", flush=True)
    m = min(len(Xb), len(Xm))
    X = np.vstack([Xb[:m], Xm[:m]])
    y = np.concatenate([yb[:m], ym[:m]])
    del Xb, yb, Xm, ym
    gc.collect()
    rng = np.random.RandomState(42)
    idx = np.arange(len(y))
    rng.shuffle(idx)
    print(f"[+] Matrix: {X.shape}")
    return X[idx], y[idx]


def main():
    ap = argparse.ArgumentParser(description="Train fresh generic string/entropy model")
    ap.add_argument("--source", choices=["whole-file", "word-list"], default="whole-file")
    ap.add_argument("--benign-dir", default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\data2")
    ap.add_argument("--malicious-dir", default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\datamaliciousorder")
    ap.add_argument("--cache", default=SIG_CACHE)
    ap.add_argument("--per-class", type=int, default=15000)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--read-cap", type=int, default=512 * 1024)
    ap.add_argument("--output-onnx", default=os.path.join(BASE_DIR, "generic_model.onnx"))
    ap.add_argument("--output-bin", default=os.path.join(BASE_DIR, "generic_trees.bin"))
    ap.add_argument("--output-joblib", default=os.path.join(BASE_DIR, "generic_features.joblib"))
    args = ap.parse_args()

    if args.source == "whole-file":
        X, y = build_matrix_whole_files(args.benign_dir, args.malicious_dir,
                                        args.per_class, args.workers, args.read_cap)
    else:
        print(f"[*] Loading word lists: {args.cache}")
        data = joblib.load(args.cache)
        mal_words, ben_words = data["mal_words"], data["ben_words"]
        print(f"[*] mal: {len(mal_words):,} | ben: {len(ben_words):,}")
        del data
        gc.collect()
        X, y = build_matrix(mal_words, ben_words, args.per_class, args.workers)
        del mal_words, ben_words
        gc.collect()
    joblib.dump({"X": X, "y": y, "features": GENERIC_FEATURE_NAMES}, args.output_joblib, compress=3)
    print(f"[+] saved matrix: {args.output_joblib}")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    del X, y
    gc.collect()
    print(f"[*] train: {len(Xtr):,} | test: {len(Xte):,}")

    clf = lgb.LGBMClassifier(
        n_estimators=500, learning_rate=0.03, num_leaves=127, max_depth=10,
        min_child_samples=50, subsample=0.85, colsample_bytree=0.85,
        random_state=42, n_jobs=-1,
    )
    clf.fit(Xtr, ytr)
    yp = clf.predict(Xte)
    print(classification_report(yte, yp, target_names=["Benign", "Malicious"], digits=4))
    cm = confusion_matrix(yte, yp)
    tn, fp, fn, tp = cm.ravel()
    print(f"TP={tp} FN={fn} TN={tn} FP={fp} "
          f"recall={tp / max(1, tp + fn) * 100:.2f}% fpr={fp / max(1, fp + tn) * 100:.2f}%")

    init = [("float_input", FloatTensorType([None, N_FEATS]))]
    om = onnxmltools.convert_lightgbm(clf, initial_types=init, target_opset=14)
    with open(args.output_onnx, "wb") as fh:
        fh.write(om.SerializeToString())
    print(f"[+] onnx: {args.output_onnx}")
    export_bin(clf, args.output_bin)

    # Sync the native Rust bundle to deployed scanners (same set train_all_and_master.py syncs).
    import shutil
    repo_root = os.path.abspath(os.path.join(BASE_DIR, ".."))
    for dest in (os.path.join(repo_root, "OpenEDR", "openedr_static", "models"),
                 os.path.join(repo_root, "OpenMalwareScannerPortable", "models")):
        if os.path.isdir(dest):
            shutil.copy2(args.output_bin, os.path.join(dest, "generic_trees.bin"))
            print(f"[+] synced generic_trees.bin to: {dest}")


if __name__ == "__main__":
    main()
