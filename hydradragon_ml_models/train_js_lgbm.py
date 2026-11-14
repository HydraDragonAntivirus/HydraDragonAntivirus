#!/usr/bin/env python3
"""
HydraDragon - JavaScript LightGBM trainer -> js_trees.bin (OpenEDR static engine)

Features come from the engine itself: js_feature_dump (Rust) includes
OpenEDR/openedr_static/src/ml/js_features.rs by path, so training and scanning use the
exact same extractor. There is no Python re-implementation to drift from it.

    python train_js_lgbm.py
    python train_js_lgbm.py --malicious D:\\js\\bad D:\\js\\bad2 --benign D:\\js\\good
    python train_js_lgbm.py --dataset-paths C:\\multron\\dataset_paths.json
    python train_js_lgbm.py --reuse-csv          # retrain from the last js_features.csv

Folders: javascript_malware / javascript_clean in dataset_paths.json (every folder, see
dataset_paths.py), or --malicious / --benign (one or more each).

Writes js_trees.bin here and copies it to OpenEDR/openedr_static/models and
OpenMalwareScannerPortable/models (skip with --no-sync).
"""

import argparse
import csv
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

import lightgbm as lgb
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

import dataset_paths

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DUMP_CRATE = os.path.join(BASE_DIR, "js_feature_dump")
JS_DUMP_EXE = os.path.join(DUMP_CRATE, "target", "release", "js_feature_dump.exe")
ENGINE_THRESHOLD = 0.90  # JS_TREE_THRESHOLD in OpenEDR/openedr_static/src/engine.rs


def extract_js_features_from_file(filepath: str):
    """Extracts 51 JS features for a single file via js_feature_dump (OpenEDR js_features.rs)."""
    if not filepath or not os.path.isfile(filepath):
        return None
    if not os.path.isfile(JS_DUMP_EXE):
        return None
    with tempfile.TemporaryDirectory() as tmpdir:
        mal_lst = os.path.join(tmpdir, "mal.lst")
        ben_lst = os.path.join(tmpdir, "ben.lst")
        out_csv = os.path.join(tmpdir, "out.csv")
        with open(mal_lst, "w", encoding="utf-8") as fh:
            fh.write(filepath + "\n")
        with open(ben_lst, "w", encoding="utf-8") as fh:
            fh.write("")
        res = subprocess.run([JS_DUMP_EXE, "@" + mal_lst, "@" + ben_lst, out_csv, "1"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode != 0 or not os.path.isfile(out_csv):
            return None
        with open(out_csv, newline="", encoding="utf-8") as fh:
            rd = csv.reader(fh)
            _ = next(rd, None)
            row = next(rd, None)
            if not row or len(row) < 2 + len(JS_FEATURE_NAMES):
                return None
            return [float(v) for v in row[2:2 + len(JS_FEATURE_NAMES)]]


def extract_js_features_from_source(source: str):
    """Extracts the JS features (JS_FEATURE_NAMES) from a JS source string via js_feature_dump."""
    if not source:
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as tf:
        tf.write(source)
        tpath = tf.name
    try:
        return extract_js_features_from_file(tpath)
    finally:
        try:
            os.remove(tpath)
        except OSError:
            pass


# JsFeatureVector::to_array order (OpenEDR/openedr_static/src/ml/features.rs).
# No parse_success / base64_usage / crypto_references / base64_like_strings / url_strings:
# the extractor pinned them to one value (unparseable input is rejected; base64, hashing
# and URL counts were turned off as false-positive sources), so the trees could not use them.
JS_FEATURE_NAMES = [
    "file_size", "entropy", "function_count", "variable_declarations",
    "call_expressions", "member_expressions", "binary_expressions", "conditional_statements",
    "loop_statements", "try_catch_blocks", "array_literals", "object_literals", "max_nesting_depth",
    "eval_usage", "suspicious_call_count", "hex_encoded_strings", "unicode_encoded_strings",
    "char_code_usage", "escape_usage", "bracket_notation_calls", "obfuscation_score",
    "is_obfuscated", "network_operations", "file_system_operations",
    "registry_operations", "process_operations", "suspicious_api_calls", "suspicious_score",
    "total_strings", "avg_string_length", "max_string_length", "long_strings_count",
    "hex_strings", "total_lines", "code_lines", "comment_lines",
    "blank_lines", "avg_line_length", "max_line_length", "cyclomatic_complexity", "total_identifiers",
    "short_identifiers", "long_identifiers", "avg_identifier_length", "suspicious_naming",
    "random_like_identifiers",
    # No ben_str_hits / mal_ben_str_ratio / unknown_str_ratio: the benign string filter is
    # built from the training corpus, so they measured "seen in training".
    "mal_str_hits", "mal_str_density",
    "deob_modifications", "deob_unpacked", "total_unique_strings_log",
    # 51..54: URL ML (url_ml_metrics.rs): whitelist-gated url_trees.bin scores of the
    # script's URLs (raw source, deobfuscated code, decoded string literals).
    "url_unwhitelisted_count_log", "url_ml_max_prob", "url_ml_mean_prob", "url_ml_high_count_log",
]


def parse_args():
    ap = argparse.ArgumentParser(description="Train js_trees.bin from the engine's own JS features")
    dataset_paths.add_args(ap, "javascript")
    ap.add_argument("--features-csv", default=os.path.join(BASE_DIR, "js_features.csv"))
    ap.add_argument("--reuse-csv", action="store_true", help="Train from an existing --features-csv, no extraction")
    ap.add_argument("--max-samples-per-class", type=int, default=0,
                    help="0 = unlimited (default): every benign file is used")
    ap.add_argument("--balance", action="store_true",
                    help="Old behaviour: undersample both classes to 50/50 (default: use ALL samples)")
    ap.add_argument("--target-fpr", type=float, default=0.001,
                    help="Calibrated threshold: at most this share of validation benign files above it "
                         "(0 = above every validation benign file)")
    ap.add_argument("--output-bin", default=os.path.join(BASE_DIR, "js_trees.bin"))
    ap.add_argument("--no-sync", action="store_true", help="Do not copy js_trees.bin into the engine model folders")
    return ap.parse_args()


def dump_features(args):
    """Builds and runs js_feature_dump (Rust, the engine's extractor) -> CSV."""
    # No extension filter: js_feature_dump keeps every UTF-8 file the engine's JS
    # extractor accepts (decided by content, as at scan time).
    mal, ben = dataset_paths.collect(args, "javascript", max_per_class=args.max_samples_per_class)
    lists = []
    for name, files in (("js_malicious.lst", mal), ("js_benign.lst", ben)):
        # js_feature_dump reads UTF-8 lists: a name with a lone UTF-16 surrogate (valid
        # on Windows) cannot be written there or opened from it.
        ok = []
        for f in files:
            try:
                f.encode("utf-8")
                ok.append(f)
            except UnicodeEncodeError:
                pass
        if len(ok) < len(files):
            print(f"[*] {name}: {len(files) - len(ok)} files skipped (name not valid Unicode)", flush=True)
        files = ok
        path = os.path.join(BASE_DIR, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(files) + "\n")
        lists.append("@" + path)
    print("[*] Extracting features with js_feature_dump (OpenEDR js_features.rs)...", flush=True)
    cmd = ["cargo", "run", "--release", "--manifest-path", os.path.join(DUMP_CRATE, "Cargo.toml"), "--",
           lists[0], lists[1], args.features_csv, str(args.max_samples_per_class)]
    if subprocess.run(cmd).returncode != 0:
        sys.exit("js_feature_dump failed")


def load_features(path, max_per_class, balance=False):
    """ALL rows of the js_feature_dump CSV (label,path,<51 features>): every benign file
    is kept (false positives are the critical failure). Duplicate rows are removed and
    rows labelled both ways are dropped. `balance` restores the old 50/50 undersampling."""
    mal, ben = [], []
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(fh)
        header = next(rd)[2:]
        missing = [n for n in JS_FEATURE_NAMES if n not in header]
        if missing:
            sys.exit(f"CSV lacks {missing} (js_features.rs changed? re-extract)")
        # Columns by name: an older CSV still holding retired features trains as is.
        cols = [2 + header.index(n) for n in JS_FEATURE_NAMES]
        for row in rd:
            (mal if row[0] == "1" else ben).append([float(row[i]) for i in cols])
    mal = np.unique(np.asarray(mal, dtype=np.float32), axis=0)
    ben = np.unique(np.asarray(ben, dtype=np.float32), axis=0)
    both = {r.tobytes() for r in ben} & {r.tobytes() for r in mal}
    if both:
        mal = np.array([r for r in mal if r.tobytes() not in both], dtype=np.float32)
        ben = np.array([r for r in ben if r.tobytes() not in both], dtype=np.float32)
    print(f"[*] After dedup: {len(mal)} malicious, {len(ben)} benign ({len(both)} conflicting rows dropped)")
    rng = np.random.default_rng(42)
    if balance:
        n = min(len(mal), len(ben))
        if max_per_class > 0:
            n = min(n, max_per_class)
        mal = mal[rng.choice(len(mal), n, replace=False)]
        ben = ben[rng.choice(len(ben), n, replace=False)]
        print(f"[*] --balance: undersampled to {n} each (50/50)")
    X = np.vstack([mal, ben])
    y = np.array([1] * len(mal) + [0] * len(ben), dtype=np.int32)
    print(f"[+] Dataset: {len(X)} samples ({len(mal)} malicious, {len(ben)} benign, ratio "
          f"1:{len(ben) / max(len(mal), 1):.2f})")
    const = [JS_FEATURE_NAMES[i] for i in range(X.shape[1]) if np.all(X[:, i] == X[0, i])]
    print(f"[*] Constant features (the trees cannot use them): {const}")
    return X, y


def export_bin(clf, out_path):
    """LightGBM -> tree bundle read by OpenEDR/openedr_static/src/ml/tree_model.rs (<IIfIIBf nodes)."""
    dump = clf.booster_.dump_model()
    chunks = [struct.pack("<I", len(dump["tree_info"]))]
    for info in dump["tree_info"]:
        nodes, nxt = {}, [0]

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
    print(f"[+] Exported {out_path} ({len(raw):,} bytes, {len(dump['tree_info'])} trees)")


def bin_predict(path, X):
    """Scores X exactly like tree_model.rs (f32 thresholds, sum of leaves, sigmoid)."""
    data = open(path, "rb").read()
    (n_trees,) = struct.unpack_from("<I", data, 0)
    off, trees = 4, []
    for _ in range(n_trees):
        (n,) = struct.unpack_from("<I", data, off)
        off += 4
        nodes = {}
        for _ in range(n):
            i, f, t, l, r, leaf, w = struct.unpack_from("<IIfIIBf", data, off)
            off += 25
            nodes[i] = (f, np.float32(t), l, r, leaf, w)
        trees.append(nodes)
    out = np.zeros(len(X))
    for k, row in enumerate(np.asarray(X, dtype=np.float32)):
        s = 0.0
        for nodes in trees:
            nid = 0
            while True:
                f, t, l, r, leaf, w = nodes[nid]
                if leaf:
                    s += w
                    break
                nid = l if row[f] <= t else r
        out[k] = s
    return 1.0 / (1.0 + np.exp(-out))


def main():
    args = parse_args()
    if not (args.reuse_csv and os.path.isfile(args.features_csv)):
        dump_features(args)
    X, y = load_features(args.features_csv, args.max_samples_per_class, balance=args.balance)

    # 70 % train, 15 % validation (threshold), 15 % test (final numbers), as train_pe_lgbm.
    X_train, X_rest, y_train, y_rest = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_rest, y_rest, test_size=0.50, random_state=42,
                                                    stratify=y_rest)
    print(f"[*] Training LightGBM: {len(X_train)} train / {len(X_val)} validation / {len(X_test)} test")
    clf = lgb.LGBMClassifier(
        n_estimators=400, learning_rate=0.03, num_leaves=63, max_depth=8, min_child_samples=30,
        subsample=0.85, colsample_bytree=0.85, random_state=42, n_jobs=-1, verbose=-1,
    )
    clf.fit(X_train, y_train)

    # Threshold from the validation benign scores: at most target-fpr of them above it.
    val_ben = np.sort(clf.predict_proba(X_val[y_val == 0])[:, 1])
    k = int(np.ceil(len(val_ben) * (1.0 - args.target_fpr)))
    thr = float(val_ben[min(k, len(val_ben) - 1)]) + 1e-6 if len(val_ben) else ENGINE_THRESHOLD
    thr = min(max(thr, 0.5), 0.9999)

    p = clf.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, (p >= 0.5).astype(int), target_names=["Benign", "Malicious"], digits=4))

    def report(label, t):
        tn, fp, fn, tp = confusion_matrix(y_test, (p >= t).astype(int), labels=[0, 1]).ravel()
        print(f"[+] {label} {t:.4f}: TP={tp} FN={fn} TN={tn} FP={fp} | "
              f"recall={tp / max(1, tp + fn) * 100:.2f}% | FPR={fp / max(1, fp + tn) * 100:.3f}%")

    report("At the engine threshold", ENGINE_THRESHOLD)
    report(f"Calibrated on validation (target FPR {args.target_fpr * 100:.3f}%)", thr)
    if args.target_fpr == 0 and np.any(p[y_test == 0] >= thr):
        # A test benign file still scores above every validation benign file: for a
        # zero-FPR target, go above every held-out benign file (validation and test).
        # The test split then no longer checks the threshold independently.
        thr = min(max(thr, float(p[y_test == 0].max()) + 1e-6), 0.9999)
        report("Above every held-out benign file (validation + test)", thr)
    print(f"[!] Set the JS threshold to {thr:.4f} for this model (dashboard: ML thresholds).")
    with open(os.path.splitext(args.output_bin)[0] + "_threshold.json", "w") as f:
        json.dump({"js_tree_threshold": round(thr, 4), "target_fpr": args.target_fpr}, f)

    export_bin(clf, args.output_bin)
    n_chk = min(2000, len(X_test))
    diff = float(np.abs(bin_predict(args.output_bin, X_test[:n_chk]) - p[:n_chk]).max())
    print(f"[+] js_trees.bin vs LightGBM on {n_chk} test rows: max |diff| = {diff:.2e}")
    if diff > 1e-3:
        sys.exit("js_trees.bin does not match LightGBM; not syncing")

    if not args.no_sync:
        for dest in [os.path.join(REPO_ROOT, "OpenEDR", "openedr_static", "models"),
                     os.path.join(REPO_ROOT, "OpenMalwareScannerPortable", "models")]:
            if os.path.isdir(dest):
                shutil.copy2(args.output_bin, os.path.join(dest, "js_trees.bin"))
                print(f"[+] Synced -> {os.path.join(dest, 'js_trees.bin')}")
    print("[+] Done. Reload the engine (dashboard: Reload engines) to use the new model.")


if __name__ == "__main__":
    main()
