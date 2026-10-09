#!/usr/bin/env python3
"""
HydraDragon - JavaScript LightGBM trainer -> js_trees.bin (OpenEDR static engine)

Features come from the engine itself: js_feature_dump (Rust) includes
OpenEDR/openedr_static/src/ml/js_features.rs by path, so training and scanning use the
exact same extractor. There is no Python re-implementation to drift from it.

    python train_js_lgbm.py
    python train_js_lgbm.py --malicious D:\\js\\bad --benign D:\\js\\good
    python train_js_lgbm.py --reuse-csv          # retrain from the last js_features.csv

Writes js_trees.bin here and copies it to OpenEDR/openedr_static/models and
OpenMalwareScannerPortable/models (skip with --no-sync).
"""

import argparse
import csv
import os
import shutil
import struct
import subprocess
import sys

import lightgbm as lgb
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DUMP_CRATE = os.path.join(BASE_DIR, "js_feature_dump")
ENGINE_THRESHOLD = 0.90  # JS_TREE_THRESHOLD in OpenEDR/openedr_static/src/engine.rs
DATA = r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript"

# JsFeatureVector::to_array order (OpenEDR/openedr_static/src/ml/features.rs).
JS_FEATURE_NAMES = [
    "file_size", "entropy", "parse_success", "function_count", "variable_declarations",
    "call_expressions", "member_expressions", "binary_expressions", "conditional_statements",
    "loop_statements", "try_catch_blocks", "array_literals", "object_literals", "max_nesting_depth",
    "eval_usage", "suspicious_call_count", "hex_encoded_strings", "unicode_encoded_strings",
    "char_code_usage", "base64_usage", "escape_usage", "bracket_notation_calls", "obfuscation_score",
    "is_obfuscated", "crypto_references", "network_operations", "file_system_operations",
    "registry_operations", "process_operations", "suspicious_api_calls", "suspicious_score",
    "total_strings", "avg_string_length", "max_string_length", "long_strings_count",
    "base64_like_strings", "url_strings", "hex_strings", "total_lines", "code_lines", "comment_lines",
    "blank_lines", "avg_line_length", "max_line_length", "cyclomatic_complexity", "total_identifiers",
    "short_identifiers", "long_identifiers", "avg_identifier_length", "suspicious_naming",
    "random_like_identifiers",
]


def parse_args():
    ap = argparse.ArgumentParser(description="Train js_trees.bin from the engine's own JS features")
    ap.add_argument("--malicious", default=os.path.join(DATA, "datamaliciousorder"))
    ap.add_argument("--benign", default=os.path.join(DATA, "data2"))
    ap.add_argument("--features-csv", default=os.path.join(BASE_DIR, "js_features.csv"))
    ap.add_argument("--reuse-csv", action="store_true", help="Train from an existing --features-csv, no extraction")
    ap.add_argument("--max-samples-per-class", type=int, default=50000)
    ap.add_argument("--output-bin", default=os.path.join(BASE_DIR, "js_trees.bin"))
    ap.add_argument("--no-sync", action="store_true", help="Do not copy js_trees.bin into the engine model folders")
    return ap.parse_args()


def dump_features(args):
    """Builds and runs js_feature_dump (Rust, the engine's extractor) -> CSV."""
    print("[*] Extracting features with js_feature_dump (OpenEDR js_features.rs)...", flush=True)
    cmd = ["cargo", "run", "--release", "--manifest-path", os.path.join(DUMP_CRATE, "Cargo.toml"), "--",
           args.malicious, args.benign, args.features_csv, str(args.max_samples_per_class)]
    if subprocess.run(cmd).returncode != 0:
        sys.exit("js_feature_dump failed")


def load_features(path, max_per_class):
    """Balanced 50/50 dataset from the js_feature_dump CSV (label,path,<51 features>)."""
    mal, ben = [], []
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(fh)
        if next(rd)[2:] != JS_FEATURE_NAMES:
            sys.exit("CSV columns do not match JS_FEATURE_NAMES (js_features.rs changed?)")
        for row in rd:
            (mal if row[0] == "1" else ben).append([float(v) for v in row[2:]])
    mal = np.asarray(mal, dtype=np.float32)
    ben = np.asarray(ben, dtype=np.float32)
    n = min(len(mal), len(ben), max_per_class)
    print(f"[*] {len(mal)} malicious, {len(ben)} benign -> {n} each (50/50)")
    rng = np.random.default_rng(42)
    X = np.vstack([mal[rng.choice(len(mal), n, replace=False)], ben[rng.choice(len(ben), n, replace=False)]])
    y = np.array([1] * n + [0] * n, dtype=np.int32)
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
    X, y = load_features(args.features_csv, args.max_samples_per_class)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Training LightGBM: {len(X_train)} train / {len(X_test)} test")
    clf = lgb.LGBMClassifier(
        n_estimators=400, learning_rate=0.03, num_leaves=63, max_depth=8, min_child_samples=30,
        subsample=0.85, colsample_bytree=0.85, random_state=42, n_jobs=-1, verbose=-1,
    )
    clf.fit(X_train, y_train)

    p = clf.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, (p >= 0.5).astype(int), target_names=["Benign", "Malicious"], digits=4))
    tn, fp, fn, tp = confusion_matrix(y_test, (p >= ENGINE_THRESHOLD).astype(int), labels=[0, 1]).ravel()
    print(f"[+] At the engine threshold {ENGINE_THRESHOLD}: TP={tp} FN={fn} TN={tn} FP={fp} | "
          f"recall={tp / max(1, tp + fn) * 100:.2f}% | FPR={fp / max(1, fp + tn) * 100:.3f}%")

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
