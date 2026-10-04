#!/usr/bin/env python3
"""
Retrain generic_trees.bin from generic_features.joblib
Removes base64/entropy/hex pseudo-obfuscation feature bias.
Preserves exact 30-feature binary contract with OpenEDR static engine.
"""

import os
import struct
import shutil
import joblib
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

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
    joblib_path = os.path.join(BASE_DIR, "generic_features.joblib")
    print(f"[*] Loading {joblib_path}...", flush=True)
    data = joblib.load(joblib_path)
    X = data["X"].copy()
    y = data["y"]
    features = data["features"]
    print(f"[+] Loaded dataset matrix: {X.shape}", flush=True)

    # Neutralize string pseudo-obfuscation features that cause false positives on base64/hash tables:
    # 22: str_max_len_log
    # 24: str_entropy_avg
    # 25: str_entropy_var
    # 26: str_delta_var
    # 27: str_digit_ratio
    # 28: str_symbol_ratio
    # 29: str_hex_ratio
    zero_cols = [22, 24, 25, 26, 27, 28, 29]
    print(f"[*] Neutralizing pseudo-obfuscation feature columns: {[features[i] for i in zero_cols]}", flush=True)
    X[:, zero_cols] = 0.0

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)

    print(f"[*] Training LightGBM on {len(Xtr):,} training samples...", flush=True)
    clf = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.03,
        num_leaves=63,
        max_depth=7,
        min_child_samples=50,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    clf.fit(Xtr, ytr)
    yp = clf.predict(Xte)
    cm = confusion_matrix(yte, yp)
    tn, fp, fn, tp = cm.ravel()
    print(f"[+] Evaluation: TP={tp} FN={fn} TN={tn} FP={fp} | Recall={tp / max(1, tp + fn) * 100:.2f}% | FPR={fp / max(1, fp + tn) * 100:.2f}%", flush=True)

    out_bin = os.path.join(BASE_DIR, "generic_trees.bin")
    export_bin(clf, out_bin)

    # Sync to engine model paths
    targets = [
        os.path.join(REPO_ROOT, "OpenEDR", "openedr_static", "models"),
        os.path.join(REPO_ROOT, "OpenMalwareScannerPortable", "models"),
    ]
    for dest in targets:
        if os.path.isdir(dest):
            dest_file = os.path.join(dest, "generic_trees.bin")
            shutil.copy2(out_bin, dest_file)
            print(f"[+] Synced generic_trees.bin -> {dest_file}", flush=True)

    print("[+] Retraining and synchronization complete!", flush=True)

if __name__ == "__main__":
    main()
