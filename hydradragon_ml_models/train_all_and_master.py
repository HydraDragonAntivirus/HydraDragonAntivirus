#!/usr/bin/env python3
"""
HydraDragon Universal AI Engine - Master & Specialist Multi-Modal Trainer
Trains all 4 domain expert models DIRECTLY from existing pre-extracted balanced joblibs:
  1. PE Model (pe_features_full.joblib) -> pe_model.onnx & pe_trees.bin (65 features)
  2. JS Model (js_features_39k.joblib)  -> js_model.onnx & js_trees.bin (51 features)
  3. APK Model (apk_features.joblib)    -> apk_model.onnx & apk_trees.bin (24 features)
  4. URL Model (url_features_cache.joblib) -> url_model.onnx, url_trees.bin & url_model.bin (32 features)
And trains the unified:
  5. Master Universal Model -> hydradragon_master.onnx
"""

import os
import sys
import gc
import struct
import shutil
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

PORTABLE_MODELS = os.path.join(REPO_ROOT, "OpenMalwareScannerPortable", "models")
OPENEDR_STATIC_MODELS = os.path.join(REPO_ROOT, "OpenEDR", "openedr_static", "models")
OWLYSHIELD_MODELS = os.path.join(REPO_ROOT, "OpenEDR", "owlyshield_predict", "models")

# -------------------------------------------------------------
# Binary Tree Exporters
# -------------------------------------------------------------
class StandardTree:
    def __init__(self):
        self.nodes = []

    def emit(self):
        out = [struct.pack("<I", len(self.nodes))]
        for (i, f, t, l, r, leaf, w) in self.nodes:
            out.append(struct.pack("<IIfIIBf", i, f, t, l, r, 1 if leaf else 0, w))
        return b"".join(out)

def convert_lightgbm_standard(dump):
    trees = []
    for info in dump["tree_info"]:
        t, nxt = StandardTree(), [0]
        def new_id():
            nxt[0] += 1
            return nxt[0]
        queue = [(info["tree_structure"], 0)]
        nodes = {}
        while queue:
            node, nid = queue.pop(0)
            if "leaf_value" in node:
                nodes[nid] = (nid, 0, 0.0, 0, 0, True, float(node["leaf_value"]))
            else:
                l, r = new_id(), new_id()
                nodes[nid] = (nid, int(node["split_feature"]), float(node["threshold"]), l, r, False, 0.0)
                queue.append((node["left_child"], l))
                queue.append((node["right_child"], r))
        t.nodes = [nodes[k] for k in sorted(nodes)]
        trees.append(t)
    return trees

def export_standard_tree_bundle(clf, out_path: str):
    dump = clf.booster_.dump_model()
    trees = convert_lightgbm_standard(dump)
    raw = struct.pack("<I", len(trees)) + b"".join(t.emit() for t in trees)
    with open(out_path, "wb") as f:
        f.write(raw)
    print(f"  [+] Exported standard tree bundle: {out_path} ({len(raw):,} bytes, {len(trees)} trees)", flush=True)

def export_hdtr_url_model(clf, n_features: int, out_path: str):
    dump = clf.booster_.dump_model()
    trees = convert_lightgbm_standard(dump)
    n_trees = len(trees)
    
    header = b"HDTR" + struct.pack("<HH", n_features, n_trees)
    chunks = [header]
    
    for t in trees:
        n_nodes = len(t.nodes)
        chunks.append(struct.pack("<I", n_nodes))
        for (nid, feat, thr, left, right, is_leaf, weight) in t.nodes:
            val_or_thresh = weight if is_leaf else thr
            node_bytes = struct.pack("<BBHffII", 1 if is_leaf else 0, 0, feat, val_or_thresh, left, right)
            chunks.append(node_bytes)
            
    raw = b"".join(chunks)
    with open(out_path, "wb") as f:
        f.write(raw)
    print(f"  [+] Exported HDTR URL bundle: {out_path} ({len(raw):,} bytes, {n_trees} trees)", flush=True)

def export_onnx(clf, n_features: int, out_path: str):
    initial_type = [("float_input", FloatTensorType([None, n_features]))]
    onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"  [+] Exported ONNX model: {out_path}", flush=True)

# -------------------------------------------------------------
# Domain Trainers
# -------------------------------------------------------------
def train_domain(name: str, joblib_path: str, n_features: int, max_samples: int = 0,
                 n_estimators: int = 250, num_leaves: int = 63, max_depth: int = 8,
                 lr: float = 0.03):
    print("\n" + "=" * 65, flush=True)
    print(f" [*] TRAINING {name.upper()} MODEL ({os.path.basename(joblib_path)})", flush=True)
    print("=" * 65, flush=True)
    
    if not os.path.exists(joblib_path):
        raise FileNotFoundError(f"Missing joblib file: {joblib_path}")
        
    print(f"  [>] Loading dataset from: {joblib_path}...", flush=True)
    data = joblib.load(joblib_path)
    X = data["X"]
    y = data["y"]
    del data
    gc.collect()
    
    # Balance 50/50
    mal_idx = np.where(y == 1)[0]
    ben_idx = np.where(y == 0)[0]
    target_each = min(len(mal_idx), len(ben_idx))
    if max_samples > 0 and target_each > max_samples // 2:
        target_each = max_samples // 2
        
    np.random.seed(42)
    sel_mal = np.random.choice(mal_idx, target_each, replace=False)
    sel_ben = np.random.choice(ben_idx, target_each, replace=False)
    sel = np.concatenate([sel_mal, sel_ben])
    np.random.shuffle(sel)
    
    X = X[sel]
    y = y[sel]
    del mal_idx, ben_idx, sel_mal, sel_ben, sel
    gc.collect()
    
    print(f"  [+] Dataset Balanced: {len(X):,} samples ({target_each:,} Malicious, {target_each:,} Benign)", flush=True)
    print(f"  [+] Feature Dimension: {X.shape[1]} (Expected: {n_features})", flush=True)
    assert X.shape[1] == n_features, f"Feature dimension mismatch: {X.shape[1]} vs {n_features}"
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    
    clf = lgb.LGBMClassifier(
        n_estimators=n_estimators,
        learning_rate=lr,
        num_leaves=num_leaves,
        max_depth=max_depth,
        min_child_samples=25,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.0,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) * 100.0 if (tp + fn) > 0 else 0.0
    print(f"  [+] {name.upper()} Evaluation: Recall={recall:.2f}%, FPR={fpr:.2f}% (TP={tp}, FP={fp}, TN={tn}, FN={fn})", flush=True)
    
    # Sample 10k test predictions for meta-master model
    sample_n = min(10000, len(X_test))
    meta_sub_X = X_test[:sample_n]
    meta_sub_y = y_test[:sample_n]
    meta_probs = clf.predict_proba(meta_sub_X)[:, 1]
    
    del X, y, X_train, X_test, y_train, y_test, meta_sub_X
    gc.collect()
    
    return clf, meta_probs, meta_sub_y

def main():
    print("=" * 70, flush=True)
    print("  HydraDragon Antivirus - Universal 4-Domain + Master AI Pipeline  ", flush=True)
    print("=" * 70, flush=True)
    
    meta_records = {}
    
    # 1. PE Model (65 Features)
    pe_clf, pe_probs, pe_y = train_domain("pe", os.path.join(BASE_DIR, "pe_features_full.joblib"),
                                          n_features=65, n_estimators=300, num_leaves=127, max_depth=10)
    pe_onnx = os.path.join(BASE_DIR, "pe_model.onnx")
    pe_bin = os.path.join(BASE_DIR, "pe_trees.bin")
    export_onnx(pe_clf, 65, pe_onnx)
    export_standard_tree_bundle(pe_clf, pe_bin)
    meta_records["pe"] = (pe_probs, pe_y)
    
    # 2. JS Model (51 Features)
    js_clf, js_probs, js_y = train_domain("js", os.path.join(BASE_DIR, "js_features_39k.joblib"),
                                          n_features=51, n_estimators=250, num_leaves=63, max_depth=8)
    js_onnx = os.path.join(BASE_DIR, "js_model.onnx")
    js_bin = os.path.join(BASE_DIR, "js_trees.bin")
    export_onnx(js_clf, 51, js_onnx)
    export_standard_tree_bundle(js_clf, js_bin)
    meta_records["js"] = (js_probs, js_y)
    
    # 3. APK Model (24 Features)
    apk_clf, apk_probs, apk_y = train_domain("apk", os.path.join(BASE_DIR, "apk_features.joblib"),
                                             n_features=24, n_estimators=200, num_leaves=63, max_depth=8)
    apk_onnx = os.path.join(BASE_DIR, "apk_model.onnx")
    apk_bin = os.path.join(BASE_DIR, "apk_trees.bin")
    export_onnx(apk_clf, 24, apk_onnx)
    export_standard_tree_bundle(apk_clf, apk_bin)
    meta_records["apk"] = (apk_probs, apk_y)
    
    # 4. URL Model (32 Features) - 200k samples from 15.3M url_features_cache.joblib
    url_clf, url_probs, url_y = train_domain("url", os.path.join(BASE_DIR, "url_features_cache.joblib"),
                                             n_features=32, max_samples=200000, n_estimators=300, num_leaves=63, max_depth=8)
    url_onnx = os.path.join(BASE_DIR, "url_model.onnx")
    url_bin = os.path.join(BASE_DIR, "url_trees.bin")
    url_hdtr = os.path.join(BASE_DIR, "url_model.bin")
    export_onnx(url_clf, 32, url_onnx)
    export_standard_tree_bundle(url_clf, url_bin)
    export_hdtr_url_model(url_clf, 32, url_hdtr)
    meta_records["url"] = (url_probs, url_y)
    
    # 5. Sync to Distribution Folders
    print("\n" + "=" * 65, flush=True)
    print(" [*] SYNCHRONIZING BINARY TREES TO EDR & PORTABLE SCANNERS", flush=True)
    print("=" * 65, flush=True)
    
    for dest_dir in [PORTABLE_MODELS, OPENEDR_STATIC_MODELS]:
        if os.path.exists(dest_dir):
            shutil.copy2(pe_bin, os.path.join(dest_dir, "pe_trees.bin"))
            shutil.copy2(js_bin, os.path.join(dest_dir, "js_trees.bin"))
            shutil.copy2(apk_bin, os.path.join(dest_dir, "apk_trees.bin"))
            shutil.copy2(url_bin, os.path.join(dest_dir, "url_trees.bin"))
            print(f"  [+] Synced 4 trees to: {dest_dir}", flush=True)
            
    if os.path.exists(OWLYSHIELD_MODELS):
        shutil.copy2(url_hdtr, os.path.join(OWLYSHIELD_MODELS, "url_model.bin"))
        shutil.copy2(url_bin, os.path.join(OWLYSHIELD_MODELS, "url_trees.bin"))
        print(f"  [+] Synced url_model.bin & url_trees.bin to: {OWLYSHIELD_MODELS}", flush=True)

    owly_root = os.path.join(REPO_ROOT, "OpenEDR", "owlyshield_predict")
    if os.path.exists(owly_root):
        shutil.copy2(url_hdtr, os.path.join(owly_root, "url_model.bin"))
        print(f"  [+] Synced url_model.bin to: {owly_root}", flush=True)

    # 6. Train Unified Master Model (hydradragon_master.onnx)
    print("\n" + "=" * 65, flush=True)
    print(" [*] BUILDING UNIFIED MASTER MULTI-MODAL MODEL (hydradragon_master.onnx)", flush=True)
    print("=" * 65, flush=True)
    
    # Master vector: [is_pe, is_js, is_apk, is_url, pe_prob, js_prob, apk_prob, url_prob] (8 features)
    X_master = []
    y_master = []
    
    for p, y_val in zip(meta_records["pe"][0], meta_records["pe"][1]):
        X_master.append([1.0, 0.0, 0.0, 0.0, float(p), 0.0, 0.0, 0.0])
        y_master.append(y_val)
    for p, y_val in zip(meta_records["js"][0], meta_records["js"][1]):
        X_master.append([0.0, 1.0, 0.0, 0.0, 0.0, float(p), 0.0, 0.0])
        y_master.append(y_val)
    for p, y_val in zip(meta_records["apk"][0], meta_records["apk"][1]):
        X_master.append([0.0, 0.0, 1.0, 0.0, 0.0, 0.0, float(p), 0.0])
        y_master.append(y_val)
    for p, y_val in zip(meta_records["url"][0], meta_records["url"][1]):
        X_master.append([0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, float(p)])
        y_master.append(y_val)
        
    X_master = np.array(X_master, dtype=np.float32)
    y_master = np.array(y_master, dtype=np.int32)
    
    print(f"  [+] Master Meta-Ensemble Dataset: {len(X_master):,} samples (50/50 Balanced)", flush=True)
    
    X_m_tr, X_m_te, y_m_tr, y_m_te = train_test_split(X_master, y_master, test_size=0.15, random_state=42, stratify=y_master)
    master_clf = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.05, num_leaves=31, max_depth=6, random_state=42)
    master_clf.fit(X_m_tr, y_m_tr)
    
    y_m_pred = master_clf.predict(X_m_te)
    print("\n" + "=" * 30 + " MASTER MODEL EVALUATION " + "=" * 30, flush=True)
    print(classification_report(y_m_te, y_m_pred, target_names=["Benign", "Malicious"], digits=4), flush=True)
    
    master_onnx = os.path.join(BASE_DIR, "hydradragon_master.onnx")
    export_onnx(master_clf, 8, master_onnx)
    print(f"\n[+] SUCCESS: hydradragon_master.onnx and all 4 domain models are fully built and synchronized!", flush=True)

if __name__ == "__main__":
    main()
