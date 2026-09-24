#!/usr/bin/env python3
"""
HydraDragon ML Model Trainer - Android APK Edition
Extracts the exact 24-dimensional DEX and AndroidManifest.xml features,
matching OpenEDR/openedr_web/src/apk.rs and tools/apk_train.py.
Extracts out-of-core chunks to disk to eliminate memory pressure (< 1.5 GB RAM).
Enforces exact 50% Benign / 50% Malicious class balance.
Exports both:
  1. `apk_model.onnx` (Standard ONNX format)
  2. `apk_trees.bin` (25-byte binary forest bundle for Rust openedr_web)
"""

import os
import sys
import math
import struct
import argparse
import glob
import gc
from typing import List, Optional
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

# Import feature extractor from OpenEDR/openedr_web/tools/apk_train.py
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "OpenEDR", "openedr_web", "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

try:
    from apk_train import apk_features, FEATURE_NAMES, Tree, convert_lightgbm
except ImportError:
    # Fallback to local import if tools not in expected path
    sys.path.append(os.path.join(os.getcwd(), "OpenEDR", "openedr_web", "tools"))
    from apk_train import apk_features, FEATURE_NAMES, Tree, convert_lightgbm

def find_apk_files(dir_path: str, max_files: int = 50000):
    files = []
    if not os.path.exists(dir_path):
        return files
    for root, _, filenames in os.walk(dir_path):
        for f in filenames:
            if f.lower().endswith((".apk", ".zip")):
                files.append(os.path.join(root, f))
                if len(files) >= max_files:
                    return files
    return files

def extract_single_apk(filepath: str) -> Optional[List[float]]:
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        return apk_features(data)
    except Exception:
        return None

def extract_apk_chunks_to_disk(file_list: List[str], label_name: str, label_val: int, chunk_dir: str, chunk_size: int = 1000, workers: int = 3):
    from concurrent.futures import ProcessPoolExecutor
    os.makedirs(chunk_dir, exist_ok=True)
    total_files = len(file_list)
    print(f"[*] Extracting {label_name} APKs ({total_files} files) into chunks of {chunk_size} to {chunk_dir} with {workers} workers...")
    
    chunk_idx = 0
    total_valid = 0
    
    for i in range(0, total_files, chunk_size):
        chunk_files = file_list[i : i + chunk_size]
        chunk_path = os.path.join(chunk_dir, f"chunk_apk_{label_name.lower()}_{chunk_idx:04d}.joblib")
        
        if os.path.exists(chunk_path):
            print(f"  [>] Chunk {chunk_idx:04d} already exists on disk, skipping.")
            chunk_idx += 1
            continue
            
        feats = []
        with ProcessPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(extract_single_apk, chunk_files, chunksize=50))
            for res in results:
                if res is not None:
                    feats.append(res)
                
        if feats:
            X_chunk = np.array(feats, dtype=np.float32)
            y_chunk = np.full(len(feats), label_val, dtype=np.int32)
            joblib.dump({"X": X_chunk, "y": y_chunk}, chunk_path, compress=3)
            total_valid += len(feats)
            print(f"  [+] Saved {chunk_path}: {len(feats)} valid APKs (Processed {min(i + chunk_size, total_files)}/{total_files})")
        else:
            print(f"  [-] Chunk {chunk_idx:04d} had 0 valid APKs.")
            
        del feats
        gc.collect()
        chunk_idx += 1
        
    print(f"[+] Total {label_name} APK samples extracted: {total_valid}")
    return total_valid

def load_apk_chunks_balanced(chunk_dir: str):
    chunk_files = glob.glob(os.path.join(chunk_dir, "chunk_apk_*.joblib"))
    if not chunk_files:
        raise RuntimeError(f"No APK chunk files found in {chunk_dir}")
        
    print(f"[*] Found {len(chunk_files)} chunk files in {chunk_dir}. Loading and balancing 50/50...")
    X_mal_list, X_ben_list = [], []
    
    for cf in chunk_files:
        data = joblib.load(cf)
        X_sub = data["X"]
        y_sub = data["y"]
        if y_sub[0] == 1:
            X_mal_list.append(X_sub)
        else:
            X_ben_list.append(X_sub)
            
    if not X_mal_list or not X_ben_list:
        raise RuntimeError(f"Need both Malicious and Benign chunks in {chunk_dir} to train!")
        
    X_mal = np.vstack(X_mal_list)
    X_ben = np.vstack(X_ben_list)
    
    n_mal = len(X_mal)
    n_ben = len(X_ben)
    target_each = min(n_mal, n_ben)
    print(f"[*] Raw APK counts: {n_mal} Malicious, {n_ben} Benign -> Balancing to {target_each} each (50/50)")
    
    np.random.seed(42)
    idx_mal = np.random.choice(n_mal, target_each, replace=False)
    idx_ben = np.random.choice(n_ben, target_each, replace=False)
    
    X = np.vstack([X_mal[idx_mal], X_ben[idx_ben]])
    y = np.array([1] * target_each + [0] * target_each, dtype=np.int32)
    
    joblib_out = os.path.join(os.path.dirname(__file__), "apk_features.joblib")
    joblib.dump({"X": X, "y": y}, joblib_out, compress=3)
    print(f"[+] Saved complete balanced APK dataset to: {joblib_out}")
    
    del X_mal, X_ben, X_mal_list, X_ben_list
    gc.collect()
    
    print(f"[+] Loaded perfectly balanced APK dataset: {len(X)} samples ({target_each} Malicious, {target_each} Benign)")
    return X, y

def parse_args():
    parser = argparse.ArgumentParser(description="Train LightGBM APK Model and Export to ONNX + Bin")
    parser.add_argument("--malicious", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\malware", help="Directory of malware APKs")
    parser.add_argument("--benign", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign", help="Directory of benign APKs")
    parser.add_argument("--output-onnx", type=str, default="apk_model.onnx", help="Output ONNX model path")
    parser.add_argument("--output-bin", type=str, default="apk_trees.bin", help="Output 25-byte tree bundle path")
    parser.add_argument("--max-samples-per-class", type=int, default=30000, help="Max samples to scan from each class")
    parser.add_argument("--chunk-dir", type=str, default="cache_chunks_apk", help="Directory to store APK feature chunks")
    parser.add_argument("--chunk-size", type=int, default=1000, help="Number of APK files per disk chunk")
    parser.add_argument("--extract-only", action="store_true", help="Only extract chunks to disk, do not train")
    parser.add_argument("--train-only", action="store_true", help="Only train from existing chunk directory")
    return parser.parse_args()

def main():
    args = parse_args()
    print("=" * 65)
    print(" HydraDragon Antivirus - High Precision APK LightGBM Trainer ")
    print(" (Out-of-Core Low RAM Chunked Engine) ")
    print("=" * 65)

    if not args.train_only:
        print("[*] Discovering APK files...")
        mal_files = find_apk_files(args.malicious, args.max_samples_per_class)
        ben_files = find_apk_files(args.benign, args.max_samples_per_class)
        print(f"[+] Discovered {len(mal_files)} malicious APKs and {len(ben_files)} benign APKs.")

        extract_apk_chunks_to_disk(mal_files, "MALICIOUS", 1, args.chunk_dir, args.chunk_size)
        extract_apk_chunks_to_disk(ben_files, "BENIGN", 0, args.chunk_dir, args.chunk_size)

    if args.extract_only:
        print("[+] APK feature extraction complete. Exiting as --extract-only was specified.")
        return

    X, y = load_apk_chunks_balanced(args.chunk_dir)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train)} | Test set: {len(X_test)}")

    print("[*] Training LightGBM Classifier (50/50 Balanced)...")
    clf = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.03,
        num_leaves=63,
        max_depth=8,
        min_child_samples=25,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.0,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"], digits=4))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) * 100.0 if (tp + fn) > 0 else 0.0
    print(f"Confusion Matrix: TP={tp}, FN={fn}, TN={tn}, FP={fp}")
    print(f"APK Malware Recall (Detection Rate): {recall:.2f}%")
    print(f"False Positive Rate (FPR):          {fpr:.2f}%")
    print("=" * 79)

    print(f"[*] Converting LightGBM APK model to ONNX: {args.output_onnx}...")
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))]
    onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
    with open(args.output_onnx, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"[+] APK ONNX model successfully saved to {args.output_onnx}!")

    if args.output_bin:
        print(f"[*] Exporting 25-byte tree bundle: {args.output_bin}...")
        dump = clf.booster_.dump_model()
        trees = convert_lightgbm(dump)
        raw_bundle = struct.pack("<I", len(trees)) + b"".join(t.emit() for t in trees)
        with open(args.output_bin, "wb") as f:
            f.write(raw_bundle)
        print(f"[+] APK 25-byte tree bundle saved to {args.output_bin} ({len(raw_bundle)} bytes)!")

if __name__ == "__main__":
    main()
