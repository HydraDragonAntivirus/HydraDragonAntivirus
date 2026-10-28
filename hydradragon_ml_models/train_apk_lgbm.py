#!/usr/bin/env python3
"""
HydraDragon ML Model Trainer - Android APK Edition (58-Dimensional)

Features come directly from the engine itself: apk_feature_dump (Rust) includes
OpenEDR/openedr_static/src/apk.rs by path, so training and scanning use the
exact same extractor (SIMD-accelerated via `ripzip`, no single-threaded flate2/miniz_oxide).
There is zero Python re-implementation drift.

Features:
  - 0..23: Frozen original DEX and Manifest baseline (backward-compatible)
  - 24..30: Native ELF architectures (.so) and imported/exported symbols
  - 31..37: Manifest high-risk capability permissions
  - 38..46: Dalvik sensitive API calls (reflection, crypto, exec, sms, device ID)
  - 47..51: Packaging, assets, protector anomalies
  - 52..57: XOR-filter String ML threat density & hit metrics

Exports:
  1. `apk_model.onnx` (Standard ONNX format)
  2. `apk_trees.bin` (25-byte binary forest bundle for Rust openedr_static)
"""

import argparse
import csv
import gc
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import List, Optional

import lightgbm as lgb
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

try:
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False

import dataset_paths

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DUMP_CRATE = os.path.join(BASE_DIR, "apk_feature_dump")
APK_DUMP_EXE = os.path.join(DUMP_CRATE, "target", "release", "apk_feature_dump.exe")
ENGINE_THRESHOLD = 0.85

APK_FEATURE_NAMES = [
    # 0..23: Frozen original DEX and Manifest baseline
    "dex_classes",
    "dex_strings",
    "dex_methods",
    "dex_files",
    "elf_so_count",
    "perm_total",
    "activities",
    "services",
    "receivers",
    "min_sdk",
    "target_sdk",
    "entropy",
    "entry_count",
    "file_size_log",
    "manifest_size_log",
    "dex_size_log",
    "so_size_log",
    "dangerous_perm_count",
    "sms_trio",
    "has_manifest",
    "multidex",
    "compression_ratio",
    "avg_entry_size_log",
    "native_with_perms",

    # 24..30: Native .so detailed architecture & symbols
    "has_arm64",
    "has_arm32",
    "has_x86",
    "has_x86_64",
    "so_exported_jni_count",
    "so_imported_symbols_count",
    "so_suspicious_imports_count",

    # 31..37: Manifest high-risk capability flags
    "perm_boot_completed",
    "perm_accessibility_service",
    "perm_device_admin",
    "perm_system_alert_window",
    "perm_install_packages",
    "perm_read_phone_state",
    "perm_external_storage_write",

    # 38..46: Dalvik sensitive API invocation signals
    "api_reflection_calls",
    "api_dynamic_dex_loading",
    "api_crypto_cipher_calls",
    "api_process_exec_calls",
    "api_sms_send_calls",
    "api_device_id_calls",
    "api_network_http_calls",
    "api_package_manager_queries",
    "api_anti_debug_root_calls",

    # 47..51: Packaging, assets, protector anomalies
    "assets_entry_count",
    "assets_size_log",
    "has_hidden_payload_in_assets",
    "is_protector_packed",
    "has_non_standard_dex",

    # 52..57: String ML & Threat density metrics
    "mal_str_hits",
    "ben_str_hits",
    "mal_ben_str_ratio",
    "mal_str_density",
    "unknown_str_ratio",
    "total_unique_strings_log",
]


def ensure_dump_binary():
    if os.path.isfile(APK_DUMP_EXE):
        return APK_DUMP_EXE
    print("[*] Compiling apk_feature_dump (release mode)...")
    res = subprocess.run(["cargo", "build", "--release", "--manifest-path",
                          os.path.join(DUMP_CRATE, "Cargo.toml")])
    if res.returncode != 0 or not os.path.isfile(APK_DUMP_EXE):
        print(f"[-] Failed to compile {APK_DUMP_EXE}", file=sys.stderr)
        sys.exit(1)
    return APK_DUMP_EXE


def dump_features(args):
    exe = ensure_dump_binary()
    print("[*] Collecting APK files...")
    mal_files, ben_files = dataset_paths.collect(
        args, "android", max_per_class=args.max_samples_per_class)
    print(f"[+] Found {len(mal_files)} malicious APKs and {len(ben_files)} benign APKs")

    with tempfile.TemporaryDirectory() as tmpdir:
        mal_lst = os.path.join(tmpdir, "mal.lst")
        ben_lst = os.path.join(tmpdir, "ben.lst")
        with open(mal_lst, "w", encoding="utf-8") as fh:
            fh.write("\n".join(mal_files))
        with open(ben_lst, "w", encoding="utf-8") as fh:
            fh.write("\n".join(ben_files))
        cmd = [exe, "@" + mal_lst, "@" + ben_lst, args.features_csv]
        if args.max_samples_per_class > 0:
            cmd.append(str(args.max_samples_per_class))
        print(f"[*] Running: {' '.join(cmd)}")
        res = subprocess.run(cmd)
        if res.returncode != 0:
            sys.exit(res.returncode)


def load_features(csv_path: str, max_per_class: int = 0, balance: bool = False):
    print(f"[*] Loading APK features from: {csv_path}")
    mal, ben = [], []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        expected_len = 2 + len(APK_FEATURE_NAMES)
        for row in reader:
            if not row or len(row) < expected_len:
                continue
            lbl = int(row[0])
            feats = [float(x) for x in row[2:expected_len]]
            if lbl == 1:
                mal.append(feats)
            else:
                ben.append(feats)

    mal = np.unique(np.array(mal, dtype=np.float32), axis=0) if mal else np.empty((0, len(APK_FEATURE_NAMES)), dtype=np.float32)
    ben = np.unique(np.array(ben, dtype=np.float32), axis=0) if ben else np.empty((0, len(APK_FEATURE_NAMES)), dtype=np.float32)

    # Dedup identical vectors labelled differently
    both = {r.tobytes() for r in ben} & {r.tobytes() for r in mal}
    if both:
        mal = np.array([r for r in mal if r.tobytes() not in both], dtype=np.float32)
        ben = np.array([r for r in ben if r.tobytes() not in both], dtype=np.float32)
    print(f"[*] After dedup: {len(mal)} malicious, {len(ben)} benign ({len(both)} conflicting rows dropped)")

    if balance:
        rng = np.random.default_rng(42)
        n = min(len(mal), len(ben))
        if max_per_class > 0:
            n = min(n, max_per_class)
        mal = mal[rng.choice(len(mal), n, replace=False)]
        ben = ben[rng.choice(len(ben), n, replace=False)]
        print(f"[*] --balance: undersampled to {n} each (50/50)")

    X = np.vstack([mal, ben])
    y = np.array([1] * len(mal) + [0] * len(ben), dtype=np.int32)
    print(f"[+] Dataset: {len(X)} samples ({len(mal)} malicious, {len(ben)} benign, ratio 1:{len(ben) / max(len(mal), 1):.2f})")
    return X, y


def export_bin(clf, out_path):
    """LightGBM -> 25-byte tree bundle read by OpenEDR/openedr_static/src/ml/tree_model.rs (<IIfIIBf nodes)."""
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


def sync_bundle(bundle_path):
    targets = [
        os.path.join(REPO_ROOT, "OpenEDR", "openedr_static", "models", "apk_trees.bin"),
        os.path.join(REPO_ROOT, "OpenMalwareScannerPortable", "models", "apk_trees.bin"),
    ]
    for dst in targets:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(bundle_path, dst)
        print(f"[+] Synced {bundle_path} -> {dst}")


def parse_args():
    parser = argparse.ArgumentParser(description="Train LightGBM APK 58-D Model and Export to ONNX + apk_trees.bin")
    dataset_paths.add_args(parser, "android")
    parser.add_argument("--features-csv", type=str, default="apk_features.csv", help="Output/Input CSV for APK features")
    parser.add_argument("--reuse-csv", action="store_true", help="Retrain from existing features CSV")
    parser.add_argument("--output-onnx", type=str, default="apk_model.onnx", help="Output ONNX model path")
    parser.add_argument("--output-bin", type=str, default="apk_trees.bin", help="Output 25-byte tree bundle path")
    parser.add_argument("--max-samples-per-class", type=int, default=0, help="Max samples to scan from each class (0 = unlimited)")
    parser.add_argument("--balance", action="store_true", help="Undersample both classes to 50/50")
    parser.add_argument("--no-sync", action="store_true", help="Do not copy apk_trees.bin to engine model directories")
    return parser.parse_args()


def main():
    args = parse_args()
    print("=" * 70)
    print(" HydraDragon Antivirus - 58-Dimensional APK LightGBM Trainer ")
    print(" (Zero-Drift Rust ripzip Extractor Parity) ")
    print("=" * 70)

    if not (args.reuse_csv and os.path.isfile(args.features_csv)):
        dump_features(args)

    X, y = load_features(args.features_csv, args.max_samples_per_class, balance=args.balance)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train)} | Test set: {len(X_test)}")

    print("[*] Training LightGBM Classifier...")
    clf = lgb.LGBMClassifier(
        n_estimators=350,
        learning_rate=0.03,
        num_leaves=63,
        max_depth=8,
        min_child_samples=25,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.0,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    clf.fit(X_train, y_train)

    p = clf.predict_proba(X_test)[:, 1]
    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, (p >= 0.5).astype(int), target_names=["Benign", "Malicious"], digits=4))
    cm = confusion_matrix(y_test, (p >= ENGINE_THRESHOLD).astype(int), labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) * 100.0 if (tp + fn) > 0 else 0.0
    print(f"[+] At engine threshold {ENGINE_THRESHOLD}: TP={tp}, FN={fn}, TN={tn}, FP={fp}")
    print(f"APK Malware Recall: {recall:.2f}% | FPR: {fpr:.3f}%")
    print("=" * 79)

    if HAS_ONNX and args.output_onnx:
        try:
            print(f"[*] Converting LightGBM APK model to ONNX: {args.output_onnx}...")
            initial_type = [("float_input", FloatTensorType([None, len(APK_FEATURE_NAMES)]))]
            onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
            with open(args.output_onnx, "wb") as f:
                f.write(onnx_model.SerializeToString())
            print(f"[+] APK ONNX model saved to {args.output_onnx}")
        except Exception as e:
            print(f"[!] ONNX export warning: {e}")

    if args.output_bin:
        export_bin(clf, args.output_bin)
        if not args.no_sync:
            sync_bundle(args.output_bin)


if __name__ == "__main__":
    main()
