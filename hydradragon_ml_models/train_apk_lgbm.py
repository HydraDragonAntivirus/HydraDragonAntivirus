#!/usr/bin/env python3
"""
HydraDragon ML Model Trainer - Android APK Edition (62-Dimensional)

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
  - 58..61: URL ML (whitelist-gated url_trees.bin scores of the DEX / ELF / manifest URLs)

Exports:
  1. `apk_model.onnx` (Standard ONNX format)
  2. `apk_trees.bin` (25-byte binary forest bundle for Rust openedr_static)
"""

import argparse
import csv
import itertools
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

    # 52..54: String ML & Threat density metrics (no ben_str_hits / mal_ben_str_ratio /
    # unknown_str_ratio: the benign string filter is built from the training corpus, so
    # they measured "seen in training")
    "mal_str_hits",
    "mal_str_density",
    "total_unique_strings_log",

    # 55..58: URL ML (url_ml_metrics.rs)
    "url_unwhitelisted_count_log",
    "url_ml_max_prob",
    "url_ml_mean_prob",
    "url_ml_high_count_log",
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
        header = (next(reader, None) or [])[2:]
        missing = [n for n in APK_FEATURE_NAMES if n not in header]
        if missing:
            sys.exit(f"CSV lacks {missing} (apk.rs changed? re-extract)")
        # Columns by name, not position: an older CSV still holding retired features
        # (ben_str_hits, mal_ben_str_ratio, unknown_str_ratio) trains on the right columns.
        cols = [2 + header.index(n) for n in APK_FEATURE_NAMES]
        expected_len = 1 + max(cols)
        for row in reader:
            if not row or len(row) < expected_len:
                continue
            lbl = int(row[0])
            feats = [float(row[i]) for i in cols]
            if lbl == 1:
                mal.append(feats)
            else:
                ben.append(feats)

    mal = np.unique(np.array(mal, dtype=np.float32), axis=0) if mal else np.empty((0, len(APK_FEATURE_NAMES)),
                                                                                  dtype=np.float32)
    ben = np.unique(np.array(ben, dtype=np.float32), axis=0) if ben else np.empty((0, len(APK_FEATURE_NAMES)),
                                                                                  dtype=np.float32)

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
    print(f"[+] Dataset: {len(X)} samples ({len(mal)} malicious, {len(ben)} benign, ratio "
          f"1:{len(ben) / max(len(mal), 1):.2f})")
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


# Base LightGBM parameters; --auto-tune searches num_leaves / min_child_samples around them.
BASE_PARAMS = dict(
    learning_rate=0.03,
    num_leaves=63,
    max_depth=8,
    min_child_samples=25,
    subsample=0.85,
    subsample_freq=1,
    colsample_bytree=0.85,
    scale_pos_weight=1.0,
    random_state=42,
    n_jobs=-1,
    verbose=-1,
)
TUNE_GRID = {"num_leaves": (31, 63, 127), "min_child_samples": (10, 25, 50)}
MAX_TREES = 2000
EARLY_STOP_ROUNDS = 100


def fit_early_stopped(params, X_train, y_train, X_val, y_val):
    """Fit with up to MAX_TREES trees, stopping when validation logloss has not improved for
    EARLY_STOP_ROUNDS rounds. Returns (classifier, best tree count)."""
    clf = lgb.LGBMClassifier(n_estimators=MAX_TREES, **params)
    stop = [lgb.early_stopping(EARLY_STOP_ROUNDS, verbose=False)]
    try:  # LightGBM >= 4.7 deprecates eval_set in favour of eval_X / eval_y
        clf.fit(X_train, y_train, eval_X=(X_val,), eval_y=(y_val,), eval_metric="binary_logloss", callbacks=stop)
    except TypeError:
        clf.fit(X_train, y_train, eval_set=[(X_val, y_val)], eval_metric="binary_logloss", callbacks=stop)
    return clf, max(int(clf.best_iteration_ or MAX_TREES), 1)


def calibrate_threshold(prob_benign, target_fpr):
    """Lowest threshold at which at most `target_fpr` of these benign scores are flagged."""
    s = np.sort(prob_benign)
    if not len(s):
        return ENGINE_THRESHOLD
    k = int(np.ceil(len(s) * (1.0 - target_fpr)))
    thr = float(s[min(k, len(s) - 1)]) + 1e-6
    return min(max(thr, 0.5), 0.9999)


def report(name, y, prob, thr):
    tn, fp, fn, tp = confusion_matrix(y, (prob >= thr).astype(int), labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) else 0.0
    rec = tp / (tp + fn) * 100.0 if (tp + fn) else 0.0
    print(f"  {name:<32} thr={thr:.4f}  Recall={rec:6.2f}%  FPR={fpr:7.4f}%  (TP={tp} FN={fn} TN={tn} FP={fp})")
    return rec, fpr


def select_model(args, X_train, y_train, X_val, y_val):
    """Parameters and tree count picked on the validation set. Without --auto-tune only the
    tree count (early stopping) is chosen; with it every TUNE_GRID combination is tried and
    the one with the best validation recall at the target FPR wins (lower logloss breaks ties)."""
    combos = [dict()]
    if args.auto_tune:
        keys = list(TUNE_GRID)
        combos = [dict(zip(keys, v)) for v in itertools.product(*(TUNE_GRID[k] for k in keys))]
        print(f"[*] --auto-tune: {len(combos)} parameter sets, target FPR {args.target_fpr * 100:.3f}%")
    best = None
    for c in combos:
        params = {**BASE_PARAMS, **c}
        clf, trees = fit_early_stopped(params, X_train, y_train, X_val, y_val)
        p_val = clf.predict_proba(X_val, num_iteration=trees)[:, 1]
        thr = calibrate_threshold(p_val[y_val == 0], args.target_fpr)
        rec = float(np.mean(p_val[y_val == 1] >= thr)) * 100.0 if np.any(y_val == 1) else 0.0
        eps = 1e-7
        loss = float(-np.mean(y_val * np.log(p_val + eps) + (1 - y_val) * np.log(1 - p_val + eps)))
        print(f"  num_leaves={params['num_leaves']:<4} min_child_samples={params['min_child_samples']:<3} "
              f"trees={trees:<5} val recall@thr={rec:6.2f}% (thr {thr:.4f})  val logloss={loss:.4f}")
        key = (rec, -loss)
        if best is None or key > best[0]:
            best = (key, params, trees)
    return best[1], best[2]


def parse_args():
    parser = argparse.ArgumentParser(description=f"Train LightGBM APK {len(APK_FEATURE_NAMES)}-D Model and Export to "
                                                 "ONNX + apk_trees.bin")
    dataset_paths.add_args(parser, "android")
    parser.add_argument("--features-csv", type=str, default="apk_features.csv",
                        help="Output/Input CSV for APK features")
    parser.add_argument("--reuse-csv", action="store_true",
                        help="Retrain from existing features CSV (extracts when it is missing)")
    parser.add_argument("--train-only", action="store_true", help="Train from the existing features CSV; never extract")
    parser.add_argument("--extract-only", action="store_true", help="Only write the features CSV; do not train")
    parser.add_argument("--auto-tune", action="store_true",
                        help="Try num_leaves x min_child_samples and keep the best on the validation set")
    parser.add_argument("--target-fpr", type=float, default=0.001,
                        help="Calibrate the threshold so at most this share of validation benign is flagged (0.001 = "
                             "0.1%%)")
    parser.add_argument("--output-onnx", type=str, default="apk_model.onnx", help="Output ONNX model path")
    parser.add_argument("--output-bin", type=str, default="apk_trees.bin", help="Output 25-byte tree bundle path")
    parser.add_argument("--max-samples-per-class", type=int, default=0,
                        help="Max samples to scan from each class (0 = unlimited)")
    parser.add_argument("--balance", action="store_true", help="Undersample both classes to 50/50")
    parser.add_argument("--no-sync", action="store_true", help="Do not copy apk_trees.bin to engine model directories")
    return parser.parse_args()


def main():
    args = parse_args()
    print("=" * 70)
    print(f" HydraDragon Antivirus - {len(APK_FEATURE_NAMES)}-Dimensional APK LightGBM Trainer ")
    print(" (Zero-Drift Rust ripzip Extractor Parity) ")
    print("=" * 70)

    if args.extract_only and args.train_only:
        sys.exit("--extract-only and --train-only exclude each other")
    if args.train_only:
        if not os.path.isfile(args.features_csv):
            sys.exit(f"--train-only: {args.features_csv} does not exist (run --extract-only first)")
    elif args.extract_only or not (args.reuse_csv and os.path.isfile(args.features_csv)):
        dump_features(args)
    if args.extract_only:
        print(f"[+] Features written to {args.features_csv}. Exiting as --extract-only was specified.")
        return

    X, y = load_features(args.features_csv, args.max_samples_per_class, balance=args.balance)
    # 70 % train, 15 % validation (tree count, parameters, threshold), 15 % test (final numbers).
    X_train, X_rest, y_train, y_rest = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_rest, y_rest, test_size=0.50, random_state=42, stratify=y_rest)
    print(f"[*] Train: {len(X_train)} | Validation: {len(X_val)} | Test: {len(X_test)}")

    print("[*] Selecting tree count" + (" and parameters" if args.auto_tune else "") + " on the validation set...")
    params, trees = select_model(args, X_train, y_train, X_val, y_val)
    print(f"[+] Selected: num_leaves={params['num_leaves']} min_child_samples={params['min_child_samples']} "
          f"trees={trees}")

    # Refit with exactly the selected tree count, so the ONNX and .bin exports hold no extra trees.
    clf = lgb.LGBMClassifier(n_estimators=trees, **params)
    clf.fit(X_train, y_train)

    thr = calibrate_threshold(clf.predict_proba(X_val[y_val == 0])[:, 1], args.target_fpr)
    p = clf.predict_proba(X_test)[:, 1]
    print("\n" + "=" * 30 + " EVALUATION REPORT (test set) " + "=" * 30)
    print(classification_report(y_test, (p >= 0.5).astype(int), target_names=["Benign", "Malicious"], digits=4))
    report("default 0.50", y_test, p, 0.50)
    report(f"engine APK_TREE_THRESHOLD {ENGINE_THRESHOLD}", y_test, p, ENGINE_THRESHOLD)
    report(f"calibrated (target FPR {args.target_fpr * 100:.3f}%)", y_test, p, thr)
    print(f"\n[!] Set the APK threshold to {thr:.4f} for this model "
          f"(APK_TREE_THRESHOLD env var or dashboard: ML thresholds).")
    if args.output_bin:
        thr_path = os.path.splitext(args.output_bin)[0] + "_threshold.json"
        with open(thr_path, "w") as f:
            json.dump({"apk_tree_threshold": round(thr, 4), "target_fpr": args.target_fpr,
                       "trees": trees, "num_leaves": params["num_leaves"],
                       "min_child_samples": params["min_child_samples"]}, f)
        print(f"[+] Wrote {thr_path}")
    print("=" * 89)

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
