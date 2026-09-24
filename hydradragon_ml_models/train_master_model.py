#!/usr/bin/env python3
"""
HydraDragon Master Unified Multi-Modal AI Engine
Trains the SINGLE unified master model: `hydradragon_master.onnx`

Architecture:
  1. Universal String & Byte Core (24 features):
     - Aho-Corasick ClamAV (.ndb/.ldb) & yarGen Goodware match counts
     - Malicious/Benign hit ratios & densities
     - Byte and String Shannon Entropies
     - Base64, Hex runs, URLs, IPs, Suspicious commands
  2. Multi-Modal Specialist Heads (8 features):
     - is_pe, is_js, is_apk, is_url (4 indicator flags)
     - expert_score_pe, expert_score_js, expert_score_apk, expert_score_url (4 head scores)

Guarantees:
  - Low-RAM: Out-of-core chunked feature extraction to disk (RAM < 1.5 GB)
  - Asymmetry inside Symmetry: Exact 50/50 balance across EVERY sub-domain
  - Single Output Model: `hydradragon_master.onnx` detects ANY file, text, script, or binary!
"""

import os
import sys
import math
import glob
import gc
import random
import argparse
from typing import List, Tuple, Optional, Dict

import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

# Add current dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from string_matcher import UniversalStringMatcher, STRING_FEATURE_NAMES
from train_url_lgbm import extract_url_features

# Master 32 Feature Names
MASTER_FEATURE_NAMES = STRING_FEATURE_NAMES + [
    "is_pe", "is_js", "is_apk", "is_url",
    "expert_score_pe", "expert_score_js", "expert_score_apk", "expert_score_url"
]
assert len(MASTER_FEATURE_NAMES) == 32

def extract_master_features_from_data(data: bytes, entity_type: str = "generic") -> List[float]:
    """
    Extracts the full 32-dimensional master feature vector from raw bytes.
    entity_type can be: 'pe', 'js', 'apk', 'url', 'generic' (text, shellcode, unknown binary)
    """
    matcher = UniversalStringMatcher.get_instance()
    # 1. First 24 Universal String & Byte Features
    str_feats = matcher.extract_features(data)

    # 2. Next 8 Multi-Modal Specialist Features
    is_pe = 1.0 if entity_type == "pe" or (entity_type == "generic" and data.startswith(b"MZ")) else 0.0
    is_js = 1.0 if entity_type == "js" else 0.0
    is_apk = 1.0 if entity_type == "apk" or (entity_type == "generic" and data.startswith(b"PK\x03\x04") and b"AndroidManifest.xml" in data[:4096]) else 0.0
    is_url = 1.0 if entity_type == "url" else 0.0

    score_pe = 0.0
    score_js = 0.0
    score_apk = 0.0
    score_url = 0.0

    # Quick heuristics for head score when standalone
    if is_pe:
        # Heuristic based on entropy, size, and header
        score_pe = 1.0 if (str_feats[3] > 6.8 or str_feats[10] > 1.5) else 0.0
    elif is_js:
        score_js = 1.0 if (str_feats[19] > 1.0 or str_feats[14] > 2.0) else 0.0
    elif is_apk:
        score_apk = 1.0 if str_feats[10] > 1.0 else 0.0

    ext_feats = [is_pe, is_js, is_apk, is_url, score_pe, score_js, score_apk, score_url]
    return str_feats + ext_feats

def extract_master_features_from_file(file_path: str, entity_type: str = "generic") -> Optional[List[float]]:
    try:
        with open(file_path, "rb") as f:
            data = f.read(10 * 1024 * 1024) # Cap at 10 MB per file
        return extract_master_features_from_data(data, entity_type)
    except Exception:
        return None

def _worker_extract_file(item: Tuple[str, str]) -> Optional[List[float]]:
    fp, entity_type = item
    return extract_master_features_from_file(fp, entity_type)

def extract_domain_dataset(file_list: List[str], entity_type: str, label_name: str, label_val: int,
                           cache_dir: str, workers: int = None):
    from concurrent.futures import ProcessPoolExecutor, as_completed
    workers = workers or min(os.cpu_count() or 4, 8)
    os.makedirs(cache_dir, exist_ok=True)

    cache_file = os.path.join(cache_dir, f"features_{entity_type}_{label_name.lower()}.joblib")
    if os.path.exists(cache_file):
        print(f"  [>] Cache already exists for [{entity_type.upper()}-{label_name}]: {cache_file} (skipping extraction)", flush=True)
        return

    total_files = len(file_list)
    print(f"\n{'='*65}", flush=True)
    print(f"[*] Extracting [{entity_type.upper()}] {label_name} ({total_files:,} files) with {workers} parallel workers...", flush=True)
    print(f"    Output Cache File: {cache_file}", flush=True)
    print(f"{'='*65}", flush=True)

    feats = []
    batch_args = [(fp, entity_type) for fp in file_list]
    done_count = 0

    # Stream tasks efficiently using executor.map with chunksize
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for res in executor.map(_worker_extract_file, batch_args, chunksize=100):
            done_count += 1
            if res is not None:
                feats.append(res)
            if done_count % 1000 == 0 or done_count == total_files:
                pct = (done_count / total_files) * 100.0
                print(f"  -> Progress [{entity_type.upper()}-{label_name}]: {done_count:,}/{total_files:,} ({pct:.1f}%) | Valid Extracted: {len(feats):,}", flush=True)

    if feats:
        X_data = np.array(feats, dtype=np.float32)
        y_data = np.full(len(feats), label_val, dtype=np.int32)
        joblib.dump({"X": X_data, "y": y_data, "type": entity_type}, cache_file, compress=3)
        file_size_mb = os.path.getsize(cache_file) / (1024 * 1024)
        print(f"[+] Saved {cache_file}: {len(feats):,} valid samples ({file_size_mb:.2f} MB)", flush=True)
    else:
        print(f"[!] Warning: 0 valid samples extracted for [{entity_type.upper()}-{label_name}]", flush=True)

    del feats
    gc.collect()

def extract_website_url_dataset(website_dir: str, cache_dir: str, max_samples: int = 100000):
    cache_ben = os.path.join(cache_dir, "features_url_benign.joblib")
    cache_mal = os.path.join(cache_dir, "features_url_malicious.joblib")
    if os.path.exists(cache_ben) and os.path.exists(cache_mal):
        print(f"  [>] Cache already exists for URL/Domain dataset (skipping extraction)", flush=True)
        return

    print(f"\n{'='*65}", flush=True)
    print(f"[*] Processing phishingormalware.py Domains, URLs & IPs...", flush=True)
    print(f"{'='*65}", flush=True)

    if not os.path.exists(website_dir):
        print(f"[!] Warning: website_dir not found at {website_dir}", flush=True)
        return

    # 1. Load Whitelist Pool (Strict reference for collision dropping)
    wl_files = [
        "WhiteListDomains.csv", "WhiteListSubDomains.csv",
        "DomainsPopularityWhiteList.csv", "SubDomainsPopularityWhiteList.csv",
        "WhiteListIPv4.csv", "WhiteListIPv6.csv"
    ]
    whitelist_set = set()
    whitelist_list = []
    for wf in wl_files:
        p = os.path.join(website_dir, wf)
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i == 0:
                        continue
                    item = line.split(",")[0].strip().lower()
                    if len(item) >= 4 and not item.startswith("#"):
                        if item not in whitelist_set:
                            whitelist_set.add(item)
                            whitelist_list.append(item)

    print(f"[+] Loaded {len(whitelist_set):,} clean Whitelist entries from phishingormalware.py", flush=True)

    # 2. Load Malicious Pool from phishingormalware.py outputs
    mal_files = [
        "MalwareDomains.csv", "PhishingDomains.csv", "MiningDomains.csv",
        "SpamDomains.csv", "IPv4Malware.csv", "IPv4PhishingActive.csv",
        "IPv4BruteForce.csv", "IPv4DDoS.csv", "MaliciousMailDomains.csv"
    ]
    raw_mal_list = []
    for mf in mal_files:
        p = os.path.join(website_dir, mf)
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i == 0:
                        continue
                    if i > 250000:
                        break
                    item = line.split(",")[0].strip().lower()
                    if len(item) >= 4 and not item.startswith("#"):
                        raw_mal_list.append(item)

    print(f"[+] Collected {len(raw_mal_list):,} raw Malicious candidates from phishingormalware.py", flush=True)

    # 3. Filter: Whitelist ALWAYS wins! Drop any malicious entry present in whitelist
    cleaned_mal_set = set()
    dropped_count = 0
    for m in raw_mal_list:
        if m in whitelist_set:
            dropped_count += 1
            continue
        cleaned_mal_set.add(m)

    print(f"[+] Dropped {dropped_count:,} Malicious candidates colliding with Whitelist.", flush=True)
    print(f"[+] Remaining Clean Malicious entries: {len(cleaned_mal_set):,}", flush=True)

    # 4. Strict 50/50 balance
    cleaned_mal_list = list(cleaned_mal_set)
    target_count = min(len(cleaned_mal_list), len(whitelist_list))
    if max_samples > 0:
        target_count = min(target_count, max_samples)

    np.random.seed(42)
    selected_mal = np.random.choice(cleaned_mal_list, target_count, replace=False)
    selected_ben = np.random.choice(whitelist_list, target_count, replace=False)

    print(f"  [+] URL/Domain Sub-group Target: {target_count:,} Benign vs {target_count:,} Malicious (Exact 50/50)", flush=True)

    # 5. Extract 32 Master features from entries
    print("[*] Extracting features for Malicious URLs/Domains...", flush=True)
    X_mal = []
    for entry in selected_mal:
        feats = extract_master_features_from_data(entry.encode("utf-8"), "url")
        X_mal.append(feats)

    print("[*] Extracting features for Benign URLs/Domains...", flush=True)
    X_ben = []
    for entry in selected_ben:
        feats = extract_master_features_from_data(entry.encode("utf-8"), "url")
        X_ben.append(feats)

    X_mal_arr = np.array(X_mal, dtype=np.float32)
    y_mal_arr = np.ones(len(X_mal), dtype=np.int32)
    joblib.dump({"X": X_mal_arr, "y": y_mal_arr, "type": "url"}, cache_mal, compress=3)

    X_ben_arr = np.array(X_ben, dtype=np.float32)
    y_ben_arr = np.zeros(len(X_ben), dtype=np.int32)
    joblib.dump({"X": X_ben_arr, "y": y_ben_arr, "type": "url"}, cache_ben, compress=3)

    print(f"[+] Saved {cache_mal}: {len(X_mal):,} valid samples", flush=True)
    print(f"[+] Saved {cache_ben}: {len(X_ben):,} valid samples", flush=True)

def load_all_master_chunks_stratified(cache_dir: str):
    """
    Loads category-level joblib files (features_pe_benign, features_pe_malicious, etc.)
    and enforces STRICT 50/50 symmetry across EVERY category (PE, JS, APK, URL)!
    """
    joblib_files = glob.glob(os.path.join(cache_dir, "features_*.joblib"))
    # Also support older chunk files if any exist
    if not joblib_files:
        joblib_files = glob.glob(os.path.join(cache_dir, "chunk_*.joblib"))
    if not joblib_files:
        raise RuntimeError(f"No feature files found in {cache_dir}")

    print(f"\n[*] Found {len(joblib_files)} dataset files in {cache_dir}. Loading with category-level 50/50 symmetry...")

    # Group by (entity_type, label)
    pools: Dict[str, Dict[int, List[np.ndarray]]] = {}

    for jf in joblib_files:
        data = joblib.load(jf)
        etype = data.get("type", "generic")
        lbl = int(data["y"][0])

        if etype not in pools:
            pools[etype] = {0: [], 1: []}
        pools[etype][lbl].append(data["X"])

    final_X_list = []
    final_y_list = []

    print("\n" + "=" * 65)
    print(" CATEGORY-LEVEL STRATIFIED 50/50 BALANCE REPORT ")
    print("=" * 65)

    for etype, labels in pools.items():
        if not labels[0] or not labels[1]:
            print(f"  [-] Skipping {etype}: missing Benign or Malicious data.")
            continue

        X_ben = np.vstack(labels[0])
        X_mal = np.vstack(labels[1])

        target_half = min(len(X_ben), len(X_mal))
        np.random.seed(42)
        idx_ben = np.random.choice(len(X_ben), target_half, replace=False)
        idx_mal = np.random.choice(len(X_mal), target_half, replace=False)

        final_X_list.append(X_ben[idx_ben])
        final_y_list.append(np.zeros(target_half, dtype=np.int32))

        final_X_list.append(X_mal[idx_mal])
        final_y_list.append(np.ones(target_half, dtype=np.int32))

        print(f"  [{etype.upper():8}] -> {target_half:,} Benign vs {target_half:,} Malicious (Exact 50/50)")

    if not final_X_list:
        raise RuntimeError("No balanced data could be formed!")

    X = np.vstack(final_X_list)
    y = np.concatenate(final_y_list)

    # Shuffle
    indices = np.arange(len(y))
    np.random.seed(42)
    np.random.shuffle(indices)

    X_final = X[indices]
    y_final = y[indices]

    print("=" * 65)
    print(f"[+] Total Master Dataset: {len(X_final):,} samples (Shape: {X_final.shape})")
    print(f"    Class 0 (Benign):    {np.sum(y_final == 0):,} (50.0%)")
    print(f"    Class 1 (Malicious): {np.sum(y_final == 1):,} (50.0%)")
    print("=" * 65 + "\n")

    return X_final, y_final

def parse_args():
    parser = argparse.ArgumentParser(description="Train HydraDragon Master Multi-Modal AI Model (Single ONNX Output)")
    parser.add_argument("--pe-benign", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2")
    parser.add_argument("--pe-malware", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder")
    parser.add_argument("--js-dir", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript")
    parser.add_argument("--apk-benign", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign")
    parser.add_argument("--apk-malware", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\malware")
    parser.add_argument("--website-dir", type=str, default=r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\website")
    parser.add_argument("--output-onnx", type=str, default="hydradragon_master.onnx")
    parser.add_argument("--cache-dir", "--chunk-dir", dest="chunk_dir", type=str, default="cache_chunks_master", help="Directory where domain feature files (PE, JS, APK) are cached")
    parser.add_argument("--max-samples-per-group", type=int, default=0, help="Max samples per group (0 = unlimited, takes ALL available files)")
    parser.add_argument("--workers", type=int, default=3, help="Number of parallel worker processes (default: 3 for memory stability)")
    parser.add_argument("--extract-only", action="store_true")
    parser.add_argument("--train-only", action="store_true")
    parser.add_argument("--scan", type=str, default=None, help="Scan a single file or URL with the master model")
    return parser.parse_args()

def scan_target(target: str, model_path: str = "hydradragon_master.onnx"):
    if not os.path.exists(model_path):
        print(f"[!] Model not found: {model_path}. Train the model first.")
        return

    import onnxruntime as ort
    sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    in_name = sess.get_inputs()[0].name

    if target.startswith("http://") or target.startswith("https://") or ("." in target and not os.path.exists(target)):
        # URL or Domain target
        data = target.encode("utf-8")
        feats = extract_master_features_from_data(data, "url")
    else:
        # File target
        feats = extract_master_features_from_file(target, "generic")
        if feats is None:
            print(f"[!] Could not read file: {target}")
            return

    X_in = np.array([feats], dtype=np.float32)
    res = sess.run(None, {in_name: X_in})
    label = int(res[0][0])
    prob_dict = res[1][0] if len(res) > 1 else {0: 1.0 - label, 1: float(label)}
    mal_prob = prob_dict.get(1, 0.0)

    verdict = "MALICIOUS (ZARARLI)" if label == 1 else "BENIGN (TEMIZ)"
    print("\n" + "=" * 60)
    print(f" TARGET:     {target}")
    print(f" VERDICT:    {verdict}")
    print(f" MALICIOUS:  {mal_prob * 100:.2f}%")
    print(f" BENIGN:     {(1.0 - mal_prob) * 100:.2f}%")
    print("=" * 60 + "\n")

def main():
    args = parse_args()
    print("=" * 68)
    print(" HydraDragon Antivirus - MASTER UNIFIED MULTI-MODAL TRAINER ")
    print(" (Single Universal ONNX Model Engine) ")
    print("=" * 68)

    if args.scan:
        scan_target(args.scan, args.output_onnx)
        return

    # 0. Warm up UniversalStringMatcher in main process so cache is built ONCE:
    print("[*] Initializing Master Universal String Automata in main process...", flush=True)
    UniversalStringMatcher.get_instance()

    if not args.train_only:
        # 1. Discover PE Files
        def get_files(d, limit):
            flist = []
            if os.path.exists(d):
                bname = os.path.basename(d)
                target_str = f"{limit:,} files" if limit and limit > 0 else "ALL files (unlimited)"
                print(f"  [>] Scanning {bname} (target: {target_str})...", flush=True)
                for r, _, fns in os.walk(d):
                    for fn in fns:
                        flist.append(os.path.join(r, fn))
                        if limit and limit > 0 and len(flist) >= limit:
                            print(f"  [+] Collected {len(flist):,} files from {bname}", flush=True)
                            return flist
                print(f"  [+] Collected {len(flist):,} files from {bname}", flush=True)
            return flist

        print("[*] Collecting cross-corpus datasets for extraction...", flush=True)
        # 1. Discover PE Files (Collect Malware first, then match Benign exactly to Malware count)
        pe_mal = get_files(args.pe_malware, args.max_samples_per_group)
        pe_limit = len(pe_mal) if (args.max_samples_per_group <= 0 or args.max_samples_per_group > len(pe_mal)) else args.max_samples_per_group
        pe_ben = get_files(args.pe_benign, pe_limit)
        print(f"  [+] PE Sub-group Target: {len(pe_ben):,} Benign vs {len(pe_mal):,} Malicious (Exact 50/50)", flush=True)

        extract_domain_dataset(pe_ben, "pe", "BENIGN", 0, args.chunk_dir, workers=args.workers)
        extract_domain_dataset(pe_mal, "pe", "MALICIOUS", 1, args.chunk_dir, workers=args.workers)

        # 2. Discover JS Files (Equal balance)
        print(f"  [>] Scanning JS directory {os.path.basename(args.js_dir)}...", flush=True)
        js_ben, js_mal = [], []
        lim = args.max_samples_per_group
        if os.path.exists(args.js_dir):
            for r, _, fns in os.walk(args.js_dir):
                is_m = "mal" in r.lower() or "virus" in r.lower()
                for fn in fns:
                    p = os.path.join(r, fn)
                    if is_m and (lim <= 0 or len(js_mal) < lim):
                        js_mal.append(p)
                    elif not is_m and (lim <= 0 or len(js_ben) < lim):
                        js_ben.append(p)
                if lim > 0 and len(js_ben) >= lim and len(js_mal) >= lim:
                    break
        min_js = min(len(js_ben), len(js_mal))
        js_ben = js_ben[:min_js]
        js_mal = js_mal[:min_js]
        print(f"  [+] JS Sub-group Target: {len(js_ben):,} Benign vs {len(js_mal):,} Malicious (Exact 50/50)", flush=True)

        extract_domain_dataset(js_ben, "js", "BENIGN", 0, args.chunk_dir, workers=args.workers)
        extract_domain_dataset(js_mal, "js", "MALICIOUS", 1, args.chunk_dir, workers=args.workers)

        # 3. Discover APK Files (Collect Malware first, then match Benign exactly to Malware count)
        apk_mal = get_files(args.apk_malware, args.max_samples_per_group)
        apk_limit = len(apk_mal) if (args.max_samples_per_group <= 0 or args.max_samples_per_group > len(apk_mal)) else args.max_samples_per_group
        apk_ben = get_files(args.apk_benign, apk_limit)
        print(f"  [+] APK Sub-group Target: {len(apk_ben):,} Benign vs {len(apk_mal):,} Malicious (Exact 50/50)", flush=True)

        extract_domain_dataset(apk_ben, "apk", "BENIGN", 0, args.chunk_dir, workers=args.workers)
        extract_domain_dataset(apk_mal, "apk", "MALICIOUS", 1, args.chunk_dir, workers=args.workers)

        # 4. Discover & Extract phishingormalware.py URL, Domain & IP Dataset (Exact 50/50, Whitelist Priority)
        extract_website_url_dataset(args.website_dir, args.chunk_dir, max_samples=args.max_samples_per_group or 100000)

    if args.extract_only:
        print("[+] Domain dataset extraction completed. Exiting as --extract-only was specified.")
        return

    # Load All Chunks with Stratified Sub-group Symmetry
    X, y = load_all_master_chunks_stratified(args.chunk_dir)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train):,} | Test set: {len(X_test):,}")

    print("[*] Training Master LightGBM Classifier (50/50 Stratified Balanced)...")
    clf = lgb.LGBMClassifier(
        n_estimators=400,
        learning_rate=0.03,
        num_leaves=127,
        max_depth=10,
        min_child_samples=40,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.0,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Malicious (1)"], digits=4))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) * 100.0 if (tp + fn) > 0 else 0.0
    print(f"Confusion Matrix: TP={tp:,}, FN={fn:,}, TN={tn:,}, FP={fp:,}")
    print(f"Malware Recall (Detection Rate): {recall:.2f}%")
    print(f"False Positive Rate (FPR):       {fpr:.2f}%")
    print("=" * 79)

    print(f"[*] Converting Master LightGBM model to SINGLE ONNX: {args.output_onnx}...")
    initial_type = [("float_input", FloatTensorType([None, len(MASTER_FEATURE_NAMES)]))]
    onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
    with open(args.output_onnx, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"[+] SINGLE MASTER ONNX MODEL successfully saved to: {args.output_onnx}!")

if __name__ == "__main__":
    main()
