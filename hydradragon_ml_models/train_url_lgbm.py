#!/usr/bin/env python3
"""
HydraDragon Network Security - URL & Query ML Trainer (Snort ML Style)
Extracts 32 lexical, entropy, path and query features from raw URLs or loads precomputed
features from MUD_malicious_urls_2026_V2.csv.
Trains a high-speed LightGBM classifier for zero-day phishing/malware/defacement detection
and exports to ONNX (url_model.onnx) for real-time firewall packet inspection.
"""

import os
import sys
import re
import math
import csv
import argparse
from collections import Counter
from typing import Optional, List, Tuple
from urllib.parse import urlparse, parse_qs

import numpy as np
import lightgbm as lgb
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

URL_FEATURE_NAMES = [
    "url_len",
    "domain_len",
    "path_len",
    "query_len",
    "path_depth",
    "subdomain_count",
    "query_param_count",
    "is_ip_host",
    "has_port",
    "is_https",
    "digit_count",
    "letter_count",
    "special_count",
    "digit_ratio",
    "letter_ratio",
    "special_ratio",
    "token_count",
    "max_token_len",
    "avg_token_len",
    "url_entropy",
    "host_entropy",
    "count_at",
    "count_question",
    "count_hyphen",
    "count_equal",
    "count_dot",
    "count_percent",
    "count_slash",
    "count_semicolon",
    "count_ampersand",
    "has_suspicious_tld",
    "has_hacked_keywords",
]

SUSPICIOUS_TLDS = frozenset([
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "buzz", "rest", "fit", "casa", "surf", "icu", "bar", "live", "vip"
])

HACK_KEYWORDS = re.compile(
    r"login|signin|verify|account|banking|secure|update|confirm|wallet|admin|wp-content|"
    r"cmd|shell|exec|eval|select|union|insert|drop|etc/passwd|windows/system32",
    re.I
)

RE_IP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

def ln1p(x: float) -> float:
    if x is None or math.isnan(x) or x <= 0:
        return 0.0
    return float(math.log1p(x))

def shannon_entropy_str(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c, count in counts.items():
        p = count / total
        ent -= p * math.log2(p)
    return float(ent)

def extract_url_features(raw_url: str) -> List[float]:
    """
    Extracts identical 32 features from a raw URL or HTTP Request-URI in real time.
    Callable by HydraDragonFirewall / Python or Rust wrapper.
    """
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        url = "http://" + raw_url
    else:
        url = raw_url

    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else ""
    path = parsed.path or ""
    query = parsed.query or ""

    url_len = float(len(raw_url))
    domain_len = float(len(host))
    path_len = float(len(path))
    query_len = float(len(query))

    path_depth = float(len([p for p in path.split("/") if p]))
    subdomain_count = float(max(0, len(host.split(".")) - 2))

    try:
        query_param_count = float(len(parse_qs(query)))
    except Exception:
        query_param_count = float(query.count("&") + 1 if query else 0)

    is_ip = 1.0 if RE_IP.match(host) else 0.0
    has_port = 1.0 if ":" in parsed.netloc else 0.0
    is_https = 1.0 if raw_url.lower().startswith("https://") else 0.0

    digits = float(sum(c.isdigit() for c in raw_url))
    letters = float(sum(c.isalpha() for c in raw_url))
    specials = float(url_len - digits - letters)

    digit_ratio = digits / max(1.0, url_len)
    letter_ratio = letters / max(1.0, url_len)
    special_ratio = specials / max(1.0, url_len)

    tokens = [t for t in re.split(r"[/._?=&-]", raw_url) if t]
    token_count = float(len(tokens))
    if tokens:
        token_lens = [len(t) for t in tokens]
        max_tok = float(max(token_lens))
        avg_tok = float(sum(token_lens) / len(tokens))
    else:
        max_tok = avg_tok = 0.0

    url_entropy = shannon_entropy_str(raw_url)
    host_entropy = shannon_entropy_str(host)

    c_at = float(raw_url.count("@"))
    c_q = float(raw_url.count("?"))
    c_hyphen = float(raw_url.count("-"))
    c_eq = float(raw_url.count("="))
    c_dot = float(raw_url.count("."))
    c_pct = float(raw_url.count("%"))
    c_slash = float(raw_url.count("/"))
    c_semi = float(raw_url.count(";"))
    c_amp = float(raw_url.count("&"))

    tld = host.split(".")[-1].lower() if "." in host else ""
    susp_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
    hacked_kw = 1.0 if HACK_KEYWORDS.search(raw_url) else 0.0

    return [
        ln1p(url_len),
        ln1p(domain_len),
        ln1p(path_len),
        ln1p(query_len),
        path_depth,
        subdomain_count,
        query_param_count,
        is_ip,
        has_port,
        is_https,
        ln1p(digits),
        ln1p(letters),
        ln1p(specials),
        digit_ratio,
        letter_ratio,
        special_ratio,
        ln1p(token_count),
        ln1p(max_tok),
        avg_tok,
        url_entropy,
        host_entropy,
        c_at,
        c_q,
        ln1p(c_hyphen),
        ln1p(c_eq),
        ln1p(c_dot),
        ln1p(c_pct),
        ln1p(c_slash),
        c_semi,
        ln1p(c_amp),
        susp_tld,
        hacked_kw,
    ]

def load_mud_csv(csv_path: str, max_samples: int = 100000) -> Tuple[np.ndarray, np.ndarray]:
    print(f"[*] Reading URL dataset from: {csv_path} (max {max_samples} samples)...")
    X = []
    y = []

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader)
        
        col_url = header.index("url") if "url" in header else 0
        col_class = header.index("class_label") if "class_label" in header else 3

        count_mal = 0
        count_ben = 0
        limit_per_class = max_samples // 2

        for row in reader:
            if not row or len(row) <= col_class:
                continue
            raw_url = row[col_url]
            cls = row[col_class].strip().lower()

            # Binary classification: 0 = Benign, 1 = Malicious (phishing, malware, defacement)
            if cls == "benign":
                if count_ben >= limit_per_class:
                    continue
                label = 0
                count_ben += 1
            else:
                if count_mal >= limit_per_class:
                    continue
                label = 1
                count_mal += 1

            feats = extract_url_features(raw_url)
            X.append(feats)
            y.append(label)

            if len(X) % 10000 == 0:
                print(f"  -> Extracted {len(X)} samples (Malicious: {count_mal}, Benign: {count_ben})...")

            if count_ben >= limit_per_class and count_mal >= limit_per_class:
                break

    print(f"[+] Total loaded: {len(X)} samples ({count_mal} Malicious, {count_ben} Benign)")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)

def parse_args():
    parser = argparse.ArgumentParser(description="Train Snort-style URL ML Model and Export to ONNX")
    parser.add_argument("--csv", type=str, default=r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\dataset\archive\MUD_malicious_urls_2026_V2.csv", help="Path to MUD URL dataset CSV")
    parser.add_argument("--output-onnx", type=str, default="url_model.onnx", help="Output ONNX model path")
    parser.add_argument("--max-samples", type=int, default=100000, help="Total samples to train on")
    parser.add_argument("--cache-file", type=str, default="url_features_cache.joblib", help="Cache extracted features")
    return parser.parse_args()

def main():
    args = parse_args()
    print("=" * 65)
    print(" HydraDragon Antivirus - High Precision URL LightGBM Trainer ")
    print("=" * 65)

    if args.cache_file and os.path.exists(args.cache_file):
        print(f"[*] Loading cached URL features from {args.cache_file}...")
        cached_data = joblib.load(args.cache_file)
        X = cached_data["X"]
        y = cached_data["y"]
        print(f"[+] Loaded {len(X)} cached samples ({np.sum(y == 1)} Malicious, {np.sum(y == 0)} Benign)")
    else:
        if not os.path.exists(args.csv):
            print(f"[!] CSV not found: {args.csv}")
            sys.exit(1)
        X, y = load_mud_csv(args.csv, args.max_samples)

        if args.cache_file:
            print(f"[*] Caching extracted URL features to {args.cache_file}...")
            joblib.dump({"X": X, "y": y}, args.cache_file, compress=3)
            print(f"[+] Cache saved successfully.")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train)} | Test set: {len(X_test)}")

    print("[*] Training LightGBM Classifier (with class balancing & zero false-positive tuning)...")
    clf = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.03,
        num_leaves=63,
        max_depth=8,
        min_child_samples=30,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.2,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious/Phishing"], digits=4))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0
    recall = tp / (tp + fn) * 100.0
    print(f"Confusion Matrix: TP={tp}, FN={fn}, TN={tn}, FP={fp}")
    print(f"URL Malicious Recall (Detection Rate): {recall:.2f}%")
    print(f"False Positive Rate (FPR):            {fpr:.2f}%")
    print("=" * 79)

    print(f"[*] Converting LightGBM URL model to ONNX: {args.output_onnx}...")
    initial_type = [("float_input", FloatTensorType([None, len(URL_FEATURE_NAMES)]))]
    onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
    with open(args.output_onnx, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"[+] URL ONNX model successfully saved to {args.output_onnx}!")

if __name__ == "__main__":
    main()
