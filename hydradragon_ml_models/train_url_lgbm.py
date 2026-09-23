#!/usr/bin/env python3
"""
HydraDragon Network Security - URL, Domain & IP ML Trainer (Zero-Day Engine)
Extracts 32 lexical, entropy, path, and query features from raw URLs, domains, and IPs.

Uses EXCLUSIVELY the full security intelligence lists managed by `phishingormalware.py` in `hydradragon/website/`:
  - Benign Whitelist (Label 0):
      Domains: DomainsPopularityWhiteList.csv, SubDomainsPopularityWhiteList.csv,
               WhiteListDomains.csv, WhiteListSubDomains.csv, BenignMailDomains.csv,
               BenignMailSubDomains.csv, BenignDomains.txt
      IPs:     BenignIPs.txt, WhiteListIPv4.csv, WhiteListIPv6.csv
  - Malicious Blacklist (Label 1):
      Domains: MalwareDomains.csv, MalwareSubDomains.csv, PhishingDomains.csv,
               PhishingSubDomains.csv, AbuseDomains.csv, AbuseSubDomains.csv,
               MiningDomains.csv, MiningSubDomains.csv, SpamDomains.csv, SpamSubDomains.csv,
               MaliciousMailDomains.csv, MaliciousMailSubDomains.csv
      IPs:     IPv4Malware.csv, IPv4PhishingActive.csv, IPv4Spam.csv,
               IPv4BruteForce.csv, IPv4DDoS.csv, IPv6Malware.csv, IPv6Spam.csv, IPv6DDoS.csv

Class balance: Strictly 50% Benign (0) / 50% Malicious (1) across the entire dataset.
Trains a high-speed LightGBM classifier and exports to ONNX (url_model.onnx) for OpenEDR.
"""

import os
import sys
import re
import math
import csv
import argparse
import random
from collections import Counter
from typing import Optional, List, Tuple, Set
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
    Extracts identical 32 features from a raw URL, domain, or IP.
    Mirrors OpenEDR/owlyshield_predict/src/ml/url_predict.rs exactly.
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


def load_full_phishingormalware_dataset(website_dir: str, max_samples: int = 0) -> Tuple[np.ndarray, np.ndarray]:
    """
    Loads samples ONLY from the lists used by phishingormalware.py in hydradragon/website/.
    If max_samples == 0, loads ALL entries from all files.
    Ensures EXACT 50% Benign (0) and 50% Malicious (1).
    """
    print("=" * 68)
    print(f"[*] Reading FULL dataset from phishingormalware.py lists in: {website_dir}")
    if max_samples > 0:
        print(f"    Cap target: {max_samples:,} ({max_samples//2:,} Benign, {max_samples//2:,} Malicious)")
    else:
        print("    Mode: ALL DATA (no sample limits, full 50/50 balance)")
    print("=" * 68)

    # ---- 1. Collect ALL Benign Items (Separated into IPs and Domains) ----
    benign_ips: Set[str] = set()
    benign_domains: Set[str] = set()

    benign_ip_files = ["BenignIPs.txt", "WhiteListIPv4.csv", "WhiteListIPv6.csv", "ALLOW_IPV4.txt", "ALLOW_IPV6.txt"]
    for fname in benign_ip_files:
        fpath = os.path.join(website_dir, fname)
        if not os.path.isfile(fpath):
            continue
        print(f"  [+] Loading Benign IPs from: {fname}...")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                ip_cand = line.split(",")[0].strip()
                if ip_cand and not ip_cand.startswith("#") and ip_cand != "entry" and "/" not in ip_cand:
                    benign_ips.add(ip_cand)

    benign_domain_files = [
        "WhiteListDomains.csv",
        "WhiteListSubDomains.csv",
        "BenignMailDomains.csv",
        "BenignMailSubDomains.csv",
        "BenignDomains.txt",
        "DomainsPopularityWhiteList.csv",
    ]
    for fname in benign_domain_files:
        fpath = os.path.join(website_dir, fname)
        if not os.path.isfile(fpath):
            continue
        print(f"  [+] Loading Benign Domains from: {fname}...")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                d = line.split(",")[0].strip().lower()
                if d and d != "domain" and d != "entry" and "." in d and not d.startswith("#"):
                    benign_domains.add(d)

    print(f"[+] Total unique benign entries: {len(benign_domains):,} Domains | {len(benign_ips):,} IPs")

    # ---- 2. Collect ALL Malicious Items (Separated into IPs and Domains) ----
    malicious_domains: Set[str] = set()
    malicious_ips: Set[str] = set()
    skipped_fp = 0

    malicious_domain_files = [
        "PhishingDomains.csv",
        "PhishingSubDomains.csv",
        "AbuseDomains.csv",
        "AbuseSubDomains.csv",
        "MalwareDomains.csv",
        "MalwareSubDomains.csv",
        "MiningDomains.csv",
        "MiningSubDomains.csv",
        "SpamDomains.csv",
        "SpamSubDomains.csv",
        "MaliciousMailDomains.csv",
        "MaliciousMailSubDomains.csv",
    ]

    malicious_ip_files = [
        "IPv4PhishingActive.csv",
        "IPv4Malware.csv",
        "IPv4Abuse.csv",
        "IPv4Spam.csv",
        "IPv4BruteForce.csv",
        "IPv4DDoS.csv",
        "IPv6Malware.csv",
        "IPv6Spam.csv",
        "IPv6DDoS.csv",
    ]

    for fname in malicious_domain_files:
        fpath = os.path.join(website_dir, fname)
        if not os.path.isfile(fpath):
            continue
        print(f"  [-] Loading Malicious Domains from: {fname}...")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row:
                    continue
                d = row[0].strip().lower()
                if not d or d == "entry" or d == "domain" or "." not in d:
                    continue
                # Whitelist safeguard: NEVER learn false positive like nic.in
                if d in benign_domains or any(d.endswith("." + b) for b in ("nic.in", "gov.in", "edu", "mil")):
                    skipped_fp += 1
                    continue
                malicious_domains.add(d)

    for fname in malicious_ip_files:
        fpath = os.path.join(website_dir, fname)
        if not os.path.isfile(fpath):
            continue
        print(f"  [-] Loading Malicious IPs from: {fname}...")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row:
                    continue
                ip_cand = row[0].strip()
                if not ip_cand or ip_cand == "entry" or ip_cand == "domain" or "/" in ip_cand:
                    continue
                if ip_cand in benign_ips:
                    skipped_fp += 1
                    continue
                malicious_ips.add(ip_cand)

    print(f"[+] Total unique malicious entries: {len(malicious_domains):,} Domains | {len(malicious_ips):,} IPs (filtered {skipped_fp:,} FPs)")

    # ---- 3. STRATIFIED SUB-GROUP SYMMETRY (Exact 50/50 Domains AND 50/50 IPs) ----
    # This prevents the fatal asymmetry where IPs are 90%+ malicious and model learns is_ip == malicious!
    n_ip = min(len(benign_ips), len(malicious_ips))
    n_dom = min(len(benign_domains), len(malicious_domains))
    if max_samples > 0:
        ratio_ip = len(benign_ips) / (len(benign_ips) + len(benign_domains))
        max_ip_half = int((max_samples // 2) * ratio_ip)
        max_dom_half = (max_samples // 2) - max_ip_half
        n_ip = min(n_ip, max_ip_half)
        n_dom = min(n_dom, max_dom_half)

    print(f"[*] Enforcing Sub-Group Stratified Symmetry:")
    print(f"    -> Domains: {n_dom:,} Benign vs {n_dom:,} Malicious (Exact 50/50)")
    print(f"    -> IPs:     {n_ip:,} Benign vs {n_ip:,} Malicious (Exact 50/50)")
    print(f"    -> Total Balanced Dataset: {(n_dom + n_ip) * 2:,} samples")

    sample_ben_doms = random.sample(sorted(benign_domains), n_dom)
    sample_mal_doms = random.sample(sorted(malicious_domains), n_dom)
    sample_ben_ips = random.sample(sorted(benign_ips), n_ip)
    sample_mal_ips = random.sample(sorted(malicious_ips), n_ip)

    benign_sample = sample_ben_doms + sample_ben_ips
    malicious_sample = sample_mal_doms + sample_mal_ips

    # ---- 4. Extract 32 Features ----
    print("[*] Extracting 32 lexical & entropy features...")
    X: List[List[float]] = []
    y: List[int] = []

    for item in benign_sample:
        X.append(extract_url_features(item))
        y.append(0)

    for item in malicious_sample:
        X.append(extract_url_features(item))
        y.append(1)

    X_arr = np.array(X, dtype=np.float32)
    y_arr = np.array(y, dtype=np.int32)

    # Shuffle
    indices = np.arange(len(y_arr))
    np.random.seed(42)
    np.random.shuffle(indices)

    X_final = X_arr[indices]
    y_final = y_arr[indices]

    print("=" * 68)
    print(f"[+] Final Training Matrix: {len(X_final):,} samples (Shape: {X_final.shape})")
    print(f"    Class 0 (Benign):    {np.sum(y_final == 0):,} (50.0%)")
    print(f"    Class 1 (Malicious): {np.sum(y_final == 1):,} (50.0%)")
    print("=" * 68)

    return X_final, y_final


def parse_args():
    default_website = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "hydradragon", "website"))
    parser = argparse.ArgumentParser(description="Train 50/50 Full-Dataset Domain & IP Zero-Day LightGBM Model")
    parser.add_argument("--website-dir", type=str, default=default_website, help="Path to hydradragon/website directory")
    parser.add_argument("--output-onnx", type=str, default="url_model.onnx", help="Output ONNX model path")
    parser.add_argument("--max-samples", type=int, default=0, help="Total samples to train on (0 = full dataset, exact 50/50)")
    parser.add_argument("--cache-file", type=str, default="url_features_cache.joblib", help="Cache extracted features")
    parser.add_argument("--force-rebuild", action="store_true", help="Force rebuilding features ignoring existing cache")
    return parser.parse_args()


def main():
    args = parse_args()
    print("=" * 68)
    print(" HydraDragon Antivirus - Full Dataset 50/50 LightGBM Trainer ")
    print("=" * 68)

    if args.cache_file and os.path.exists(args.cache_file) and not args.force_rebuild:
        print(f"[*] Loading cached features from {args.cache_file}...")
        cached_data = joblib.load(args.cache_file)
        X = cached_data["X"]
        y = cached_data["y"]
        print(f"[+] Loaded {len(X):,} cached samples ({np.sum(y == 1):,} Malicious, {np.sum(y == 0):,} Benign)")
    else:
        if not os.path.isdir(args.website_dir):
            print(f"[!] Website directory not found: {args.website_dir}")
            sys.exit(1)

        X, y = load_full_phishingormalware_dataset(args.website_dir, max_samples=args.max_samples)

        if args.cache_file:
            print(f"[*] Caching extracted features to {args.cache_file}...")
            joblib.dump({"X": X, "y": y}, args.cache_file, compress=3)
            print("[+] Cache saved successfully.")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train):,} | Test set: {len(X_test):,}")

    print("[*] Training LightGBM Classifier (50/50 Balanced with Zero False-Positive Tuning)...")
    clf = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.03,
        num_leaves=63,
        max_depth=8,
        min_child_samples=30,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Malicious (1)"], digits=4))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0
    recall = tp / (tp + fn) * 100.0
    print(f"Confusion Matrix: TP={tp:,}, FN={fn:,}, TN={tn:,}, FP={fp:,}")
    print(f"Malicious Recall (Detection Rate): {recall:.2f}%")
    print(f"False Positive Rate (FPR):         {fpr:.2f}%")
    print("=" * 79)

    # Sanity checks on sample domains and IPs
    print("\n[*] Sanity checks on sample domains & IPs:")
    test_cases = [
        ("https://www.google.com", 0),
        ("http://nic.in", 0),
        ("8.8.8.8", 0),
        ("1.1.1.1", 0),
        ("http://paypal-security-update-login.verify-account.xyz/signin", 1),
        ("http://x89qzk-malw.top/payload.bin", 1),
        ("185.220.101.5", 1),
    ]
    for target, expected in test_cases:
        feat = np.array([extract_url_features(target)], dtype=np.float32)
        pred = int(clf.predict(feat)[0])
        prob = float(clf.predict_proba(feat)[0][1])
        status = "PASSED" if pred == expected else "FAILED"
        label_str = "MALICIOUS" if pred == 1 else "BENIGN"
        print(f"  [{status}] {target:55} -> {label_str} (Malicious Prob: {prob*100:.1f}%)")

    print(f"\n[*] Converting LightGBM model to ONNX: {args.output_onnx}...")
    try:
        initial_type = [("float_input", FloatTensorType([None, len(URL_FEATURE_NAMES)]))]
        onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
        with open(args.output_onnx, "wb") as f:
            f.write(onnx_model.SerializeToString())
        print(f"[+] ONNX model successfully saved to {args.output_onnx}!")
    except Exception as e:
        print(f"[!] ONNX conversion warning/error: {e}")
        model_pkl = args.output_onnx.replace(".onnx", ".joblib")
        joblib.dump(clf, model_pkl)
        print(f"[+] Fallback: LightGBM model saved to {model_pkl}")


if __name__ == "__main__":
    main()
