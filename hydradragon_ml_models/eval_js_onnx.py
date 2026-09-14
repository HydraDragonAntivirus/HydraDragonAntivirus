#!/usr/bin/env python3
"""
Evaluate trained ONNX JavaScript model against a directory of JS files.
Reports Detection Rate, False Positives, and probability brackets.
"""

import os
import sys
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import numpy as np
import onnxruntime as ort

# Import JS feature extractor
sys.path.insert(0, os.path.dirname(__file__))
from train_js_lgbm import extract_js_features_from_file

def scan_single_js_file(p):
    feat = extract_js_features_from_file(p)
    if feat is None:
        return None
    return (p, feat)

def main():
    parser = argparse.ArgumentParser(description="Evaluate JS ONNX model on a directory")
    parser.add_argument("directory", type=str, help="Directory containing JS samples")
    parser.add_argument("--model", type=str, default="js_model.onnx", help="Path to ONNX model")
    parser.add_argument("--max-samples", type=int, default=50000, help="Max samples to scan")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 8, help="Worker threads")
    parser.add_argument("--batch-size", type=int, default=1000, help="Inference batch size")
    args = parser.parse_args()

    if not os.path.exists(args.model):
        print(f"[!] Model not found: {args.model}")
        sys.exit(1)

    print(f"[*] Loading JS ONNX model from: {args.model}")
    opts = ort.SessionOptions()
    opts.log_severity_level = 3
    session = ort.InferenceSession(args.model, sess_options=opts, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name

    print(f"[*] Listing files in {args.directory} (max {args.max_samples})...")
    files_to_scan = []
    for root, _, files in os.walk(args.directory):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in (".js", ".jse", ".vbs", ".html", ".htm", ".txt", ""):
                files_to_scan.append(os.path.join(root, f))
                if len(files_to_scan) >= args.max_samples:
                    break
        if len(files_to_scan) >= args.max_samples:
            break

    total_candidates = len(files_to_scan)
    print(f"[*] Found {total_candidates} candidate files. Extracting JS features & evaluating...")

    scanned = 0
    b_high = 0
    b_susp = 0
    b_safe = 0

    batch_feats = []
    batch_paths = []

    def evaluate_batch(feats, paths):
        nonlocal scanned, b_high, b_susp, b_safe
        if not feats:
            return
        x = np.array(feats, dtype=np.float32)
        outputs = session.run(None, {input_name: x})
        probs = outputs[1]
        
        if isinstance(probs, list) and isinstance(probs[0], dict):
            mal_probs = [float(p.get(1, 0.0)) for p in probs]
        elif isinstance(probs, np.ndarray):
            mal_probs = [float(p[1]) for p in probs]
        else:
            mal_probs = [float(p[0]) for p in outputs[0]]

        for p, prob in zip(paths, mal_probs):
            scanned += 1
            if prob >= 0.50:
                b_high += 1
            elif prob >= 0.30:
                b_susp += 1
            else:
                b_safe += 1

    processed = 0
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_single_js_file, p): p for p in files_to_scan}
        for future in as_completed(futures):
            processed += 1
            if processed % 5000 == 0 or processed == total_candidates:
                print(f"  -> Evaluated: {processed}/{total_candidates} ({(processed/total_candidates)*100:.1f}%) | Detected Malicious so far: {b_high} ({b_high/max(1, scanned)*100:.2f}%)")
            res = future.result()
            if res is not None:
                path, feat = res
                batch_feats.append(feat)
                batch_paths.append(path)
                if len(batch_feats) >= args.batch_size:
                    evaluate_batch(batch_feats, batch_paths)
                    batch_feats = []
                    batch_paths = []

    if batch_feats:
        evaluate_batch(batch_feats, batch_paths)

    print("\n" + "=" * 50)
    print(f"JS SCAN SUMMARY FOR: {args.directory}")
    print(f"Total Candidate Files:   {total_candidates}")
    print(f"Valid Scanned JS:        {scanned}")
    print(f"High Malicious (>= 50%): {b_high} ({b_high/max(1, scanned)*100:.2f}%)")
    print(f"Suspicious     (30-50%): {b_susp} ({b_susp/max(1, scanned)*100:.2f}%)")
    print(f"Clean          (< 30%):  {b_safe} ({b_safe/max(1, scanned)*100:.2f}%)")
    print("=" * 50)

if __name__ == "__main__":
    main()
