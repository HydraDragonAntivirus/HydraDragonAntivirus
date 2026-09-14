#!/usr/bin/env python3
"""
Evaluate trained ONNX PE model against a folder of executables.
Reports Detection Rate, False Positives, and probability brackets.
"""

import os
import sys
import argparse
import numpy as np
import onnxruntime as ort

# Import feature extractor from train script
sys.path.insert(0, os.path.dirname(__file__))
from train_pe_lgbm import extract_pe_features_from_file

def main():
    parser = argparse.ArgumentParser(description="Evaluate PE ONNX model on a directory")
    parser.add_argument("directory", type=str, help="Directory containing PE samples")
    parser.add_argument("--model", type=str, default="pe_model.onnx", help="Path to ONNX model")
    parser.add_argument("--max-samples", type=int, default=500, help="Max samples to scan")
    args = parser.parse_args()

    if not os.path.exists(args.model):
        print(f"[!] Model not found: {args.model}")
        sys.exit(1)

    print(f"[*] Loading ONNX model from: {args.model}")
    session = ort.InferenceSession(args.model, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name

    print(f"[*] Scanning {args.directory} (max {args.max_samples} files)...")
    scanned = 0
    b_high = 0
    b_susp = 0
    b_safe = 0

    files_to_scan = []
    for root, _, files in os.walk(args.directory):
        for f in files:
            files_to_scan.append(os.path.join(root, f))
            if len(files_to_scan) >= args.max_samples:
                break
        if len(files_to_scan) >= args.max_samples:
            break

    for p in files_to_scan:
        feat = extract_pe_features_from_file(p)
        if feat is None:
            continue

        scanned += 1
        x = np.array([feat], dtype=np.float32)
        outputs = session.run(None, {input_name: x})
        
        # ONNX LightGBM classifier output[1] contains list of maps/probabilities
        probs = outputs[1]
        if isinstance(probs, list) and isinstance(probs[0], dict):
            mal_prob = float(probs[0].get(1, 0.0))
        elif isinstance(probs, np.ndarray):
            mal_prob = float(probs[0][1])
        else:
            mal_prob = float(outputs[0][0])

        if mal_prob >= 0.50:
            b_high += 1
            print(f"  [HIGH-MALICIOUS: {mal_prob*100:6.2f}%] {p}")
        elif mal_prob >= 0.30:
            b_susp += 1
            print(f"  [SUSPICIOUS:     {mal_prob*100:6.2f}%] {p}")
        else:
            b_safe += 1
            if scanned <= 5:
                print(f"  [CLEAN:          {mal_prob*100:6.2f}%] {p}")

    print("\n" + "=" * 50)
    print(f"SCAN SUMMARY FOR: {args.directory}")
    print(f"Total Scanned PEs:       {scanned}")
    print(f"High Malicious (>= 50%): {b_high} ({b_high/max(1, scanned)*100:.2f}%)")
    print(f"Suspicious     (30-50%): {b_susp} ({b_susp/max(1, scanned)*100:.2f}%)")
    print(f"Clean          (< 30%):  {b_safe} ({b_safe/max(1, scanned)*100:.2f}%)")
    print("=" * 50)

if __name__ == "__main__":
    main()
