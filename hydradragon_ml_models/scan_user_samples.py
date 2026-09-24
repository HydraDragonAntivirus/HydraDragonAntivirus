#!/usr/bin/env python3
"""
Scan user samples with HydraDragon Master Engine + Specialist Heads.
Pure ONNX only. Zero automata. Master vector is 8-dim.
"""

import os
import sys
import glob

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from scan_pure_onnx import scan_file_pure_onnx


def main():
    target_dir = r"C:\Users\semae\OneDrive\Belgeler\ransomwarevirusu"
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
    print("=" * 75)
    print(" HydraDragon Security Engine - Target Sample Deep Inspection ")
    print(f" Directory: {target_dir}")
    print(" Pure ONNX, zero automata.")
    print("=" * 75, flush=True)

    files = glob.glob(os.path.join(target_dir, "*"))
    files = [f for f in files if os.path.isfile(f) and not f.endswith(".log")]
    if not files:
        print(f"No files found in: {target_dir}")
        return

    for fp in files:
        try:
            scan_file_pure_onnx(fp)
        except Exception as e:
            print(f"[!] Failed to scan {fp}: {e}")

    print("\n" + "=" * 75)
    print(" Scan complete.")
    print("=" * 75)


if __name__ == "__main__":
    main()
