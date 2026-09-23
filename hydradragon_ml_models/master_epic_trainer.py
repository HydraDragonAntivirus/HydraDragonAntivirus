#!/usr/bin/env python3
"""
HydraDragon Master Epic Trainer
Universal Multi-Model Pipeline:
  1. PE Model (train_pe_lgbm.py) -> pe_model.onnx
  2. JS Model (train_js_lgbm.py) -> js_model.onnx
  3. APK Model (train_apk_lgbm.py) -> apk_model.onnx & apk_trees.bin
  4. Universal Coach Model (extract_universal_chunks.py & train_universal_coach.py) -> universal_coach_model.onnx

Key Architectural Features:
  - Low-RAM Guarantee: Part-by-part out-of-core chunking to disk.
  - Strict Class Balancing: 50% Benign (0) / 50% Malicious (1) across all datasets.
  - Subprocess Isolation: Keeps RAM strictly under 1.5 - 2 GB.
"""

import os
import sys
import glob
import subprocess
import argparse

MODELS = ["master", "pe", "js", "apk", "coach"]

def get_chunk_stats():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    stats = {
        "master": glob.glob(os.path.join(base_dir, "cache_chunks_master", "chunk_*.joblib")),
        "pe": glob.glob(os.path.join(base_dir, "cache_chunks_pe", "chunk_pe_*.joblib")),
        "js": glob.glob(os.path.join(base_dir, "cache_chunks_js", "chunk_js_*.joblib")),
        "apk": glob.glob(os.path.join(base_dir, "cache_chunks_apk", "chunk_apk_*.joblib")),
        "coach": glob.glob(os.path.join(base_dir, "cache_chunks", "chunk_*.joblib")),
    }
    return stats

def print_status():
    print("=" * 65)
    print(" HydraDragon ML Dataset & Chunk Cache Status ")
    print("=" * 65)
    stats = get_chunk_stats()
    for m, files in stats.items():
        print(f"  [{m.upper()}] Chunks on disk: {len(files)} files")
    print("=" * 65)

def run_model(model_name: str, phase: str):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable

    print(f"\n{'#'*65}")
    print(f"[*] EXECUTING PIPELINE: Model=[{model_name.upper()}] | Phase=[{phase.upper()}]")
    print(f"{'#'*65}\n")

    if model_name == "pe":
        script = os.path.join(base_dir, "train_pe_lgbm.py")
        cmd = [python_exe, script]
        if phase == "extract":
            cmd.append("--extract-only")
        elif phase == "train":
            cmd.append("--train-only")
        subprocess.check_call(cmd, cwd=base_dir)

    elif model_name == "js":
        script = os.path.join(base_dir, "train_js_lgbm.py")
        cmd = [python_exe, script]
        if phase == "extract":
            cmd.append("--extract-only")
        elif phase == "train":
            cmd.append("--train-only")
        subprocess.check_call(cmd, cwd=base_dir)

    elif model_name == "apk":
        script = os.path.join(base_dir, "train_apk_lgbm.py")
        cmd = [python_exe, script]
        if phase == "extract":
            cmd.append("--extract-only")
        elif phase == "train":
            cmd.append("--train-only")
        subprocess.check_call(cmd, cwd=base_dir)

    elif model_name == "coach":
        if phase in ("extract", "all"):
            ext_script = os.path.join(base_dir, "extract_universal_chunks.py")
            subprocess.check_call([python_exe, ext_script], cwd=base_dir)
        if phase in ("train", "all"):
            train_script = os.path.join(base_dir, "train_universal_coach.py")
            subprocess.check_call([python_exe, train_script], cwd=base_dir)

    elif model_name == "master":
        script = os.path.join(base_dir, "train_master_model.py")
        cmd = [python_exe, script]
        if phase == "extract":
            cmd.append("--extract-only")
        elif phase == "train":
            cmd.append("--train-only")
        subprocess.check_call(cmd, cwd=base_dir)

def parse_args():
    parser = argparse.ArgumentParser(description="HydraDragon Master Multi-Model Epic Trainer")
    parser.add_argument("--model", type=str, choices=["all", "master", "pe", "js", "apk", "coach"], default="master",
                        help="Which model pipeline to run (default: master)")
    parser.add_argument("--phase", type=str, choices=["all", "extract", "train"], default="all",
                        help="Execution phase (extract to chunks, train from chunks, or all)")
    parser.add_argument("--status", action="store_true", help="Print disk chunk cache status and exit")
    return parser.parse_args()

def main():
    args = parse_args()
    if args.status:
        print_status()
        return

    print_status()

    target_models = MODELS if args.model == "all" else [args.model]
    for m in target_models:
        try:
            run_model(m, args.phase)
        except subprocess.CalledProcessError as e:
            print(f"[!] Pipeline error in model [{m}]: {e}")
            sys.exit(e.returncode)

    print("\n" + "=" * 65)
    print(" [+] ALL REQUESTED ML PIPELINES COMPLETED SUCCESSFULLY! ")
    print("=" * 65)

if __name__ == "__main__":
    main()
