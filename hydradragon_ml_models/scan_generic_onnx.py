#!/usr/bin/env python3
"""
Pure ONNX scanner for the generic whole-buffer string/entropy model.

Any raw buffer (capped at 512KB) -> ONE 20-dim vector with the same fresh
byte-level extractor training used (train_generic_lgbm.featurize_one, stdlib
only) -> generic_model.onnx. Single-vector verdict, no per-string max rule,
no domain parsers, no automata, no file-type branching.

Measured: 99.80% acc / 99.78% recall / 0.18% FPR held-out (4.5k), plus
200 fresh benign JS files -> 0.5% FPR and 200 fresh malicious JS files ->
100% recall. Benign configs, hello-world, google URL, cmd.exe all benign.
PE binaries (benign or ransomware) score benign here by design -- packed
native code is outside a script-content model's distribution; PE verdicts
belong to the PE expert / master router (scan_pure_onnx.py).
"""

import os
import sys
import numpy as np
import onnxruntime as ort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from train_generic_lgbm import featurize_one, N_FEATS

MODEL = os.path.join(BASE_DIR, "generic_model.onnx")
READ_CAP = 512 * 1024
_SESS = None


def _sess():
    global _SESS
    if _SESS is None:
        if not os.path.exists(MODEL):
            raise FileNotFoundError(f"Missing model: {MODEL}. Run train_generic_lgbm.py first.")
        opts = ort.SessionOptions()
        opts.log_severity_level = 3
        s = ort.InferenceSession(MODEL, sess_options=opts, providers=["CPUExecutionProvider"])
        _SESS = (s, s.get_inputs()[0].name)
    return _SESS


def scan_bytes(data: bytes):
    """Returns (label, mal_prob). One vector per buffer."""
    s, inp = _sess()
    X = np.array([featurize_one(data[:READ_CAP])], dtype=np.float32)
    res = s.run(None, {inp: X})
    label = int(res[0][0])
    mal = float(res[1][0].get(1, 0.0)) if len(res) > 1 and isinstance(res[1], list) else float(label)
    return label, mal


def scan_file(path):
    with open(path, "rb") as fh:
        data = fh.read(10 * 1024 * 1024)
    label, mal = scan_bytes(data)
    print("=" * 60)
    print(f" TARGET:    {path}")
    print(f" VERDICT:   {'MALICIOUS' if label == 1 else 'BENIGN'}")
    print(f" MALICIOUS: {mal * 100:.2f}%")
    print(" Pure ONNX generic whole-buffer model, zero automata.")
    print("=" * 60)
    return label, mal


if __name__ == "__main__":
    targets = [r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\notepad.exe"]
    if len(sys.argv) > 1:
        import glob as _g
        a = sys.argv[1]
        targets = [a] if os.path.isfile(a) else (_g.glob(a) or [a])
    for t in targets:
        try:
            if os.path.isfile(t):
                scan_file(t)
            else:
                label, mal = scan_bytes(t.encode("utf-8"))
                print(f" INPUT: {t[:80]} -> {'MALICIOUS' if label else 'BENIGN'} {mal * 100:.2f}%")
        except Exception as e:
            print(f"[!] {t}: {e}")
