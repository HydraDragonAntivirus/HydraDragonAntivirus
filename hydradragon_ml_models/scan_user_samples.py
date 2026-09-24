#!/usr/bin/env python3
"""
Scan and evaluate user samples with HydraDragon Master Engine and Specialist Heads.
Tests:
  - 0KBAttack.exe
  - AntivirusBypass.7z
  - AntivirusBypass.exe
  - Winball501Ransom.exe
"""

import os
import sys
import glob
import numpy as np
import onnxruntime as ort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from string_matcher import UniversalStringMatcher, STRING_FEATURE_NAMES
from train_pe_lgbm import extract_pe_features_from_file

def main():
    target_dir = r"C:\Users\semae\OneDrive\Belgeler\ransomwarevirusu"
    print("=" * 75)
    print(" HydraDragon Security Engine - Target Sample Deep Inspection ")
    print(f" Directory: {target_dir}")
    print("=" * 75, flush=True)

    master_model_path = os.path.join(BASE_DIR, "hydradragon_master.onnx")
    pe_model_path = os.path.join(BASE_DIR, "pe_model.onnx")

    sess_opts = ort.SessionOptions()
    sess_opts.log_severity_level = 3
    master_sess = ort.InferenceSession(master_model_path, sess_options=sess_opts, providers=["CPUExecutionProvider"])
    pe_sess = ort.InferenceSession(pe_model_path, sess_options=sess_opts, providers=["CPUExecutionProvider"])

    master_in = master_sess.get_inputs()[0].name
    pe_in = pe_sess.get_inputs()[0].name

    print("[*] Loading Universal Aho-Corasick Matcher (ClamAV + YARA-X + yarGen)...", flush=True)
    matcher = UniversalStringMatcher.get_instance()

    files = glob.glob(os.path.join(target_dir, "*"))
    files = [f for f in files if os.path.isfile(f) and not f.endswith(".log")]

    for fp in files:
        fname = os.path.basename(fp)
        fsize = os.path.getsize(fp)
        print("\n" + "-" * 75)
        print(f"[*] ANALYZING: {fname} ({fsize:,} bytes)")
        print("-" * 75)

        with open(fp, "rb") as f:
            data = f.read(10 * 1024 * 1024)

        # 1. Universal String & Byte Features (24 features)
        str_feats = matcher.extract_features(data)

        # Check PE
        is_pe = 1.0 if data.startswith(b"MZ") else 0.0
        is_js = 1.0 if fname.lower().endswith(".js") else 0.0
        is_apk = 1.0 if fname.lower().endswith(".apk") else 0.0
        is_url = 0.0

        pe_prob = 0.0
        if is_pe:
            pe_raw_feats = extract_pe_features_from_file(fp)
            if pe_raw_feats is not None:
                pe_X = np.array([pe_raw_feats], dtype=np.float32)
                pe_res = pe_sess.run(None, {pe_in: pe_X})
                pe_prob_dict = pe_res[1][0] if len(pe_res) > 1 else {1: float(pe_res[0][0])}
                pe_prob = pe_prob_dict.get(1, 0.0)

        # Build 32-dim Master Vector
        ext_8 = [is_pe, is_js, is_apk, is_url, pe_prob, 0.0, 0.0, 0.0]
        master_vec = str_feats + ext_8

        # Master ONNX Inference
        m_X = np.array([master_vec], dtype=np.float32)
        m_res = master_sess.run(None, {master_in: m_X})
        m_label = int(m_res[0][0])
        m_prob_dict = m_res[1][0] if len(m_res) > 1 else {0: 1.0 - m_label, 1: float(m_label)}
        m_mal_prob = m_prob_dict.get(1, 0.0)

        verdict = "MALICIOUS (ZARARLI)" if m_label == 1 or m_mal_prob >= 0.50 else "BENIGN (TEMIZ)"

        print(f"  » MASTER MODEL VERDICT: {verdict}")
        print(f"  » Zararlı Olasılığı:   %{m_mal_prob * 100:.2f}")
        print(f"  » Temiz Olasılığı:     %{(1.0 - m_mal_prob) * 100:.2f}")
        if is_pe:
            print(f"  » PE Specialist Skoru: %{pe_prob * 100:.2f}")

        # Signature & Byte Telemetry
        print("  » Algılanan İmzalar & Özellikler:")
        print(f"     - Byte Shannon Entropisi:       {str_feats[3]:.4f}")
        print(f"     - ClamAV/YARA/yarGen İmzaları: {int(np.expm1(str_feats[6]))} adet toplam hit, {int(np.expm1(str_feats[7]))} benzersiz")
        print(f"     - Temiz Sistem İmzaları:        {int(np.expm1(str_feats[8]))} hit")
        print(f"     - Şüpheli Komut Enjeksiyonu:   {int(np.expm1(str_feats[19]))} adet")
        print(f"     - Base64 / Hex Run Sayısı:      {int(np.expm1(str_feats[15]))} / {int(np.expm1(str_feats[16]))}")

    print("\n" + "=" * 75)
    print(" Tarama Tamamlandı.")
    print("=" * 75)

if __name__ == "__main__":
    main()
