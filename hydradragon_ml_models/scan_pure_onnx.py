#!/usr/bin/env python3
"""
HydraDragon Pure ONNX Scanner - Zero Automata, Instant Inference.
PE (65) + JS (51) + APK (24) + URL (32) + Master (8) -> all ONNX.
Raw-byte, file-type independent verdict. No string_matcher import.
"""

import os
import sys
import numpy as np
import onnxruntime as ort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(BASE_DIR), "OpenEDR", "openedr_web", "tools"))

from train_pe_lgbm import extract_pe_features_from_file
from train_js_lgbm import extract_js_features_from_file, extract_js_features_from_source
from train_url_lgbm import extract_url_features
from apk_train import apk_features

MODELS = {
    "pe": ("pe_model.onnx", 65),
    "js": ("js_model.onnx", 51),
    "apk": ("apk_model.onnx", 24),
    "url": ("url_model.onnx", 32),
    "master": ("hydradragon_master.onnx", 8),
}

_SESS = {}


def get_sess(kind):
    if kind not in _SESS:
        fname, _ = MODELS[kind]
        path = os.path.join(BASE_DIR, fname)
        if not os.path.exists(path):
            return None, None
        opts = ort.SessionOptions()
        opts.log_severity_level = 3
        s = ort.InferenceSession(path, sess_options=opts, providers=["CPUExecutionProvider"])
        _SESS[kind] = (s, s.get_inputs()[0].name)
    return _SESS[kind]


def predict_prob(kind, feats):
    sess, inp = get_sess(kind)
    if sess is None or feats is None:
        return 0.0
    X = np.array([feats], dtype=np.float32)
    try:
        res = sess.run(None, {inp: X})
    except Exception:
        return 0.0
    if len(res) > 1 and isinstance(res[1], list) and isinstance(res[1][0], dict):
        return float(res[1][0].get(1, 0.0))
    if len(res) > 1 and isinstance(res[1], np.ndarray) and res[1].size == 2:
        return float(res[1][0][1])
    try:
        return float(res[0][0] == 1)
    except Exception:
        return 0.0


def detect_type(data: bytes, path: str):
    ext = os.path.splitext(path)[1].lower()
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"PK\x03\x04") and b"AndroidManifest.xml" in data[:8192]:
        return "apk"
    if ext in (".js", ".jse", ".vbs", ".html", ".htm", ".ps1"):
        return "js"
    if ext in (".apk", ".zip"):
        return "apk"
    # icerik koklama: JS parse edilebilirse JS
    try:
        txt = data[:65536].decode("utf-8", errors="strict")
        if "<script" in txt[:4096].lower() or "function" in txt[:4096]:
            return "js"
    except Exception:
        pass
    # URL / metin ise
    try:
        txt = data[:4096].decode("utf-8", errors="ignore").strip()
        if txt.startswith("http") or ("." in txt and len(txt) < 2048 and "\x00" not in txt):
            return "url"
    except Exception:
        pass
    return "generic"


def scan_bytes_pure_onnx(data: bytes, path_hint=""):
    ftype = detect_type(data, path_hint)

    is_pe = 1.0 if ftype == "pe" else 0.0
    is_js = 1.0 if ftype == "js" else 0.0
    is_apk = 1.0 if ftype == "apk" else 0.0
    is_url = 1.0 if ftype == "url" else 0.0

    pe_prob = js_prob = apk_prob = url_prob = 0.0
    detail = {}

    # PE: in-memory via temp file (MZ check)
    if data.startswith(b"MZ"):
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
                tf.write(data[:10 * 1024 * 1024])
                tmp = tf.name
            try:
                pf = extract_pe_features_from_file(tmp)
                if pf is not None:
                    pe_prob = predict_prob("pe", pf)
                    detail["pe"] = pe_prob
            finally:
                os.unlink(tmp)
        except Exception:
            pass

    # Match training distribution: only the routed domain prob is active.
    # PE route
    if ftype == "pe" and data.startswith(b"MZ"):
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
                tf.write(data[:10 * 1024 * 1024])
                tmp = tf.name
            try:
                pf = extract_pe_features_from_file(tmp)
                if pf is not None:
                    pe_prob = predict_prob("pe", pf)
                    detail["pe"] = pe_prob
            finally:
                os.unlink(tmp)
        except Exception:
            pass
    # APK route
    elif ftype == "apk":
        try:
            af = apk_features(data)
            if af is not None:
                apk_prob = predict_prob("apk", af)
                detail["apk"] = apk_prob
        except Exception:
            pass
    # JS route
    elif ftype == "js":
        try:
            txt = data.decode("utf-8", errors="ignore")
            jf = extract_js_features_from_source(txt[:500000])
            if jf is not None:
                js_prob = predict_prob("js", jf)
                detail["js"] = js_prob
        except Exception:
            pass
    # URL route
    elif ftype == "url":
        try:
            txt = data.decode("utf-8", errors="ignore").strip().split()[0][:2048]
            uf = extract_url_features(txt)
            url_prob = predict_prob("url", uf)
            detail["url"] = url_prob
        except Exception:
            pass
    # Generic: best effort, flags stay 0. Text-like -> JS+URL, binary -> PE/APK probe.
    else:
        head = data[:8192]
        null_ratio = head.count(0) / max(1, len(head))
        try:
            probe_txt = data[:32768].decode("utf-8", errors="strict")
            is_text = null_ratio < 0.01 and len(probe_txt.strip()) >= 5
        except Exception:
            is_text = False
        if is_text:
            try:
                jf = extract_js_features_from_source(data.decode("utf-8", errors="ignore")[:500000])
                if jf is not None:
                    js_prob = predict_prob("js", jf)
                    detail["js"] = js_prob
            except Exception:
                pass
            try:
                txt = data.decode("utf-8", errors="ignore").strip().split()[0][:2048]
                if txt:
                    uf = extract_url_features(txt)
                    url_prob = predict_prob("url", uf)
                    detail["url"] = url_prob
            except Exception:
                pass
        else:
            if data.startswith(b"MZ"):
                import tempfile
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
                        tf.write(data[:10 * 1024 * 1024])
                        tmp = tf.name
                    try:
                        pf = extract_pe_features_from_file(tmp)
                        if pf is not None:
                            pe_prob = predict_prob("pe", pf)
                            detail["pe"] = pe_prob
                    finally:
                        os.unlink(tmp)
                except Exception:
                    pass
            try:
                af = apk_features(data)
                if af is not None:
                    apk_prob = predict_prob("apk", af)
                    detail["apk"] = apk_prob
            except Exception:
                pass

    # Master 8-vector: [is_pe,is_js,is_apk,is_url,pe,js,apk,url]
    master_vec = [is_pe, is_js, is_apk, is_url, pe_prob, js_prob, apk_prob, url_prob]
    sess, inp = get_sess("master")
    mal_prob = 0.0
    label = 0
    if sess is not None:
        X = np.array([master_vec], dtype=np.float32)
        res = sess.run(None, {inp: X})
        label = int(res[0][0])
        if len(res) > 1 and isinstance(res[1], list):
            mal_prob = float(res[1][0].get(1, 0.0))
        else:
            mal_prob = float(label)
    else:
        # no master model: max expert score
        mal_prob = max(pe_prob, js_prob, apk_prob, url_prob)
        label = 1 if mal_prob >= 0.5 else 0
    return {
        "ftype": ftype,
        "master_vec": master_vec,
        "mal_prob": mal_prob,
        "label": label if mal_prob < 0.5 else 1,
        "experts": {"pe": pe_prob, "js": js_prob, "apk": apk_prob, "url": url_prob},
        "detail": detail,
    }


def scan_file_pure_onnx(target_path, model_path=None):
    if not os.path.exists(target_path):
        print(f"[!] File not found: {target_path}")
        return None
    if os.path.isdir(target_path):
        print(f"[!] Directory given, single file expected: {target_path}")
        return None
    with open(target_path, "rb") as f:
        data = f.read(10 * 1024 * 1024)
    r = scan_bytes_pure_onnx(data, target_path)
    verdict = "MALICIOUS" if r["label"] == 1 else "BENIGN"
    print("=" * 65)
    print(f" TARGET:       {target_path}")
    print(f" TYPE:         {r['ftype']}  MasterVec: {['%.2f' % v for v in r['master_vec']]}")
    print(f" VERDICT:      {verdict}")
    print(f" MALICIOUS:    {r['mal_prob'] * 100:.2f}%  (PE:{r['experts']['pe']*100:.1f}% JS:{r['experts']['js']*100:.1f}% APK:{r['experts']['apk']*100:.1f}% URL:{r['experts']['url']*100:.1f}%)")
    print(" Pure ONNX, zero automata.")
    print("=" * 65)
    return r


if __name__ == "__main__":
    targets = [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\notepad.exe",
    ]
    if len(sys.argv) > 1:
        import glob as _g
        arg = sys.argv[1]
        if os.path.isfile(arg):
            targets = [arg]
        else:
            found = _g.glob(arg)
            targets = found if found else [arg]
    for t in targets:
        scan_file_pure_onnx(t)
