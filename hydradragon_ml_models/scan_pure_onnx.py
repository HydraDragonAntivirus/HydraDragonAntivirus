#!/usr/bin/env python3
"""
HydraDragon Pure ONNX Scanner - Zero Automata, Instant Inference.
PE (v1 65 + v2 Inner/Shell with Multron Dynamic String WL + yarGen .xf + Unicorn + Disassembler)
+ Generic Whole-Buffer (20) + JS (51) + APK (24) + URL (32) + Master (8) -> all ONNX.
"""

import csv
import os
import subprocess
import sys
import tempfile
import numpy as np
import onnxruntime as ort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(BASE_DIR), "OpenEDR", "openedr_web", "tools"))

from train_pe_lgbm import (
    extract_pe_features_from_file,
    extract_pe_features_from_data,
    PE_DUMP_EXE,
    UNICORN_DIR,
    PE_MIMICRY_NAMES,
    PE_STRING_ML_NAMES,
)
from train_js_lgbm import extract_js_features_from_file, extract_js_features_from_source
from train_url_lgbm import extract_url_features
from train_generic_lgbm import featurize_buffer
from apk_train import apk_features

MODELS = {
    "pe": ("pe_model.onnx", 65),
    "pe_inner": ("pe_model_inner.onnx", 79),
    "pe_shell": ("pe_model_shell.onnx", 73),
    "generic": ("generic_model.onnx", 20),
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
            return None, None, None
        opts = ort.SessionOptions()
        opts.log_severity_level = 3
        s = ort.InferenceSession(path, sess_options=opts, providers=["CPUExecutionProvider"])
        _SESS[kind] = (s, s.get_inputs()[0].name, s.get_inputs()[0].shape[1])
    return _SESS[kind]


def predict_prob(kind, feats):
    sess, inp, exp_dim = get_sess(kind)
    if sess is None or feats is None:
        return 0.0
    if exp_dim and len(feats) > exp_dim:
        feats = feats[:exp_dim]
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


def evaluate_pe_v2_inner_or_shell(filepath: str):
    """Runs pe_feature_dump.exe --v2 (Unicorn + Disassembler + Multron Dynamic String WL + yarGen .xf)
    and routes to pe_model_inner.onnx (unpacked/content) or pe_model_shell.onnx (outer shell)."""
    if not filepath or not os.path.isfile(filepath) or not os.path.isfile(PE_DUMP_EXE):
        return None
    with tempfile.TemporaryDirectory() as tmpdir:
        lst = os.path.join(tmpdir, "in.lst")
        out = os.path.join(tmpdir, "out.csv")
        with open(lst, "w", encoding="utf-8") as fh:
            fh.write(filepath + "\n")
        env = dict(os.environ, PATH=UNICORN_DIR + os.pathsep + os.environ.get("PATH", ""), UC_IGNORE_REG_BREAK="1")
        code = subprocess.run([PE_DUMP_EXE, "--v2", "@" + lst, out], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if code != 0 or not os.path.isfile(out):
            return None
        with open(out, newline="", encoding="utf-8") as fh:
            rd = csv.reader(fh)
            names = next(rd, None)
            row_raw = next(rd, None)
            if not names or not row_raw:
                return None
            names = names[1:]
            row = [float(v) for v in row_raw[1:]]

    source_i = names.index("inner_source")
    is_pe_i = names.index("inner_is_pe")
    is_unpacked_content = (row[source_i] in (1.0, 2.0, 4.0)) and (row[is_pe_i] == 1.0)

    if is_unpacked_content:
        sel = list(range(names.index("inner_size_of_optional_header"), names.index("inner_size_of_optional_header") + 65))
        sel += [names.index(f"inner_{n}") for n in ("ascii_strings", "utf16_strings", "ascii_unicode_ratio", "is_dotnet")]
        sel += [names.index(f"inner_{n}") for n in PE_MIMICRY_NAMES if f"inner_{n}" in names]
        sel += [names.index(f"inner_{n}") for n in PE_STRING_ML_NAMES if f"inner_{n}" in names]
        vec = [row[i] for i in sel]
        prob = predict_prob("pe_inner", vec)
        str_metrics = {n: row[names.index(f"inner_{n}")] for n in PE_STRING_ML_NAMES if f"inner_{n}" in names}
        return {"kind": "pe_inner", "prob": prob, "str_metrics": str_metrics}
    else:
        sel = list(range(names.index("shell_size_of_optional_header"), names.index("shell_size_of_optional_header") + 65))
        sel += [names.index(f"shell_{n}") for n in ("ascii_strings", "utf16_strings", "ascii_unicode_ratio", "is_dotnet")]
        sel += [names.index(f"shell_{n}") for n in PE_MIMICRY_NAMES if f"shell_{n}" in names]
        vec = [row[i] for i in sel]
        prob = predict_prob("pe_shell", vec)
        return {"kind": "pe_shell", "prob": prob, "str_metrics": {}}


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
    try:
        txt = data[:65536].decode("utf-8", errors="strict")
        if "<script" in txt[:4096].lower() or "function" in txt[:4096]:
            return "js"
    except Exception:
        pass
    try:
        txt = data[:4096].decode("utf-8", errors="ignore").strip()
        if txt.startswith("http") or ("." in txt and len(txt) < 2048 and "\x00" not in txt):
            return "url"
    except Exception:
        pass
    return "generic"


def scan_bytes_pure_onnx(data: bytes, path_hint=""):
    if not data or len(data) == 0:
        return None

    ftype = detect_type(data, path_hint)

    is_pe = 1.0 if ftype == "pe" else 0.0
    is_js = 1.0 if ftype == "js" else 0.0
    is_apk = 1.0 if ftype == "apk" else 0.0
    is_url = 1.0 if ftype == "url" else 0.0

    pe_prob = js_prob = apk_prob = url_prob = gen_prob = 0.0
    detail = {}

    try:
        gf = featurize_buffer(data[:512 * 1024])
        if gf is not None:
            gen_prob = predict_prob("generic", gf)
            detail["generic"] = gen_prob
    except Exception:
        pass

    if ftype == "pe" and data.startswith(b"MZ"):
        try:
            pf = extract_pe_features_from_data(data)
            if pf is not None:
                pe_prob = predict_prob("pe", pf)
                detail["pe_v1"] = pe_prob
        except Exception:
            pass
        if path_hint and os.path.isfile(path_hint):
            v2_info = evaluate_pe_v2_inner_or_shell(path_hint)
            if v2_info is not None:
                detail[v2_info["kind"]] = v2_info["prob"]
                if v2_info["str_metrics"]:
                    detail["inner_string_ml"] = v2_info["str_metrics"]
                pe_prob = max(pe_prob, v2_info["prob"])
    elif ftype == "apk":
        try:
            af = apk_features(data)
            if af is not None:
                apk_prob = predict_prob("apk", af)
                detail["apk"] = apk_prob
        except Exception:
            pass
    elif ftype == "js":
        try:
            txt = data.decode("utf-8", errors="ignore")
            jf = extract_js_features_from_source(txt[:500000])
            if jf is not None:
                js_prob = predict_prob("js", jf)
                detail["js"] = js_prob
        except Exception:
            pass
    elif ftype == "url":
        try:
            txt = data.decode("utf-8", errors="ignore").strip().split()[0][:2048]
            uf = extract_url_features(txt)
            url_prob = predict_prob("url", uf)
            detail["url"] = url_prob
        except Exception:
            pass
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
                try:
                    pf = extract_pe_features_from_data(data)
                    if pf is not None:
                        pe_prob = predict_prob("pe", pf)
                        detail["pe"] = pe_prob
                except Exception:
                    pass
            try:
                af = apk_features(data)
                if af is not None:
                    apk_prob = predict_prob("apk", af)
                    detail["apk"] = apk_prob
            except Exception:
                pass

    master_vec = [is_pe, is_js, is_apk, is_url, pe_prob, js_prob, apk_prob, url_prob]

    if all(v == 0.0 for v in master_vec) and gen_prob == 0.0:
        return {
            "ftype": ftype,
            "master_vec": master_vec,
            "mal_prob": 0.0,
            "label": 0,
            "experts": {"pe": 0.0, "js": 0.0, "apk": 0.0, "url": 0.0, "generic": 0.0},
            "detail": detail,
        }

    sess, inp, _ = get_sess("master")
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
        mal_prob = max(pe_prob, js_prob, apk_prob, url_prob)
        label = 1 if mal_prob >= 0.5 else 0

    # Combine with Generic Whole-Buffer expert if domain expert was evaded by compiler/symbol bloat
    effective_prob = max(mal_prob, gen_prob)
    effective_label = 1 if effective_prob >= 0.5 else label

    return {
        "ftype": ftype,
        "master_vec": master_vec,
        "mal_prob": effective_prob,
        "master_prob": mal_prob,
        "label": effective_label,
        "experts": {"pe": pe_prob, "js": js_prob, "apk": apk_prob, "url": url_prob, "generic": gen_prob},
        "detail": detail,
    }


def scan_file_pure_onnx(target_path, model_path=None):
    if not target_path or not os.path.exists(target_path):
        print(f"[!] File not found or inaccessible: {target_path}")
        return None
    if os.path.isdir(target_path):
        print(f"[!] Directory given, single file expected: {target_path}")
        return None
    try:
        with open(target_path, "rb") as f:
            data = f.read(10 * 1024 * 1024)
    except Exception as e:
        print(f"[!] Cannot read file {target_path}: {e}")
        return None

    if not data or len(data) == 0:
        print(f"[-] Empty file, skipping: {target_path}")
        return None

    r = scan_bytes_pure_onnx(data, target_path)
    if r is None:
        print(f"[-] Unscannable / empty buffer: {target_path}")
        return None

    verdict = "MALICIOUS" if r["label"] == 1 else "BENIGN"
    print("=" * 70)
    print(f" TARGET:       {target_path}")
    print(f" TYPE:         {r['ftype']}  MasterVec: {['%.2f' % v for v in r['master_vec']]}")
    print(f" VERDICT:      {verdict}")
    print(
        f" MALICIOUS:    {r['mal_prob'] * 100:.2f}%  "
        f"(Master:{r.get('master_prob', 0.0)*100:.1f}% PE:{r['experts']['pe']*100:.1f}% "
        f"Gen:{r['experts']['generic']*100:.1f}% JS:{r['experts']['js']*100:.1f}% "
        f"APK:{r['experts']['apk']*100:.1f}% URL:{r['experts']['url']*100:.1f}%)"
    )
    if "inner_string_ml" in r["detail"]:
        sm = r["detail"]["inner_string_ml"]
        print(
            f" INNER STR ML: mal_hits={sm.get('mal_str_hits',0):.2f} "
            f"ben_hits={sm.get('ben_str_hits',0):.2f} "
            f"ratio={sm.get('mal_ben_str_ratio',0):.3f} "
            f"decomp={sm.get('decompiler_strings',0):.2f} "
            f"unicorn={sm.get('unicorn_trace_strings',0):.2f}"
        )
    print("=" * 70)
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
