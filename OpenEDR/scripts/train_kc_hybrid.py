import json, math, os, sys
from collections import Counter
import numpy as np

IDENTITY_KEYS = {"imagefile", "imagepath", "cmdline", "commandline", "exepath", "appname"}
EXCLUDE_SUB = {"verdict", "threat", "hash", "ticktime", "creationtime", "accesstime", "$$"}
EXCLUDE_EQ = {"id", "pid", "gid", "sid", "time"}
EXCLUDE_END = ("_id", ".id")
DATA_KEYS = {"data", "content", "blob", "script", "scripttext", "value"}

def key_excluded(kl: str) -> bool:
    if kl in EXCLUDE_EQ: return True
    if kl.endswith(EXCLUDE_END): return True
    return any(s in kl for s in EXCLUDE_SUB)

def dirclass(p: str) -> str:
    l = p.lower().replace("/", "\\")
    if not l: return "none"
    if "startup" in l: return "startup"
    if "\\system32" in l or "\\syswow64" in l or l.startswith("%systemroot%"): return "system32"
    if "programdata" in l: return "programdata"
    if "\\temp\\" in l or "\\tmp\\" in l: return "temp"
    if "appdata" in l: return "appdata"
    if l.startswith("\\\\.\\pipe\\"): return "pipe"
    if "harddisk" in l: return "device"
    if "\\windows\\" in l or l.startswith("%systemroot%"): return "windows_other"
    if "program files" in l: return "progfiles"
    if "\\users\\" in l: return "user"
    return "other"

def ext_of(p: str) -> str:
    l = p.lower()
    pos = l.rfind(".")
    if pos != -1:
        tail = l[pos + 1 :]
        if 1 <= len(tail) <= 5 and tail.isalnum():
            return tail
    return "none"

def is_pathy(s: str) -> bool:
    return ("\\" in s or "/" in s or s.startswith("%")) and len(s) > 3

def logbucket(x: float) -> str:
    if not math.isfinite(x) or x <= 0.0: return "0"
    return str(int(math.floor(math.log10(x + 1.0))))

def trim_prefix(prefix: str) -> str:
    return prefix[:-1] if prefix.endswith(".") else prefix

def flatten(prefix: str, val, f: dict, depth: int = 0):
    if depth > 4 or len(f) > 2000: return
    if isinstance(val, dict):
        for k, v in val.items():
            kl = k.lower()
            if key_excluded(kl): continue
            if "kernelstack" in kl: continue
            if kl in DATA_KEYS:
                f[f"{prefix}{kl}_present"] = 1.0
                length = len(v) if isinstance(v, str) else len(str(v))
                f[f"{prefix}{kl}_len~{logbucket(length)}"] = 1.0
                continue
            if any(idk in kl for idk in IDENTITY_KEYS):
                f[f"has_{prefix}{kl}"] = 1.0
                continue
            flatten(f"{prefix}{kl}.", v, f, depth + 1)
    elif isinstance(val, list):
        f[f"len_{trim_prefix(prefix)}={logbucket(len(val))}"] = 1.0
        for item in val[:5]:
            flatten(prefix, item, f, depth + 1)
    elif isinstance(val, bool):
        f[f"{trim_prefix(prefix)}={1 if val else 0}"] = 1.0
    elif isinstance(val, (int, float)):
        f[f"{trim_prefix(prefix)}~{logbucket(float(val))}"] = 1.0
    elif isinstance(val, str):
        if not val or val in ("<undefined>", "null"): return
        if is_pathy(val):
            f[f"{prefix}dir={dirclass(val)}"] = 1.0
            f[f"{prefix}ext={ext_of(val)}"] = 1.0
            f[f"{prefix}len~{logbucket(len(val))}"] = 1.0
        elif len(val) > 80:
            f[f"{prefix}longlen~{logbucket(len(val))}"] = 1.0
        else:
            f[f"{trim_prefix(prefix)}={val.lower()}"] = 1.0

def kstack_features(raw: dict, f: dict):
    for key in ("kernelStackSymbols", "kernelstacksymbols", "kernelStack", "kernelstack"):
        s = raw.get(key)
        if not s or not isinstance(s, str): continue
        mods = set()
        nframes = 0
        delims = [";", ","]
        tokens = [s]
        for d in delims:
            new_tokens = []
            for t in tokens: new_tokens.extend(t.split(d))
            tokens = new_tokens
        for p in tokens:
            p = p.strip().lower()
            if not p or all(c == "0" for c in p): continue
            nframes += 1
            first = p.split("+")[0].split("!")[0]
            base = os.path.basename(first.replace("/", "\\"))
            if base and len(base) < 64: mods.add(base)
        for m in sorted(mods):
            f[f"kstack_mod={m}"] = 1.0
        f[f"kstack_frames~{logbucket(nframes)}"] = 1.0
        break

def extract_features(event: str, details: str, raw: dict, dt_prev=None) -> dict:
    f = {f"event={event}": 1.0}
    for tag, name in [("[File:", "File"), ("[Reg:", "Reg"), ("[API:", "API"), ("[Net:", "Net")]:
        if details.startswith(f" {tag}") or details.startswith(tag):
            f[f"det={name}"] = 1.0
    best = None
    for tag in ("[File:", "[Reg:", "[API:", "[Net:"):
        pos = details.find(tag)
        if pos != -1:
            if best is None or pos < best[0]: best = (pos, tag)
    if best is not None:
        after = details[best[0] :]
        colon = after.find(":")
        if colon != -1:
            val = after[colon + 1 :].lstrip()
            end = val.find("]")
            if end != -1:
                val = val[:end]
                if is_pathy(val):
                    f[f"detdir={dirclass(val)}"] = 1.0
                    f[f"detext={ext_of(val)}"] = 1.0
                elif "!" in val:
                    parts = val.split("!", 1)
                    f[f"detmod={parts[0].lower()}"] = 1.0
                    f[f"detfn={parts[1].lower()}"] = 1.0
    flatten("raw.", raw, f, 0)
    kstack_features(raw, f)
    if dt_prev is not None and dt_prev >= 0:
        f[f"dt_prev~{logbucket(dt_prev)}"] = 1.0
    else:
        f["dt_prev~none"] = 1.0
    f["has_net"] = 1.0 if "[Net:" in details else 0.0
    f["has_target"] = 1.0 if isinstance(raw.get("target"), dict) else 0.0
    f["has_thread"] = 1.0 if isinstance(raw.get("thread"), dict) else 0.0
    f["has_stack"] = 1.0 if raw.get("kernelStackSymbols") is not None else 0.0
    acc = raw.get("accessMask")
    if acc is not None: f[f"access={acc}"] = 1.0
    else: f["access=None"] = 1.0
    return f

def is_malicious_record(exe: str, raw: dict) -> bool:
    l_exe = exe.lower()
    if "trojan" in l_exe or "yddqr" in l_exe or "malware" in l_exe: return True
    if raw.get("flsVerdict") in (2, 3, "2", "3"): return True
    if raw.get("threatName"): return True
    return False

def main():
    dataset_path = r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\data\unknown_killchain_20260912.jsonl"
    output_model_path = r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenEDR\owlyshield_predict\models\kc_hybrid_model.json"
    if len(sys.argv) > 1: dataset_path = sys.argv[1]
    if len(sys.argv) > 2: output_model_path = sys.argv[2]
    print(f"[*] Loading dataset from: {dataset_path}")
    benign_features = []
    malware_features = []
    feature_freq = Counter()
    total_lines = 0
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            try: d = json.loads(line)
            except Exception: continue
            exe = d.get("exe", "")
            event = d.get("event", "")
            details = d.get("details", "")
            raw = d.get("raw", {})
            feats = extract_features(event, details, raw)
            for k in feats: feature_freq[k] += 1
            if is_malicious_record(exe, raw): malware_features.append(feats)
            else: benign_features.append(feats)
    print(f"[*] Total parsed: {total_lines}")
    print(f"    - Benign events: {len(benign_features)}")
    print(f"    - Malware events: {len(malware_features)}")
    vocab = [k for k, count in feature_freq.items() if count >= 3]
    vocab.sort()
    feat_to_idx = {k: i for i, k in enumerate(vocab)}
    n_features = len(vocab)
    print(f"[*] Vocabulary size: {n_features}")
    def build_matrix(feature_list):
        mat = np.zeros((len(feature_list), n_features), dtype=np.float32)
        for row_idx, f_dict in enumerate(feature_list):
            for k, v in f_dict.items():
                if k in feat_to_idx: mat[row_idx, feat_to_idx[k]] = v
        return mat
    print("[*] Building feature matrices...")
    X_benign = build_matrix(benign_features)
    X_malware = build_matrix(malware_features)
    EPS = 1e-4
    mu_benign = np.mean(X_benign, axis=0)
    sd_benign = np.std(X_benign, axis=0) + EPS
    mu_malware = np.mean(X_malware, axis=0)
    sd_malware = np.std(X_malware, axis=0) + EPS
    def compute_distances(X, mu, sd):
        z = np.abs(X - mu) / sd
        return np.sum(z, axis=1)
    print("[*] Computing centroid distance distributions...")
    dist_benign_to_benign = compute_distances(X_benign, mu_benign, sd_benign)
    dist_benign_to_malware = compute_distances(X_benign, mu_malware, sd_malware)
    dist_malware_to_malware = compute_distances(X_malware, mu_malware, sd_malware)
    dist_malware_to_benign = compute_distances(X_malware, mu_benign, sd_benign)
    benign_threshold = float(np.percentile(dist_benign_to_benign, 95))
    malware_threshold = float(np.percentile(dist_malware_to_malware, 95))
    print(f"[*] Distance Metrics:")
    print(f"    - Benign intra-distance (mean / 95th): {np.mean(dist_benign_to_benign):.2f} / {benign_threshold:.2f}")
    print(f"    - Benign to Malware-centroid: {np.mean(dist_benign_to_malware):.2f}")
    print(f"    - Malware intra-distance (mean / 95th): {np.mean(dist_malware_to_malware):.2f} / {malware_threshold:.2f}")
    print(f"    - Malware to Benign-centroid: {np.mean(dist_malware_to_benign):.2f}")
    benign_correct = sum(1 for d_b, d_m in zip(dist_benign_to_benign, dist_benign_to_malware) if d_b <= benign_threshold and d_b < d_m)
    benign_false_pos = sum(1 for d_b, d_m in zip(dist_benign_to_benign, dist_benign_to_malware) if d_m <= malware_threshold and d_m < d_b)
    benign_unknown = len(benign_features) - benign_correct - benign_false_pos
    malware_correct = sum(1 for d_m, d_b in zip(dist_malware_to_malware, dist_malware_to_benign) if d_m <= malware_threshold and d_m < d_b)
    malware_false_neg = sum(1 for d_m, d_b in zip(dist_malware_to_malware, dist_malware_to_benign) if d_b <= benign_threshold and d_b < d_m)
    malware_unknown = len(malware_features) - malware_correct - malware_false_neg
    print("\n=== Validation Evaluation (Tri-State Decision) ===")
    print(f"Benign Samples ({len(benign_features)}):")
    print(f"  -> Clean (Recognized White): {benign_correct} ({benign_correct / len(benign_features):.1%})")
    print(f"  -> Unknown / Anomaly (HIPS Candidate): {benign_unknown} ({benign_unknown / len(benign_features):.1%})")
    print(f"  -> False Positive (Classified Malware): {benign_false_pos} ({benign_false_pos / len(benign_features):.1%})")
    print(f"Malware Samples ({len(malware_features)}):")
    print(f"  -> Malware (Recognized Black / Quarantine): {malware_correct} ({malware_correct / len(malware_features):.1%})")
    print(f"  -> Unknown / Anomaly (HIPS Candidate): {malware_unknown} ({malware_unknown / len(malware_features):.1%})")
    print(f"  -> False Negative (Classified Clean): {malware_false_neg} ({malware_false_neg / len(malware_features):.1%})")
    model_data = {
        "kind": "hybrid_centroid",
        "n_features": n_features,
        "vocab": vocab,
        "mu_benign": [float(x) for x in mu_benign],
        "sd_benign": [float(x) for x in sd_benign],
        "mu_malware": [float(x) for x in mu_malware],
        "sd_malware": [float(x) for x in sd_malware],
        "meta": {
            "benign_threshold": benign_threshold,
            "malware_threshold": malware_threshold,
            "training_samples": total_lines,
            "benign_count": len(benign_features),
            "malware_count": len(malware_features),
        },
    }
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    with open(output_model_path, "w", encoding="utf-8") as f:
        json.dump(model_data, f, indent=2)
    print(f"\n[+] Successfully saved trained hybrid model to: {output_model_path}")

if __name__ == "__main__": main()
