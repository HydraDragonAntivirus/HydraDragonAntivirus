#!/usr/bin/env python3
"""Find poisoned / mislabeled rows in the PE v2 training chunks (the ones behind false positives).

Every row is scored by a model that never saw it (k-fold out-of-fold score), so a row
the rest of the data contradicts stands out instead of being memorised:

  mal_suspect  labelled malicious, out-of-fold score below --mal-cut: the rest of the
               data says it looks clean. A clean file in a malware folder (a PUA's legit
               installer, a runtime DLL dropped next to malware, ...) teaches the model
               that clean code is malware: that is what turns into false positives.
  ben_flagged  labelled benign, scored at or above --threshold: a false positive the
               model would raise today (or malware in a clean folder).
  conflict     the same feature vector under both labels (dropped by the trainer).

Each ben_flagged row is traced to the malicious-labelled rows that share the most tree
leaves with it in a model trained on everything (`blamed` = how many false positives a
row is among the top --blame-k causes of). A mal_suspect with a high `blamed` count is
the poison to look at first.

Output (nothing in the dataset or the chunks is changed):
  pe_label_noise.csv           every finding, worst first, with the file path when the
                               chunk has one (chunks built before train_pe_lgbm stored
                               paths have none: rebuild them to get paths)
  pe_label_noise_exclude.txt   row keys of the mal_suspect rows; review it, delete the
                               lines you want kept, then
                               `train_pe_lgbm.py --features v2 --train-only --exclude-rows pe_label_noise_exclude.txt`

A file that really is clean is better fixed at the source: give it a "clean" analyst
verdict (human_verdicts.jsonl), which every later training run follows.
"""

import argparse
import csv
import glob
import hashlib
import os
import sys

import joblib
import lightgbm as lgb
import numpy as np
from sklearn.model_selection import StratifiedKFold

import dataset_paths


def row_key(row: np.ndarray) -> str:
    """Stable id of a feature row (same as train_pe_lgbm --exclude-rows)."""
    return hashlib.sha1(np.ascontiguousarray(row, dtype=np.float32).tobytes()).hexdigest()[:20]


def load(chunk_dir):
    files = dataset_paths.ChunkManifest(chunk_dir).chunk_files(
        chunk_dir, "chunk_pe_", glob.glob(os.path.join(chunk_dir, "chunk_pe_*.joblib")))
    X, y, src, paths, names = [], [], [], [], None
    for cf in files:
        d = joblib.load(cf)
        if len(d["y"]) == 0:
            continue
        n = list(d.get("names", []))
        if names is None:
            names = n
        elif n != names:
            print(f"[*] skipping {os.path.basename(cf)}: other feature names than the other chunks")
            continue
        X.append(d["X"])
        y.append(d["y"])
        base = os.path.basename(cf)
        src += [f"{base}:{i}" for i in range(len(d["y"]))]
        p = d.get("paths")
        paths += list(p) if p is not None and len(p) == len(d["y"]) else [""] * len(d["y"])
    if not X:
        sys.exit(f"no PE chunks in {chunk_dir}")
    return np.vstack(X).astype(np.float32), np.concatenate(y).astype(np.int32), src, paths, names


def model(trees):
    # Same shape as train_pe_lgbm; min_child_samples keeps a single bad row from getting its own leaf.
    return lgb.LGBMClassifier(n_estimators=trees, learning_rate=0.05, num_leaves=127, max_depth=10,
                              min_child_samples=50, subsample=0.85, subsample_freq=1,
                              colsample_bytree=0.85, random_state=42, n_jobs=-1, verbose=-1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chunk-dir", default="cache_chunks_pe_v2")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--threshold", type=float, default=0.95, help="the scanner's PE cutoff (dashboard: ML thresholds)")
    ap.add_argument("--mal-cut", type=float, default=0.10, help="malicious-labelled rows scoring below this are suspects")
    ap.add_argument("--blame-k", type=int, default=10, help="malicious rows blamed per false positive")
    ap.add_argument("--max-blame", type=int, default=5000, help="trace at most this many false positives")
    # Next to the scripts by default, so train_pe_lgbm --exclude-rows finds it from any folder.
    base = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--out", default=os.path.join(base, "pe_label_noise.csv"))
    ap.add_argument("--exclude-out", default=os.path.join(base, "pe_label_noise_exclude.txt"))
    args = ap.parse_args()
    if not os.path.isabs(args.chunk_dir) and not os.path.isdir(args.chunk_dir):
        args.chunk_dir = os.path.join(base, args.chunk_dir)

    X, y, src, paths, _ = load(args.chunk_dir)
    keys = np.array([row_key(r) for r in X])
    print(f"[*] {len(X)} rows ({int(y.sum())} malicious, {int((y == 0).sum())} benign), "
          f"{sum(1 for p in paths if p)} with a file path")

    # One row per (key, label); a key under both labels is a conflict.
    lab_of = {}
    for k, l in zip(keys, y):
        lab_of.setdefault(k, set()).add(int(l))
    conflict = {k for k, s in lab_of.items() if len(s) == 2}
    first = {}
    for i, (k, l) in enumerate(zip(keys, y)):
        if k not in conflict:
            first.setdefault((k, int(l)), i)
    uidx = np.array(sorted(first.values()))
    Xu, yu = X[uidx], y[uidx]
    print(f"[*] {len(uidx)} unique rows, {len(conflict)} feature vectors under both labels")

    oof = np.zeros(len(uidx), dtype=np.float64)
    skf = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=42)
    for f, (tr, te) in enumerate(skf.split(Xu, yu), 1):
        m = model(args.trees).fit(Xu[tr], yu[tr])
        oof[te] = m.predict_proba(Xu[te])[:, 1]
        print(f"  fold {f}/{args.folds} done", flush=True)

    ben, mal = yu == 0, yu == 1
    fp = ben & (oof >= args.threshold)
    sus = mal & (oof < args.mal_cut)
    print(f"[+] out-of-fold at {args.threshold}: FP={int(fp.sum())} of {int(ben.sum())} benign "
          f"({fp.sum() / max(ben.sum(), 1) * 100:.4f}%), recall={(mal & (oof >= args.threshold)).sum() / max(mal.sum(), 1) * 100:.2f}%")
    print(f"[+] malicious-labelled rows that look clean (oof < {args.mal_cut}): {int(sus.sum())}")

    # Blame: which malicious-labelled rows land in the same leaves as each false positive.
    blamed = np.zeros(len(uidx), dtype=np.int64)
    fp_idx = np.flatnonzero(fp)
    if len(fp_idx):
        fp_idx = fp_idx[np.argsort(-oof[fp_idx])][: args.max_blame]
        print(f"[*] tracing {len(fp_idx)} false positives to their malicious neighbours...")
        full = model(args.trees).fit(Xu, yu)
        mal_idx = np.flatnonzero(mal)
        leaves_mal = full.predict(Xu[mal_idx], pred_leaf=True).astype(np.int32)
        leaves_fp = full.predict(Xu[fp_idx], pred_leaf=True).astype(np.int32)
        k = min(args.blame_k, len(mal_idx))
        for lf in leaves_fp:
            shared = (leaves_mal == lf).sum(axis=1)
            top = np.argpartition(-shared, k - 1)[:k]
            blamed[mal_idx[top]] += 1

    rows = []
    for j in np.flatnonzero(sus | fp | (blamed > 0)):
        i = uidx[j]
        kind = "mal_suspect" if sus[j] else ("ben_flagged" if fp[j] else "mal_blamed")
        rows.append((kind, keys[i], int(yu[j]), float(oof[j]), int(blamed[j]), src[i], paths[i]))
    for i in range(len(X)):
        if keys[i] in conflict:
            rows.append(("conflict", keys[i], int(y[i]), float("nan"), 0, src[i], paths[i]))
    order = {"mal_suspect": 0, "mal_blamed": 1, "ben_flagged": 2, "conflict": 3}
    rows.sort(key=lambda r: (order[r[0]], -r[4], r[3] if r[2] == 1 else -r[3]))
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["kind", "key", "label", "oof_score", "blamed", "chunk_row", "path"])
        for r in rows:
            w.writerow([r[0], r[1], r[2], f"{r[3]:.5f}", r[4], r[5], r[6]])
    with open(args.exclude_out, "w", encoding="utf-8") as fh:
        fh.write("# row keys to leave out of training (train_pe_lgbm.py --exclude-rows); delete lines to keep a row\n")
        for r in rows:
            if r[0] == "mal_suspect":
                fh.write(f"{r[1]}  # oof={r[3]:.4f} blamed={r[4]} {r[6] or r[5]}\n")

    hot = int(((blamed > 0) & sus).sum())
    print(f"[+] {hot} of the suspects are among the causes of a false positive")
    print(f"[+] wrote {args.out} ({len(rows)} rows) and {args.exclude_out} ({int(sus.sum())} keys)")


if __name__ == "__main__":
    main()
