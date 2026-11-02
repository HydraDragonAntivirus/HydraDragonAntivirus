# PE model training

`train_pe_lgbm.py --features v2` produces the one PE model the scanner uses: a tree
ensemble over the full v2 feature vector (165 features, `openedr_static`
`ml/pe_combined.rs`). The vector describes the file as it is (shell), what is inside it
(the image after emulation, the payload it unpacks to, or the PE an archive / installer
holds), where that inner part came from, and the string counts of both together. The
model sees `inner_source` and `inner_is_pe` as features, so it learns on its own how
much to trust the shell or the content; there is no separate inner / shell model.

## Prerequisites

- Install packages from `requirements.txt` in the Python environment used for training.
- Build `pe_feature_dump` in release mode and make sure `OpenMalwareScannerPortable`
  (which contains `unicorn.dll`) is available at the configured path. The trainer adds
  that folder to `PATH` when it invokes the dumper.
- Configure the malicious and benign PE dataset folders using `dataset_paths.py`
  options or `dataset_paths.json`.

From the repository root, build the feature dumper:

```powershell
cd hydradragon_ml_models/pe_feature_dump
cargo build --release
cd ..
```

## Train

Run from `hydradragon_ml_models`:

```powershell
python train_pe_lgbm.py --features v2
```

This extracts v2 features into `cache_chunks_pe_v2` with `pe_feature_dump` (the
engine's own extractor, so training and scanning see the same numbers), trains on
every sample, and writes `pe_trees.bin`, `pe_model.onnx` and `pe_trees_threshold.json`.
The tree bundle is copied to the `openedr_static` and portable scanner model folders
(`--no-sync` skips that). The scanner loads `models/pe_trees.bin`; without it, PEs get
no ML score.

To reuse already extracted chunks and skip feature extraction:

```powershell
python train_pe_lgbm.py --features v2 --train-only
```

Use `--chunk-dir PATH` if the cached chunks are elsewhere. To only create or refresh
the chunks:

```powershell
python train_pe_lgbm.py --features v2 --extract-only
```

A new `pe_feature_dump` build makes the next run rebuild the chunks.

## Threshold

The report shows recall and false-positive rate on a held-out test set at 0.50, 0.90
and the threshold calibrated for `--target-fpr` (default 0.1 %). The scanner's default
cutoff is `0.95`; change it in the dashboard (ML thresholds, PE) or with
`POST /api/ml-thresholds {"pe": 0.90}`. Validate on held-out samples before deploying.

`python train_pe_lgbm.py` without `--features v2` still trains the old 65-feature v1
model; the scanner does not use it.

See `dataset_paths.py --help` and `python train_pe_lgbm.py --help` for dataset and
training options.
