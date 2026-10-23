# PE model training

`train_pe_lgbm.py` produces two PE models: one for successfully unpacked PE contents
and one for samples without a parseable unpacked PE. Runtime uses only these models;
the old single PE model and combined v2 model are not loaded for inference.

## Prerequisites

- Install packages from `requirements.txt` in the Python environment used for training.
- For v2 extraction, build `pe_feature_dump` in release mode and make sure
  `OpenMalwareScannerPortable` (which contains `unicorn.dll`) is available at the
  configured path. The trainer adds that folder to `PATH` when it invokes the dumper.
- Configure the normal malicious and benign PE dataset folders using
  `dataset_paths.py` options or `dataset_paths.json`.

From the repository root, build the feature dumper:

```powershell
cd hydradragon_ml_models/pe_feature_dump
cargo build --release
cd ..
```

## Train the unpacked-content model

Run from `hydradragon_ml_models` to train both sides of the inference split:

```powershell
python train_pe_lgbm.py --features v2 --inner-only
python train_pe_lgbm.py --features v2 --not-unpacked-only
```

This extracts v2 features into `cache_chunks_pe_v2`, then trains from samples where
the emulator successfully produced a parseable inner PE (`inner_source = Unpacked`,
`inner_is_pe = 1`). It excludes extracted archive members and failed/no-unpack samples.
The training columns are only the 65 inner PE features, inner ASCII/UTF-16 string
features, and the inner .NET marker. Shell, combined-string, and shell-relative
features are not used.

The run writes `pe_trees_inner.bin`, `pe_model_inner.onnx`, and
`pe_trees_inner_threshold.json`, and copies the tree bundle to the `openedr_static`
and portable scanner model folders when present. The scanner uses this model for
successfully unpacked inner PEs. If the inner model is absent, it does not substitute
the shell model for that sample, avoiding a shell-driven ML verdict.

The second command trains the complementary shell-only model from samples without a
successfully unpacked parseable inner PE. It uses only the outer PE structure, shell
strings, and shell .NET marker; inner and combined features are excluded. It writes
`pe_trees_shell.bin`, `pe_model_shell.onnx`, and `pe_trees_shell_threshold.json`, then
syncs the tree bundle to both scanner model folders. At scan time, a parseable
unpacked inner PE selects `pe_trees_inner.bin`; every other PE selects
`pe_trees_shell.bin`. There is no PE model fallback: if the model for the selected
route is missing, that sample receives no PE ML score.

The scanner's PE cutoffs are independent: dashboard/API field `peInner` applies to
the inner model and `peShell` to the shell model. Both defaults are `0.95`. Validate
thresholds on held-out samples before deployment.

To reuse already extracted v2 chunks and skip feature extraction:

```powershell
python train_pe_lgbm.py --features v2 --inner-only --train-only
python train_pe_lgbm.py --features v2 --not-unpacked-only --train-only
```

Use `--chunk-dir PATH` if the cached chunks are elsewhere. If you only want to create
or refresh the raw v2 chunks first:

```powershell
python train_pe_lgbm.py --features v2 --extract-only
```

Check the training report and calibrated threshold before deploying a newly trained
model. Inner-model coverage depends on how many benign and malicious samples actually
unpack to a valid PE; samples that do not unpack successfully are not part of this
model's training set.

See `dataset_paths.py --help` and `python train_pe_lgbm.py --help` for dataset and
training options.
