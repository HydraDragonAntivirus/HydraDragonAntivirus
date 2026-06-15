# HydraDragon ML Trainer

Standalone trainer for HydraDragonAV PE and JavaScript malware models.

HydraDragonAV stays as the scanner/runtime. This crate only trains `.mpk` model files from labeled folders. Nested directories are scanned recursively.

## Your Dataset Paths

PE:

- benign: `C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2`
- malicious: `C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder`

JavaScript:

- benign: `C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\data2`
- malicious: `C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\datamaliciousorder`

## Build Trainer

```cmd
cd /d C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_trainer && cargo build --release
```

## Train PE Model

```cmd
cd /d C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_trainer && target\release\hydradragon_ml_trainer.exe pe --benign "C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2" --malicious "C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder" --output "C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models\pe_model" --epochs 5 --batch-size 256 --threads 0
```

This writes:

```text
C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models\pe_model.mpk
```

## Train JavaScript Model

```cmd
cd /d C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_trainer && target\release\hydradragon_ml_trainer.exe js --benign "C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\data2" --malicious "C:\Users\semae\OneDrive\Belgeler\usbdosyalar\javascript\datamaliciousorder" --output "C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models\js_model" --epochs 5 --batch-size 256 --threads 0
```

This writes:

```text
C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models\js_model.mpk
```

## Use Model in HydraDragonAV Scanner

Build the scanner once:

```cmd
cd /d C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragonav && cargo build --release
```

PE scan with the PE model:

```cmd
set ML_MODEL_PATH=C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models\pe_model.mpk && C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragonav\target\release\hydradragonav.exe scan C:\path\to\sample.exe
```

JavaScript scan with the JavaScript model:

```cmd
set ML_MODEL_PATH=C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon_ml_models\js_model.mpk && C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragonav\target\release\hydradragonav.exe scan C:\path\to\sample.js
```

## Notes

`--threads 0` means full power: use all logical CPU cores for PE/JS feature extraction. To limit CPU usage, replace it with a fixed value like `--threads 8`.

The PE folders are large, so PE feature extraction can take a while. If you want a quick smoke test, temporarily lower `--epochs` to `1`; it still scans all files, but training itself finishes faster after feature extraction.
