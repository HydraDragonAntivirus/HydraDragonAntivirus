# openedr_web — Web/WASM edition of the OpenEDR static engine

New standalone project (`OpenEDR/openedr_web`, crate `openedr_web`, `cdylib`).
Runs fully client-side: ML tree ensembles (PE/JS/URL/APK), PE string
rules, heuristics, URL scoring. No filesystem, no Win32, no cloud, no
Hayabusa, no archive extraction, no Unicorn-in-Rust.

## APK support (our own tree model, like PE/JS)

`.apk` files are detected by extension or ZIP central directory
(`AndroidManifest.xml` / `*.dex` / `lib/*.so`) and scored by:

1. **APK forest** (`src/apk.rs` + `src/ml/tree_model.rs`): a fixed 24-float
   feature vector (DEX counts, manifest fields, entropy, sizes, permission
   signals — see `APK_TREE_FEATURE_NAMES`) feeds a random-forest bundle
   (`www/models/apk_trees.bin`), executed by the **same** scorer as the
   PE/JS/URL trees. Python trains, Rust only reads weights — exactly like
   `pe_trees.bin` / `js_trees.bin`.
2. **APK heuristics** (always on, no model needed): SMS-trio permissions,
   dangerous-permission combos, packed high entropy, large DEX API surface,
   native `.so` + sensitive permissions, multidex weight.
3. **YARA-X + HydraSig** over capped manifest/DEX bytes (never the whole
   archive, so 60 MB APKs cannot OOM the tab), with APK file-type tags so
   `FileType: apk` rules match.

New model kind: `web_load_model(3, ...)` loads `apk_trees.bin`;
`web_apk_loaded()` reports 1/0 for the demo status light. Without the
bundle the engine degrades to heuristics+YARA — APKs return
`Unknown`/`Suspicious`/`Malicious`, never `Error`/null pointer.

### Training our own APK model (Python trains, Rust reads)

```bash
pip install lightgbm numpy   # preferred; else: pip install scikit-learn numpy
python tools/apk_train.py \
  --benign  ../HydraDragonAV-Mobile/dataset/benign \
  --malware "../HydraDragonAV-Mobile/dataset/malware/MalwareBazaar/27.06.2026 - 203930_212345/apk" \
  --output www/models/apk_trees.bin
# -> www/models/apk_trees.bin + apk_trees.meta.json (threshold, val stats)
```

Bake the printed threshold into `src/engine.rs::APK_TREE_THRESHOLD`.
`www/models/apk_trees.bin` currently ships a 3-stump starter bundle (SMS
trio / permission count / entropy) so the demo light is green immediately —
replace it with the trained bundle above for real scoring.

Parity check (Python features vs Rust features must match):
```sh
cargo run -p openedr_web --bin apk-feats -- suspicious.apk
python tools/apk_train.py --parity suspicious.apk
```

## Benign whitelist (incl. APK hashes)

`www/hash_rules/benign_sha256.xf` is built from the four
`benign_sha256.txt` copies (static DB, docs, portable ×2), which now include
the SHA-256 of every benign APK in `HydraDragonAV-Mobile/dataset/benign`
(2802 fresh hashes, 259391 keys total):

```sh
cargo run -p xorfilter_writer --release -- benign_sha256.txt benign_sha256.xf
# -> www/hash_rules/benign_sha256.xf
cargo run -p xorfilter_writer --release -- --check benign_sha256.xf <sha256>
```

## What's in / out vs desktop (`openedr_static`)

| Layer | Desktop | Web v1 |
| :--- | :---: | :---: |
| PE/JS/URL tree ML (`.bin`) | ✅ | ✅ (bytes-loaded, same files) |
| APK ML (own forest, `apk_trees.bin`) | ❌ (mobile has its own) | ✅ (same scorer as PE/JS trees, kind 3) |
| APK heuristics (permissions/entropy/DEX) | ❌ | ✅ (no model needed) |
| PE disasm features (idx 51–53) | capstone native | `0.0`, or via capstone.js `_ex` API |
| PE string rules (registry YAML → in-scan) | ❌ (separate `check_registry` API) | ✅ new |
| Null-pad / overlay heuristics | ✅ | ✅ (score-only, no rescan engines) |
| EICAR, SHA-256 whitelist | ✅ | ✅ |
| YARA-X rules (`.yrc` bundle / `.yar` source) | ✅ | ✅ (same engine, `web_load_yara`) |
| ClamAV signatures (~70MB DB) | ✅ | ❌ (engine needs threads; DB fetch is phase 2) |
| Unicorn unpacker | ✅ native | ❌ in-Rust; JS-side assist via unicorn.js |
| Authenticode / catalog | ✅ WinTrust | ❌ (`signer_info` always null) |
| Hayabusa EVTX / registry API | ✅ | ❌ removed by design |
| `scan_time_ms` | measured | always `0` (no clock on wasm32-unknown) |

Thresholds and verdict gating mirror desktop (PE_ML 0.71, JS_ML 0.75,
URL 0.50, Malicious ≥ 0.85, Suspicious ≥ 0.50).

## Vendored sources

`src/ml/{features,js_features,url_features,pe_features,tree_model}.rs` and
`src/report.rs` are byte-identical copies from `openedr_static` except:
`tree_model.rs` lost `from_bin_file` (no fs), `pe_features.rs` lost capstone
(counts arrive from JS). `string_rules.rs` evaluates `pua_registry.yaml`
using hydradragonsig's `RuleSet` engine with FileType PE gating to ensure
rules only match validated PE executables.
The desktop `registry_rules` API path is unsupported — rules run as validated-PE string scans.

## C ABI (linear memory, no wasm-bindgen needed)

`web_alloc / web_free | web_load_model(kind 0/1/2) | web_load_url_whitelist(.xf) |
web_load_benign_whitelist(.xf) | web_set_registry_rules |
web_scan_bytes | web_scan_bytes_ex(has_counts,total,add,mov) |
web_scan_url | web_inspect_url(_content) | web_self_test | web_output_len | web_free_str`

## Whitelists

* URL/domain/IP whitelist: BinaryFuse16 `.xf` via `web_load_url_whitelist`
  (exact host + parent-domain walk, same as before).
* SHA-256 benign whitelist: BinaryFuse16 `.xf` via `web_load_benign_whitelist`
  — aynen IP/domain whitelist gibi. No `.txt` path: the demo only fetches
  `hash_rules/benign_sha256.xf`.

Build the benign filter offline with the shared builder (same key/format as
every other filter in the repo):

```sh
cargo run -p xorfilter_writer --release -- benign_sha256.txt benign_sha256.xf
# -> www/hash_rules/benign_sha256.xf  (~2.16 bytes/key vs ~65 bytes/line txt)
cargo run -p xorfilter_writer --release -- --check benign_sha256.xf <sha256>
cargo run -p xorfilter_writer --release -- --fp benign_sha256.xf 100000 hex
```

## Build

```sh
cd OpenEDR/openedr_web
cargo build --target wasm32-unknown-unknown --release
# -> target/wasm32-unknown-unknown/release/openedr_web.wasm
```

Copy the `.wasm` next to `www/index.html`, copy runtime data (see
`www/vendor/README.txt`), serve over http:
`python3 -m http.server 8080` inside `www/`.

## JS-side assists (`www/app.js`)

* **capstone.js** (`vendor/capstone.js`, global `MCapstone`): disassembles PE
  sections (≤64KB each) → `(total, add, mov)` → `web_scan_bytes_ex`.
  Absent → plain `web_scan_bytes` (features read 0.0).
* **unicorn.js x86** (`vendor/unicorn_x86.js`, global `MUnicorn`): maps the
  image at `0x400000`, runs the entry point (200k insn cap), diffs section
  memory, re-scans changed regions ≥4KB (max 3) and merges them as
  `Unpacked:` detections. Any failure → static-only fallback.
