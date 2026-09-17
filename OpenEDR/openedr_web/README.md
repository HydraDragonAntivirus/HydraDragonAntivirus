# openedr_web — Web/WASM edition of the OpenEDR static engine

New standalone project (`OpenEDR/openedr_web`, crate `openedr_web`, `cdylib`).
Runs fully client-side: ML tree ensembles, PE string rules, heuristics, URL
scoring. No filesystem, no Win32, no cloud, no Hayabusa, no archive
extraction, no Unicorn-in-Rust.

## What's in / out vs desktop (`openedr_static`)

| Layer | Desktop | Web v1 |
| :--- | :---: | :---: |
| PE/JS/URL tree ML (`.bin`) | ✅ | ✅ (bytes-loaded, same files) |
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

`web_alloc / web_free | web_load_model(kind 0/1/2) | web_set_registry_rules |
web_set_benign | web_scan_bytes | web_scan_bytes_ex(has_counts,total,add,mov) |
web_scan_url | web_self_test | web_output_len | web_free_str`

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
