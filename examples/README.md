# OpenEDR / HydraDragon Static Antivirus SDK Examples

This directory contains production-ready SDK wrappers and sample applications in multiple programming languages to integrate with `openedr_static.dll`.

## 📦 Supported Languages & Directories

| Language | Folder | SDK File | Example File | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Python** | [`python/`](python/) | `openedr_sdk.py` | `scan_example.py`, `openedr_cli.py` | `ctypes` wrapper, JSON parsing, CLI |
| **Python daemon** | [`python/`](python/) | `openedr_daemon.py` | `daemon_example.py` | Polling watcher + worker threads, callbacks, quarantine |

---

## 👁️ Daemon Mode (Python)

```python
from openedr_sdk import OpenEdrScanner
from openedr_daemon import DaemonScanner

scanner = OpenEdrScanner(rules_dir="OpenMalwareScannerPortable")
daemon = DaemonScanner(
    scanner,
    ["C:/Users/you/Downloads"],   # watch dirs
    poll_interval=2.0,            # rescan sweep cadence (s)
    workers=2,                    # parallel scan threads
    flag=("Malicious", "Suspicious"),
    on_detection=lambda hit: print(hit["verdict"], hit["path"]),
    quarantine_dir=None,          # set a path to auto-move hits
).start()
# ... daemon.stop() on exit. stats: daemon.stats
```

Notes: unchanged files are skipped by `(size, mtime)`, identical content by
`sha256` verdict cache. The DLL itself is one-shot only (`scan_file`, ...);
the daemon loop lives in this SDK layer.

| **C** | [`c/`](c/) | `openedr_static.h` | `main.c`, `daemon.c` | Standard C ABI header & FFI |
| **C++** | [`cpp/`](cpp/) | `openedr.hpp` | `main.cpp`, `daemon.cpp` | Modern C++ RAII with auto memory freeing |
| **C# (.NET)** | [`csharp/`](csharp/) | `OpenEdrScanner.cs`, `DaemonWatcher.cs` | `Program.cs` (`dotnet run [-- daemon DIR]`) | P/Invoke wrapper with `IDisposable` |
| **Go** | [`go/`](go/) | `openedr/openedr.go` | `main.go`, `daemon/` | Pure Windows `syscall.LazyDLL` (no CGO needed) |
| **Rust** | [`rust/`](rust/) | `src/main.rs` | `src/main.rs`, `examples/daemon.rs` | Safe Rust FFI binding |
| **Node.js** | [`nodejs/`](nodejs/) | `openedr.js` | `index.js`, `daemon.js` | Fast FFI wrapper via `koffi` |

## 👁️ Daemon Mode (all languages)

| Language | Run |
| :--- | :--- |
| Python | `python daemon_example.py [watchDir]` |
| Node.js | `node daemon.js [watchDir]` |
| C# | `dotnet run -- daemon [watchDir]` |
| Go | `go run ./daemon [watchDir]` |
| Rust | `cargo run --example daemon [watchDir]` |
| C++ | compile `daemon.cpp`, run `daemon.exe [watchDir]` |
| C | compile `daemon.c`, run `daemon.exe [watchDir]` |

All daemons poll the watch dir, scan new/changed files and print
`Malicious`/`Suspicious` hits. Python/Node/C#/Go skip identical content by
SHA-256; Rust/C/C++ skip by (size, mtime) — the DLL itself stays one-shot.

---

## 🚀 C FFI API Overview

```c
// 1. Initialize scanner engine (loads ClamAV, YARA-X, ML models, Signers, Hashes)
int32_t openedr_static_init(const char* base_rules_dir);

// 2. Scan file on disk -> Returns JSON string (caller frees with openedr_static_free_string)
char* openedr_static_scan_file(const char* file_path);

// 3. Scan memory buffer -> Returns JSON string
char* openedr_static_scan_bytes(const uint8_t* data, size_t len, const char* file_name);

// 4. Scan URL using ONNX Tree ML -> Returns JSON string
char* openedr_static_scan_url(const char* url);

// 5. Check Registry key -> Returns JSON string
char* openedr_static_check_registry(const char* reg_path);

// 6. Scan EVTX log file with Hayabusa rules -> Returns JSON string
char* openedr_static_scan_evtx(const char* evtx_path);

// 7. Scan live Windows system event logs -> Returns JSON string
char* openedr_static_scan_system_events(void);

// 8. Check hosts file (NULL = system default) -> Returns JSON string
char* openedr_static_check_hosts_file(const char* hosts_path);

// 9. Restore hosts file (NULL = system default, backup 0/1) -> Returns JSON string
char* openedr_static_restore_hosts_file(const char* hosts_path, int32_t create_backup);

// 10. Free heap-allocated C string
void openedr_static_free_string(char* s);
```

## 📄 Report JSON Schema (`scan_file` / `scan_bytes`)

```jsonc
{
  "target": "C:\\sample.exe",
  "file_size": 457984,
  "sha256": "...",
  "verdict": "Malicious",         // Malicious | Suspicious | Clean | Unknown | Error
  "max_threat_score": 1.0,
  "detections": [
    { "layer": "ClamAV", "name": "Win.Tool.Disabledefender-9973916-0", "score": 1.0 }
  ],
  "signer_info": {
    "is_signed": false,
    "is_trusted": false,
    "signer_name": null,          // Authenticode subject, or catalog signer
    "status": "unsigned",         // trusted | signed_untrusted | unsigned | ...
    "is_catalog_signed": false    // true when trust comes from CatRoot catalog
  },
  "pua_registry_matches": [],
  "scan_time_ms": 810
}
```

---

## 🐍 Python Quickstart

```python
from openedr_sdk import OpenEdrScanner

scanner = OpenEdrScanner(rules_dir="OpenMalwareScannerPortable")
report = scanner.scan_file("sample.exe")
print("Verdict:", report["verdict"])
```

Run example:
```bash
cd examples/python
python scan_example.py
```

CLI (`openedr_cli.py`) wraps the same SDK:

```bash
cd examples/python
python openedr_cli.py scan C:\sample.exe
python openedr_cli.py scan C:\Downloads -r --json
python openedr_cli.py url https://example.com/login
python openedr_cli.py registry "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\App"
python openedr_cli.py evtx C:\Windows\System32\winevt\Logs\Security.evtx
python openedr_cli.py hosts
python openedr_cli.py hosts --restore
```

`--dll` / `--rules` default to `OpenMalwareScannerPortable`. Exit code `1` means Malicious/Suspicious.

---

## ⚡ C++ Quickstart

```cpp
#include "openedr.hpp"

openedr::Scanner scanner("OpenMalwareScannerPortable");
std::string report = scanner.scan_file("sample.exe");
std::cout << report << std::endl;
```

---

## 🔷 C# (.NET) Quickstart

```csharp
using OpenEdr.Sdk;

using var scanner = new OpenEdrScanner("OpenMalwareScannerPortable");
string report = scanner.ScanFile("sample.exe");
Console.WriteLine(report);
```

---

## 🦫 Go Quickstart

```go
scanner, err := openedr.NewScanner("openedr_static.dll", "OpenMalwareScannerPortable")
report, err := scanner.ScanFile("sample.exe")
fmt.Println(report)
```

---

## 🟢 Node.js Quickstart

```javascript
const { OpenEdrScanner } = require('./openedr');

const scanner = new OpenEdrScanner('openedr_static.dll', 'OpenMalwareScannerPortable');
const report = scanner.scanFile('sample.exe');
console.log('Verdict:', report.verdict);
```
