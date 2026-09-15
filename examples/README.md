# OpenEDR / HydraDragon Static Antivirus SDK Examples

This directory contains production-ready SDK wrappers and sample applications in multiple programming languages to integrate with `openedr_static.dll`.

## 📦 Supported Languages & Directories

| Language | Folder | SDK File | Example File | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Python** | [`python/`](python/) | `openedr_sdk.py` | `scan_example.py` | `ctypes` wrapper with JSON parsing |
| **C** | [`c/`](c/) | `openedr_static.h` | `main.c` | Standard C ABI header & FFI |
| **C++** | [`cpp/`](cpp/) | `openedr.hpp` | `main.cpp` | Modern C++ RAII with auto memory freeing |
| **C# (.NET)** | [`csharp/`](csharp/) | `OpenEdrScanner.cs` | `Program.cs` | P/Invoke wrapper with `IDisposable` |
| **Go** | [`go/`](go/) | `openedr/openedr.go` | `main.go` | Pure Windows `syscall.LazyDLL` (no CGO needed) |
| **Rust** | [`rust/`](rust/) | `src/main.rs` | `src/main.rs` | Safe Rust FFI binding |
| **Node.js** | [`nodejs/`](nodejs/) | `openedr.js` | `index.js` | Fast FFI wrapper via `koffi` |

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

// 6. Query Comodo FLS cloud (1=Safe, 2=Malicious, 0=Unknown, -1=Error)
int32_t openedr_static_check_fls_sha1(const char* sha1_hex);

// 7. Free heap-allocated C string
void openedr_static_free_string(char* s);
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
