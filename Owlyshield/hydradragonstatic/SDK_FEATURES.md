# SDK-Inspired Features in HydraDragonStatic

This document describes the professional antivirus SDK design patterns incorporated into HydraDragonStatic, inspired by enterprise AV engine architectures.

## Overview

HydraDragonStatic now includes enterprise-grade features inspired by professional antivirus SDK architectures, while maintaining its deterministic, signature-based scanning philosophy. These enhancements provide structured APIs and comprehensive metadata for professional deployment scenarios.

## Inspiration Source

The architecture patterns are inspired by professional antivirus engine SDKs that provide:
- Structured scan result codes for programmatic integration
- Memory scanning capabilities for runtime analysis
- Registry key/value buffer scanning for deterministic integration tests and telemetry pipelines
- Archive unpacking configuration with depth and size controls
- Core initialization options for flexible engine behavior
- Reusable core wrapper with initialized core metadata
- Comprehensive scan statistics for monitoring and reporting
- Industry-standard threat naming conventions
- Cached atom/anchor matching for high-throughput static signature evaluation

## New Features

### 1. Scan Result Codes (`ScanResultCode`)

Professional AV-style result codes matching industry standards:

```rust
pub enum ScanResultCode {
    Ok = 0,              // File does not contain malicious code
    Heuristic = 1,       // Detected suspicious code (heuristic analysis)
    Malicious = 2,       // Malicious code is detected (infected file)
    GeneralError = -1,   // General error of the scan engine
    WrongHandle = -2,    // Incorrect scan/core handle range
    UnknownHandle = -3,  // Scan/core handle is not initialized
    PathTooLong = -4,    // Supplied file path is too long
    OpenError = -5,      // Error opening/reading the file
    FileTooLarge = -6,   // File too large for scanning
    UnsupportedFormat = -7, // Unsupported file format
}
```

**Usage:**
- Result codes are automatically set based on scan verdict
- Included in JSON output as numeric `result_code` field
- Helper methods: `is_clean()`, `is_infected()`, `is_error()`

### 2. Memory Scanning API

Scan in-memory buffers without disk I/O:

```rust
use hydradragonstatic::{models::MemoryScanContext, scan_memory, ScanOptions};

let ctx = MemoryScanContext {
    buffer: suspicious_bytes,
    identifier: "process_memory_region".to_string(),
    base_address: Some(0x400000),
};

let report = scan_memory(&ctx, &rules, &options)?;
```

**Use Cases:**
- Runtime process memory analysis
- Network stream scanning
- Extracted payload analysis
- Forensic memory dumps

### 3. Registry Buffer Scanning API

Scan caller-supplied registry key/value content without reading the live registry:

```rust
use hydradragonstatic::{models::RegistryScanContext, scan_registry_key};

let ctx = RegistryScanContext {
    key: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
    value_name: Some("Updater".to_string()),
    value_data: Some(b"powershell -enc ...".to_vec()),
};

let report = scan_registry_key(&ctx, &rules, &options)?;
```

### 4. Archive Unpacking Configuration (`UnpackConfig`)

Control in-memory ZIP/JAR/APK member scanning behavior:

```rust
pub struct UnpackConfig {
    pub max_archive_size: u64,      // Maximum size of archive (bytes)
    pub max_archive_depth: u32,     // Maximum extraction depth
    pub enable_archives: bool,      // Enable ZIP/archive unpacking
    pub enable_installers: bool,    // Enable installer unpacking
    pub enable_containers: bool,    // Enable container format unpacking
    pub break_on_threat: bool,      // Stop on first detected threat
}
```

**Default Configuration:**
- `max_archive_size`: 100 MB
- `max_archive_depth`: 5 levels
- `enable_archives`: true
- `enable_installers`: false
- `enable_containers`: false
- `break_on_threat`: true

CLI controls:

```bash
hydradragonstatic sample.zip --rules rules/ --max-archive-mib 100 --max-archive-depth 5
hydradragonstatic sample.zip --rules rules/ --no-archive-scan
hydradragonstatic sample.zip --rules rules/ --no-break-archive-scan
```

### 5. Core Initialization Options (`CoreInitOptions`)

Professional engine initialization controls:

```rust
pub struct CoreInitOptions {
    pub break_archive_scan: bool,   // Stop checking archive on detected threats
    pub debug_mode: bool,           // Run core in debug mode with verbose logging
    pub load_simple: bool,          // Load reduced signature base
    pub enable_heuristics: bool,    // Enable heuristic analysis
    pub enable_behavioral: bool,    // Enable behavioral detection
}
```

**Default Configuration:**
- `break_archive_scan`: true
- `debug_mode`: false
- `load_simple`: false
- `enable_heuristics`: true
- `enable_behavioral`: true

### 6. Reusable Core Wrapper (`EngineCore`)

Initialize once and reuse rules/options across file, memory, and registry scans:

```rust
use hydradragonstatic::{EngineCore, ScanOptions};

let core = EngineCore::init(rules, ScanOptions::default());
let core_data = core.core_data();
let report = core.scan_path(sample_path)?;
```

`core_data.signature_records` reports how many external signatures were loaded.

### 7. Scan Statistics (`ScanStatistics`)

Comprehensive scan metadata tracking:

```rust
pub struct ScanStatistics {
    pub files_scanned: u32,          // Number of objects scanned
    pub infections_found: u32,       // Number of infected objects
    pub suspicious_found: u32,       // Number of suspicious objects
    pub is_container: bool,          // Is this file a container/archive
    pub archive_members: u32,        // Number of archive members extracted
    pub scan_duration_ms: u64,       // Scan duration in milliseconds
    pub signature_records_used: u32, // Signature database records used
}
```

**Automatic Tracking:**
- Scan duration measured automatically
- Container detection based on file type
- Infection/suspicious counts updated from findings
- Statistics included in JSON output

### 8. Archive Member Results (`ArchiveMemberResult`)

Track nested file scanning results:

```rust
pub struct ArchiveMemberResult {
    pub name: String,               // Display name of extracted file
    pub path: String,               // Full virtual path within archive
    pub result_code: ScanResultCode, // Scan result code
    pub threat_name: Option<String>, // Detected threat name if infected
    pub size: u64,                  // Member file size
    pub depth: u32,                 // Nested depth level
}
```

### 9. Threat Name Detection

SDK-style threat naming from matched signatures:

```json
{
  "threat_name": "Trojan.Generic.Malware",
  "result_code": 2,
  "verdict": "malware",
  "malware_families": ["Trojan.Generic"]
}
```

**Threat Name Generation:**
- Uses `family` field from matched rule if available
- Falls back to `rule_id` if no family specified
- Follows industry-standard malware naming conventions
- Included in JSON output as `threat_name` field

## Integration Examples

### Basic File Scan with SDK Features

```rust
use hydradragonstatic::{scan_path, ScanOptions, models::*};

let options = ScanOptions {
    max_file_size: Some(128 * 1024 * 1024),
    core_options: CoreInitOptions {
        enable_heuristics: true,
        enable_behavioral: true,
        ..Default::default()
    },
    unpack_config: UnpackConfig {
        max_archive_size: 50 * 1024 * 1024,
        max_archive_depth: 3,
        ..Default::default()
    },
    ..Default::default()
};

let report = scan_path(&path, &rules, &options)?;

println!("Result Code: {:?}", report.result_code);
println!("Threat Name: {:?}", report.threat_name);
println!("Scan Duration: {}ms", report.statistics.scan_duration_ms);
```

### Memory Scanning

```rust
use hydradragonstatic::{scan_memory, models::MemoryScanContext};

let ctx = MemoryScanContext {
    buffer: process_memory,
    identifier: format!("PID_{}_Region_{:x}", pid, base_addr),
    base_address: Some(base_addr),
};

let report = scan_memory(&ctx, &rules, &options)?;

if report.result_code.is_infected() {
    println!("Infected memory region: {}", report.threat_name.unwrap());
}
```

### Registry Buffer Scanning

```rust
use hydradragonstatic::{scan_registry_key, models::RegistryScanContext};

let ctx = RegistryScanContext {
    key: r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System".to_string(),
    value_name: Some("DisableTaskMgr".to_string()),
    value_data: Some(b"1".to_vec()),
};

let report = scan_registry_key(&ctx, &rules, &options)?;
```

## JSON Output Schema

The SDK features add the following fields to JSON output:

```json
{
  "path": "sample.exe",
  "result_code": 2,
  "verdict": "malware",
  "threat_name": "Trojan.Generic.Malware",
  "statistics": {
    "files_scanned": 1,
    "infections_found": 1,
    "suspicious_found": 0,
    "is_container": false,
    "archive_members": 0,
    "scan_duration_ms": 45,
    "signature_records_used": 421
  },
  "archive_members": [],
  "findings": [...]
}
```

## Design Philosophy

These SDK-inspired features maintain HydraDragonStatic's core principles:

1. **Deterministic**: All features produce consistent, reproducible results
2. **Signature-Based**: No machine learning or cloud dependencies
3. **External Rules**: No built-in signatures, all rules are external
4. **Transparent**: Clear result codes and comprehensive statistics
5. **Professional**: Enterprise-grade APIs for production deployment

## Compatibility

- All existing functionality remains unchanged
- New fields are optional in JSON output
- Default configurations match previous behavior
- Backward compatible with existing rule files

## Performance Impact

- Minimal overhead: statistics tracking adds <1ms per scan
- Memory scanning avoids disk I/O overhead
- Archive configuration allows performance tuning
- Result code generation is zero-cost abstraction
- Literal set matching uses cached Aho-Corasick automatons
- Byte signatures search exact anchors first and verify wildcard masks only at candidate offsets
- Simple native signature expressions short-circuit atom evaluation

## Future Enhancements

Potential future SDK-inspired additions:

- Callback system for archive member scanning progress
- Batch scanning with connection pooling
- Signature database versioning and update tracking
- Multi-threaded archive extraction
- Custom unpacker plugin system

## Credits

Architecture patterns inspired by professional antivirus SDK designs, adapted for HydraDragonStatic's deterministic, signature-based philosophy.
