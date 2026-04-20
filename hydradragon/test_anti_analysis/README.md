# Signature Monster SDK

A comprehensive usermode system artifact checking library for malware signature detection, written in Rust.

## Overview

Signature Monster provides functions to query various system artifacts that can be used to create or match malware signatures. All operations are performed purely in usermode.

This SDK is inspired by the Go examples in the repository and provides a modern Rust implementation with YAML-based rule support and optional testing modules.

## Features

### Core Modules

| Module | Description |
|--------|-------------|
| `hwid` | Hardware ID checks (Processor ID, UUID, MAC, etc.) via PowerShell |
| `registry` | Registry key/value checks via Windows API |
| `filesystem` | File path existence and attribute checks via Windows API |
| `process` | Process enumeration, window title checks via Windows API |
| `user` | Username, SID, group membership checks |
| `services` | Windows service enumeration via Service Control Manager |
| `tasks` | Scheduled task enumeration via PowerShell |
| `disk` | Disk drive model enumeration |
| `signatures` | YAML signature loading and Rust code generation |

### Optional Modules (Features)

| Feature | Module | Description |
|---------|--------|-------------|
| `antidll` | `antidll` | Anti-DLL injection protection using mitigation policies |
| `processutils` | `processutils` | Process utilities (admin check, uptime, privileges, etc.) |
| `regprotect` | `regprotect` | Registry protection via DACL modification (lock keys against everyone) |
| `testing` | All | Enables all optional modules for testing |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
signaturemonster = { path = "../signaturemonster" }

# With optional features
signaturemonster = { path = "../signaturemonster", features = ["testing"] }
```

## Usage

### Basic Usage

```rust
use signaturemonster::SignatureChecker;

fn main() {
    let checker = SignatureChecker::new();
    
    // Check if a process is running
    if checker.process.is_running("notepad.exe") {
        println!("Notepad is running!");
    }
    
    // Check registry key
    if checker.registry.key_exists(r"HKLM\SOFTWARE\Microsoft\Windows") {
        println!("Registry key exists!");
    }
    
    // Get hardware ID info
    if let Ok(hwid) = checker.hwid.get_all() {
        println!("Computer: {:?}", hwid.computer_name);
        println!("UUID: {:?}", hwid.system_uuid);
    }
    
    // Check window titles
    if checker.process.window_title_contains("Chrome") {
        println!("Chrome window is open!");
    }
}
```

### Loading YAML Signatures

```rust
use signaturemonster::{SignatureDatabase, SignatureChecker};

fn main() -> signaturemonster::Result<()> {
    // Load signatures from YAML
    let db = SignatureDatabase::load_from_yaml("signatures/sample.yaml")?;
    let checker = SignatureChecker::new();
    
    // Check each rule
    for rule in &db.rules {
        if rule.matches(&checker)? {
            println!("MATCHED: {} - {}", rule.name, rule.description);
        }
    }
    
    Ok(())
}
```

### Using the Signature Builder

```rust
use signaturemonster::{SignatureBuilder, SignatureChecker, HwidField, MatchType};

fn main() -> signaturemonster::Result<()> {
    // Build a rule programmatically
    let rule = SignatureBuilder::new("custom_rule")
        .name("Custom VM Detection")
        .description("Detects virtual machine environment")
        .match_any()
        .disk_model("vmware")
        .disk_model("vbox")
        .process("vmtoolsd.exe")
        .registry_key(r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools")
        .build();
    
    let checker = SignatureChecker::new();
    if rule.matches(&checker)? {
        println!("Running in a VM!");
    }
    
    Ok(())
}
```

### Generating Rust Code from YAML

```rust
use signaturemonster::SignatureDatabase;

fn main() -> signaturemonster::Result<()> {
    let db = SignatureDatabase::load_from_yaml("signatures/sample.yaml")?;
    
    // Generate Rust code for compile-time embedding
    db.save_rust_code("src/generated_signatures.rs")?;
    
    println!("Generated Rust code!");
    Ok(())
}
```

### Using Optional Features

```rust
// Requires: features = ["antidll"]
#[cfg(feature = "antidll")]
use signaturemonster::AntiDllInjection;

// Requires: features = ["processutils"]
#[cfg(feature = "processutils")]
use signaturemonster::ProcessUtils;

fn main() {
    #[cfg(feature = "antidll")]
    {
        let antidll = AntiDllInjection::new();
        if let Ok(true) = antidll.set_microsoft_signed_only() {
            println!("DLL injection protection enabled!");
        }
    }
    
    #[cfg(feature = "processutils")]
    {
        let utils = ProcessUtils::new();
        println!("Is Admin: {}", utils.is_admin());
        if let Ok(uptime) = utils.get_uptime_seconds() {
            println!("Uptime: {} seconds", uptime);
        }
        if let Ok(true) = utils.is_resolution_suspicious() {
            println!("Screen resolution seems suspicious (VM?)");
        }
    }

    #[cfg(feature = "regprotect")]
    {
        use signaturemonster::regprotect::COMMON_PERSISTENCE_PATHS;
        let reg_protect = signaturemonster::RegistryProtection::new();
        
        // Lock common persistence keys
        for path in COMMON_PERSISTENCE_PATHS {
            if let Err(e) = reg_protect.lock_key(path) {
                eprintln!("Failed to lock key {}: {}", path, e);
            } else {
                println!("Locked key: {}", path);
            }
        }
    }
}
```

## YAML Signature Format

```yaml
version: "1.0.0"
description: "Signature database description"
author: "Your Name"

rules:
  - id: "unique_rule_id"
    name: "Human Readable Name"
    description: "What this rule detects"
    match_type: Any  # Any, All, or AtLeast(n)
    conditions:
      - type: Process
        name: "process.exe"
        regex: false
      - type: Registry
        path: "HKLM\\SOFTWARE\\Key"
        value_name: "ValueName"  # optional
        expected_data: "data"    # optional
      - type: File
        path: "C:\\path\\to\\file.exe"
        must_exist: true
      - type: User
        name: "username"
        regex: false
      - type: Service
        name: "ServiceName"
        must_be_running: true
      - type: ScheduledTask
        name: "TaskName"
        regex: false
      - type: DiskModel
        pattern: "pattern"
        regex: false
      - type: Hwid
        field: SystemUuid  # ProcessorId, MotherboardSerial, etc.
        pattern: "pattern"
        regex: false
    actions:
      - type: Exit
        code: 1
      - type: LockRegistry
        path: "HKLM\\Software\\MyKey"
      # - type: MakeCritical
      # - type: SelfDelete
      # - type: ForceBsod

## Build System, Obfuscation & Embedded Signatures

Signature Monster includes a powerful `build.rs` script that performs two key functions during the build process:

1.  **YAML Signature Compilation**: It automatically compiles your rules from `signatures/sample.yaml` into native Rust code (`src/generated_signatures.rs`). This embeds your signatures directly into the binary, preventing users from bypassing checks by simply deleting external files.
2.  **Whole-Crate Obfuscation**: It scans your entire source tree (including the generated signatures), obfuscates string literals with strong encryption (AES-256 + Base encoding pipeline), randomizes identifiers, and flattens the code into a single hardened file: `src/obfuscated.rs`.

### Usage

1.  Edit `signatures/sample.yaml`.
2.  Run `cargo build`.
    *   This generates `src/generated_signatures.rs` (used by the standard library build).
    *   This ALSO generates `src/obfuscated.rs` (a standalone, hardened version of the library).

### Skipping Obfuscation (Fast Builds)

The obfuscation process is intensive and can take time. For rapid development and testing, you can skip the obfuscation step (but still generate signatures) by setting the `SKIP_OBFUSCATION` environment variable:

**Windows (CMD)**:
```cmd
set SKIP_OBFUSCATION=1
cargo build
```

**PowerShell**:
```powershell
$env:SKIP_OBFUSCATION=1
cargo build
```

### Using Embedded Signatures

You can access the embedded signatures in your code:

```rust
use signaturemonster::generated_signatures::get_embedded_signatures;

let rules = get_embedded_signatures();
```


## CLI Tool

Run the CLI to see system information:

```bash
cargo run --bin signaturemonster-cli
```

## Based On

This SDK is a modern Rust reimplementation of the detection techniques from the Go examples:

- `examples/AntiDebug/` - Debugger and analysis tool detection
- `examples/AntiVirtualization/` - VM and sandbox detection
- `examples/AntiDLLInjection/` - DLL injection protection
- `examples/ProcessUtils/` - Process utilities

## License

GPLv2
