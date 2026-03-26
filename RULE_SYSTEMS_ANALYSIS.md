# HydraDragon Platform - Rule Systems Analysis

## Overview
The HydraDragon Platform uses multiple rule systems for different security functions:

---

## 1. Rule Systems Identified

### A. **YARA Rules** (Malware Signatures)
- **Location**: `hydradragon/yara/`
- **Purpose**: File content-based malware detection
- **Files**: 
  - `clean_rules.yar` (50MB+)
  - `machine_learning.yar`
  - `javascript.yara`
  - `valhalla-rules.yar`
- **Format**: YARA syntax with PE import analysis

### B. **HydraDragonFirewall - Network Rules** (YAML)
- **Location**: `HydraDragonFirewall/hydradragonfirewall/rules.yaml`
- **Purpose**: Network traffic filtering and inspection
- **Protocol Support**: HTTP, HTTPS, TCP, UDP
- **Capabilities**: Domain/URL matching, JSON payload inspection, encoding detection

### C. **Owlyshield - Behavioral Detection Rules** (YAML)
- **Location**: `hydradragon/Owlyshield/rules/`
- **Purpose**: Real-time behavior monitoring and heuristics
- **Features**: Registry operations, file access, process creation, API calls
- **Components**:
  - Registry HIPS (Host Intrusion Prevention System)
  - File system filter rules
  - Process protection rules
  - Dynamic hook rules

### D. **Owlyshield - Kernel Driver Rules** (C++)
- **Location**: `Owlyshield/owlyshield_minifilter/`
- **Purpose**: Kernel-level file and registry access blocking
- **Implementation**: Mini-filter driver with blocked paths list

---

## 2. HydraDragonFirewall Directory Structure

```
HydraDragonFirewall/
├── hydradragonfirewall/          # Main Rust/Tauri application
│   ├── src/                      # Source code
│   ├── rules.yaml               # PRIMARY RULE FILE (YAML format)
│   ├── capabilities/            # Tauri capabilities/permissions
│   ├── settings.json           # Configuration
│   └── Cargo.toml              # Rust dependencies
├── HydraDragonClient/           # Client application
├── COMODO/                      # Integration with COMODO
├── everything/                  # File search integration
├── windivert-bin/              # Network packet diversion
└── windivert-rust-master/       # Rust bindings for WinDivert
```

---

## 3. Owlyshield Directory Structure & Rules

```
Owlyshield/
├── owlyshield_minifilter/
│   ├── OwlyshieldRansomFilter/  # Kernel driver (C++)
│   │   ├── Communication.cpp    # User-kernel communication
│   │   ├── DriverData.cpp       # Blocked paths management
│   │   ├── FSFilter.cpp         # File system filtering
│   │   └── Regedit.cpp         # Registry interception
│   └── HyperDbg/               # Debugging engine
└── owlyshield_predict/          # ML-based prediction engine

hydradragon/Owlyshield/rules/
├── regseek_registry_hips_default.yaml    # Registry HIPS rules
├── credential_access_rules.yaml           # Credential theft detection
├── signature_artifact_detection_rules.yaml # Anti-analysis detection
├── defense_evasion_rules.yaml             # EDR evasion detection
├── WinVerifyTrust.yaml                    # Code signature validation
├── behavior_rules.yaml                    # General behavior rules
├── persistence_extended_rules.yaml        # Persistence techniques
└── [others...]                            # 21 YAML rule files total

hydradragon/HydraDragoon_Protection_Rules/Owlyshield/
├── FSFilter/
│   └── default_rules.txt         # File system filter exclude rules
├── ProcessProtection/
│   └── default_rules.txt         # Process protection exclude rules
├── DynamicHook/
│   └── default_rules.txt         # Dynamic hook exclude rules
```

---

## 4. Existing Rules That Restrict File/Registry Access

### Example 1: Registry Protection Rule (regseek_registry_hips_default.yaml)

```yaml
- name: "RegSeek Registry HIPS - System Modifications"
  description: "Prompts before broad system reconfiguration touching hostname, boot, Windows Update, servicing, power, VSS, memory management, device restrictions, and related modification surfaces documented by RegSeek."
  author: "Emirhan Ucan"
  status: experimental
  level: high
  severity: 88
  tags: [regseek, hips, registry, system-modifications]
  mitre_attack: ["T1112", "T1490", "T1562.001"]
  
  detection_logic:
    any_of: [system_identity, boot_and_servicing, system_controls, storage_and_devices]
  
  named_conditions:
    system_identity:
      registry_keys:
        - "HKLM/SYSTEM/CurrentControlSet/Control/ComputerName/ComputerName*"
        - "HKLM/SYSTEM/CurrentControlSet/Control/TimeZoneInformation*"
        - "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/SoftwareProtectionPlatform*"
      registry_operations: [create, set, delete, rename]
    
    boot_and_servicing:
      registry_keys:
        - "HKLM/SYSTEM/CurrentControlSet/Control/SafeBoot*"
        - "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Component Based Servicing*"
        - "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/WindowsUpdate*"
      registry_operations: [create, set, delete, rename]
  
  response:
    ask_user: true
    terminate_process: true
    notify_user: true
    auto_revert: true
    record: true
```

**Key Features:**
- Monitors registry operations on critical keys
- Supports wildcard patterns (`*`)
- Multiple registry operations: `create, set, delete, rename`
- Response actions: `ask_user`, `terminate_process`, `notify_user`, `auto_revert`, `record`

---

### Example 2: File System Detection Rule (signature_artifact_detection_rules.yaml)

```yaml
- name: "HEUR:Win.AntiAnalysis.SignatureArtifactPathProbe.gen"
  author: "Emirhan Ucan"
  date: "2026-03-25"
  status: test
  level: high
  severity: 78
  description: |
    Detects filesystem probes against analysis, sandbox, debugger, and virtualization
    artifacts. This catches malware that checks for local analyst tools or sandbox 
    footprints by touching their on-disk paths.
  
  named_conditions:
    signature_artifact_path_probe:
      orderless: true
      file_paths:
        - "C:\\Program Files\\Sandboxie\\*"
        - "C:\\Program Files (x86)\\Sandboxie\\*"
        - "*\\vmtoolsd.exe"
        - "*\\vmacthlp.exe"
        - "*\\vboxservice.exe"
        - "*\\x64dbg.exe"
        - "*\\ollydbg.exe"
        - "*\\ida64.exe"
        - "*\\ghidra.exe"
        - "*\\wireshark.exe"
        - "*\\procmon.exe"
        - "*\\pestudio.exe"
      min_matches: 1
  
  detection_logic:
    condition: "signature_artifact_path_probe"
  
  response:
    notify_user: true
    status_access_denied: true  # Blocks access
    record: true
  
  tags: ["anti-analysis", "anti-debug", "anti-vm", "signature-artifacts", "path-probe"]
  mitre_attack: ["T1497", "T1497.001", "T1497.003"]
```

**Key Features:**
- File path matching with wildcards
- Multiple file access operations can be monitored
- `status_access_denied: true` **blocks** the access
- MITRE ATT&CK framework mapping
- Detailed response actions

---

### Example 3: Registry Key Read Detection (signature_artifact_detection_rules.yaml)

```yaml
- name: "HEUR:Win.AntiAnalysis.SignatureArtifactRegistryRead.gen"
  author: "Emirhan Ucan"
  date: "2026-03-25"
  status: test
  level: high
  severity: 76
  description: |
    Detects registry read and enumeration probes against sandbox, virtualization,
    and analysis artifacts. This catches reg query, PowerShell registry providers, 
    and native registry APIs used to fingerprint the host before payload execution.
  
  named_conditions:
    signature_artifact_registry_read:
      orderless: true
      registry_keys:
        - "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools*"
        - "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions*"
        - "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS*"
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie*"
        - "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
        - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VMTools*"
        - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxService*"
        - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SbieSvc*"
      registry_operations: ["read"]
      min_matches: 1
  
  detection_logic:
    condition: "signature_artifact_registry_read"
  
  response:
    notify_user: true
    record: true
  
  tags: ["anti-analysis", "anti-debug", "anti-vm", "signature-artifacts", "registry-read"]
  mitre_attack: ["T1497", "T1497.001"]
  false_positives:
    - "System inventory, EDR, and IT management software reading virtualization software keys"
    - "Administrators using reg.exe or PowerShell to audit installed VM tools"
```

**Key Features:**
- Monitors specific registry operations: `["read"]`, `["create", "set", "delete", "rename"]`
- Registry hive support: `HKLM`, `HKCU`, `HKCR`, `HKU`
- Wildcard patterns with registry paths
- `min_matches` for threshold-based detection
- Response actions can vary (ask, deny, log, terminate)

---

## 5. Rule Configuration Features

### YAML Rule Structure Components:

| Component | Purpose | Example |
|-----------|---------|---------|
| `name` | Unique rule identifier | "Block Registry Key X" |
| `description` | Human-readable explanation | "Prevents modification of..." |
| `author` | Rule creator | "Emirhan Ucan" |
| `status` | Rule maturity | `test`, `experimental`, `stable` |
| `level` | Severity level | `low`, `medium`, `high`, `critical` |
| `severity` | Numeric severity (1-100) | `88` |
| `tags` | Categories | `["registry", "persistence"]` |
| `mitre_attack` | ATT&CK techniques | `["T1112", "T1490"]` |

### Detection Logic:

```yaml
detection_logic:
  any_of: [condition1, condition2]      # OR logic
  all_of: [condition1, condition2]      # AND logic
  or:
    - condition: "name1"
    - condition: "name2"
  and:
    - condition: "name1"
    - condition: "name2"
```

### Response Actions:

```yaml
response:
  ask_user: true                         # Prompt user for permission
  terminate_process: true                # Kill the responsible process
  notify_user: true                      # Show notification
  auto_revert: true                      # Roll back changes
  record: true                           # Log the event
  status_access_denied: true             # Block the operation
  quarantine: true                       # Isolate suspicious file
```

---

## 6. File System Blocking Rules (Kernel Level)

**Location**: `Owlyshield/owlyshield_minifilter/OwlyshieldRansomFilter/DriverData.cpp`

```cpp
// Blocked Path Handling
BOOLEAN DriverData::AddBlockedPath(PDIRECTORY_ENTRY newEntry) {
    KeAcquireSpinLock(&blockedPathsLock, &oldIrql);
    // Add to kernel-level blocked paths list
    InsertHeadList(&blockedPaths, &newEntry->entry);
    blockedPathsSize++;
    KeReleaseSpinLock(&blockedPathsLock, oldIrql);
}

BOOLEAN DriverData::IsPathBlocked(CONST PUNICODE_STRING path) {
    // Kernel-level check - very efficient
    // Uses spin locks for thread safety
}
```

**Features:**
- Kernel-level file path blocking (fast, no user-mode overhead)
- Thread-safe using spin locks
- Dynamic path list updates
- Used for: Ransomware protection, critical file protection

---

## 7. Exclude Rules Format

**Location**: `hydradragon/HydraDragoon_Protection_Rules/Owlyshield/*/default_rules.txt`

```
# Dynamic hook exclude rules (normalized/contains match, case-insensitive)
# Put full path fragments under C:\ only.

# System processes (commented out - can be uncommented)
# c:\windows\system32\smss.exe
# c:\windows\system32\csrss.exe
# c:\windows\system32\services.exe

# HydraDragonAntivirus-specific examples
c:\program files\hydradragonantivirus
desktop\sanctum\
appdata\roaming\sanctum\
c:\windows\system32\tasks\hydradragonantivirus
```

**Features:**
- Simple text-based format
- Case-insensitive matching
- Full path fragment matching
- Comments with `#`

---

## 8. Key Locations Summary

| System | Rule Files | Format | Operations |
|--------|-----------|--------|-----------|
| **HydraDragonFirewall** | `rules.yaml` | YAML | Network, HTTP, HTTPS, DNS, TCP |
| **Owlyshield Registry HIPS** | `regseek_registry_hips_default.yaml` | YAML | Registry: read, create, set, delete, rename |
| **Owlyshield File Filter** | `FSFilter/default_rules.txt` | Text | File: read, write, delete, rename |
| **Owlyshield Behavioral** | `*.yaml` (21 files) | YAML | Process, API, registry, file access |
| **Kernel Mini-Filter** | C++ driver code | C++ | Kernel-level file/registry blocking |
| **YARA Signatures** | `*.yar`, `*.yara` | YARA | File content matching, PE analysis |

---

## 9. Creating New Rules - Quick Reference

### To Restrict Registry Key Access:
1. Edit or create YAML file in `hydradragon/Owlyshield/rules/`
2. Define `named_conditions` with registry keys and operations
3. Set `detection_logic` (AND/OR conditions)
4. Define `response` actions (ask_user, terminate_process, status_access_denied, record)

### To Restrict File Access:
1. Use file system filter rules or behavioral rules
2. Define `file_paths` with wildcard patterns
3. Set `file_operations` (create, read, write, delete, rename)
4. Set response actions (block, notify, quarantine)

### To Exclude Paths:
1. Edit `default_rules.txt` in appropriate directory
2. Add path fragment (one per line)
3. Use `#` for comments
4. Case-insensitive matching

---

## 10. Example Use Cases

**Protect Windows Defender Registry:**
```yaml
- name: "Protect Windows Defender Registry"
  registry_keys:
    - "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender*"
    - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend*"
  registry_operations: [create, set, delete, rename]
  response:
    terminate_process: true
    ask_user: true
```

**Block Sensitive File Access:**
```yaml
- name: "Block Access to Sensitive Files"
  file_paths:
    - "C:\\Windows\\System32\\drivers\\etc\\hosts"
    - "C:\\Windows\\System32\\config\\sam"
    - "C:\\Windows\\System32\\config\\security"
  file_operations: [read, write, delete]
  response:
    status_access_denied: true
    record: true
```

**Credential Access Detection:**
```yaml
- name: "LSASS Memory Dump Detection"
  api_calls:
    - "ReadProcessMemory"
  target_process: "lsass.exe"
  response:
    terminate_process: true
    notify_user: true
```

---

## 11. Rule Development Checklist

- [ ] Unique rule name
- [ ] Clear description
- [ ] Author attribution
- [ ] Status level (test/experimental/stable)
- [ ] Severity and level classification
- [ ] MITRE ATT&CK mapping
- [ ] Comprehensive named_conditions
- [ ] Appropriate detection_logic (and/or)
- [ ] Defined response actions
- [ ] Tags for categorization
- [ ] False positive considerations documented
- [ ] YAML syntax validation

---

## Conclusion

The HydraDragon Platform uses a **multi-layered rule system**:
- **Network layer**: HydraDragonFirewall (YAML rules)
- **User-mode behavioral**: Owlyshield YAML rules (21+ configuration files)
- **Kernel layer**: Mini-filter driver with binary blocking
- **Signature-based**: YARA rules for file content matching

This provides **defense-in-depth** protection with both blocking and monitoring capabilities at multiple system levels.
