# Owlyshield Ransom DLL Integration

## Overview

`owlyshield_ransom.dll` is now integrated into the OpenEDR `edrsvc` project. The DLL provides ransomware protection through behavioral analysis and is loaded in-process by the EDR service.

## Integration Points

### 1. Build System
- **vcxproj**: Modified `OpenEDR/edrav2/iprj/edrsvc/build/vs2022/edrsvc.vcxproj`
  - Added post-build event to copy `owlyshield_ransom.dll` to output directory
  - Added additional library directory for linking
  - Added source files: `owlyshield_integration.cpp`, `owlyshield_integration.h`
  - Added FFI header: `owlyshield_ransom.h`

### 2. Source Files
- **owlyshield_ransom.h**: C FFI interface declarations
- **owlyshield_integration.cpp**: C++ wrapper for loading and managing the DLL
- **owlyshield_integration.h**: Public API for OpenEDR components

### 3. Rust DLL Exports
The DLL exports three C-ABI functions (defined in `OpenEDR/owlyshield_predict/src/ffi.rs`):

```c
int32_t owlyshield_dll_start();
int32_t owlyshield_dll_ingest(const uint8_t* data, uint32_t len);
void owlyshield_dll_stop();
```

## Usage in OpenEDR Service

### Initialization
```cpp
#include "owlyshield_integration.h"

// In your service startup code:
if (!cmd::win::InitOwlyshield())
{
    LOGERROR("Failed to initialize Owlyshield protection");
    // Handle error appropriately
}
```

### Event Ingestion
```cpp
// When receiving events from the kernel driver:
std::vector<uint8_t> serialized_event = /* MessagePack serialized IOMessage */;

if (!cmd::win::OwlyshieldIngest(serialized_event.data(), serialized_event.size()))
{
    LOGERROR("Failed to ingest event into Owlyshield");
}
```

### Shutdown
```cpp
// In your service shutdown code:
cmd::win::ShutdownOwlyshield();
```

## Return Codes

- `OWLY_OK (0)`: Success
- `OWLY_ALREADY_STARTED (1)`: Engine already initialized
- `OWLY_DRIVER_ERROR (2)`: Kernel driver communication error
- `OWLY_NOT_STARTED (3)`: Engine not started before ingest
- `OWLY_DESERIALIZE_ERROR (4)`: MessagePack deserialization failed

## Building

### 1. Build Rust DLL
```bash
cd OpenEDR/owlyshield_predict
cargo build --release --lib
```

This produces: `target/release/owlyshield_ransom.dll`

### 2. Build OpenEDR
Open `OpenEDR/edrav2/build/vs2022/edrav2.sln` in Visual Studio 2022 and build the solution.

The post-build event will automatically copy `owlyshield_ransom.dll` to the output directory.

## Deployment

The `owlyshield_ransom.dll` must be in the same directory as `edrsvc.exe` at runtime. The post-build script handles this automatically during development.

For production deployment, ensure both files are packaged together:
- `edrsvc.exe`
- `owlyshield_ransom.dll`

## Architecture

```
┌─────────────────────────────────────────┐
│         OpenEDR Service (edrsvc.exe)    │
│                                         │
│  ┌────────────────────────────────┐   │
│  │  owlyshield_integration.cpp     │   │
│  │  - InitOwlyshield()             │   │
│  │  - OwlyshieldIngest()           │   │
│  │  - ShutdownOwlyshield()         │   │
│  └───────────┬────────────────────┘   │
│              │ FFI calls              │
│              ▼                         │
│  ┌────────────────────────────────┐   │
│  │   owlyshield_ransom.dll         │   │
│  │   (Rust library)                │   │
│  │                                 │   │
│  │  - Behavioral Analysis          │   │
│  │  - Ransomware Detection         │   │
│  │  - Event Processing             │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

## Troubleshooting

### DLL Not Found
- Verify `owlyshield_ransom.dll` is in the same directory as `edrsvc.exe`
- Check Windows Event Log for specific error messages

### Initialization Failure
- Ensure the kernel driver is loaded and accessible
- Check that the process has sufficient privileges
- Review Owlyshield logs for detailed error information

### Build Errors
- Ensure Rust toolchain is installed (rustup)
- Verify Visual Studio 2022 with C++ development tools
- Check that all project dependencies are restored

## Notes

- The DLL runs in the same process space as `edrsvc.exe`
- Thread safety is handled internally by the Rust library
- The worker thread is spawned by `owlyshield_dll_start()`
- Events are processed asynchronously via a channel

## Integration Example

See `OpenEDR/edrav2/iprj/edrsvc/src/service.cpp` for a complete integration example where Owlyshield is initialized during service startup and shutdown during service stop.
