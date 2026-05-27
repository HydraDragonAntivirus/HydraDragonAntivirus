# HydraDragon Controller (Rust)

A lightweight, efficient controller for HydraDragon Antivirus components written in Rust.

## Features

- **Low CPU Usage**: Simple idle loop with no continuous monitoring
- **Fast Startup**: Async component initialization
- **Clean Shutdown**: Proper cleanup on Ctrl+C
- **No Auto-Restart**: Components run independently

## Components Started

1. **Owlyshield Service** - Ransomware protection
2. **HydraDragon Firewall** - Network filtering
3. **OpenEDR** - Endpoint detection and response
4. **Sanctum** - ELAM + PPL protection
5. **HydraDragon AV Engine** - C++ scanning engine
6. **HydraDragon Python Engine** - ML-based detection

## Building

```bash
cd HydraDragonController
cargo build --release
```

The binary will be at `target/release/hydradragoncontroller.exe`

## Usage

Run as Administrator:

```bash
hydradragoncontroller.exe
```

Press `Ctrl+C` to stop all components and exit.
