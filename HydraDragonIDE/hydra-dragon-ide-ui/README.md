# HydraDragonIDE

**Static Analysis Engine for HydraDragon Antivirus**

A cross-platform binary analysis IDE built entirely in Rust:
- **Backend**: [Tauri 2](https://tauri.app/) (native OS window, file picker, Rust commands)
- **Frontend**: [Yew](https://yew.rs/) compiled to WebAssembly via [Trunk](https://trunkrs.dev/)

---

## Features

| Module | Description |
|--------|-------------|
| **Hex Editor** | Paginated 16-col hex view with clickable byte selection and YARA hit colouring |
| **Disassembler** | Capstone-powered x86-32/64, ARM, ARM64 with call/jmp/ret highlighting |
| **YARA-X Scanner** | Pure-Rust YARA-X engine — edit rules in-app, scan, see per-byte annotations |
| **XOR Decoder** | Single-byte brute-force (top-20 ASCII candidates) + arbitrary-key decode |
| **Base64** | Encode/decode regions or paste arbitrary Base64 strings |
| **String Extractor** | ASCII + UTF-16LE wide strings, filterable, min-length configurable |
| **Entropy Analyser** | Shannon entropy per 256-byte block, heat-map visualisation, high-entropy table |
| **PE/ELF Headers** | goblin-based parser: fields, sections (with entropy), imports, exports |

---

## Prerequisites

### Rust toolchain

```bash
# Install rustup if not present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WASM target (for the Yew frontend)
rustup target add wasm32-unknown-unknown
```

### Trunk (WASM bundler)

```bash
cargo install trunk
```

### Tauri CLI v2

```bash
cargo install tauri-cli --version "^2"
```

### System libraries

**Linux (Debian/Ubuntu)**
```bash
sudo apt update
sudo apt install -y \
    libwebkit2gtk-4.1-dev \
    build-essential \
    curl \
    wget \
    file \
    libssl-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    libgtk-3-dev \
    pkg-config
```

**macOS** – Xcode Command Line Tools:
```bash
xcode-select --install
```

**Windows** – Install [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) (usually pre-installed on Win 10/11) and the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

---

## Project structure

```
HydraDragonIDE/
├── Cargo.toml              # Yew/WASM frontend crate
├── Trunk.toml              # Trunk build config
├── index.html              # Trunk entry point
├── style.css               # IDE dark theme
├── src/
│   ├── main.rs             # Yew renderer entry
│   ├── app.rs              # Full UI component (all tabs)
│   ├── invoke.rs           # Tauri IPC helper
│   └── types.rs            # Shared serde types (mirror of backend)
└── src-tauri/
    ├── Cargo.toml          # Tauri backend crate
    ├── build.rs
    ├── tauri.conf.json
    ├── capabilities/
    │   └── default.json
    └── src/
        ├── main.rs         # Binary entry point → lib::run()
        ├── lib.rs          # All tauri::command handlers + app builder
        ├── state.rs        # AppState (file buffer, YARA hits)
        ├── disasm.rs       # Capstone wrapper (x86/ARM multi-arch)
        ├── yara_scan.rs    # YARA-X scan + per-byte hit mask
        ├── decoders.rs     # XOR brute-force/decode + Base64
        ├── entropy.rs      # Shannon entropy per block + summary
        ├── strings.rs      # ASCII + wide string extraction
        └── pe_info.rs      # PE32/PE64/ELF header parser (goblin)
```

---

## Development

```bash
# From the project root — starts Trunk (port 1420) + Tauri hot-reload
cargo tauri dev
```

Tauri will open the native window automatically. The Yew frontend hot-reloads on every `src/*.rs` or `style.css` save.

---

## Release build

```bash
cargo tauri build
```

The installer/binary is written to `src-tauri/target/release/bundle/`.

---

## Key dependencies

| Crate | Version | Role |
|-------|---------|------|
| `tauri` | 2.x | Desktop window, IPC, file system |
| `yew` | 0.21 | WASM UI framework |
| `trunk` | CLI | Rust→WASM bundler |
| `capstone` | 0.12 | Multi-arch disassembler |
| `yara-x` | 0.9 | Pure-Rust YARA engine |
| `goblin` | 0.8 | PE/ELF/Mach-O parser |
| `rfd` | 0.14 | Native file dialog |
| `base64` | 0.22 | Base64 encode/decode |
| `sha2` | 0.10 | SHA-256 file fingerprint |
| `hex` | 0.4 | Hex encode/decode |

---

## Roadmap (next phases)

- [ ] Entropy-guided auto-jump ("go to highest entropy section")
- [ ] YARA rule generator from selected byte range
- [ ] Multi-file comparison (diff hunks like OpenHydraFileAnalyzer)
- [ ] Control-flow graph (CFG) from disasm jump targets
- [ ] Unicorn-based emulator tab for dynamic unpacking
- [ ] ClamAV signature (.ndb/.ldb) viewer
- [ ] CAPA integration for capability matching
- [ ] DetectItEasy (die) packer identification
- [ ] yarGen rule generation from string clusters

---

## License

MIT — part of the [HydraDragon Antivirus](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus) project.
