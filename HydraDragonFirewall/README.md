# HydraDragon Remote Desktop

A LAN-based remote desktop solution for Windows 10/11. Similar to Supremo/AnyDesk but entirely local, open-source, and privacy-focused.

## ✨ Features

- **Dual Mode**: Single app works as both remote server and viewer client
- **LAN Only**: Secure connections restricted to local network
- **Screen Sharing**: Real-time screen capture with JPEG compression
- **Remote Input**: Keyboard and mouse control with SendInput API
- **User Consent**: Connection requests require explicit approval
- **Session Passwords**: 6-digit one-time passwords for each session
- **Keyboard Navigation**: Fully accessible without mouse (F1, F2, F5, Esc)
- **System Tray**: Runs in background with tray icon

## 🔧 Requirements

- Windows 10/11
- .NET 8.0 Runtime
- LAN network connection

## 🚀 Quick Start

### Running the Application

```powershell
cd HydraDragonClient\HydraDragonClient
dotnet run
```

Or build and run the executable:

```powershell
dotnet build -c Release
.\bin\Release\net8.0-windows\HydraDragonClient.exe
```

### Usage

1. **As Remote (accepting connections)**:
   - Launch the app - server starts automatically
   - Note your IP address and session password shown on screen
   - Share these with the person who wants to connect

2. **As Client (connecting to remote)**:
   - Press `F1` to open connection dialog
   - Enter the remote machine's IP and password
   - Wait for remote user to accept the connection

## ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `F1` | Open connection dialog |
| `F2` | Generate new session password |
| `F5` | Toggle mouse control |
| `Escape` | Disconnect from remote |
| `Tab` | Navigate UI elements |

## 🔒 Security

- Connections restricted to LAN IP ranges (10.x, 172.16-31.x, 192.168.x)
- Session passwords hashed with SHA-256
- User must explicitly accept each connection request
- Connection logging with timestamps

## 🛡️ HydraDragon Firewall (Rust)

A high-performance, kernel-mode packet filter powered by WinDivert.

- **Technology**: Rust + WinDivert (Windows Packet Filter)
- **Features**:
  - **Packet Inspection**: Deep packet inspection for all incoming/outgoing traffic.
  - **Process Association**: Identifies the PID and executable name for every network flow.
  - **EDR Hooks**: Uses `MinHook` to intercept user-mode `connect` keys in real-time, forwarding events via Named Pipes.
  - **Web Filtering**: Blocks malicious IPs and domains using optimized blocklists (Scam, Malware, Phishing).
  - **Entropy + Payload Visibility**: Logs Shannon entropy and a hex preview of payload bytes for forensic review of suspicious packets.
  - **Context-Rich Logging**: Every allow/block entry now carries full URL/host/DNS details, IP/port tuples, PID, direction, entropy, and the first payload bytes so remote requests can't hide behind raw IP addresses.
  - **HTTP Header Telemetry**: Captures HTTP method/path along with User-Agent, Content-Type, and Referer headers for each inspected request so domain/URL decisions include client fingerprinting.
  - **Payload URL Harvesting**: Scans packet payloads for embedded URLs/domains (even on non-standard ports) to expose malware beacons, C2 callbacks, and suspicious redirects to the rule engine and logs.
  - **Signature-First Filtering**: Built-in whitelist feeds are removed; every packaged threat feed (including prior "whitelist" CSVs) is treated as a blocking signature so only explicit allow rules or per-app approvals can open traffic.
  - **Default-Deny Remote Policy**: Non-localhost traffic is blocked unless the user approves the app or crafts an allow rule, ensuring nothing is silently trusted.
  - **Performance**: Zero-copy packet handling for minimal latency.

### Building the firewall components

The Rust firewall and Tauri UI rely on system libraries that are not bundled with the repo. On Debian/Ubuntu-based systems install the GTK/GLib toolchain and pkg-config helpers before running `cargo check` or `cargo tauri dev`:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libglib2.0-dev libgtk-3-dev libayatana-appindicator3-dev
```

The WinDivert driver itself must be present on Windows when running the firewall; see `copy_driver.ps1` for automating the driver copy step.

## 📂 File Transfer

Seamlessly transfer files between connected machines.

- **Sender**: Click "Send File" on the Client toolbar.
- **Receiver**: Files are automatically saved to the Desktop.
- **Protocol**: Chunked binary transfer with integrity checks.

## 📁 Project Structure

```
HydraDragonClient/
├── Client/          # Client connection logic
├── Config/          # Application settings
├── Input/           # Keyboard/mouse injection
├── Network/         # TCP message channel
├── Protocol/        # Message definitions
├── Remote/          # Remote server logic
├── ScreenCapture/   # BitBlt screen capture
├── Security/        # Crypto and validation
├── UI/              # Forms and controls
├── MainForm.cs      # Main application window
└── Program.cs       # Entry point
```

## 📜 License

GPL-3.0 License - See [LICENSE](LICENSE) file
