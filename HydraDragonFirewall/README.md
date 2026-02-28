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


## 📜 License

GPL-3.0 License - See [LICENSE](LICENSE) file
