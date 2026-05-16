/// Shared types and constants for HydraDragon Firewall
/// This lightweight crate contains only serializable types with no platform-specific dependencies,
/// making it suitable for both native and WASM targets.

use serde::{Deserialize, Serialize};

/// Quarantine directory path (shared constant)
pub const QUARANTINE_PATH: &str = r"C:\ProgramData\HydraDragonQuarantine";

/// Default certificate installation consent (true = automatic installation enabled by default)
pub const DEFAULT_CERT_INSTALL_CONSENT: bool = true;

/// Default TLS proxy listen host
pub const DEFAULT_TLS_LISTEN_HOST: &str = "127.0.0.1";

/// Default TLS proxy listen port
pub const DEFAULT_TLS_LISTEN_PORT: u16 = 8877;

/// Default QUIC blocking setting
pub const DEFAULT_BLOCK_QUIC_UDP_443: bool = true;

/// Default auto-start setting for TLS proxy
pub const DEFAULT_TLS_AUTO_START: bool = true;

/// TLS inspection mode
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInspectionMode {
    /// Only capture TLS metadata (SNI, certificates) without decryption
    MetadataOnly,
    /// Full MITM proxy with decryption
    TlsProxy,
}

impl Default for TlsInspectionMode {
    fn default() -> Self {
        Self::TlsProxy
    }
}

/// TLS proxy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsProxyConfig {
    pub mode: TlsInspectionMode,
    pub listen_host: String,
    pub listen_port: u16,
    pub block_quic_udp_443: bool,
    /// Whether to auto-start the embedded proxy when the firewall starts.
    pub auto_start: bool,
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
    /// Whether user has consented to certificate installation for MITM interception.
    /// If false, certificates will not be automatically installed.
    #[serde(default)]
    pub cert_install_consent: bool,
}

impl Default for TlsProxyConfig {
    fn default() -> Self {
        Self {
            mode: TlsInspectionMode::TlsProxy,
            listen_host: DEFAULT_TLS_LISTEN_HOST.to_string(),
            listen_port: DEFAULT_TLS_LISTEN_PORT,
            block_quic_udp_443: DEFAULT_BLOCK_QUIC_UDP_443,
            auto_start: DEFAULT_TLS_AUTO_START,
            bypass_hosts: Vec::new(),
            cert_install_consent: DEFAULT_CERT_INSTALL_CONSENT,
        }
    }
}
