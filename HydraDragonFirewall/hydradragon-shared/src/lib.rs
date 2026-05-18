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

/// Default handshake timeout in milliseconds
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5000;

/// Default request timeout in seconds
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default response timeout in seconds
pub const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 30;

/// Helper function for serde default - returns true for cert_install_consent
fn default_cert_install_consent() -> bool {
    DEFAULT_CERT_INSTALL_CONSENT
}

/// Helper function for serde default - returns default listen host
fn default_listen_host() -> String {
    DEFAULT_TLS_LISTEN_HOST.to_string()
}

/// Helper function for serde default - returns default listen port
fn default_listen_port() -> u16 {
    DEFAULT_TLS_LISTEN_PORT
}

/// Helper function for serde default - returns true for block_quic_udp_443
fn default_block_quic_udp_443() -> bool {
    DEFAULT_BLOCK_QUIC_UDP_443
}

/// Helper function for serde default - returns true for auto_start
fn default_auto_start() -> bool {
    DEFAULT_TLS_AUTO_START
}

/// Helper function for serde default - returns default handshake timeout
fn default_handshake_timeout_ms() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_MS
}

/// Helper function for serde default - returns default request timeout
fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

/// Helper function for serde default - returns default response timeout
fn default_response_timeout_secs() -> u64 {
    DEFAULT_RESPONSE_TIMEOUT_SECS
}

/// TLS inspection mode
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInspectionMode {
    /// Only capture TLS metadata (SNI, certificates) without decryption
    MetadataOnly,
    /// Transparent TLS Proxy/Inspector with decryption via the transparent network layers.
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
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_block_quic_udp_443")]
    pub block_quic_udp_443: bool,
    /// Whether to auto-start the embedded proxy when the firewall starts.
    #[serde(default = "default_auto_start")]
    pub auto_start: bool,
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
    /// Whether user has consented to certificate installation for transparent TLS proxy interception.
    /// If false, certificates will not be automatically installed.
    #[serde(default = "default_cert_install_consent")]
    pub cert_install_consent: bool,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_response_timeout_secs")]
    pub response_timeout_secs: u64,
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
            handshake_timeout_ms: DEFAULT_HANDSHAKE_TIMEOUT_MS,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            response_timeout_secs: DEFAULT_RESPONSE_TIMEOUT_SECS,
        }
    }
}
