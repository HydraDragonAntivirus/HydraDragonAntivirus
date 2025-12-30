use crate::engine::{FirewallSettings, PacketInfo, Protocol};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawPacket {
    pub id: String,
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub length: usize,
    pub payload_hex: String,
    pub payload_preview: String,
    pub summary: String,
    // Process Correlation
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
    // SDK/Rule Context
    pub action: String,
    pub rule: String,
}

impl RawPacket {
    pub fn from_parts(
        id: impl Into<String>,
        data: &[u8],
        info: &PacketInfo,
        context: &PacketContext,
        action: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        let payload_preview = String::from_utf8_lossy(data)
            .chars()
            .take(120)
            .collect::<String>();

        let summary = format!(
            "{}:{} -> {}:{} ({:?})",
            info.src_ip, info.src_port, info.dst_ip, info.dst_port, info.protocol
        );

        let payload_hex = data
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        Self {
            id: id.into(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            src_ip: info.src_ip.to_string(),
            dst_ip: info.dst_ip.to_string(),
            src_port: info.src_port,
            dst_port: info.dst_port,
            protocol: info.protocol,
            length: data.len(),
            payload_hex,
            payload_preview,
            summary,
            process_id: context.process_id,
            process_name: context.process_name.clone(),
            process_path: context.process_path.clone(),
            action: action.into(),
            rule: rule.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PacketContext {
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
}

/// Trait for components that passively listen to/log network traffic.
pub trait PacketListener: Send + Sync {
    fn on_packet(&self, data: &[u8], info: &PacketInfo, context: &PacketContext);
}

/// Trait for components that can modify network packets.
pub trait PacketChanger: Send + Sync {
    /// Modify packet data. Returns true if modification occurred.
    fn modify(&self, data: &mut Vec<u8>, info: &PacketInfo, context: &PacketContext) -> bool;
}

/// Trait for security signatures that evaluate packet payloads for threats.
pub trait SecuritySignature: Send + Sync {
    /// Evaluate the payload. Returns Some(reason) if a threat is detected.
    fn evaluate(
        &self,
        data: &[u8],
        settings: &FirewallSettings,
        context: &PacketContext,
    ) -> Option<String>;

    /// Unique name/identifier for this signature.
    fn name(&self) -> &str;

    /// Optional metadata describing the signature.
    fn metadata(&self) -> SignatureMetadata {
        SignatureMetadata {
            name: self.name().to_string(),
            description: String::from("Generic SDK signature"),
            severity: Severity::Informational,
            category: SignatureCategory::Behavior,
            references: vec![],
        }
    }
}

pub struct SdkRegistry {
    pub listeners: Vec<Arc<dyn PacketListener>>,
    pub changers: Vec<Arc<dyn PacketChanger>>,
    pub signatures: Vec<RegisteredSignature>,
}

impl SdkRegistry {
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            changers: Vec::new(),
            signatures: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register_default_signatures();
        registry
    }

    pub fn register_listener(&mut self, listener: Arc<dyn PacketListener>) {
        self.listeners.push(listener);
    }

    pub fn register_changer(&mut self, changer: Arc<dyn PacketChanger>) {
        self.changers.push(changer);
    }

    pub fn register_signature(&mut self, signature: Arc<dyn SecuritySignature>) {
        self.signatures.push(RegisteredSignature {
            enabled: true,
            signature,
        });
    }

    pub fn register_default_signatures(&mut self) {
        self.register_signature(Arc::new(DiscordWebhookSignature));
        self.register_signature(Arc::new(StringPatternSignature::new(PatternConfig {
            name: "Possible AWS Secret".to_string(),
            needle: "AWS_SECRET_ACCESS_KEY=".to_string(),
            case_sensitive: false,
            utf16: false,
            detect_reversed: false,
            severity: Severity::High,
            category: SignatureCategory::Credentials,
            description: Some(
                "Detects accidental leakage of AWS secret environment variables".to_string(),
            ),
        })));
        self.register_signature(Arc::new(StringPatternSignature::new(PatternConfig {
            name: "Suspicious Powershell Download".to_string(),
            needle: "Invoke-WebRequest".to_string(),
            case_sensitive: false,
            utf16: true,
            detect_reversed: false,
            severity: Severity::Medium,
            category: SignatureCategory::CommandAndControl,
            description: Some("Detects UTF-16 encoded PowerShell download commands".to_string()),
        })));
        self.register_signature(Arc::new(StringPatternSignature::new(PatternConfig {
            name: "Reversed Powershell Beacon".to_string(),
            needle: "powershell".to_string(),
            case_sensitive: false,
            utf16: false,
            detect_reversed: true,
            severity: Severity::High,
            category: SignatureCategory::Behavior,
            description: Some(
                "Detects simple reversed PowerShell tokens often used in obfuscation".to_string(),
            ),
        })));
        self.register_signature(Arc::new(RegexSignature::new(RegexSignatureConfig {
            name: "Encoded PowerShell Command".to_string(),
            pattern: String::from(r"powershell\\s+-enc\\s+[A-Za-z0-9/+]{20,}={0,2}"),
            case_insensitive: true,
            utf16: false,
            severity: Severity::High,
            category: SignatureCategory::CommandAndControl,
            description: Some("Detects base64-encoded PowerShell execution flags".to_string()),
            references: vec![
                "https://attack.mitre.org/techniques/T1059/001".to_string(),
                "https://aka.ms/powershell".to_string(),
            ],
        })));
    }

    pub fn toggle_signature(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(entry) = self
            .signatures
            .iter_mut()
            .find(|entry| entry.signature.name().eq_ignore_ascii_case(name))
        {
            entry.enabled = enabled;
            return true;
        }
        false
    }

    pub fn list_signatures(&self) -> Vec<SignatureMetadata> {
        self.signatures
            .iter()
            .filter(|entry| entry.enabled)
            .map(|entry| entry.signature.metadata())
            .collect()
    }

    pub fn evaluate_signatures(
        &self,
        data: &[u8],
        settings: &FirewallSettings,
        context: &PacketContext,
    ) -> Vec<SignatureFinding> {
        self.signatures
            .iter()
            .filter(|entry| entry.enabled)
            .filter_map(|entry| {
                entry
                    .signature
                    .evaluate(data, settings, context)
                    .map(|reason| SignatureFinding {
                        signature: entry.signature.name().to_string(),
                        reason,
                        metadata: entry.signature.metadata(),
                    })
            })
            .collect()
    }
}

// Example implementation of a signature that could replace the hardcoded Discord check
pub struct DiscordWebhookSignature;

impl SecuritySignature for DiscordWebhookSignature {
    fn evaluate(
        &self,
        data: &[u8],
        _settings: &FirewallSettings,
        context: &PacketContext,
    ) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        if text.contains("discordapp.com/api/webhooks") || text.contains("discord.com/api/webhooks")
        {
            return Some(format!(
                "Discord Webhook detected in {} ({})",
                context.process_name, context.process_id
            ));
        }
        None
    }

    fn name(&self) -> &str {
        "DiscordWebhook"
    }

    fn metadata(&self) -> SignatureMetadata {
        SignatureMetadata {
            name: self.name().to_string(),
            description: "Detects Discord webhook URLs leaving the host".to_string(),
            severity: Severity::Medium,
            category: SignatureCategory::Exfiltration,
            references: vec!["https://discord.com/developers/docs/resources/webhook".to_string()],
        }
    }
}

pub struct StringPatternSignature {
    config: PatternConfig,
}

impl StringPatternSignature {
    pub fn new(config: PatternConfig) -> Self {
        Self { config }
    }

    fn find_utf8(&self, data: &[u8]) -> bool {
        let haystack = String::from_utf8_lossy(data);
        let mut matched = if self.config.case_sensitive {
            haystack.contains(&self.config.needle)
        } else {
            haystack
                .to_lowercase()
                .contains(&self.config.needle.to_lowercase())
        };

        if !matched && self.config.detect_reversed {
            let reversed: String = haystack.chars().rev().collect();
            matched = if self.config.case_sensitive {
                reversed.contains(&self.config.needle)
            } else {
                reversed
                    .to_lowercase()
                    .contains(&self.config.needle.to_lowercase())
            };
        }

        matched
    }

    fn find_utf16(&self, data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }

        let mut utf16_data = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks(2) {
            if let [lo, hi] = chunk {
                utf16_data.push(u16::from_le_bytes([*lo, *hi]));
            }
        }

        let Ok(string) = String::from_utf16(&utf16_data) else {
            return false;
        };

        let mut matched = if self.config.case_sensitive {
            string.contains(&self.config.needle)
        } else {
            string
                .to_lowercase()
                .contains(&self.config.needle.to_lowercase())
        };

        if !matched && self.config.detect_reversed {
            let reversed: String = string.chars().rev().collect();
            matched = if self.config.case_sensitive {
                reversed.contains(&self.config.needle)
            } else {
                reversed
                    .to_lowercase()
                    .contains(&self.config.needle.to_lowercase())
            };
        }

        matched
    }
}

impl SecuritySignature for StringPatternSignature {
    fn evaluate(
        &self,
        data: &[u8],
        _settings: &FirewallSettings,
        context: &PacketContext,
    ) -> Option<String> {
        let matched = if self.config.utf16 {
            self.find_utf16(data)
        } else {
            self.find_utf8(data)
        };

        if matched {
            return Some(format!(
                "{} detected in {} (PID {})",
                self.config.needle, context.process_name, context.process_id
            ));
        }

        None
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn metadata(&self) -> SignatureMetadata {
        SignatureMetadata {
            name: self.config.name.clone(),
            description: self
                .config
                .description
                .clone()
                .unwrap_or_else(|| "Pattern-based packet inspection".to_string()),
            severity: self.config.severity,
            category: self.config.category.clone(),
            references: vec![],
        }
    }
}

pub struct RegexSignature {
    config: RegexSignatureConfig,
    regex: Regex,
}

impl RegexSignature {
    pub fn new(config: RegexSignatureConfig) -> Self {
        let regex = if config.case_insensitive {
            Regex::new(&format!("(?i){}", config.pattern)).expect("invalid regex pattern")
        } else {
            Regex::new(&config.pattern).expect("invalid regex pattern")
        };

        Self { config, regex }
    }

    fn maybe_decode_utf16(&self, data: &[u8]) -> Option<String> {
        if data.len() < 2 {
            return None;
        }

        let mut utf16_data = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks(2) {
            if let [lo, hi] = chunk {
                utf16_data.push(u16::from_le_bytes([*lo, *hi]));
            }
        }

        String::from_utf16(&utf16_data).ok()
    }
}

impl SecuritySignature for RegexSignature {
    fn evaluate(
        &self,
        data: &[u8],
        _settings: &FirewallSettings,
        context: &PacketContext,
    ) -> Option<String> {
        let haystack = if self.config.utf16 {
            self.maybe_decode_utf16(data)
                .unwrap_or_else(|| String::from_utf8_lossy(data).to_string())
        } else {
            String::from_utf8_lossy(data).to_string()
        };

        if self.regex.is_match(&haystack) {
            return Some(format!(
                "{} matched on {} (PID {})",
                self.config.name, context.process_name, context.process_id
            ));
        }

        None
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn metadata(&self) -> SignatureMetadata {
        SignatureMetadata {
            name: self.config.name.clone(),
            description: self
                .config
                .description
                .clone()
                .unwrap_or_else(|| "Regex packet inspection".to_string()),
            severity: self.config.severity,
            category: self.config.category.clone(),
            references: self.config.references.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatternConfig {
    pub name: String,
    pub needle: String,
    pub case_sensitive: bool,
    pub utf16: bool,
    pub detect_reversed: bool,
    pub severity: Severity,
    pub category: SignatureCategory,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegexSignatureConfig {
    pub name: String,
    pub pattern: String,
    pub case_insensitive: bool,
    pub utf16: bool,
    pub severity: Severity,
    pub category: SignatureCategory,
    pub description: Option<String>,
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureFinding {
    pub signature: String,
    pub reason: String,
    pub metadata: SignatureMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: SignatureCategory,
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignatureCategory {
    Exfiltration,
    CommandAndControl,
    Credentials,
    Behavior,
    Custom,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone)]
pub struct RegisteredSignature {
    pub enabled: bool,
    pub signature: Arc<dyn SecuritySignature>,
}
