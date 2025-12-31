// HydraDragonFirewall SDK - Complete Implementation
// Features: Base58, Base64, Reverse, Hex, HTTP, HTTPS, UDP, TCP, ICMP, ARP,
// IP Address, Domain, URL, File Type, Regex, YAML Signatures, Comments,
// Traffic Attack, Block, Allow, Ask, Change Packet, Solve Packet, Inject DLL,
// Port, Localhost, Routine, AND/OR Conditions, Rule Name, Description

use crate::engine::{FirewallSettings, PacketInfo, Protocol};
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// ENCODING SUPPORT (Features 1-4)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContentEncoding {
    Base58,
    Base64,
    Reverse,
    Hex,
    #[default]
    Plain,
}

impl ContentEncoding {
    /// Decode content based on encoding type
    pub fn decode(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            ContentEncoding::Base58 => {
                let text = String::from_utf8_lossy(data);
                bs58::decode(text.trim()).into_vec().ok()
            }
            ContentEncoding::Base64 => {
                let text = String::from_utf8_lossy(data);
                base64::engine::general_purpose::STANDARD
                    .decode(text.trim())
                    .ok()
            }
            ContentEncoding::Reverse => {
                Some(data.iter().rev().cloned().collect())
            }
            ContentEncoding::Hex => {
                let text = String::from_utf8_lossy(data);
                let hex_str = text.trim().replace(" ", "");
                if hex_str.len() % 2 != 0 {
                    return None;
                }
                let mut result = Vec::with_capacity(hex_str.len() / 2);
                for i in (0..hex_str.len()).step_by(2) {
                    if let Ok(byte) = u8::from_str_radix(&hex_str[i..i + 2], 16) {
                        result.push(byte);
                    } else {
                        return None;
                    }
                }
                Some(result)
            }
            ContentEncoding::Plain => Some(data.to_vec()),
        }
    }

    /// Encode content to specified format
    pub fn encode(&self, data: &[u8]) -> String {
        match self {
            ContentEncoding::Base58 => bs58::encode(data).into_string(),
            ContentEncoding::Base64 => {
                base64::engine::general_purpose::STANDARD.encode(data)
            }
            ContentEncoding::Reverse => {
                String::from_utf8_lossy(&data.iter().rev().cloned().collect::<Vec<u8>>())
                    .to_string()
            }
            ContentEncoding::Hex => {
                data.iter().map(|b| format!("{:02x}", b)).collect()
            }
            ContentEncoding::Plain => String::from_utf8_lossy(data).to_string(),
        }
    }
}

// ============================================================================
// PROTOCOL SUPPORT (Features 5-11)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleProtocol {
    HTTP,
    HTTPS,
    UDP,
    TCP,
    ICMP,
    ARP,
    #[default]
    Any,
}

impl RuleProtocol {
    /// Check if protocol matches the packet
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        match self {
            RuleProtocol::Any => true,
            RuleProtocol::TCP => packet.protocol == Protocol::TCP,
            RuleProtocol::UDP => packet.protocol == Protocol::UDP,
            RuleProtocol::ICMP => packet.protocol == Protocol::ICMP,
            RuleProtocol::HTTP => {
                packet.protocol == Protocol::TCP
                    && (packet.dst_port == 80 || packet.src_port == 80)
            }
            RuleProtocol::HTTPS => {
                packet.protocol == Protocol::TCP
                    && (packet.dst_port == 443 || packet.src_port == 443)
            }
            RuleProtocol::ARP => {
                // ARP is typically identified by Raw protocol number 0x0806
                matches!(packet.protocol, Protocol::Raw(n) if n == 0)
            }
        }
    }
}

// ============================================================================
// IP ADDRESS MATCHING (Feature 11)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IpMatcher {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub cidr_ranges: Vec<String>,
}

impl IpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        if self.addresses.is_empty() && self.cidr_ranges.is_empty() {
            return true; // Empty matcher = any
        }

        let ip_str = ip.to_string();

        // Check exact addresses
        for addr in &self.addresses {
            if addr == "*" || addr == "any" || addr == &ip_str {
                return true;
            }
        }

        // Check CIDR ranges
        for cidr in &self.cidr_ranges {
            if self.ip_in_cidr(ip, cidr) {
                return true;
            }
        }

        false
    }

    fn ip_in_cidr(&self, ip: IpAddr, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        match ip {
            IpAddr::V4(ipv4) => {
                let Ok(network) = parts[0].parse::<Ipv4Addr>() else {
                    return false;
                };
                let Ok(prefix_len) = parts[1].parse::<u32>() else {
                    return false;
                };

                if prefix_len > 32 {
                    return false;
                }

                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };

                let ip_u32 = u32::from(ipv4);
                let network_u32 = u32::from(network);

                (ip_u32 & mask) == (network_u32 & mask)
            }
            IpAddr::V6(ipv6) => {
                let Ok(network) = parts[0].parse::<Ipv6Addr>() else {
                    return false;
                };
                let Ok(prefix_len) = parts[1].parse::<u32>() else {
                    return false;
                };

                if prefix_len > 128 {
                    return false;
                }

                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };

                let ip_u128 = u128::from(ipv6);
                let network_u128 = u128::from(network);

                (ip_u128 & mask) == (network_u128 & mask)
            }
        }
    }
}

// ============================================================================
// DOMAIN MATCHING (Feature 12)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DomainMatcher {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
}

impl DomainMatcher {
    pub fn matches(&self, hostname: Option<&str>) -> bool {
        if self.domains.is_empty() {
            return true;
        }

        let Some(host) = hostname else {
            return false;
        };

        let host_check = if self.case_insensitive {
            host.to_lowercase()
        } else {
            host.to_string()
        };

        for pattern in &self.domains {
            let pattern_check = if self.case_insensitive {
                pattern.to_lowercase()
            } else {
                pattern.clone()
            };

            if self.wildcard_match(&pattern_check, &host_check) {
                return true;
            }
        }

        false
    }

    fn wildcard_match(&self, pattern: &str, text: &str) -> bool {
        if pattern == "*" || pattern == "any" {
            return true;
        }

        // Handle *.example.com
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..];
            return text.ends_with(suffix) || text == &pattern[2..];
        }

        // Handle *keyword*
        if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
            let keyword = &pattern[1..pattern.len() - 1];
            return text.contains(keyword);
        }

        // Handle keyword*
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            return text.starts_with(prefix);
        }

        // Handle *keyword
        if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            return text.ends_with(suffix);
        }

        text == pattern
    }
}

// ============================================================================
// URL MATCHING (Feature 13)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UrlMatcher {
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl UrlMatcher {
    pub fn matches(&self, url: Option<&str>) -> bool {
        if self.patterns.is_empty() {
            return true;
        }

        let Some(u) = url else {
            return false;
        };

        let url_lower = u.to_lowercase();

        for pattern in &self.patterns {
            let pattern_lower = pattern.to_lowercase();
            if self.wildcard_match(&pattern_lower, &url_lower) {
                return true;
            }
        }

        false
    }

    fn wildcard_match(&self, pattern: &str, text: &str) -> bool {
        if pattern == "*" || pattern == "any" {
            return true;
        }

        // Handle */path/* style patterns
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 1 {
            return text == pattern;
        }

        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if let Some(found_pos) = text[pos..].find(part) {
                if i == 0 && found_pos != 0 {
                    return false; // First part must be at start if no leading *
                }
                pos += found_pos + part.len();
            } else {
                return false;
            }
        }

        // If pattern doesn't end with *, text must end exactly
        if !pattern.ends_with('*') && pos != text.len() {
            return false;
        }

        true
    }
}

// ============================================================================
// FILE TYPE MATCHING (Feature 14)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FileTypeMatcher {
    #[serde(default)]
    pub file_types: Vec<String>,
}

impl FileTypeMatcher {
    pub fn matches(&self, detected_type: Option<&str>) -> bool {
        if self.file_types.is_empty() {
            return true;
        }

        let Some(ftype) = detected_type else {
            return false;
        };

        let ftype_lower = ftype.to_lowercase();
        self.file_types
            .iter()
            .any(|t| t.to_lowercase() == ftype_lower)
    }
}

// ============================================================================
// REGEX MATCHING (Feature 15)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RegexMatcher {
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub case_insensitive: bool,
}

impl RegexMatcher {
    pub fn matches(&self, data: &[u8]) -> bool {
        if self.pattern.is_empty() {
            return true;
        }

        let text = String::from_utf8_lossy(data);
        let pattern_str = if self.case_insensitive {
            format!("(?i){}", self.pattern)
        } else {
            self.pattern.clone()
        };

        match Regex::new(&pattern_str) {
            Ok(re) => re.is_match(&text),
            Err(_) => false,
        }
    }
}

// ============================================================================
// PORT MATCHING (Feature 25)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PortMatcher {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub ranges: Vec<(u16, u16)>,
}

impl PortMatcher {
    pub fn matches(&self, port: u16) -> bool {
        if self.ports.is_empty() && self.ranges.is_empty() {
            return true;
        }

        if self.ports.contains(&port) {
            return true;
        }

        for (start, end) in &self.ranges {
            if port >= *start && port <= *end {
                return true;
            }
        }

        false
    }
}

// ============================================================================
// LOCALHOST DETECTION (Feature 26)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalhostType {
    Loopback,   // 127.x.x.x
    PrivateA,   // 10.x.x.x
    PrivateB,   // 172.16-31.x.x
    PrivateC,   // 192.168.x.x
    Any,        // 0.0.0.0
    #[default]
    All,        // Match any localhost/private type
    None,       // Disable localhost matching
}

impl LocalhostType {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => match self {
                LocalhostType::None => true, // Always passes (no filter)
                LocalhostType::Loopback => ipv4.octets()[0] == 127,
                LocalhostType::PrivateA => ipv4.octets()[0] == 10,
                LocalhostType::PrivateB => {
                    ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31
                }
                LocalhostType::PrivateC => {
                    ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168
                }
                LocalhostType::Any => ipv4 == Ipv4Addr::new(0, 0, 0, 0),
                LocalhostType::All => {
                    LocalhostType::Loopback.matches(ip)
                        || LocalhostType::PrivateA.matches(ip)
                        || LocalhostType::PrivateB.matches(ip)
                        || LocalhostType::PrivateC.matches(ip)
                        || LocalhostType::Any.matches(ip)
                }
            },
            IpAddr::V6(ipv6) => match self {
                LocalhostType::None => true,
                LocalhostType::Loopback => ipv6.is_loopback(),
                LocalhostType::PrivateA | LocalhostType::PrivateB | LocalhostType::PrivateC => {
                    ipv6.is_unique_local() || ipv6.is_unicast_link_local()
                }
                LocalhostType::Any => ipv6.is_unspecified(),
                LocalhostType::All => {
                    ipv6.is_loopback() || ipv6.is_unique_local() || ipv6.is_unicast_link_local()
                        || ipv6.is_unspecified()
                }
            },
        }
    }
}

// ============================================================================
// TRAFFIC ROUTINE (Feature 27)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TrafficRoutine {
    #[serde(default)]
    pub from_ip: Option<String>,
    #[serde(default)]
    pub from_port: Option<u16>,
    #[serde(default)]
    pub to_ip: Option<String>,
    #[serde(default)]
    pub to_port: Option<u16>,
}

impl TrafficRoutine {
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        // Match source IP
        if let Some(ref from_ip) = self.from_ip {
            if from_ip != "any" && from_ip != "*" {
                let ip_str = packet.src_ip.to_string();
                if from_ip != &ip_str {
                    return false;
                }
            }
        }

        // Match source port
        if let Some(from_port) = self.from_port {
            if from_port != 0 && from_port != packet.src_port {
                return false;
            }
        }

        // Match destination IP
        if let Some(ref to_ip) = self.to_ip {
            if to_ip != "any" && to_ip != "*" {
                let ip_str = packet.dst_ip.to_string();
                if to_ip != &ip_str {
                    return false;
                }
            }
        }

        // Match destination port
        if let Some(to_port) = self.to_port {
            if to_port != 0 && to_port != packet.dst_port {
                return false;
            }
        }

        true
    }
}

// ============================================================================
// ACTIONS (Features 18-24)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    TrafficAttack,  // Feature 18: Detect/log attack patterns
    Block,          // Feature 19
    #[default]
    Allow,          // Feature 20
    Ask,            // Feature 21: Prompt user
    ChangePacket,   // Feature 22: Modify packet
    SolvePacket,    // Feature 23: Fix/normalize packet
    InjectDll,      // Feature 24: Inject DLL to watch
}

// ============================================================================
// CONDITION LOGIC (Feature 28)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConditionLogic {
    #[default]
    And,
    Or,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentMatchData {
    pub pattern: String,
    pub encoding: ContentEncoding,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCondition {
    Protocol(RuleProtocol),
    SrcIp(IpMatcher),
    DstIp(IpMatcher),
    SrcPort(PortMatcher),
    DstPort(PortMatcher),
    Domain(DomainMatcher),
    Url(UrlMatcher),
    FileType(FileTypeMatcher),
    Regex(RegexMatcher),
    Localhost(LocalhostType),
    ContentMatch(ContentMatchData),
}

impl RuleCondition {
    pub fn matches(&self, packet: &PacketInfo, payload: &[u8]) -> bool {
        match self {
            RuleCondition::Protocol(proto) => proto.matches(packet),
            RuleCondition::SrcIp(matcher) => matcher.matches(packet.src_ip),
            RuleCondition::DstIp(matcher) => matcher.matches(packet.dst_ip),
            RuleCondition::SrcPort(matcher) => matcher.matches(packet.src_port),
            RuleCondition::DstPort(matcher) => matcher.matches(packet.dst_port),
            RuleCondition::Domain(matcher) => matcher.matches(packet.hostname.as_deref()),
            RuleCondition::Url(matcher) => matcher.matches(packet.full_url.as_deref()),
            RuleCondition::FileType(matcher) => {
                matcher.matches(packet.detected_file_type.as_deref())
            }
            RuleCondition::Regex(matcher) => matcher.matches(payload),
            RuleCondition::Localhost(localhost_type) => {
                localhost_type.matches(packet.src_ip) || localhost_type.matches(packet.dst_ip)
            }
            RuleCondition::ContentMatch(data) => {
                // Try to find pattern in decoded content
                if let Some(decoded) = data.encoding.decode(payload) {
                    let text = String::from_utf8_lossy(&decoded);
                    text.contains(&data.pattern)
                } else {
                    false
                }
            }
        }
    }
}

// ============================================================================
// SDK RULE (Features 16, 17, 29, 30)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRule {
    // Feature 29: Rule name
    pub name: String,
    // Feature 30: Description
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    // Features 5-11: Protocol
    #[serde(default)]
    pub protocol: RuleProtocol,
    // Features 18-24: Action
    #[serde(default)]
    pub action: RuleAction,
    // Feature 28: Condition logic (AND/OR)
    #[serde(default)]
    pub condition_logic: ConditionLogic,
    // Features 1-4: Content encoding
    #[serde(default)]
    pub encoding: ContentEncoding,
    // Feature 11: Source IP
    #[serde(default)]
    pub src_ip: Option<IpMatcher>,
    // Feature 11: Destination IP
    #[serde(default)]
    pub dst_ip: Option<IpMatcher>,
    // Feature 25: Source port
    #[serde(default)]
    pub src_port: Option<PortMatcher>,
    // Feature 25: Destination port
    #[serde(default)]
    pub dst_port: Option<PortMatcher>,
    // Feature 12: Domain matching
    #[serde(default)]
    pub domain: Option<DomainMatcher>,
    // Feature 13: URL matching
    #[serde(default)]
    pub url: Option<UrlMatcher>,
    // Feature 14: File type matching
    #[serde(default)]
    pub file_type: Option<FileTypeMatcher>,
    // Feature 15: Regex matching
    #[serde(default)]
    pub regex: Option<RegexMatcher>,
    // Feature 26: Localhost type
    #[serde(default)]
    pub localhost_type: Option<LocalhostType>,
    // Feature 27: Traffic routine
    #[serde(default)]
    pub routine: Option<TrafficRoutine>,
    // Feature 28: Additional conditions
    #[serde(default)]
    pub conditions: Vec<RuleCondition>,
    // Packet modification data (for ChangePacket action)
    #[serde(default)]
    pub change_data: Option<String>,
    // DLL path (for InjectDll action)
    #[serde(default)]
    pub inject_dll_path: Option<String>,
}

fn default_true() -> bool {
    true
}

impl SdkRule {
    /// Evaluate if this rule matches the packet
    pub fn matches(&self, packet: &PacketInfo, payload: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }

        let mut matches: Vec<bool> = Vec::new();

        // Protocol check
        if !self.protocol.matches(packet) {
            matches.push(false);
        } else {
            matches.push(true);
        }

        // Source IP check
        if let Some(ref matcher) = self.src_ip {
            matches.push(matcher.matches(packet.src_ip));
        }

        // Destination IP check
        if let Some(ref matcher) = self.dst_ip {
            matches.push(matcher.matches(packet.dst_ip));
        }

        // Source port check
        if let Some(ref matcher) = self.src_port {
            matches.push(matcher.matches(packet.src_port));
        }

        // Destination port check
        if let Some(ref matcher) = self.dst_port {
            matches.push(matcher.matches(packet.dst_port));
        }

        // Domain check
        if let Some(ref matcher) = self.domain {
            matches.push(matcher.matches(packet.hostname.as_deref()));
        }

        // URL check
        if let Some(ref matcher) = self.url {
            matches.push(matcher.matches(packet.full_url.as_deref()));
        }

        // File type check
        if let Some(ref matcher) = self.file_type {
            matches.push(matcher.matches(packet.detected_file_type.as_deref()));
        }

        // Regex check
        if let Some(ref matcher) = self.regex {
            // Apply encoding before regex match
            let check_data = self.encoding.decode(payload).unwrap_or_else(|| payload.to_vec());
            matches.push(matcher.matches(&check_data));
        }

        // Localhost check
        if let Some(ref localhost_type) = self.localhost_type {
            let src_match = localhost_type.matches(packet.src_ip);
            let dst_match = localhost_type.matches(packet.dst_ip);
            matches.push(src_match || dst_match);
        }

        // Routine check
        if let Some(ref routine) = self.routine {
            matches.push(routine.matches(packet));
        }

        // Additional conditions
        for condition in &self.conditions {
            let check_data = self.encoding.decode(payload).unwrap_or_else(|| payload.to_vec());
            matches.push(condition.matches(packet, &check_data));
        }

        // Apply condition logic
        if matches.is_empty() {
            return true; // Empty rule matches everything
        }

        match self.condition_logic {
            ConditionLogic::And => matches.iter().all(|&m| m),
            ConditionLogic::Or => matches.iter().any(|&m| m),
        }
    }
}

// ============================================================================
// YAML RULE FILE FORMAT (Feature 16, 17)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRuleFile {
    #[serde(default)]
    pub rules: Vec<SdkRule>,
}

impl SdkRuleFile {
    /// Load rules from YAML file (supports # comments - Feature 17)
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read rules file: {}", e))?;

        Self::load_from_string(&content)
    }

    /// Load rules from YAML string
    pub fn load_from_string(content: &str) -> Result<Self, String> {
        // YAML natively supports # comments (Feature 17)
        serde_yaml::from_str(content)
            .map_err(|e| format!("Failed to parse rules YAML: {}", e))
    }

    /// Save rules to YAML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let content = serde_yaml::to_string(self)
            .map_err(|e| format!("Failed to serialize rules: {}", e))?;

        fs::write(path, content).map_err(|e| format!("Failed to write rules file: {}", e))
    }
}

// ============================================================================
// SDK RULE RESULT
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleMatchResult {
    pub rule_name: String,
    pub action: RuleAction,
    pub description: String,
    pub change_data: Option<String>,
    pub inject_dll_path: Option<String>,
}

// ============================================================================
// SDK REGISTRY
// ============================================================================

pub struct SdkRegistry {
    pub rules: Vec<SdkRule>,
    pub listeners: Vec<Arc<dyn PacketListener>>,
    pub changers: Vec<Arc<dyn PacketChanger>>,
}

impl SdkRegistry {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            listeners: Vec::new(),
            changers: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.load_default_rules();
        registry
    }

    pub fn load_default_rules(&mut self) {
        // Load from rules.yaml if it exists
        match SdkRuleFile::load_from_file("rules.yaml") {
            Ok(rule_file) => {
                println!("[SDK] Loaded {} rules from rules.yaml", rule_file.rules.len());
                self.rules = rule_file.rules;
            }
            Err(e) => {
                eprintln!("[SDK] Failed to load rules.yaml: {}", e);
            }
        }
    }

    pub fn load_rules_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let rule_file = SdkRuleFile::load_from_file(path)?;
        self.rules = rule_file.rules;
        Ok(())
    }

    pub fn add_rule(&mut self, rule: SdkRule) {
        self.rules.push(rule);
    }

    pub fn register_listener(&mut self, listener: Arc<dyn PacketListener>) {
        self.listeners.push(listener);
    }

    pub fn register_changer(&mut self, changer: Arc<dyn PacketChanger>) {
        self.changers.push(changer);
    }

    /// Evaluate all rules against packet, return first matching rule
    pub fn evaluate(
        &self,
        packet: &PacketInfo,
        payload: &[u8],
        _settings: &FirewallSettings,
        _context: &PacketContext,
    ) -> Option<RuleMatchResult> {
        for rule in &self.rules {
            if rule.matches(packet, payload) {
                return Some(RuleMatchResult {
                    rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                    description: rule.description.clone(),
                    change_data: rule.change_data.clone(),
                    inject_dll_path: rule.inject_dll_path.clone(),
                });
            }
        }
        None
    }

    /// Get all matching rules (not just first)
    pub fn evaluate_all(
        &self,
        packet: &PacketInfo,
        payload: &[u8],
        _settings: &FirewallSettings,
        _context: &PacketContext,
    ) -> Vec<RuleMatchResult> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(packet, payload))
            .map(|rule| RuleMatchResult {
                rule_name: rule.name.clone(),
                action: rule.action.clone(),
                description: rule.description.clone(),
                change_data: rule.change_data.clone(),
                inject_dll_path: rule.inject_dll_path.clone(),
            })
            .collect()
    }

    pub fn list_rules(&self) -> Vec<&SdkRule> {
        self.rules.iter().collect()
    }

    pub fn toggle_rule(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.name == name) {
            rule.enabled = enabled;
            return true;
        }
        false
    }
}

// ============================================================================
// PACKET CONTEXT
// ============================================================================

#[derive(Clone, Debug)]
pub struct PacketContext {
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
}

// ============================================================================
// TRAITS
// ============================================================================

/// Trait for components that passively listen to/log network traffic
pub trait PacketListener: Send + Sync {
    fn on_packet(&self, data: &[u8], info: &PacketInfo, context: &PacketContext);
}

/// Trait for components that can modify network packets
pub trait PacketChanger: Send + Sync {
    fn modify(&self, data: &mut Vec<u8>, info: &PacketInfo, context: &PacketContext) -> bool;
}

// ============================================================================
// RAW PACKET (For logging/export)
// ============================================================================

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
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
    pub action: String,
    pub rule: String,
    pub hostname: Option<String>,
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
            hostname: info.hostname.clone(),
        }
    }
}

// ============================================================================
// HOOK SETTINGS (Feature 30 - Process Hooking)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HookSettings {
    pub enabled: bool,
    pub whitelist_paths: Vec<String>,
}

impl Default for HookSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            whitelist_paths: vec![
                "\\desktop\\sanctum".to_string(),
                "\\appdata\\roaming\\sanctum".to_string(),
                "\\appdata\\local\\sanctum".to_string(),
                "\\program files\\hydradragonantivirus".to_string(),
            ],
        }
    }
}

impl HookSettings {
    pub fn is_whitelisted(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        self.whitelist_paths
            .iter()
            .any(|p| path_lower.contains(&p.to_lowercase()))
    }

    pub fn add_whitelist_path(&mut self, path: String) {
        if !self.whitelist_paths.contains(&path) {
            self.whitelist_paths.push(path);
        }
    }

    pub fn remove_whitelist_path(&mut self, path: &str) {
        self.whitelist_paths.retain(|p| p != path);
    }
}
