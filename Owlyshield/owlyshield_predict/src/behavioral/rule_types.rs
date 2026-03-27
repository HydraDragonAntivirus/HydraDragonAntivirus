use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use regex::Regex;

// =============================================================================
// HELPER FUNCTIONS & DEFAULTS
// =============================================================================

pub fn default_zero() -> usize { 0 }
pub fn default_severity() -> u8 { 50 }
pub fn default_true() -> bool { true }

pub fn expand_environment_variables(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let re = match Regex::new(r"%([^%]+)%") {
        Ok(r) => r,
        Err(_) => return text.to_string(),
    };
    re.replace_all(text, |caps: &regex::Captures| {
        let var_name = &caps[1].to_uppercase();
        match std::env::var(var_name) {
            Ok(val) => val,
            Err(_) => caps[0].to_string()
        }
    }).to_string()
}

// =============================================================================
// COMMON ENUMS & STRUCTS
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub enum Comparison {
    #[default]
    Gt,
    Lt,
    Eq,
    Ne,
    Gte,
    Lte,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub enum MatchMode {
    #[default]
    Any,
    All,
    Exact,
    Substring,
    Regex,
    Glob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLinePattern {
    pub pattern: PatternSpec,
    #[serde(default)]
    pub is_regex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StringModifier {
    Nocase, Contains, Startswith, Endswith, Re, Base64, Not,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PatternSpec {
    Simple(String),
    Complex {
        pattern: String,
        #[serde(default)]
        modifiers: Vec<StringModifier>,
    },
}

impl PatternSpec {
    pub fn pattern(&self) -> &str {
        match self {
            PatternSpec::Simple(p) => p,
            PatternSpec::Complex { pattern, .. } => pattern,
        }
    }

    pub fn pattern_mut(&mut self) -> &mut String {
        match self {
            PatternSpec::Simple(pattern) => pattern,
            PatternSpec::Complex { pattern, .. } => pattern,
        }
    }
    
    pub fn modifiers(&self) -> &[StringModifier] {
        match self {
            PatternSpec::Simple(_) => &[],
            PatternSpec::Complex { modifiers, .. } => modifiers,
        }
    }
    
    pub fn has_modifier(&self, modifier: &StringModifier) -> bool {
        self.modifiers().iter().any(|m| std::mem::discriminant(m) == std::mem::discriminant(modifier))
    }
    
    pub fn is_case_insensitive(&self) -> bool {
        self.has_modifier(&StringModifier::Nocase)
    }
    
    pub fn is_regex(&self) -> bool {
        self.has_modifier(&StringModifier::Re)
    }
    
    pub fn is_contains(&self) -> bool {
        self.has_modifier(&StringModifier::Contains)
    }
    
    pub fn is_startswith(&self) -> bool {
        self.has_modifier(&StringModifier::Startswith)
    }
    
    pub fn is_endswith(&self) -> bool {
        self.has_modifier(&StringModifier::Endswith)
    }
    
    pub fn is_negated(&self) -> bool {
        self.has_modifier(&StringModifier::Not)
    }

    pub fn matches(&self, cache: &Arc<RwLock<HashMap<String, Regex>>>, text: &str, force_regex: bool) -> bool {
        let mut pattern = self.pattern().to_string();

        if self.has_modifier(&StringModifier::Base64)
            && let Ok(decoded) = STANDARD.decode(pattern.as_bytes()) {
                pattern = String::from_utf8_lossy(&decoded).into_owned();
            }

        let case_insensitive = !matches!(self, PatternSpec::Complex { .. }) || self.is_case_insensitive();

        let matched = if force_regex || self.is_regex() {
            let regex_pattern = if case_insensitive && !pattern.starts_with("(?i)") {
                format!("(?i){}", pattern)
            } else {
                pattern.clone()
            };
            Regex::new(&regex_pattern).map_or(false, |re| re.is_match(text))
        } else {
            let candidate = if case_insensitive {
                text.to_lowercase()
            } else {
                text.to_string()
            };
            let needle = if case_insensitive {
                pattern.to_lowercase()
            } else {
                pattern
            };

            if self.is_startswith() {
                candidate.starts_with(&needle)
            } else if self.is_endswith() {
                candidate.ends_with(&needle)
            } else if self.is_contains() {
                candidate.contains(&needle)
            } else {
                matches_pattern(cache, &needle, &candidate)
            }
        };

        if self.is_negated() { !matched } else { matched }
    }
}

impl CommandLinePattern {
    pub fn matches(&self, cache: &Arc<RwLock<HashMap<String, Regex>>>, text: &str) -> bool {
        self.pattern.matches(cache, text, self.is_regex)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq)]
pub enum RuleStatus {
    #[default]
    Stable,
    Experimental,
    Test,
    Deprecated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq)]
pub enum DetectionLevel {
    Informational,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogSource {
    pub product: String,
    pub service: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedPaths {
    #[serde(default)]
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub write_protected: bool,
    #[serde(default)]
    pub read_protected: bool,
    #[serde(default)]
    pub execute_protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanConfig {
    #[serde(default)]
    pub target_processes: Vec<String>,
    #[serde(default)]
    pub scan_on_io_event: bool,
    #[serde(default)]
    pub scan_every_n_ops: u64,
    #[serde(default)]
    pub min_scan_interval_secs: u64,
}

// =============================================================================
// NETWORK-SPECIFIC TYPES
// =============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::Raw(_) => "RAW",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub size: usize,
    pub outbound: bool,
    pub process_id: u32,
    pub dns_query: Option<String>,
    pub hostname: Option<String>,
    pub full_url: Option<String>,
    pub tls_handshake: bool,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_user_agent: Option<String>,
    pub http_content_type: Option<String>,
    pub http_referer: Option<String>,
    pub payload_entropy: Option<f64>,
    pub payload_sample: Option<String>,
    pub payload_urls: Vec<String>,
    pub payload_domains: Vec<String>,
    pub image_path: String,
    pub detected_file_type: Option<String>,
    pub http_request_body: Option<String>,
    pub http_response_body: Option<String>,
    pub domain: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleProtocol {
    HTTP,
    HTTPS,
    UDP,
    TCP,
    ICMP,
    ARP,
    DNS,
    QUIC,
    TLSSNI,
    #[default]
    ANY,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IpMatcher {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub cidr_ranges: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PortMatcher {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub ranges: Vec<(u16, u16)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DomainMatcher {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UrlMatcher {
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalhostType {
    Loopback, PrivateA, PrivateB, PrivateC, Any, #[default] All, None,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegexMatcher {
    pub pattern: String,
    #[serde(default)]
    pub case_insensitive: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntropyMatcher {
    pub threshold: f64,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentMatchData {
    pub pattern: String,
    pub encoding: ContentEncoding,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TrafficRoutine {
    pub from_ip: Option<String>,
    pub from_port: Option<u16>,
    pub to_ip: Option<String>,
    pub to_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct JsonMatcher {
    pub field: String,
    pub value: serde_json::Value,
}

impl JsonMatcher {
    pub fn matches(&self, payload: &[u8]) -> bool {
        let text = String::from_utf8_lossy(payload);
        if !text.trim().starts_with('{') && !text.trim().starts_with('[') {
            return false;
        }
        // Basic heuristic for JSON field matching without full parsing
        text.contains(&format!("\"{}\"", self.field)) && text.contains(&format!("{:?}", self.value))
    }
}

impl NetworkRuleCondition {
    pub fn matches_packet(&self, cache: &Arc<RwLock<HashMap<String, Regex>>>, packet: &PacketInfo, payload: &[u8]) -> bool {
        match self {
            NetworkRuleCondition::And(conds) => conds.iter().all(|c| c.matches_packet(cache, packet, payload)),
            NetworkRuleCondition::Or(conds) => conds.iter().any(|c| c.matches_packet(cache, packet, payload)),
            NetworkRuleCondition::Protocol(proto) => match proto {
                RuleProtocol::TCP => packet.protocol == Protocol::TCP,
                RuleProtocol::UDP => packet.protocol == Protocol::UDP,
                RuleProtocol::ICMP => packet.protocol == Protocol::ICMP,
                RuleProtocol::HTTP => packet.full_url.is_some() || packet.hostname.is_some() || packet.dst_port == 80 || packet.src_port == 80,
                RuleProtocol::HTTPS => packet.tls_handshake || packet.dst_port == 443 || packet.src_port == 443,
                RuleProtocol::DNS => packet.dns_query.is_some() || packet.dst_port == 53 || packet.src_port == 53,
                RuleProtocol::QUIC => packet.protocol == Protocol::UDP && (packet.dst_port == 443 || packet.src_port == 443),
                RuleProtocol::TLSSNI => packet.tls_handshake,
                RuleProtocol::ARP => matches!(packet.protocol, Protocol::Raw(0)),
                RuleProtocol::ANY => true,
            },
            NetworkRuleCondition::SrcIp(matcher) => matcher.matches(packet.src_ip),
            NetworkRuleCondition::DstIp(matcher) => matcher.matches(packet.dst_ip),
            NetworkRuleCondition::SrcPort(matcher) => matcher.matches(packet.src_port),
            NetworkRuleCondition::DstPort(matcher) => matcher.matches(packet.dst_port),
            NetworkRuleCondition::Domain(matcher) => matcher.matches(packet.hostname.as_deref()) || packet.payload_domains.iter().any(|d| matcher.matches(Some(d))),
            NetworkRuleCondition::Url(matcher) => matcher.matches(packet.full_url.as_deref()) || packet.payload_urls.iter().any(|u| matcher.matches(Some(u))),
            NetworkRuleCondition::FileType(types) => {
                if let Some(ft) = &packet.detected_file_type {
                    let ft_lower = ft.to_lowercase();
                    types.iter().any(|t| t.to_lowercase() == ft_lower)
                } else {
                    false
                }
            }
            NetworkRuleCondition::Regex(matcher) => {
                if let Some(sample) = &packet.payload_sample {
                    matcher.matches(sample.as_bytes())
                } else {
                    false
                }
            }
            NetworkRuleCondition::Localhost(l_type) => l_type.matches(if packet.outbound { packet.dst_ip } else { packet.src_ip }),
            NetworkRuleCondition::ContentMatch(data) => {
                if let Some(sample) = &packet.payload_sample {
                    if let Some(decoded) = data.encoding.decode(sample.as_bytes()) {
                        let text = String::from_utf8_lossy(&decoded);
                        text.contains(&data.pattern)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            NetworkRuleCondition::Entropy(matcher) => packet.payload_entropy.map_or(false, |e| e >= matcher.threshold),
            NetworkRuleCondition::Routine(routine) => routine.matches(packet),
            NetworkRuleCondition::SanctumDetected => true,
        }
    }
}

impl IpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        if self.addresses.is_empty() && self.cidr_ranges.is_empty() { return true; }
        let ip_str = ip.to_string();
        if self.addresses.iter().any(|a| a == "*" || a == "any" || a == &ip_str) { return true; }
        self.cidr_ranges.iter().any(|c| ip_in_cidr(ip, c))
    }
}

impl DomainMatcher {
    pub fn matches(&self, hostname: Option<&str>) -> bool {
        let Some(host) = hostname else { return false; };
        if self.domains.is_empty() { return true; }
        let host_check = if self.case_insensitive { host.to_lowercase() } else { host.to_string() };
        self.domains.iter().any(|d| {
            let d_check = if self.case_insensitive { d.to_lowercase() } else { d.clone() };
            wildcard_match(&d_check, &host_check)
        })
    }
    
    pub fn exact(domain: String) -> Self {
        Self {
            domains: vec![domain],
            case_insensitive: true,
        }
    }
}

impl UrlMatcher {
    pub fn matches(&self, url: Option<&str>) -> bool {
        let Some(u) = url else { return false; };
        if self.patterns.is_empty() { return true; }
        let u_lower = u.to_lowercase();
        self.patterns.iter().any(|p| wildcard_match(&p.to_lowercase(), &u_lower))
    }
    
    pub fn contains(pattern: String) -> Self {
        Self {
            patterns: vec![format!("*{}*", pattern)],
        }
    }
}

impl PortMatcher {
    pub fn matches(&self, port: u16) -> bool {
        if self.ports.is_empty() && self.ranges.is_empty() { return true; }
        if self.ports.contains(&port) { return true; }
        self.ranges.iter().any(|(s, e)| port >= *s && port <= *e)
    }
}

impl TrafficRoutine {
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        if let Some(ref f) = self.from_ip { if f != "*" && f != "any" && &packet.src_ip.to_string() != f { return false; } }
        if let Some(f) = self.from_port { if f != 0 && packet.src_port != f { return false; } }
        if let Some(ref t) = self.to_ip { if t != "*" && t != "any" && &packet.dst_ip.to_string() != t { return false; } }
        if let Some(t) = self.to_port { if t != 0 && packet.dst_port != t { return false; } }
        true
    }
}

impl LocalhostType {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => match self {
                LocalhostType::None => true,
                LocalhostType::Loopback => ipv4.octets()[0] == 127,
                LocalhostType::PrivateA => ipv4.octets()[0] == 10,
                LocalhostType::PrivateB => ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31,
                LocalhostType::PrivateC => ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168,
                LocalhostType::Any => ipv4 == Ipv4Addr::new(0,0,0,0),
                LocalhostType::All => ipv4.octets()[0] == 127 || ipv4.octets()[0] == 10 || (ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31) || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168),
            },
            IpAddr::V6(ipv6) => match self {
                LocalhostType::None => true,
                LocalhostType::Loopback => ipv6.is_loopback(),
                _ => ipv6.is_unique_local() || ipv6.is_unicast_link_local() || ipv6.is_unspecified(),
            }
        }
    }
}

impl RegexMatcher {
    pub fn matches(&self, data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(data);
        let p = if self.case_insensitive { format!("(?i){}", self.pattern) } else { self.pattern.clone() };
        Regex::new(&p).map_or(false, |re| re.is_match(&text))
    }
}

impl ContentEncoding {
    pub fn decode(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            ContentEncoding::Plain => Some(data.to_vec()),
            ContentEncoding::Reverse => Some(data.iter().rev().cloned().collect()),
            ContentEncoding::Hex => {
                let text = String::from_utf8_lossy(data).trim().replace(" ", "");
                if text.len() % 2 != 0 { return None; }
                let mut result = Vec::with_capacity(text.len() / 2);
                for i in (0..text.len()).step_by(2) {
                    if let Ok(byte) = u8::from_str_radix(&text[i..i + 2], 16) {
                        result.push(byte);
                    } else { return None; }
                }
                Some(result)
            }
            _ => None, // Base64/Base58 omitted for brevity or implement if needed
        }
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return false; }
    let Ok(prefix_len) = parts[1].parse::<u32>() else { return false; };
    match ip {
        IpAddr::V4(v4) => {
            let Ok(net) = parts[0].parse::<Ipv4Addr>() else { return false; };
            if prefix_len > 32 { return false; }
            let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
            (u32::from(v4) & mask) == (u32::from(net) & mask)
        }
        IpAddr::V6(v6) => {
            let Ok(net) = parts[0].parse::<Ipv6Addr>() else { return false; };
            if prefix_len > 128 { return false; }
            let mask = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };
            (u128::from(v6) & mask) == (u128::from(net) & mask)
        }
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" || pattern == "any" { return true; }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 { return text == pattern; }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() { continue; }
        if let Some(found) = text[pos..].find(part) {
            if i == 0 && found != 0 { return false; }
            pos += found + part.len();
        } else { return false; }
    }
    pattern.ends_with('*') || pos == text.len()
}

pub fn matches_pattern(cache: &Arc<RwLock<HashMap<String, Regex>>>, pattern: &str, text: &str) -> bool {
    let p = pattern.to_lowercase();
    let t = text.to_lowercase();
    if p == "*" || p == "*.*" || p.is_empty() { return true; }
    if !p.contains('*') && !p.contains('?') { return t == p || t.contains(&p); }
    let rp = format!("^{}$", regex::escape(&p).replace("\\*", ".*").replace("\\?", "."));
    
    {
        if let Ok(cache_map) = cache.read() {
            if let Some(re) = cache_map.get(&rp) {
                return re.is_match(&t);
            }
        }
    }

    let Ok(mut cache_map) = cache.write() else { return false; };
    cache_map.entry(rp.clone()).or_insert_with(|| Regex::new(&rp).unwrap_or_else(|_| Regex::new(".*").unwrap())).is_match(&t)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", untagged)]
pub enum NetworkRuleCondition {
    And(Vec<NetworkRuleCondition>),
    Or(Vec<NetworkRuleCondition>),
    Protocol(RuleProtocol),
    SrcIp(IpMatcher),
    DstIp(IpMatcher),
    SrcPort(PortMatcher),
    DstPort(PortMatcher),
    Domain(DomainMatcher),
    Url(UrlMatcher),
    SanctumDetected,
    FileType(Vec<String>),
    Regex(RegexMatcher),
    Localhost(LocalhostType),
    ContentMatch(ContentMatchData),
    Entropy(EntropyMatcher),
    Routine(TrafficRoutine),
}

// =============================================================================
// UNIFIED RESPONSE TYPES
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    #[serde(default)] pub terminate_process: bool,
    #[serde(default)] pub suspend_process: bool,
    #[serde(default)] pub quarantine: bool,
    #[serde(default, alias = "deny_access", alias = "kernel_block")]
    pub status_access_denied: bool,
    #[serde(default)] pub kill_and_remove: bool,
    #[serde(default)] pub ask_user: bool,
    #[serde(default)] pub notify_user: bool,
    #[serde(default)] pub auto_revert: bool,
    #[serde(default)] pub record: bool,
    
    // Integrated Network Actions (from SdkRule)
    #[serde(default)] pub traffic_attack: bool,
    #[serde(default)] pub change_packet: bool,
    #[serde(default)] pub solve_packet: bool,
    #[serde(default)] pub change_request_body: Option<String>,
    #[serde(default)] pub change_response_body: Option<String>,
    #[serde(default)] pub use_regex_replacement: bool,
    #[serde(default)] pub search_pattern: Option<String>,
}

// =============================================================================
// BEHAVIORAL RULE TYPES (Ported from behavior_engine.rs)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowlistEntry {
    Simple(String),
    Complex {
        pattern: String,
        #[serde(default)]
        signers: Vec<String>,
        #[serde(default)]
        must_be_signed: bool,
        #[serde(default)]
        is_absolute: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    File { op: String, path_pattern: String },
    Registry { op: String, key_pattern: String, value_name: Option<String>, expected_data: Option<String> },
    Process { op: String, pattern: String },
    Service { op: String, name_pattern: String },
    Network { op: String, dest_pattern: Option<String> },
    NetworkCondition(NetworkRuleCondition),
    Api { name_pattern: String, module_pattern: String },
    Heuristic { metric: String, threshold: f64 },
    OperationCount { op_type: String, #[serde(default)] path_pattern: Option<String>, #[serde(default)] comparison: Comparison, threshold: u64 },
    ExtensionPattern { patterns: Vec<String>, #[serde(default)] match_mode: MatchMode, op_type: String },
    ByteThreshold { direction: String, #[serde(default)] comparison: Comparison, threshold: u64 },
    EntropyThreshold { metric: String, #[serde(default)] comparison: Comparison, threshold: f64 },
    FileCount { category: String, #[serde(default)] comparison: Comparison, threshold: u64 },
    Signature { 
        #[serde(default)]
        is_trusted: Option<bool>,  
        #[serde(default)]
        is_signed: Option<bool>,   
        #[serde(default)]
        signer_pattern: Option<String> 
    },
    DirectorySpread { category: String, #[serde(default)] comparison: Comparison, threshold: u64 },
    DriveActivity { drive_type: String, op_type: String, #[serde(default)] comparison: Comparison, threshold: u32 },
    ProcessAncestry { ancestor_pattern: String, #[serde(default)] max_depth: Option<u32> },
    ExtensionRatio { extensions: Vec<String>, #[serde(default)] comparison: Comparison, threshold: f32 },
    RateOfChange { metric: String, #[serde(default)] comparison: Comparison, threshold: f64 },
    SelfModification { modification_type: String },
    CommandLineMatch { patterns: Vec<CommandLinePattern>, #[serde(default)] match_mode: MatchMode },
    SensitivePathAccess { patterns: Vec<String>, op_type: String, #[serde(default)] min_unique_paths: Option<u32> },
    ClusterPattern { #[serde(default)] min_clusters: Option<usize>, #[serde(default)] max_clusters: Option<usize> },
    TempDirectoryWrite { #[serde(default)] min_bytes: Option<u64>, #[serde(default)] min_files: Option<u32> },
    ArchiveCreation { #[serde(default)] extensions: Vec<String>, #[serde(default)] min_size: Option<u64>, #[serde(default)] in_temp: bool },
    DataExfiltrationPattern { source_patterns: Vec<String>, #[serde(default)] min_source_reads: Option<u32>, #[serde(default)] detect_temp_staging: bool, #[serde(default)] detect_archive: bool },
    MemoryScan { #[serde(default)] patterns: Vec<String>, #[serde(default)] detect_pe_headers: bool, #[serde(default)] private_only: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub name: String,
    pub conditions: Vec<RuleCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetectionCondition {
    And { and: Vec<DetectionCondition> },
    Or { or: Vec<DetectionCondition> },
    Not { not: Box<DetectionCondition> },
    Named { condition: String },
    AllOf { all_of: Vec<String> },
    AnyOf { any_of: Vec<String> },
    NOf { n_of: usize, conditions: Vec<String> },
    AtLeast { at_least: usize, conditions: Vec<String> },
    AllOfPattern { all_of_pattern: String },
    AnyOfPattern { any_of_pattern: String },
    Count { count: Vec<String>, #[serde(default)] comparison: Comparison, threshold: usize },
    Percentage { percentage: Vec<String>, #[serde(default)] comparison: Comparison, threshold: f32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleMapping {
    And { and: Vec<RuleMapping> },
    Or { or: Vec<RuleMapping> },
    Not { not: Box<RuleMapping> },
    Stage { stage: String },
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NamedConditionGroup {
    #[serde(default)] pub apis: Vec<String>,
    #[serde(default = "default_zero")] pub api_threshold: usize,
    #[serde(default)] pub file_paths: Vec<String>,
    #[serde(default)] pub file_operations: Vec<String>,
    #[serde(default)] pub require_same_file_read: bool,
    #[serde(default)] pub require_same_file_write: bool,
    #[serde(default)] pub require_same_file_rename: bool,
    #[serde(default)] pub require_same_stem_created_unknown_extension: bool,
    #[serde(default)] pub require_same_stem_written_unknown_extension: bool,
    #[serde(default)] pub registry_keys: Vec<String>,
    #[serde(default)] pub registry_values: Vec<String>,
    #[serde(default)] pub registry_operations: Vec<String>,
    #[serde(default)] pub registry_value_data_patterns: Vec<String>,
    #[serde(default)] pub network_indicators: Vec<String>,
    #[serde(default)] pub has_network_activity: bool,
    #[serde(default)] pub network_rules: Vec<NetworkRuleCondition>,
    #[serde(default)] pub network_domains: Vec<String>,
    #[serde(default)] pub dns_query_patterns: Vec<String>,
    #[serde(default)] pub network_ips: Vec<String>,
    #[serde(default)] pub firewall_blocked: Option<bool>,
    #[serde(default)] pub firewall_dst_ips: Vec<String>,
    #[serde(default)] pub firewall_dst_ports: Vec<u16>,
    #[serde(default)] pub firewall_hostnames: Vec<String>,
    #[serde(default)] pub firewall_block_reasons: Vec<String>,
    #[serde(default)] pub process_names: Vec<String>,
    #[serde(default)] pub parent_names: Vec<String>,
    #[serde(default)] pub terminated_processes: Vec<String>,
    #[serde(default)] pub created_processes: Vec<String>,
    #[serde(default)] pub detect_self_termination: bool,
    #[serde(default)] pub detect_parent_image_delete: bool,
    #[serde(default)] pub detect_parent_image_rename: bool,
    #[serde(default)] pub file_extensions: Vec<String>,
    #[serde(default)] pub detect_extension_changes: bool,
    #[serde(default)] pub detect_known_to_unknown_extension_change: bool,
    #[serde(default, alias = "extension_allowlist")] pub extension_whitelist: Vec<String>,
    #[serde(default, alias = "detect_non_allowlisted_extensions")] pub detect_non_whitelisted_extensions: bool,
    #[serde(default)] pub file_actions: Vec<String>,
    #[serde(default)] pub entropy_threshold: f64,
    #[serde(default)] pub file_size_min: Option<u64>,
    #[serde(default)] pub file_size_max: Option<u64>,
    #[serde(default)] pub cmdline_patterns: Vec<CommandLinePattern>,
    #[serde(default)] pub cmdline_keywords: Vec<String>,
    #[serde(default)] pub script_file_patterns: Vec<String>,
    #[serde(default)] pub staging_paths: Vec<String>,
    #[serde(default)] pub browsed_paths: Vec<String>,
    #[serde(default)] pub sensitive_paths: Vec<String>,
    #[serde(default)] pub temp_writes: bool,
    #[serde(default)] pub persistence_locations: Vec<String>,
    #[serde(default)] pub autorun_keys: Vec<String>,
    #[serde(default)] pub scheduled_task_apis: Vec<String>,
    #[serde(default)] pub obfuscation_indicators: Vec<String>,
    #[serde(default)] pub anti_debug_apis: Vec<String>,
    #[serde(default)] pub anti_vm_apis: Vec<String>,
    #[serde(default)] pub requires_signed: Option<bool>,
    #[serde(default)] pub is_signed: Option<bool>,
    #[serde(default)] pub is_valid_signed: Option<bool>,
    #[serde(default)] pub trusted_signers: Vec<String>,
    #[serde(default)] pub untrusted_signers: Vec<String>,
    #[serde(default)] pub hypervisor_event_labels: Vec<String>,
    #[serde(default)] pub detect_hypervisor_event: bool,
    #[serde(default)] pub hypervisor_event_threshold: usize,
    #[serde(default)] pub hypervisor_raw_event_types: Vec<u32>,
    #[serde(default)] pub hypervisor_source_pids: Vec<u32>,
    #[serde(default)] pub hypervisor_target_pids: Vec<u32>,
    #[serde(default)] pub hypervisor_raw_arg1_values: Vec<u64>,
    #[serde(default)] pub hypervisor_raw_arg2_values: Vec<u64>,
    #[serde(default)] pub hypervisor_raw_arg3_values: Vec<u64>,
    #[serde(default)] pub hypervisor_raw_arg4_values: Vec<u64>,
    #[serde(default)] pub hypervisor_memory_sizes: Vec<u64>,
    #[serde(default)] pub hypervisor_operation_statuses: Vec<i32>,
    #[serde(default)] pub hypervisor_thread_handles: Vec<u64>,
    #[serde(default)] pub hypervisor_thread_start_routines: Vec<u64>,
    #[serde(default)] pub hypervisor_access_masks: Vec<u32>,
    #[serde(default)] pub hypervisor_memory_protections: Vec<u32>,
    #[serde(default)] pub hypervisor_is_executable_memory: Option<bool>,
    #[serde(default)] pub hypervisor_raw_arg1_min: Option<u64>,
    #[serde(default)] pub hypervisor_raw_arg1_max: Option<u64>,
    #[serde(default)] pub hypervisor_raw_arg2_min: Option<u64>,
    #[serde(default)] pub hypervisor_raw_arg2_max: Option<u64>,
    #[serde(default)] pub hypervisor_raw_arg3_min: Option<u64>,
    #[serde(default)] pub hypervisor_raw_arg3_max: Option<u64>,
    #[serde(default)] pub hypervisor_raw_arg4_min: Option<u64>,
    #[serde(default)] pub hypervisor_raw_arg4_max: Option<u64>,
    #[serde(default)] pub hypervisor_memory_addresses: Vec<u64>,
    #[serde(default)] pub hypervisor_memory_address_min: Option<u64>,
    #[serde(default)] pub hypervisor_memory_address_max: Option<u64>,
    #[serde(default)] pub hypervisor_memory_size_min: Option<u64>,
    #[serde(default)] pub hypervisor_memory_size_max: Option<u64>,
    #[serde(default = "default_zero")] pub min_matches: usize,
    #[serde(default)] pub json_match: Option<JsonMatcher>,
    
    // Sanctum EDR conditions
    #[serde(default)] pub sanctum_injection_score_min: Option<f32>,
    #[serde(default)] pub sanctum_syscall_count_min: Option<usize>,
    #[serde(default)] pub sanctum_shellcode_detected: Option<bool>,
    #[serde(default)] pub sanctum_suspicious_hits: Vec<String>,
    #[serde(default)] pub sanctum_detected: Option<bool>,

    // Rootkit generic condition tracking
    #[serde(default)] pub rootkit_event_types: Vec<String>,
    #[serde(default)] pub rootkit_event_min_count: Option<usize>,
    #[serde(default)] pub rootkit_total_min: Option<usize>,
    #[serde(default)] pub rootkit_description_contains: Vec<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    #[serde(default)] pub description: String,
    #[serde(default)] pub browsed_paths: Vec<String>,
    #[serde(default)] pub accessed_paths: Vec<String>,
    #[serde(default)] pub staging_paths: Vec<String>,
    #[serde(default = "default_zero")] pub multi_access_threshold: usize,
    #[serde(default)] pub require_internet: bool,
    #[serde(default)] pub monitored_apis: Vec<String>,
    #[serde(default)] pub file_actions: Vec<String>,
    #[serde(default)] pub file_extensions: Vec<String>,
    #[serde(default)] pub suspicious_parents: Vec<String>,
    #[serde(default)] pub terminated_processes: Vec<String>,
    #[serde(default)] pub detect_self_termination: bool,
    #[serde(default)] pub entropy_threshold: f64,
    #[serde(default)] pub conditions_percentage: f32,
    #[serde(default)] pub named_conditions: HashMap<String, NamedConditionGroup>,
    #[serde(default)] pub detection_logic: Option<DetectionCondition>,
    #[serde(default = "default_true")] pub enabled: bool,
    #[serde(default)] pub stages: Vec<AttackStage>,
    #[serde(default)] pub mapping: Option<RuleMapping>,
    #[serde(default)] pub min_stages_satisfied: usize,
    #[serde(default = "default_severity")] pub severity: u8,
    #[serde(default)] pub author: Option<String>,
    #[serde(default)] pub date: Option<String>,
    #[serde(default)] pub status: RuleStatus,
    #[serde(default)] pub tags: Vec<String>,
    #[serde(default)] pub level: DetectionLevel,
    #[serde(default)] pub mitre_attack: Vec<String>,
    #[serde(default)] pub logsource: Option<LogSource>,
    #[serde(default)] pub response: ResponseAction,
    #[serde(default)] pub allowlisted_apps: Vec<AllowlistEntry>,
    #[serde(default)] pub proximity_log_threshold: f32,
    #[serde(default)] pub record_on_start: Vec<String>,
    #[serde(default)] pub debug: bool,
    #[serde(default)] pub memory_scan_config: Option<MemoryScanConfig>,
    #[serde(default)] pub protected_paths: ProtectedPaths,
    
    // Integrated high-perf network matcher triggers
    #[serde(default)] pub http_request_body_patterns: Vec<String>,
    #[serde(default)] pub http_response_body_patterns: Vec<String>,
    #[serde(default)] pub private_rules: Option<YamlValue>,
    #[serde(default)] pub is_private: bool,
}

impl BehaviorRule {
    pub fn apply_replacement(&self, body: &str) -> String {
        if !self.response.use_regex_replacement {
            if self.response.change_request_body.is_some() {
                return self.response.change_request_body.clone().unwrap_or_else(|| body.to_string());
            } else if self.response.change_response_body.is_some() {
                return self.response.change_response_body.clone().unwrap_or_else(|| body.to_string());
            }
            return body.to_string();
        }

        let Some(search) = &self.response.search_pattern else { return body.to_string(); };
        let replace_with = self.response.change_request_body.as_deref()
            .or(self.response.change_response_body.as_deref())
            .unwrap_or("");

        if let Ok(re) = Regex::new(search) {
            re.replace_all(body, replace_with).into_owned()
        } else {
            body.to_string()
        }
    }

    pub fn matches_packet(&self, cache: &Arc<RwLock<HashMap<String, Regex>>>, packet: &PacketInfo, payload: &[u8]) -> bool {
        if !self.enabled { return false; }
        
        // Match top-level HTTP body patterns if MITM is active
        for pattern in &self.http_request_body_patterns {
            if matches_pattern(cache, pattern, &String::from_utf8_lossy(payload)) { return true; }
        }

        // Match against named conditions that contain network rules
        for cond_group in self.named_conditions.values() {
            for net_cond in &cond_group.network_rules {
                if net_cond.matches_packet(cache, packet, payload) {
                    return true;
                }
            }
            
            // Match classic domain/IP indicators in named conditions
            for domain in &cond_group.network_domains {
                if packet.hostname.as_ref().map_or(false, |h| h.contains(domain)) { return true; }
            }
            for ip in &cond_group.network_ips {
                if packet.dst_ip.to_string().contains(ip) || packet.src_ip.to_string().contains(ip) { return true; }
            }
        }

        false
    }

    pub fn finalize_rich_fields(&mut self) {
        let expand_vec = |vec: &mut Vec<String>| {
            for item in vec.iter_mut() {
                *item = expand_environment_variables(item);
            }
        };
        let expand_opt_string = |opt: &mut Option<String>| {
            if let Some(s) = opt {
                *s = expand_environment_variables(s);
            }
        };
        let expand_cmd_patterns = |patterns: &mut Vec<CommandLinePattern>| {
            for p in patterns.iter_mut() {
                let expanded = expand_environment_variables(p.pattern.pattern());
                *p.pattern.pattern_mut() = expanded;
            }
        };
        let expand_network_rules = |rules: &mut Vec<NetworkRuleCondition>| {
            for r in rules.iter_mut() {
                match r {
                    NetworkRuleCondition::SrcIp(m) | NetworkRuleCondition::DstIp(m) => {
                        for p in m.addresses.iter_mut() { *p = expand_environment_variables(p); }
                    }
                    NetworkRuleCondition::Domain(m) => {
                        for p in m.domains.iter_mut() { *p = expand_environment_variables(p); }
                    }
                    NetworkRuleCondition::Url(m) => {
                        for p in m.patterns.iter_mut() { *p = expand_environment_variables(p); }
                    }
                    NetworkRuleCondition::Regex(m) => {
                        m.pattern = expand_environment_variables(&m.pattern);
                    }
                    NetworkRuleCondition::ContentMatch(m) => {
                        m.pattern = expand_environment_variables(&m.pattern);
                    }
                    _ => {}
                }
            }
        };

        expand_vec(&mut self.browsed_paths);
        expand_vec(&mut self.accessed_paths);
        expand_vec(&mut self.staging_paths);
        expand_vec(&mut self.monitored_apis);
        expand_vec(&mut self.file_actions);
        expand_vec(&mut self.file_extensions);
        expand_vec(&mut self.suspicious_parents);
        expand_vec(&mut self.terminated_processes);

        for entry in &mut self.allowlisted_apps {
            match entry {
                AllowlistEntry::Simple(s) => *s = expand_environment_variables(s),
                AllowlistEntry::Complex { pattern, signers, .. } => {
                    *pattern = expand_environment_variables(pattern);
                    expand_vec(signers);
                }
            }
        }

        for cond_group in self.named_conditions.values_mut() {
            expand_vec(&mut cond_group.apis);
            expand_vec(&mut cond_group.file_paths);
            expand_vec(&mut cond_group.registry_keys);
            expand_vec(&mut cond_group.registry_values);
            expand_vec(&mut cond_group.network_indicators);
            expand_vec(&mut cond_group.network_domains);
            expand_vec(&mut cond_group.network_ips);
            expand_vec(&mut cond_group.process_names);
            expand_vec(&mut cond_group.parent_names);
            expand_vec(&mut cond_group.terminated_processes);
            expand_vec(&mut cond_group.created_processes);
            expand_vec(&mut cond_group.file_extensions);
            expand_vec(&mut cond_group.extension_whitelist);
            expand_vec(&mut cond_group.file_actions);
            expand_cmd_patterns(&mut cond_group.cmdline_patterns);
            expand_vec(&mut cond_group.cmdline_keywords);
            expand_vec(&mut cond_group.staging_paths);
            expand_vec(&mut cond_group.browsed_paths);
            expand_vec(&mut cond_group.sensitive_paths);
            expand_vec(&mut cond_group.persistence_locations);
            expand_vec(&mut cond_group.autorun_keys);
            expand_vec(&mut cond_group.scheduled_task_apis);
            expand_vec(&mut cond_group.obfuscation_indicators);
            expand_vec(&mut cond_group.anti_debug_apis);
            expand_vec(&mut cond_group.anti_vm_apis);
            expand_vec(&mut cond_group.trusted_signers);
            expand_vec(&mut cond_group.untrusted_signers);
            expand_network_rules(&mut cond_group.network_rules);
            expand_vec(&mut cond_group.registry_value_data_patterns);
            expand_vec(&mut cond_group.dns_query_patterns);
        }

        for stage in &mut self.stages {
            for condition in &mut stage.conditions {
                match condition {
                    RuleCondition::File { path_pattern, .. } => *path_pattern = expand_environment_variables(path_pattern),
                    RuleCondition::Registry { key_pattern, value_name, expected_data, .. } => {
                        *key_pattern = expand_environment_variables(key_pattern);
                        expand_opt_string(value_name);
                        expand_opt_string(expected_data);
                    },
                    RuleCondition::Process { pattern, .. } => *pattern = expand_environment_variables(pattern),
                    RuleCondition::Service { name_pattern, .. } => *name_pattern = expand_environment_variables(name_pattern),
                    RuleCondition::Network { dest_pattern, .. } => expand_opt_string(dest_pattern),
                    RuleCondition::Api { name_pattern, module_pattern } => {
                        *name_pattern = expand_environment_variables(name_pattern);
                        *module_pattern = expand_environment_variables(module_pattern);
                    },
                    RuleCondition::OperationCount { path_pattern, .. } => expand_opt_string(path_pattern),
                    RuleCondition::ExtensionPattern { patterns, .. } => expand_vec(patterns),
                    RuleCondition::Signature { signer_pattern, .. } => expand_opt_string(signer_pattern),
                    RuleCondition::ProcessAncestry { ancestor_pattern, .. } => *ancestor_pattern = expand_environment_variables(ancestor_pattern),
                    RuleCondition::CommandLineMatch { patterns, .. } => expand_cmd_patterns(patterns),
                    RuleCondition::SensitivePathAccess { patterns, .. } => expand_vec(patterns),
                    RuleCondition::ArchiveCreation { extensions, .. } => expand_vec(extensions),
                    RuleCondition::DataExfiltrationPattern { source_patterns, .. } => expand_vec(source_patterns),
                    RuleCondition::MemoryScan { patterns, .. } => expand_vec(patterns),
                    _ => {}
                }
            }
        }

        if let Some(msc) = &mut self.memory_scan_config {
            expand_vec(&mut msc.target_processes);
        }
    }
}
