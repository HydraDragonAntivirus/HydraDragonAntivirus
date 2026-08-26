// HydraDragonFirewall SDK - Complete Implementation
// Features: Base58, Base64, Reverse, Hex, HTTP, HTTPS, UDP, TCP, ICMP, ARP,
// IP Address, Domain, URL, File Type, Regex, YAML Signatures, Comments,
// Traffic Attack, Block, Allow, Ask, Change Packet, Solve Packet,
// Port, Localhost, Routine, AND/OR Conditions, Rule Name, Description

use super::engine::{FirewallSettings, PacketInfo, Protocol};
use base64::Engine;
use daachorse::DoubleArrayAhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing;

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
            ContentEncoding::Reverse => Some(data.iter().rev().cloned().collect()),
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
            ContentEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(data),
            ContentEncoding::Reverse => {
                String::from_utf8_lossy(&data.iter().rev().cloned().collect::<Vec<u8>>())
                    .to_string()
            }
            ContentEncoding::Hex => data.iter().map(|b| format!("{:02x}", b)).collect(),
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
                packet.protocol == Protocol::TCP && (packet.dst_port == 80 || packet.src_port == 80)
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
// CONTENT MATCHING (Suricata `content:`) — literal substring, no regex cost
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ContentMatcher {
    /// Raw literal payload substring (Suricata `content:"..."`).
    #[serde(default)]
    pub literal: String,
    /// Match case-insensitively when the Suricata content had `nocase`.
    #[serde(default)]
    pub case_insensitive: bool,
}

impl ContentMatcher {
    pub fn matches(&self, payload: &[u8]) -> bool {
        if self.literal.is_empty() {
            return true;
        }
        if self.case_insensitive {
            let needle = self.literal.to_lowercase();
            if needle.is_empty() {
                return true;
            }
            let text = String::from_utf8_lossy(payload);
            text.to_lowercase().contains(&needle)
        } else {
            let needle = self.literal.as_bytes();
            payload.windows(needle.len()).any(|w| w == needle)
        }
    }
}

// ============================================================================
// REGEX MATCHING (Feature 15)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RegexMatcher {
    pub pattern: String,
    pub case_insensitive: bool,
}

fn compile_sdk_regex(pattern_str: &str) -> Option<Regex> {
    regex::RegexBuilder::new(pattern_str)
        .size_limit(4 * 1024 * 1024)
        .dfa_size_limit(4 * 1024 * 1024)
        .build()
        .ok()
}

impl RegexMatcher {
    pub fn matches(&self, data: &[u8]) -> bool {
        if self.pattern.is_empty() {
            return true;
        }

        let pattern_str = if self.case_insensitive {
            format!("(?i){}", self.pattern)
        } else {
            self.pattern.clone()
        };

        let Some(re) = compile_sdk_regex(&pattern_str) else {
            return false;
        };

        let text = String::from_utf8_lossy(data);
        re.is_match(&text)
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
// ENTROPY MATCHING (Feature 32 - New)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct EntropyMatcher {
    pub min_entropy: f64,
}

impl EntropyMatcher {
    pub fn matches(&self, entropy: Option<f64>) -> bool {
        if let Some(e) = entropy {
            return e >= self.min_entropy;
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
    Loopback, // 127.x.x.x
    PrivateA, // 10.x.x.x
    PrivateB, // 172.16-31.x.x
    PrivateC, // 192.168.x.x
    Private,  // Match any private subnets (A, B, C) except Loopback/Any
    Any,      // 0.0.0.0
    #[default]
    All, // Match any localhost/private type
    None,     // Disable localhost matching
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
                LocalhostType::PrivateC => ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168,
                LocalhostType::Private => {
                    LocalhostType::PrivateA.matches(ip)
                        || LocalhostType::PrivateB.matches(ip)
                        || LocalhostType::PrivateC.matches(ip)
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
                LocalhostType::Private => ipv6.is_unique_local() || ipv6.is_unicast_link_local(),
                LocalhostType::PrivateA | LocalhostType::PrivateB | LocalhostType::PrivateC => {
                    ipv6.is_unique_local() || ipv6.is_unicast_link_local()
                }
                LocalhostType::Any => ipv6.is_unspecified(),
                LocalhostType::All => {
                    ipv6.is_loopback()
                        || ipv6.is_unique_local()
                        || ipv6.is_unicast_link_local()
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
    TrafficAttack, // Feature 18: Detect/log attack patterns
    Block,         // Feature 19
    #[default]
    Allow, // Feature 20
    Ask,           // Feature 21: Prompt user
    Terminate,     // Terminate the process associated with the packet
    Quarantine,    // Quarantine the file associated with the process
    KillAndRemove, // Terminate and remove the file
    ChangePacket,  // Feature 22: Modify packet payload
    SolvePacket,   // Feature 23: Fix/normalize packet
    ChangeRequestBody, // Replace the HTTP request body with change_request_body
    ChangeResponseBody, // Replace the HTTP response body with change_response_body
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
#[serde(rename_all = "snake_case", untagged)]
pub enum RuleCondition {
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
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
    Entropy(EntropyMatcher),
    SanctumDetected,
    JsonMatch(JsonMatcher),
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct JsonMatcher {
    pub key: String,
    pub value: String,
}

impl JsonMatcher {
    pub fn matches(&self, payload: &[u8]) -> bool {
        let text = String::from_utf8_lossy(payload);
        if !text.trim().starts_with('{') && !text.trim().starts_with('[') {
            return false;
        }
        // Simple heuristic: key and value appear in the JSON
        text.contains(&format!("\"{}\"", self.key)) && text.contains(&self.value)
    }
}

impl RuleCondition {
    pub fn matches(&self, packet: &PacketInfo, payload: &[u8]) -> bool {
        match self {
            RuleCondition::And(conds) => conds.iter().all(|c| c.matches(packet, payload)),
            RuleCondition::Or(conds) => conds.iter().any(|c| c.matches(packet, payload)),
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
                if packet.outbound {
                    localhost_type.matches(packet.dst_ip)
                } else {
                    localhost_type.matches(packet.src_ip)
                }
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
            RuleCondition::Entropy(matcher) => matcher.matches(packet.payload_entropy),
            RuleCondition::SanctumDetected => {
                // This condition is typically evaluated by the behavior engine
                // which has access to Sanctum telemetry.
                true
            }
            RuleCondition::JsonMatch(matcher) => matcher.matches(payload),
        }
    }

    pub fn requires_entropy(&self) -> bool {
        matches!(self, RuleCondition::Entropy(_))
    }

    pub fn requires_file_type(&self) -> bool {
        matches!(self, RuleCondition::FileType(_))
    }

    fn is_meaningful_non_entropy(&self) -> bool {
        match self {
            RuleCondition::Protocol(proto) => *proto != RuleProtocol::Any,
            RuleCondition::SrcIp(matcher) => {
                !matcher.addresses.is_empty() || !matcher.cidr_ranges.is_empty()
            }
            RuleCondition::DstIp(matcher) => {
                !matcher.addresses.is_empty() || !matcher.cidr_ranges.is_empty()
            }
            RuleCondition::SrcPort(matcher) => {
                !matcher.ports.is_empty() || !matcher.ranges.is_empty()
            }
            RuleCondition::DstPort(matcher) => {
                !matcher.ports.is_empty() || !matcher.ranges.is_empty()
            }
            RuleCondition::Domain(matcher) => !matcher.domains.is_empty(),
            RuleCondition::Url(matcher) => !matcher.patterns.is_empty(),
            RuleCondition::FileType(matcher) => !matcher.file_types.is_empty(),
            RuleCondition::Regex(matcher) => !matcher.pattern.is_empty(),
            RuleCondition::Localhost(_) => true,
            RuleCondition::ContentMatch(data) => !data.pattern.is_empty(),
            RuleCondition::Entropy(_) => false,
            RuleCondition::And(conds) => conds.iter().any(|c| c.is_meaningful_non_entropy()),
            RuleCondition::Or(conds) => conds.iter().any(|c| c.is_meaningful_non_entropy()),
            RuleCondition::SanctumDetected => true,
            RuleCondition::JsonMatch(_) => true,
        }
    }
}

// ============================================================================
// SDK RULE (Features 16, 17, 29, 30)
// ============================================================================

// ---------------------------------------------------------------------------
// Suricata-style matchers (ip_proto, dsize, byte_test, flow, flowbits)
// ---------------------------------------------------------------------------

/// Matches the raw IP protocol number (Suricata `ip_proto`).
/// Example: 41 = IPv6 encapsulation (6in4), 47 = GRE, 50 = ESP.

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DsizeMatcher {
    /// Minimum payload size (inclusive)
    #[serde(default)]
    pub min: Option<usize>,
    /// Maximum payload size (inclusive)
    #[serde(default)]
    pub max: Option<usize>,
    /// Exact payload size
    #[serde(default)]
    pub exact: Option<usize>,
    /// Modulo divisor (Suricata `dsize:min:max:mod:offset`)
    #[serde(default)]
    pub mod_divisor: Option<usize>,
    /// Expected remainder when size % mod_divisor
    #[serde(default)]
    pub mod_offset: Option<usize>,
}

impl DsizeMatcher {
    pub fn matches(&self, size: usize) -> bool {
        if let Some(exact) = self.exact {
            if size != exact {
                return false;
            }
        }
        if let Some(min) = self.min {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max {
            if size > max {
                return false;
            }
        }
        if let (Some(d), Some(o)) = (self.mod_divisor, self.mod_offset) {
            if d == 0 {
                return false;
            }
            if size % d != o {
                return false;
            }
        }
        true
    }
}

/// Suricata `byte_test:bytes_to_convert,operator,value,offset[,relative][,big|little][,...]`.
/// `relative` offsets are treated as absolute from payload start (the SDK does
/// not anchor to content-match positions).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ByteTest {
    #[serde(default)]
    pub nbytes: usize,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub value: u64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub relative: bool,
    #[serde(default = "default_true")]
    pub big_endian: bool,
    #[serde(default)]
    pub string: bool,
    #[serde(default)]
    pub base: String,
    #[serde(default)]
    pub no_case: bool,
}

impl ByteTest {
    pub fn matches(&self, payload: &[u8]) -> bool {
        let n = self.nbytes.clamp(1, 8);
        let offset = self.offset.max(0) as usize;
        if offset + n > payload.len() {
            return false;
        }
        let bytes = &payload[offset..offset + n];

        if self.string {
            let hay = if self.no_case {
                bytes.to_ascii_lowercase()
            } else {
                bytes.to_vec()
            };
            let mut needle = if self.big_endian {
                self.value.to_be_bytes()[8 - n..].to_vec()
            } else {
                self.value.to_le_bytes()[..n].to_vec()
            };
            if self.no_case {
                needle = needle.to_ascii_lowercase();
            }
            return hay == needle;
        }

        let num = if self.big_endian {
            let mut b = [0u8; 8];
            b[8 - n..].copy_from_slice(bytes);
            u64::from_be_bytes(b)
        } else {
            let mut b = [0u8; 8];
            b[..n].copy_from_slice(bytes);
            u64::from_le_bytes(b)
        };

        match self.operator.as_str() {
            ">" => num > self.value,
            "<" => num < self.value,
            "=" | "==" => num == self.value,
            "!=" => num != self.value,
            ">=" => num >= self.value,
            "<=" => num <= self.value,
            "&" => (num & self.value) != 0,
            "^" => (num ^ self.value) != 0,
            _ => false,
        }
    }
}

/// Suricata `flow:established,to_client,to_server,stateless` matching.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub struct FlowMatcher {
    #[serde(default)]
    pub established: bool,
    #[serde(default)]
    pub to_client: bool,
    #[serde(default)]
    pub to_server: bool,
    #[serde(default)]
    pub stateless: bool,
}

/// Suricata `flowbits:<op>,<flag>` operation. `op` is one of
/// set / unset / toggle / isset / isnotset. set/unset/toggle are applied after
/// a rule matches; isset/isnotset gate the rule during evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FlowbitOp {
    #[serde(default)]
    pub op: String,
    #[serde(default)]
    pub flag: String,
}

/// Bidirectional flow key (5-tuple normalized so a->b == b->a).
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct FlowKey {
    a: (IpAddr, u16),
    b: (IpAddr, u16),
    proto: u8,
}

impl FlowKey {
    fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, proto: u8) -> Self {
        let x = (src_ip, src_port);
        let y = (dst_ip, dst_port);
        if x <= y {
            Self { a: x, b: y, proto }
        } else {
            Self { a: y, b: x, proto }
        }
    }
}

#[derive(Default)]
struct FlowEntry {
    seen_a: bool,
    seen_b: bool,
    flags: HashSet<String>,
    last_seen: u64,
}

/// Per-flow connection + flowbit state. Tracks which direction of each flow has
/// been observed (for `flow:established`) and the set of flowbit flags.
pub struct FlowState {
    flows: HashMap<FlowKey, FlowEntry>,
    max_flows: usize,
    ttl_secs: u64,
}

impl Default for FlowState {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            max_flows: 20_000,
            ttl_secs: 300,
        }
    }
}

impl FlowState {
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn key_of(info: &PacketInfo) -> FlowKey {
        FlowKey::new(
            info.src_ip,
            info.src_port,
            info.dst_ip,
            info.dst_port,
            info.ip_proto,
        )
    }

    /// true if this packet travels from the normalized endpoint `a` to `b`
    fn is_a_to_b(info: &PacketInfo) -> bool {
        (info.src_ip, info.src_port) <= (info.dst_ip, info.dst_port)
    }

    /// Record that a packet of this flow was seen (both directions must be seen
    /// before the flow counts as established).
    pub fn record(&mut self, info: &PacketInfo) {
        let now = Self::now();
        self.prune(now);
        let key = Self::key_of(info);
        let dir_a = Self::is_a_to_b(info);
        let entry = self.flows.entry(key).or_default();
        if dir_a {
            entry.seen_a = true;
        } else {
            entry.seen_b = true;
        }
        entry.last_seen = now;
    }

    pub fn is_established(&self, info: &PacketInfo) -> bool {
        self.flows
            .get(&Self::key_of(info))
            .map_or(false, |e| e.seen_a && e.seen_b)
    }

    pub fn has_flag(&self, info: &PacketInfo, flag: &str) -> bool {
        self.flows
            .get(&Self::key_of(info))
            .map_or(false, |e| e.flags.contains(flag))
    }

    fn entry_mut(&mut self, info: &PacketInfo) -> &mut FlowEntry {
        let now = Self::now();
        self.prune(now);
        let key = Self::key_of(info);
        let entry = self.flows.entry(key).or_default();
        entry.last_seen = now;
        entry
    }

    pub fn set_flag(&mut self, info: &PacketInfo, flag: &str) {
        self.entry_mut(info).flags.insert(flag.to_string());
    }

    pub fn unset_flag(&mut self, info: &PacketInfo, flag: &str) {
        self.entry_mut(info).flags.remove(flag);
    }

    pub fn toggle_flag(&mut self, info: &PacketInfo, flag: &str) {
        let entry = self.entry_mut(info);
        if !entry.flags.remove(flag) {
            entry.flags.insert(flag.to_string());
        }
    }

    fn prune(&mut self, now: u64) {
        if self.flows.len() < self.max_flows {
            return;
        }
        self.flows
            .retain(|_, e| now.saturating_sub(e.last_seen) < self.ttl_secs);
        while self.flows.len() >= self.max_flows {
            let mut oldest_key: Option<FlowKey> = None;
            let mut oldest_ts = u64::MAX;
            for (k, e) in &self.flows {
                if e.last_seen < oldest_ts {
                    oldest_ts = e.last_seen;
                    oldest_key = Some(k.clone());
                }
            }
            match oldest_key {
                Some(k) => {
                    self.flows.remove(&k);
                }
                None => break,
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRule {
    // Feature 29: Rule name
    pub name: String,
    // Feature 30: Description
    #[serde(default)]
    pub description: String,
    /// Severity level (from EmergingThreats `signature_severity` metadata):
    /// informational / low / medium / high / critical. Absent when unknown.
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    // Private rule flag (YARA-style): evaluated but doesn't generate alerts
    #[serde(default)]
    pub private: bool,
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
    // Feature 33: Content (literal substring) matching — cheap no-regex path
    #[serde(default)]
    pub content: Option<ContentMatcher>,
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
    // Feature 32: Entropy threshold
    #[serde(default)]
    pub entropy_threshold: Option<f64>,
    // Packet modification data (for ChangePacket action)
    #[serde(default)]
    pub change_data: Option<String>,
    /// Replacement body text for the ChangeRequestBody action
    #[serde(default)]
    pub change_request_body: Option<String>,
    /// Replacement body text for the ChangeResponseBody action
    #[serde(default)]
    pub change_response_body: Option<String>,
    /// Patterns to match against the HTTP request body (substring match, any pattern is sufficient)
    #[serde(default)]
    pub http_request_body: Option<Vec<String>>,
    /// Patterns to match against the HTTP response body (substring match, any pattern is sufficient)
    #[serde(default)]
    pub http_response_body: Option<Vec<String>>,
    /// If true, use regex replacement for the body changer
    #[serde(default)]
    pub use_regex_replacement: bool,
    /// Regex pattern to search for in the body
    #[serde(default)]
    pub search_pattern: Option<String>,
    // JSON matching
    #[serde(default)]
    pub json_match: Option<JsonMatcher>,
    /// YARA-style rule dependencies: list of private rule names that must match
    /// before this rule can trigger. Example: depends_on: ["private_rule1", "private_rule2"]
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Raw IP protocol number to match (Suricata `ip_proto`), e.g. 41 = 6in4
    #[serde(default)]
    pub ip_proto: Option<u8>,
    /// Payload size matcher (Suricata `dsize`)
    #[serde(default)]
    pub dsize: Option<DsizeMatcher>,
    /// Payload byte tests (Suricata `byte_test`)
    #[serde(default)]
    pub byte_test: Vec<ByteTest>,
    /// Flow state / direction matcher (Suricata `flow`)
    #[serde(default)]
    pub flow: Option<FlowMatcher>,
    /// Flowbit operations (Suricata `flowbits`): isset/isnotset gate matching;
    /// set/unset/toggle are applied when the rule matches.
    #[serde(default)]
    pub flowbits: Vec<FlowbitOp>,
}

fn default_true() -> bool {
    true
}

impl SdkRule {
    pub fn apply_replacement(&self, body: &str) -> String {
        if !self.use_regex_replacement {
            if self.action == RuleAction::ChangeRequestBody {
                return self
                    .change_request_body
                    .clone()
                    .unwrap_or_else(|| body.to_string());
            } else if self.action == RuleAction::ChangeResponseBody {
                return self
                    .change_response_body
                    .clone()
                    .unwrap_or_else(|| body.to_string());
            }
            return body.to_string();
        }

        let Some(search) = &self.search_pattern else {
            return body.to_string();
        };
        let replace_with = match self.action {
            RuleAction::ChangeRequestBody => self.change_request_body.as_deref().unwrap_or(""),
            RuleAction::ChangeResponseBody => self.change_response_body.as_deref().unwrap_or(""),
            _ => return body.to_string(),
        };

        if let Ok(re) = Regex::new(search) {
            re.replace_all(body, replace_with).into_owned()
        } else {
            body.to_string()
        }
    }

    /// Evaluate if this rule matches the packet (no flow context).
    pub fn matches(&self, packet: &PacketInfo, payload: &[u8]) -> bool {
        self.matches_impl(packet, payload, None)
    }

    /// Evaluate with flow context: flowbit isset/isnotset gates are checked and
    /// flowbit set/unset/toggle ops are applied when the rule matches.
    pub fn matches_with_flow(
        &self,
        packet: &PacketInfo,
        payload: &[u8],
        flow: &mut FlowState,
    ) -> bool {
        let matched = self.matches_impl(packet, payload, Some(flow));
        if matched {
            self.apply_flowbits(packet, flow);
        }
        matched
    }

    fn apply_flowbits(&self, packet: &PacketInfo, flow: &mut FlowState) {
        for op in &self.flowbits {
            match op.op.as_str() {
                "set" => flow.set_flag(packet, &op.flag),
                "unset" => flow.unset_flag(packet, &op.flag),
                "toggle" => flow.toggle_flag(packet, &op.flag),
                _ => {}
            }
        }
    }

    fn matches_impl(&self, packet: &PacketInfo, payload: &[u8], flow: Option<&FlowState>) -> bool {
        if !self.enabled {
            return false;
        }

        // We use a closure or a macro if we wanted to be extreme,
        // but a simple helper or inline checks are fine for Rust's optimizer.
        let mut check_results = std::iter::from_fn({
            let mut step = 0;
            let mut conditions_idx = 0;
            let mut byte_test_idx = 0;
            let mut flowbit_idx = 0;
            let mut decoded_payload: Option<Vec<u8>> = None;

            move || {
                loop {
                    match step {
                        0 => {
                            step += 1;
                            return Some(self.protocol.matches(packet));
                        }
                        1 => {
                            step += 1;
                            if let Some(ref matcher) = self.src_ip {
                                return Some(matcher.matches(packet.src_ip));
                            }
                        }
                        2 => {
                            step += 1;
                            if let Some(ref matcher) = self.dst_ip {
                                return Some(matcher.matches(packet.dst_ip));
                            }
                        }
                        3 => {
                            step += 1;
                            if let Some(ref matcher) = self.src_port {
                                return Some(matcher.matches(packet.src_port));
                            }
                        }
                        4 => {
                            step += 1;
                            if let Some(ref matcher) = self.dst_port {
                                return Some(matcher.matches(packet.dst_port));
                            }
                        }
                        5 => {
                            step += 1;
                            if let Some(ref matcher) = self.domain {
                                return Some(matcher.matches(packet.hostname.as_deref()));
                            }
                        }
                        6 => {
                            step += 1;
                            if let Some(ref matcher) = self.url {
                                return Some(matcher.matches(packet.full_url.as_deref()));
                            }
                        }
                        7 => {
                            step += 1;
                            if let Some(ref matcher) = self.file_type {
                                return Some(matcher.matches(packet.detected_file_type.as_deref()));
                            }
                        }
                        8 => {
                            step += 1;
                            if let Some(ref matcher) = self.content {
                                return Some(matcher.matches(payload));
                            }
                        }
                        9 => {
                            step += 1;
                            if let Some(ref matcher) = self.regex {
                                if decoded_payload.is_none() {
                                    decoded_payload = Some(
                                        self.encoding
                                            .decode(payload)
                                            .unwrap_or_else(|| payload.to_vec()),
                                    );
                                }
                                return Some(matcher.matches(decoded_payload.as_ref().unwrap()));
                            }
                        }
                        10 => {
                            step += 1;
                            if let Some(ref localhost_type) = self.localhost_type {
                                return Some(if packet.outbound {
                                    localhost_type.matches(packet.dst_ip)
                                } else {
                                    localhost_type.matches(packet.src_ip)
                                });
                            }
                        }
                        11 => {
                            step += 1;
                            if let Some(ref routine) = self.routine {
                                return Some(routine.matches(packet));
                            }
                        }
                        12 => {
                            if conditions_idx < self.conditions.len() {
                                if decoded_payload.is_none() {
                                    decoded_payload = Some(
                                        self.encoding
                                            .decode(payload)
                                            .unwrap_or_else(|| payload.to_vec()),
                                    );
                                }
                                let res = self.conditions[conditions_idx]
                                    .matches(packet, decoded_payload.as_ref().unwrap());
                                conditions_idx += 1;
                                return Some(res);
                            }
                            step += 1;
                        }
                        13 => {
                            step += 1;
                            if let Some(threshold) = self.entropy_threshold {
                                return Some(packet.payload_entropy.unwrap_or(0.0) >= threshold);
                            }
                        }
                        14 => {
                            step += 1;
                            if let Some(ref patterns) = self.http_request_body {
                                if !patterns.is_empty() {
                                    let body = packet.http_request_body.as_deref().unwrap_or("");
                                    return Some(
                                        patterns.iter().any(|p| body.contains(p.as_str())),
                                    );
                                }
                            }
                        }
                        15 => {
                            step += 1;
                            if let Some(ref patterns) = self.http_response_body {
                                if !patterns.is_empty() {
                                    let body = packet.http_response_body.as_deref().unwrap_or("");
                                    return Some(
                                        patterns.iter().any(|p| body.contains(p.as_str())),
                                    );
                                }
                            }
                        }
                        16 => {
                            step += 1;
                            if let Some(ref matcher) = self.json_match {
                                return Some(matcher.matches(payload));
                            }
                        }
                        17 => {
                            step += 1;
                            if let Some(proto) = self.ip_proto {
                                return Some(packet.ip_proto == proto);
                            }
                        }
                        18 => {
                            step += 1;
                            if let Some(ref matcher) = self.dsize {
                                return Some(matcher.matches(packet.size));
                            }
                        }
                        19 => {
                            if byte_test_idx < self.byte_test.len() {
                                let res = self.byte_test[byte_test_idx].matches(payload);
                                byte_test_idx += 1;
                                return Some(res);
                            }
                            step += 1;
                        }
                        20 => {
                            step += 1;
                            if let Some(ref fm) = self.flow {
                                if fm.to_server && !packet.outbound {
                                    return Some(false);
                                }
                                if fm.to_client && packet.outbound {
                                    return Some(false);
                                }
                                if fm.established {
                                    match flow {
                                        Some(f) => {
                                            if !f.is_established(packet) {
                                                return Some(false);
                                            }
                                        }
                                        None => {}
                                    }
                                }
                            }
                        }
                        21 => {
                            while flowbit_idx < self.flowbits.len() {
                                let op = &self.flowbits[flowbit_idx];
                                flowbit_idx += 1;
                                match op.op.as_str() {
                                    "isset" => {
                                        return Some(match flow {
                                            Some(f) => f.has_flag(packet, &op.flag),
                                            None => true,
                                        });
                                    }
                                    "isnotset" => {
                                        return Some(match flow {
                                            Some(f) => !f.has_flag(packet, &op.flag),
                                            None => true,
                                        });
                                    }
                                    _ => {}
                                }
                            }
                            step += 1;
                        }
                        _ => return None,
                    }
                }
            }
        });

        match self.condition_logic {
            ConditionLogic::And => check_results.all(|m| m),
            ConditionLogic::Or => {
                // For OR logic, we need to know if we even had any checks
                // because an empty rule matches everything by default in original logic.
                // However, AND of empty is true, OR of empty would be false?
                // The original code:
                // if matches.is_empty() { return true; }
                // match self.condition_logic { AND => all, OR => any }
                // So OR of empty was true?? That seems wrong but I should preserve it if so.

                let mut any_checked = false;
                let mut found_match = false;
                for m in check_results {
                    any_checked = true;
                    if m {
                        found_match = true;
                        break;
                    }
                }
                if !any_checked { true } else { found_match }
            }
        }
    }

    pub fn requires_entropy(&self) -> bool {
        self.entropy_threshold.is_some()
            || self.conditions.iter().any(RuleCondition::requires_entropy)
    }

    pub fn requires_file_type(&self) -> bool {
        self.file_type.is_some()
            || self
                .conditions
                .iter()
                .any(RuleCondition::requires_file_type)
    }

    pub fn requires_deferred_inspection(&self) -> bool {
        self.requires_entropy() || self.requires_file_type()
    }

    fn has_meaningful_non_entropy_matchers(&self) -> bool {
        if self.protocol != RuleProtocol::Any {
            return true;
        }

        if self
            .src_ip
            .as_ref()
            .is_some_and(|matcher| !matcher.addresses.is_empty() || !matcher.cidr_ranges.is_empty())
        {
            return true;
        }

        if self
            .dst_ip
            .as_ref()
            .is_some_and(|matcher| !matcher.addresses.is_empty() || !matcher.cidr_ranges.is_empty())
        {
            return true;
        }

        if self
            .src_port
            .as_ref()
            .is_some_and(|matcher| !matcher.ports.is_empty() || !matcher.ranges.is_empty())
        {
            return true;
        }

        if self
            .dst_port
            .as_ref()
            .is_some_and(|matcher| !matcher.ports.is_empty() || !matcher.ranges.is_empty())
        {
            return true;
        }

        if self
            .domain
            .as_ref()
            .is_some_and(|matcher| !matcher.domains.is_empty())
        {
            return true;
        }

        if self
            .url
            .as_ref()
            .is_some_and(|matcher| !matcher.patterns.is_empty())
        {
            return true;
        }

        if self
            .file_type
            .as_ref()
            .is_some_and(|matcher| !matcher.file_types.is_empty())
        {
            return true;
        }

        if self
            .regex
            .as_ref()
            .is_some_and(|matcher| !matcher.pattern.is_empty())
        {
            return true;
        }

        if self.localhost_type.is_some() {
            return true;
        }

        if self.routine.as_ref().is_some_and(|routine| {
            routine.from_ip.is_some()
                || routine.from_port.is_some()
                || routine.to_ip.is_some()
                || routine.to_port.is_some()
        }) {
            return true;
        }

        if self
            .conditions
            .iter()
            .any(RuleCondition::is_meaningful_non_entropy)
        {
            return true;
        }

        false
    }

    pub fn is_entropy_only_ask_rule(&self) -> bool {
        self.action == RuleAction::Ask
            && self.requires_entropy()
            && !self.has_meaningful_non_entropy_matchers()
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
    /// Load rules from YAML file (supports # comments and !include - Feature 17 extension)
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref)
            .map_err(|e| format!("Failed to read rules file {}: {}", path_ref.display(), e))?;

        let mut final_rules = Vec::new();
        let base_dir = path_ref.parent().unwrap_or(Path::new("."));

        // Pre-process: Filter out !include lines to parse the rest as valid YAML
        let sanitized_content: String = content
            .lines()
            .filter(|line| !line.trim().starts_with("!include "))
            .collect::<Vec<_>>()
            .join("\n");

        if !sanitized_content.trim().is_empty() {
            let current_file: SdkRuleFile = serde_yaml::from_str(&sanitized_content)
                .map_err(|e| format!("Failed to parse rules YAML {}: {}", path_ref.display(), e))?;
            final_rules.extend(current_file.rules);
        }

        // Process includes
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("!include ") {
                let include_path_str = trimmed["!include ".len()..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                let include_path = base_dir.join(include_path_str);

                let included_file = Self::load_from_file(&include_path)?;
                final_rules.extend(included_file.rules);
            }
        }

        Ok(Self { rules: final_rules })
    }

    /// Load rules from YAML string (legacy support)
    pub fn load_from_string(content: &str) -> Result<Self, String> {
        serde_yaml::from_str(content)
            .map_err(|e| format!("Failed to parse rules YAML string: {}", e))
    }

    /// Save rules to YAML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let content =
            serde_yaml::to_string(self).map_err(|e| format!("Failed to serialize rules: {}", e))?;

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
    /// Severity of the matched rule, if known (informational/low/medium/high/critical)
    #[serde(default)]
    pub severity: Option<String>,
    pub change_data: Option<String>,
    pub change_request_body: Option<String>,
    pub change_response_body: Option<String>,
    /// Indicates if this match came from a private rule (for logging/debugging)
    #[serde(default)]
    pub is_private_rule_match: bool,
    /// Detected subdomain if domain matching was used
    #[serde(default)]
    pub detected_subdomain: Option<String>,
    /// Detected base domain if domain matching was used
    #[serde(default)]
    pub detected_domain: Option<String>,
    /// Indicates if subdomain detection used public_suffixes.txt (true) or simple parsing (false)
    #[serde(default)]
    pub used_public_suffix_list: bool,
    /// List of private rules that matched (for debugging complex rule chains)
    #[serde(default)]
    pub matched_private_rules: Vec<String>,
}

// ============================================================================
// SDK REGISTRY
// ============================================================================

pub struct SdkRegistry {
    pub rules: Vec<SdkRule>,
    domain_index: Option<DoubleArrayAhoCorasick<u32>>,
    url_index: Option<DoubleArrayAhoCorasick<u32>>,
    content_index: Option<DoubleArrayAhoCorasick<u32>>,
    domain_pattern_rules: Vec<Box<[usize]>>,
    url_pattern_rules: Vec<Box<[usize]>>,
    content_pattern_rules: Vec<Box<[usize]>>,
    unindexed_rules: Vec<usize>,
    pub listeners: Vec<Arc<dyn PacketListener>>,
    pub changers: Vec<Arc<dyn PacketChanger>>,
    /// Per-flow connection + flowbit state (Suricata flow/flowbits)
    pub flow_state: Mutex<FlowState>,
}

impl SdkRegistry {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            domain_index: None,
            url_index: None,
            content_index: None,
            domain_pattern_rules: Vec::new(),
            url_pattern_rules: Vec::new(),
            content_pattern_rules: Vec::new(),
            unindexed_rules: Vec::new(),
            listeners: Vec::new(),
            changers: Vec::new(),
            flow_state: Mutex::new(FlowState::default()),
        }
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.load_default_rules();
        registry
    }

    pub fn load_default_rules(&mut self) {
        {
            if let Some(path) = super::get_firewall_sdk_rules_path() {
                let rules_file = if path.is_dir() {
                    path.join("rules.yaml")
                } else {
                    path.clone()
                };
                if rules_file.is_file() {
                    let path_str = rules_file.to_string_lossy().to_string();
                    if self.load_rules_from_file(&path_str).is_ok() {
                        println!(
                            "[SDK] Loaded {} rules from registry-defined path",
                            self.rules.len()
                        );
                        return;
                    }
                }
            }
        }

        // Load from rules.yaml if it exists
        match SdkRuleFile::load_from_file("firewall-rules/rules.yaml") {
            Ok(rule_file) => {
                let rule_count = rule_file.rules.len();
                self.rules = Self::sanitize_rules(rule_file.rules);
                self.rebuild_match_index();
                println!(
                    "[SDK] Loaded {} rules from firewall-rules/rules.yaml",
                    rule_count
                );
            }
            Err(e) => {
                eprintln!("[SDK] Failed to load firewall-rules/rules.yaml: {}", e);
            }
        }
    }

    pub fn load_rules_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let rule_file = SdkRuleFile::load_from_file(path)?;
        self.rules = Self::sanitize_rules(rule_file.rules);
        self.rebuild_match_index();
        Ok(())
    }

    pub fn add_rule(&mut self, rule: SdkRule) {
        self.rules.extend(Self::sanitize_rules(vec![rule]));
        self.rebuild_match_index();
    }

    fn rebuild_match_index(&mut self) {
        use std::collections::HashMap;

        let mut domain_patterns: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        let mut url_patterns: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        let mut content_patterns: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        let mut unindexed = Vec::new();

        for (rule_id, rule) in self.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }

            let mut indexed = false;

            if let Some(matcher) = &rule.domain {
                if matcher.domains.is_empty() {
                    indexed = true;
                } else {
                    for pattern in &matcher.domains {
                        if pattern == "*" || pattern.eq_ignore_ascii_case("any") {
                            indexed = true;
                            continue;
                        }
                        if let Some(literal) = Self::domain_index_literal(pattern) {
                            domain_patterns
                                .entry(literal.to_lowercase().into_bytes())
                                .or_default()
                                .push(rule_id);
                            indexed = true;
                        }
                    }
                }
            }

            if let Some(matcher) = &rule.url {
                if matcher.patterns.is_empty() {
                    indexed = true;
                } else {
                    for pattern in &matcher.patterns {
                        if pattern == "*" || pattern.eq_ignore_ascii_case("any") {
                            indexed = true;
                            continue;
                        }
                        if let Some(literal) = Self::url_index_literal(pattern) {
                            url_patterns
                                .entry(literal.to_lowercase().into_bytes())
                                .or_default()
                                .push(rule_id);
                            indexed = true;
                        }
                    }
                }
            }

            if let Some(matcher) = &rule.content {
                if matcher.literal.is_empty() {
                    indexed = true;
                } else if !matcher.case_insensitive {
                    // Case-insensitive contents cannot safely share the
                    // lowercased haystack of this index; they stay unindexed.
                    content_patterns
                        .entry(matcher.literal.as_bytes().to_vec())
                        .or_default()
                        .push(rule_id);
                    indexed = true;
                }
            }

            // Rules without a usable content index remain in the cheap fallback
            // set so protocol/IP/port-only and wildcard rules are never skipped.
            if !indexed {
                unindexed.push(rule_id);
            }
        }

        let (domain_index, domain_pattern_rules) = Self::build_daachorse_index(domain_patterns);
        let (url_index, url_pattern_rules) = Self::build_daachorse_index(url_patterns);
        let (content_index, content_pattern_rules) = Self::build_daachorse_index(content_patterns);

        self.domain_index = domain_index;
        self.url_index = url_index;
        self.content_index = content_index;
        self.domain_pattern_rules = domain_pattern_rules;
        self.url_pattern_rules = url_pattern_rules;
        self.content_pattern_rules = content_pattern_rules;
        self.unindexed_rules = unindexed;
    }

    fn build_daachorse_index(
        patterns: HashMap<Vec<u8>, Vec<usize>>,
    ) -> (Option<DoubleArrayAhoCorasick<u32>>, Vec<Box<[usize]>>) {
        if patterns.is_empty() {
            return (None, Vec::new());
        }

        let mut pattern_rules = Vec::with_capacity(patterns.len());
        let mut entries = Vec::with_capacity(patterns.len());

        for (value, (pattern, rules)) in patterns.into_iter().enumerate() {
            entries.push((pattern, value as u32));
            pattern_rules.push(rules.into_boxed_slice());
        }

        let scanner = DoubleArrayAhoCorasick::with_values(entries)
            .expect("firewall Daachorse index build should succeed");

        (Some(scanner), pattern_rules)
    }

    fn domain_index_literal(pattern: &str) -> Option<String> {
        if pattern.starts_with("*.") {
            return Some(pattern[2..].to_string());
        }
        let literal = pattern.trim_matches('*');
        (!literal.is_empty()).then(|| literal.to_string())
    }

    fn url_index_literal(pattern: &str) -> Option<String> {
        pattern
            .split('*')
            .filter(|part| !part.is_empty())
            .max_by_key(|part| part.len())
            .map(str::to_string)
    }

    fn indexed_rule_ids(&self, packet: &PacketInfo, payload: &[u8]) -> Vec<usize> {
        let mut ids = self.unindexed_rules.clone();

        if let (Some(scanner), Some(hostname)) = (&self.domain_index, packet.hostname.as_deref()) {
            let haystack = hostname.to_lowercase();
            for m in scanner.find_overlapping_iter(haystack.as_bytes()) {
                if let Some(rules) = self.domain_pattern_rules.get(m.value() as usize) {
                    ids.extend(rules.iter().copied());
                }
            }
        }

        if let (Some(scanner), Some(url)) = (&self.url_index, packet.full_url.as_deref()) {
            let haystack = url.to_lowercase();
            for m in scanner.find_overlapping_iter(haystack.as_bytes()) {
                if let Some(rules) = self.url_pattern_rules.get(m.value() as usize) {
                    ids.extend(rules.iter().copied());
                }
            }
        }

        if let Some(scanner) = &self.content_index {
            for m in scanner.find_overlapping_iter(payload) {
                if let Some(rules) = self.content_pattern_rules.get(m.value() as usize) {
                    ids.extend(rules.iter().copied());
                }
            }
        }

        ids.sort_unstable();
        ids.dedup();
        ids
    }

    pub fn register_listener(&mut self, listener: Arc<dyn PacketListener>) {
        self.listeners.push(listener);
    }

    pub fn register_changer(&mut self, changer: Arc<dyn PacketChanger>) {
        self.changers.push(changer);
    }

    /// Check if all dependencies (depends_on) are satisfied for a rule
    fn dependencies_satisfied(rule: &SdkRule, matched_private_rules: &[String]) -> bool {
        if rule.depends_on.is_empty() {
            return true; // No dependencies
        }

        // All dependencies must be in the matched_private_rules list
        rule.depends_on
            .iter()
            .all(|dep| matched_private_rules.contains(dep))
    }

    /// Lock the flow state and record this packet so `flow:established` works.
    fn flow_guard(&self, packet: &PacketInfo) -> std::sync::MutexGuard<'_, FlowState> {
        let mut guard = self.flow_state.lock().unwrap();
        guard.record(packet);
        guard
    }

    /// Forward a private-rule match to OpenEDR for further matching.
    ///
    /// Private (YARA-style) rules never alert on their own: instead of acting
    /// locally, the match is emitted as a JSONL telemetry event so the OpenEDR
    /// side can correlate it with its own policy matches. Public rule matches
    /// are handled by the firewall itself and are NOT forwarded here.
    fn send_private_match_to_openedr(rule: &SdkRule, packet: &PacketInfo) {
        let event = serde_json::json!({
            "type": "FIREWALL_PRIVATE_MATCH",
            "rule": rule.name,
            "severity": rule.severity,
            "description": rule.description,
            "process_id": packet.process_id,
            "image_path": packet.image_path,
            "protocol": format!("{:?}", packet.protocol),
            "src_ip": packet.src_ip.to_string(),
            "dst_ip": packet.dst_ip.to_string(),
            "dst_port": packet.dst_port,
            "hostname": packet.hostname,
            "dns_query": packet.dns_query,
            "full_url": packet.full_url,
            "timestamp_ms": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });

        if crate::ffi::send_telemetry_line(crate::ffi::TelemetryLine::OpenedrEvent(
            event.to_string(),
        )) {
            tracing::debug!(
                "Private rule '{}' forwarded to OpenEDR for further matching",
                rule.name
            );
        }
    }

    /// Evaluate all rules against packet, return first matching rule
    pub fn evaluate(
        &self,
        packet: &PacketInfo,
        payload: &[u8],
        _settings: &FirewallSettings,
        _context: &PacketContext,
    ) -> Option<RuleMatchResult> {
        let mut matched_private_rules = Vec::new();
        let mut flow = self.flow_guard(packet);

        for rule in &self.rules {
            if rule.matches_with_flow(packet, payload, &mut flow) {
                // Track private rule matches for debugging
                if rule.private {
                    matched_private_rules.push(rule.name.clone());
                    tracing::debug!("Private rule matched (not generating alert): {}", rule.name);
                    Self::send_private_match_to_openedr(rule, packet);
                    continue;
                }

                // Check if dependencies are satisfied (YARA-style)
                if !Self::dependencies_satisfied(rule, &matched_private_rules) {
                    tracing::debug!(
                        "Rule '{}' matched but dependencies not satisfied. Required: {:?}, Matched: {:?}",
                        rule.name,
                        rule.depends_on,
                        matched_private_rules
                    );
                    continue;
                }

                let (detected_domain, detected_subdomain, used_psl) =
                    Self::extract_domain_info(packet, rule);

                // Log private rules that were evaluated before this match
                if !matched_private_rules.is_empty() {
                    tracing::debug!(
                        "Rule '{}' matched after evaluating private rules: {:?}",
                        rule.name,
                        matched_private_rules
                    );
                }

                return Some(RuleMatchResult {
                    rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    change_data: rule.change_data.clone(),
                    change_request_body: rule.change_request_body.clone(),
                    change_response_body: rule.change_response_body.clone(),
                    is_private_rule_match: false,
                    detected_subdomain,
                    detected_domain,
                    used_public_suffix_list: used_psl,
                    matched_private_rules,
                });
            }
        }
        None
    }

    pub fn evaluate_all(
        &self,
        packet: &PacketInfo,
        payload: &[u8],
        _settings: &FirewallSettings,
        _context: &PacketContext,
    ) -> Vec<RuleMatchResult> {
        let mut matched_private_rules = Vec::new();
        let mut flow = self.flow_guard(packet);

        // First pass: collect private rule matches
        for rule in &self.rules {
            if rule.matches_with_flow(packet, payload, &mut flow) && rule.private {
                matched_private_rules.push(rule.name.clone());
                tracing::debug!("Private rule matched (not generating alert): {}", rule.name);
                Self::send_private_match_to_openedr(rule, packet);
            }
        }

        // Log if any private rules matched before collecting public matches
        if !matched_private_rules.is_empty() {
            tracing::debug!(
                "Evaluated {} private rule(s) before public rules: {:?}",
                matched_private_rules.len(),
                matched_private_rules
            );
        }

        // Second pass: collect public rule matches
        self.rules
            .iter()
            .filter_map(|rule| {
                if rule.matches_with_flow(packet, payload, &mut flow) && !rule.private {
                    // Check if dependencies are satisfied (YARA-style)
                    if !Self::dependencies_satisfied(rule, &matched_private_rules) {
                        tracing::debug!(
                            "Rule '{}' matched but dependencies not satisfied. Required: {:?}, Matched: {:?}",
                            rule.name, rule.depends_on, matched_private_rules
                        );
                        return None;
                    }
                    
                    let (detected_domain, detected_subdomain, used_psl) = Self::extract_domain_info(packet, rule);
                    
                    tracing::debug!("Public rule '{}' matched (generating alert)", rule.name);
                    
                    Some(RuleMatchResult {
                        rule_name: rule.name.clone(),
                        action: rule.action.clone(),
                        description: rule.description.clone(),
                        severity: rule.severity.clone(),
                        change_data: rule.change_data.clone(),
                        change_request_body: rule.change_request_body.clone(),
                        change_response_body: rule.change_response_body.clone(),
                        is_private_rule_match: false,
                        detected_subdomain,
                        detected_domain,
                        used_public_suffix_list: used_psl,
                        matched_private_rules: matched_private_rules.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Optimized evaluation that returns the first match found.
    /// Useful for "Block" scenarios where we don't need to see other matches.
    pub fn evaluate_first_match(
        &self,
        packet: &PacketInfo,
        payload: &[u8],
        defer_heavy_rules: bool,
    ) -> Option<RuleMatchResult> {
        let mut matched_private_rules = Vec::new();
        let mut flow = self.flow_guard(packet);

        self.indexed_rule_ids(packet, payload)
            .into_iter()
            .filter_map(|rule_id| self.rules.get(rule_id))
            .filter(|rule| !defer_heavy_rules || !rule.requires_deferred_inspection())
            .find_map(|rule| {
                if rule.matches_with_flow(packet, payload, &mut flow) {
                    if rule.private {
                        matched_private_rules.push(rule.name.clone());
                        tracing::debug!("Private rule matched (not generating alert): {}", rule.name);
                        Self::send_private_match_to_openedr(rule, packet);
                        return None;
                    }
                    
                    // Check if dependencies are satisfied (YARA-style)
                    if !Self::dependencies_satisfied(rule, &matched_private_rules) {
                        tracing::debug!(
                            "Rule '{}' matched but dependencies not satisfied. Required: {:?}, Matched: {:?}",
                            rule.name, rule.depends_on, matched_private_rules
                        );
                        return None;
                    }
                    
                    let (detected_domain, detected_subdomain, used_psl) = Self::extract_domain_info(packet, rule);
                    
                    // Log private rules that were evaluated before this match
                    if !matched_private_rules.is_empty() {
                        tracing::debug!("First match rule '{}' found after evaluating private rules: {:?}", rule.name, matched_private_rules);
                    }
                    
                    Some(RuleMatchResult {
                        rule_name: rule.name.clone(),
                        action: rule.action.clone(),
                        description: rule.description.clone(),
                        severity: rule.severity.clone(),
                        change_data: rule.change_data.clone(),
                        change_request_body: rule.change_request_body.clone(),
                        change_response_body: rule.change_response_body.clone(),
                        is_private_rule_match: false,
                        detected_subdomain,
                        detected_domain,
                        used_public_suffix_list: used_psl,
                        matched_private_rules: matched_private_rules.clone(),
                    })
                } else {
                    None
                }
            })
    }

    /// Extract domain and subdomain information from packet if domain matching was used
    /// Returns: (domain, subdomain, used_public_suffix_list)
    fn extract_domain_info(
        packet: &PacketInfo,
        rule: &SdkRule,
    ) -> (Option<String>, Option<String>, bool) {
        // Check if rule has domain matcher
        if rule.domain.is_none() {
            return (None, None, false);
        }

        let hostname = match &packet.hostname {
            Some(h) => h,
            None => return (None, None, false),
        };

        // Simple subdomain detection without public_suffixes.txt
        // This is basic but works for most cases
        // TODO: Add public_suffixes.txt support for accurate complex TLD handling
        let parts: Vec<&str> = hostname.split('.').collect();

        if parts.len() <= 2 {
            // example.com - no subdomain
            return (Some(hostname.clone()), None, false);
        }

        // For now, assume last 2 parts are domain (works for .com, .net, .org, etc.)
        // For complex TLDs like .co.uk, this would need public_suffixes.txt
        let domain = parts[parts.len() - 2..].join(".");
        let subdomain = parts[..parts.len() - 2].join(".");

        // used_public_suffix_list = false because we're using simple parsing
        (Some(domain), Some(subdomain), false)
    }

    pub fn needs_entropy(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.enabled && rule.requires_entropy())
    }

    pub fn needs_file_type(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.enabled && rule.requires_file_type())
    }

    fn sanitize_rules(mut rules: Vec<SdkRule>) -> Vec<SdkRule> {
        // Validate dependencies before sanitizing
        Self::validate_dependencies(&rules);

        for rule in &mut rules {
            let is_named_entropy_prompt = rule
                .name
                .eq_ignore_ascii_case("Ask To Block Encrypted Exfiltration")
                && rule.entropy_threshold == Some(7.95);

            if rule.enabled && (is_named_entropy_prompt || rule.is_entropy_only_ask_rule()) {
                println!(
                    "[SDK] Disabling entropy-only ask rule [{}] to keep network decisions off the hot path",
                    rule.name
                );
                rule.enabled = false;
            }
        }

        rules
    }

    /// Validate rule dependencies to prevent circular dependencies
    fn validate_dependencies(rules: &[SdkRule]) {
        use std::collections::{HashMap, HashSet};

        // Build a map of rule names to their dependencies
        let mut dep_map: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut all_rule_names: HashSet<&str> = HashSet::new();

        for rule in rules {
            all_rule_names.insert(&rule.name);
            if !rule.depends_on.is_empty() {
                dep_map.insert(
                    &rule.name,
                    rule.depends_on.iter().map(|s| s.as_str()).collect(),
                );
            }
        }

        // Check for missing dependencies
        for (rule_name, deps) in &dep_map {
            for dep in deps {
                if !all_rule_names.contains(dep) {
                    eprintln!(
                        "[SDK] Warning: Rule '{}' depends on '{}' which does not exist",
                        rule_name, dep
                    );
                }
            }
        }

        // Check for circular dependencies using DFS
        for rule_name in dep_map.keys() {
            let mut visited = HashSet::new();
            let mut stack = HashSet::new();

            if Self::has_circular_dependency(rule_name, &dep_map, &mut visited, &mut stack) {
                eprintln!(
                    "[SDK] Error: Circular dependency detected involving rule '{}'",
                    rule_name
                );
                eprintln!("[SDK] Dependency chain: {:?}", stack);
            }
        }
    }

    /// Detect circular dependencies using depth-first search
    fn has_circular_dependency<'a>(
        rule_name: &'a str,
        dep_map: &HashMap<&'a str, Vec<&'a str>>,
        visited: &mut HashSet<&'a str>,
        stack: &mut HashSet<&'a str>,
    ) -> bool {
        // If already in the current path, we found a cycle
        if stack.contains(rule_name) {
            return true;
        }

        // If already fully explored, no cycle from this node
        if visited.contains(rule_name) {
            return false;
        }

        // Mark as being explored
        visited.insert(rule_name);
        stack.insert(rule_name);

        // Check all dependencies
        if let Some(deps) = dep_map.get(rule_name) {
            for dep in deps {
                if Self::has_circular_dependency(dep, dep_map, visited, stack) {
                    return true;
                }
            }
        }

        // Remove from current path
        stack.remove(rule_name);
        false
    }

    pub fn list_rules(&self) -> Vec<&SdkRule> {
        self.rules.iter().collect()
    }

    pub fn toggle_rule(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.name == name) {
            if enabled && rule.is_entropy_only_ask_rule() {
                println!(
                    "[SDK] Refusing to enable entropy-only ask rule [{}] because it harms the hot path",
                    rule.name
                );
                rule.enabled = false;
                return false;
            }

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
