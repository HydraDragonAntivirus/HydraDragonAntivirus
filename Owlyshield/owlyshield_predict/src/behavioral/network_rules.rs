use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use regex::Regex;
use std::collections::HashMap;
use std::cell::RefCell;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
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

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "TCP" => Some(Protocol::TCP),
            "UDP" => Some(Protocol::UDP),
            "ICMP" => Some(Protocol::ICMP),
            _ => None,
        }
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
pub enum ContentEncoding {
    Base58,
    Base64,
    Reverse,
    Hex,
    #[default]
    Plain,
}

impl ContentEncoding {
    pub fn decode(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            ContentEncoding::Base58 => {
                let text = String::from_utf8_lossy(data).trim().to_string();
                bs58::decode(&text).into_vec().ok()
            }
            ContentEncoding::Base64 => {
                let text = String::from_utf8_lossy(data).trim().to_string();
                base64::engine::general_purpose::STANDARD
                    .decode(&text)
                    .ok()
            }
            ContentEncoding::Reverse => {
                Some(data.iter().rev().cloned().collect())
            }
            ContentEncoding::Hex => {
                let text = String::from_utf8_lossy(data).trim().replace(" ", "");
                if text.len() % 2 != 0 {
                    return None;
                }
                let mut result = Vec::with_capacity(text.len() / 2);
                for i in (0..text.len()).step_by(2) {
                    if let Ok(byte) = u8::from_str_radix(&text[i..i + 2], 16) {
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    TrafficAttack,
    #[default]
    Block,
    Allow,
    Ask,
    Terminate,
    Quarantine,
    KillAndRemove,
    ChangePacket,
    SolvePacket,
    ChangeRequestBody,
    ChangeResponseBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: RuleAction,
    #[serde(default)]
    pub condition: Option<RuleCondition>,
    #[serde(default)]
    pub change_request_body: Option<String>,
    #[serde(default)]
    pub change_response_body: Option<String>,
    /// If true, use regex replacement for the body changer.
    #[serde(default)]
    pub use_regex_replacement: bool,
    #[serde(default)]
    pub search_pattern: Option<String>,
    #[serde(default)]
    pub json_match: Option<JsonMatcher>,
}

fn default_true() -> bool { true }

impl SdkRule {
    pub fn apply_replacement(&self, body: &str) -> String {
        if !self.use_regex_replacement {
            if self.action == RuleAction::ChangeRequestBody {
                return self.change_request_body.clone().unwrap_or_else(|| body.to_string());
            } else if self.action == RuleAction::ChangeResponseBody {
                return self.change_response_body.clone().unwrap_or_else(|| body.to_string());
            }
            return body.to_string();
        }

        let Some(search) = &self.search_pattern else { return body.to_string(); };
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

    pub fn matches_packet(&self, cache: &RefCell<HashMap<String, Regex>>, packet: &PacketInfo, payload: &[u8]) -> bool {
        if !self.enabled { return false; }
        if let Some(ref matcher) = self.json_match {
            if !matcher.matches(payload) {
                return false;
            }
        }
        if let Some(cond) = &self.condition {
            cond.matches_packet(cache, packet, payload)
        } else {
            true // Enabled rule with no condition matches everything
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IpMatcher {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub cidr_ranges: Vec<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PortMatcher {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub ranges: Vec<(u16, u16)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TrafficRoutine {
    pub from_ip: Option<String>,
    pub from_port: Option<u16>,
    pub to_ip: Option<String>,
    pub to_port: Option<u16>,
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
    FileType(Vec<String>),
    Regex(RegexMatcher),
    Localhost(LocalhostType),
    ContentMatch(ContentMatchData),
    Entropy(EntropyMatcher),
    Routine(TrafficRoutine),
    // Backward compatibility or flat fields
    HttpMethod(String),
    HttpPath(String),
    HttpUserAgent(String),
    HttpContentType(String),
    HttpReferer(String),
    DnsQuery(String),
    JsonMatch(JsonMatcher),
    Ip(String),
    Payload(String),
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
        text.contains(&format!("\"{}\"", self.key)) && text.contains(&self.value)
    }
}

impl RuleCondition {
    pub fn matches_packet(&self, cache: &RefCell<HashMap<String, Regex>>, packet: &PacketInfo, payload: &[u8]) -> bool {
        match self {
            RuleCondition::And(conds) => conds.iter().all(|c| c.matches_packet(cache, packet, payload)),
            RuleCondition::Or(conds) => conds.iter().any(|c| c.matches_packet(cache, packet, payload)),
            RuleCondition::Protocol(proto) => match proto {
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
            RuleCondition::SrcIp(matcher) => matcher.matches(packet.src_ip),
            RuleCondition::DstIp(matcher) => matcher.matches(packet.dst_ip),
            RuleCondition::SrcPort(matcher) => matcher.matches(packet.src_port),
            RuleCondition::DstPort(matcher) => matcher.matches(packet.dst_port),
            RuleCondition::Domain(matcher) => matcher.matches(packet.hostname.as_deref()) || packet.payload_domains.iter().any(|d| matcher.matches(Some(d))),
            RuleCondition::Url(matcher) => matcher.matches(packet.full_url.as_deref()) || packet.payload_urls.iter().any(|u| matcher.matches(Some(u))),
            RuleCondition::FileType(types) => {
                if let Some(ft) = &packet.detected_file_type {
                    let ft_lower = ft.to_lowercase();
                    types.iter().any(|t| t.to_lowercase() == ft_lower)
                } else {
                    false
                }
            }
            RuleCondition::Regex(matcher) => {
                if let Some(sample) = &packet.payload_sample {
                    matcher.matches(sample.as_bytes())
                } else {
                    false
                }
            }
            RuleCondition::Localhost(l_type) => l_type.matches(if packet.outbound { packet.dst_ip } else { packet.src_ip }),
            RuleCondition::ContentMatch(data) => {
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
            RuleCondition::Entropy(matcher) => packet.payload_entropy.map_or(false, |e| e >= matcher.threshold),
            RuleCondition::Routine(routine) => routine.matches(packet),
            RuleCondition::HttpMethod(p) => packet.http_method.as_ref().map_or(false, |m| matches_pattern(cache, p, m)),
            RuleCondition::HttpPath(p) => packet.http_path.as_ref().map_or(false, |m| matches_pattern(cache, p, m)),
            RuleCondition::HttpUserAgent(p) => packet.http_user_agent.as_ref().map_or(false, |m| matches_pattern(cache, p, m)),
            RuleCondition::HttpContentType(p) => packet.http_content_type.as_ref().map_or(false, |m| matches_pattern(cache, p, m)),
            RuleCondition::HttpReferer(p) => packet.http_referer.as_ref().map_or(false, |m| matches_pattern(cache, p, m)),
            RuleCondition::DnsQuery(p) => packet.dns_query.as_ref().map_or(false, |m| matches_pattern(cache, p, m)),
            RuleCondition::SanctumDetected => true,
            RuleCondition::JsonMatch(matcher) => matcher.matches(payload),
            RuleCondition::Ip(s) | RuleCondition::Payload(s) => {
                let bytes = s.as_bytes();
                if let Some(sample) = &packet.payload_sample {
                    sample.contains(s) || bytes.iter().all(|&b| sample.as_bytes().contains(&b)) 
                } else {
                    false
                }
            }
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
    
    pub fn Exact(domain: String) -> Self {
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
    
    pub fn Contains(pattern: String) -> Self {
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

pub fn matches_pattern(cache: &RefCell<HashMap<String, Regex>>, pattern: &str, text: &str) -> bool {
    let p = pattern.to_lowercase();
    let t = text.to_lowercase();
    if p == "*" || p == "*.*" || p.is_empty() { return true; }
    if !p.contains('*') && !p.contains('?') { return t == p || t.contains(&p); }
    let rp = format!("^{}$", regex::escape(&p).replace("\\*", ".*").replace("\\?", "."));
    cache.borrow_mut().entry(rp.clone()).or_insert_with(|| Regex::new(&rp).unwrap_or_else(|_| Regex::new(".*").unwrap())).is_match(&t)
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
