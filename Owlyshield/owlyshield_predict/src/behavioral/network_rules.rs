use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    #[default]
    Block,
    Allow,
    Ask,
    ChangePacket,
    SolvePacket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleCondition {
    Protocol(RuleProtocol),
    Ip(String),
    Domain(String),
    Url(String),
    FileType(String),
    Regex(String),
    Port(u16),
    Entropy(f64),
    Localhost(bool),
    Payload(String),
    HttpMethod(String),
    HttpPath(String),
    HttpUserAgent(String),
    HttpContentType(String),
    HttpReferer(String),
    DnsQuery(String),
}

impl RuleCondition {
    pub fn matches_packet(&self, cache: &RefCell<HashMap<String, Regex>>, packet: &PacketInfo) -> bool {
        match self {
            RuleCondition::Protocol(proto) => match proto {
                RuleProtocol::TCP => packet.protocol == Protocol::TCP,
                RuleProtocol::UDP => packet.protocol == Protocol::UDP,
                RuleProtocol::ICMP => packet.protocol == Protocol::ICMP,
                RuleProtocol::HTTP => packet.full_url.is_some() || packet.hostname.is_some(),
                RuleProtocol::HTTPS => packet.tls_handshake || (packet.hostname.is_some() && packet.dst_port == 443),
                RuleProtocol::DNS => packet.dns_query.is_some() || packet.dst_port == 53 || packet.src_port == 53,
                RuleProtocol::QUIC => packet.protocol == Protocol::UDP && (packet.dst_port == 443 || packet.src_port == 443),
                RuleProtocol::TLSSNI => packet.tls_handshake,
                RuleProtocol::ANY => true,
                _ => false,
            },
            RuleCondition::Ip(pattern) => {
                matches_pattern(cache, pattern, &packet.src_ip.to_string())
                    || matches_pattern(cache, pattern, &packet.dst_ip.to_string())
            }
            RuleCondition::Domain(pattern) => {
                if let Some(hostname) = &packet.hostname {
                    if matches_pattern(cache, pattern, hostname) {
                        return true;
                    }
                }
                packet.payload_domains.iter().any(|d| matches_pattern(cache, pattern, d))
            }
            RuleCondition::Url(pattern) => {
                if let Some(url) = &packet.full_url {
                    if matches_pattern(cache, pattern, url) {
                        return true;
                    }
                }
                packet.payload_urls.iter().any(|u| matches_pattern(cache, pattern, u))
            }
            RuleCondition::FileType(pattern) => {
                if let Some(ft) = &packet.detected_file_type {
                    matches_pattern(cache, pattern, ft)
                } else {
                    false
                }
            }
            RuleCondition::Regex(pattern) => {
                // Generic regex match against payload sample if available
                if let Some(sample) = &packet.payload_sample {
                    matches_pattern(cache, pattern, sample)
                } else {
                    false
                }
            }
            RuleCondition::Port(port) => packet.src_port == *port || packet.dst_port == *port,
            RuleCondition::Entropy(threshold) => {
                packet.payload_entropy.map_or(false, |e| e >= *threshold)
            }
            RuleCondition::Localhost(require_localhost) => {
                let is_localhost = packet.src_ip.is_loopback() || packet.dst_ip.is_loopback();
                is_localhost == *require_localhost
            }
            RuleCondition::Payload(pattern) => {
                if let Some(sample) = &packet.payload_sample {
                    matches_pattern(cache, pattern, sample)
                } else {
                    false
                }
            }
            RuleCondition::HttpMethod(pattern) => {
                packet.http_method.as_ref().map_or(false, |m| matches_pattern(cache, pattern, m))
            }
            RuleCondition::HttpPath(pattern) => {
                packet.http_path.as_ref().map_or(false, |p| matches_pattern(cache, pattern, p))
            }
            RuleCondition::HttpUserAgent(pattern) => {
                packet.http_user_agent.as_ref().map_or(false, |ua| matches_pattern(cache, pattern, ua))
            }
            RuleCondition::HttpContentType(pattern) => {
                packet.http_content_type.as_ref().map_or(false, |ct| matches_pattern(cache, pattern, ct))
            }
            RuleCondition::HttpReferer(pattern) => {
                packet.http_referer.as_ref().map_or(false, |r| matches_pattern(cache, pattern, r))
            }
            RuleCondition::DnsQuery(pattern) => {
                packet.dns_query.as_ref().map_or(false, |q| matches_pattern(cache, pattern, q))
            }
        }
    }
}

pub fn matches_pattern(cache: &RefCell<HashMap<String, Regex>>, pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();

    if pattern == "*" || pattern == "*.*" || pattern.is_empty() {
        return true;
    }

    if !pattern.contains('*') && !pattern.contains('?') {
        return text == pattern || text.contains(&pattern);
    }

    let regex_pattern = format!(
        "^{}$",
        regex::escape(&pattern)
            .replace("\\*", ".*")
            .replace("\\?", ".")
    );

    let mut cache = cache.borrow_mut();
    let re = cache.entry(regex_pattern.clone()).or_insert_with(|| {
        Regex::new(&regex_pattern).unwrap_or_else(|_| Regex::new(".*").unwrap())
    });

    re.is_match(&text)
}
