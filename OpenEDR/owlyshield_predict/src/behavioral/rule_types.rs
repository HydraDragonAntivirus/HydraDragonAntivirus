use base64::{Engine as _, engine::general_purpose::STANDARD};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock, RwLock};

// =============================================================================
// HELPER FUNCTIONS & DEFAULTS
// =============================================================================

pub fn default_zero() -> usize {
    0
}
pub fn default_severity() -> u8 {
    50
}
pub fn default_true() -> bool {
    true
}


fn wide_ptr_len(ptr: *const u16) -> usize {
    let mut len = 0usize;
    unsafe {
        while !ptr.is_null() && *ptr.add(len) != 0 {
            len += 1;
        }
    }
    len
}


fn get_known_folder_path(folder_id: &windows::core::GUID) -> Option<String> {
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;
    use std::slice;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KNOWN_FOLDER_FLAG, SHGetKnownFolderPath};

    unsafe {
        let path_ptr =
            SHGetKnownFolderPath(folder_id, KNOWN_FOLDER_FLAG(0), HANDLE::default()).ok()?;
        if path_ptr.is_null() {
            return None;
        }

        let len = wide_ptr_len(path_ptr.0);
        let path_slice = slice::from_raw_parts(path_ptr.0, len);
        let path = OsString::from_wide(path_slice)
            .to_string_lossy()
            .into_owned();
        CoTaskMemFree(Some(path_ptr.0 as *const c_void));
        Some(path)
    }
}


fn resolve_special_environment_variable(var_name: &str) -> Option<String> {
    use windows::Win32::UI::Shell::{
        FOLDERID_CommonStartup, FOLDERID_Desktop, FOLDERID_Downloads, FOLDERID_Startup,
    };

    static CACHE: OnceLock<HashMap<&'static str, Option<String>>> = OnceLock::new();

    let cache = CACHE.get_or_init(|| {
        let mut map = HashMap::new();
        map.insert(
            "KNOWNFOLDER_DESKTOP",
            get_known_folder_path(&FOLDERID_Desktop),
        );
        map.insert(
            "KNOWNFOLDER_DOWNLOADS",
            get_known_folder_path(&FOLDERID_Downloads),
        );
        map.insert(
            "KNOWNFOLDER_STARTUP",
            get_known_folder_path(&FOLDERID_Startup),
        );
        map.insert(
            "KNOWNFOLDER_COMMONSTARTUP",
            get_known_folder_path(&FOLDERID_CommonStartup),
        );
        map
    });

    cache.get(var_name).cloned().flatten()
}


pub fn expand_environment_variables(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let re = match Regex::new(r"%([^%]+)%") {
        Ok(r) => r,
        Err(_) => return text.to_string(),
    };
    re.replace_all(text, |caps: &regex::Captures| {
        let var_name = caps[1].to_uppercase();
        if let Some(val) = std::env::var(&var_name)
            .ok()
            .or_else(|| resolve_special_environment_variable(&var_name))
        {
            val
        } else {
            caps[0].to_string()
        }
    })
    .to_string()
}

// =============================================================================
// COMMON ENUMS & STRUCTS
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
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
    Nocase,
    Contains,
    Startswith,
    Endswith,
    Re,
    Base64,
    Not,
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
        self.modifiers()
            .iter()
            .any(|m| std::mem::discriminant(m) == std::mem::discriminant(modifier))
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

    pub fn matches(
        &self,
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        text: &str,
        force_regex: bool,
    ) -> bool {
        let mut pattern = self.pattern().to_string();

        if self.has_modifier(&StringModifier::Base64)
            && let Ok(decoded) = STANDARD.decode(pattern.as_bytes())
        {
            pattern = String::from_utf8_lossy(&decoded).into_owned();
        }

        let case_insensitive =
            !matches!(self, PatternSpec::Complex { .. }) || self.is_case_insensitive();

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
    #[serde(alias = "stable", alias = "production")]
    Stable,
    #[serde(alias = "experimental")]
    Experimental,
    #[serde(alias = "test")]
    Test,
    #[serde(alias = "deprecated")]
    Deprecated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq)]
pub enum DetectionLevel {
    #[serde(alias = "informational", alias = "info")]
    Informational,
    #[serde(alias = "low")]
    Low,
    #[default]
    #[serde(alias = "medium")]
    Medium,
    #[serde(alias = "high")]
    High,
    #[serde(alias = "critical")]
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

fn push_unique_bytes(candidates: &mut Vec<Vec<u8>>, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    if candidates
        .iter()
        .any(|existing| existing.as_slice() == data)
    {
        return;
    }

    candidates.push(data.to_vec());
}

fn push_payload_candidate(candidates: &mut Vec<Vec<u8>>, data: &[u8]) {
    push_unique_bytes(candidates, data);
    if let Some(decoded) = decode_relaxed_hex(data) {
        push_unique_bytes(candidates, &decoded);
    }
}

fn packet_payload_candidates(packet: &PacketInfo, payload: &[u8]) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    push_payload_candidate(&mut candidates, payload);

    if let Some(body) = packet.http_request_body.as_deref() {
        push_payload_candidate(&mut candidates, body.as_bytes());
    }
    if let Some(body) = packet.http_response_body.as_deref() {
        push_payload_candidate(&mut candidates, body.as_bytes());
    }
    if let Some(sample) = packet.payload_sample.as_deref() {
        push_payload_candidate(&mut candidates, sample.as_bytes());
    }

    candidates
}

fn decoded_json_candidates(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    push_unique_bytes(&mut candidates, payload);

    for decoded in [
        ContentEncoding::Base64.decode(payload),
        ContentEncoding::Base58.decode(payload),
        ContentEncoding::Hex.decode(payload),
        ContentEncoding::Reverse.decode(payload),
    ]
    .into_iter()
    .flatten()
    {
        push_unique_bytes(&mut candidates, &decoded);
    }

    candidates
}

fn decoded_packet_payload_candidates(
    packet: &PacketInfo,
    payload: &[u8],
    encoding: &ContentEncoding,
) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    for candidate in packet_payload_candidates(packet, payload) {
        let decoded = encoding.decode(&candidate).unwrap_or(candidate);
        push_unique_bytes(&mut candidates, &decoded);
    }
    candidates
}

fn json_path_lookup<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Option<&'a serde_json::Value> {
    if field.trim().is_empty() {
        return None;
    }

    field
        .split('.')
        .try_fold(value, |current, segment| match current {
            serde_json::Value::Object(map) => map.get(segment),
            serde_json::Value::Array(items) => segment
                .parse::<usize>()
                .ok()
                .and_then(|index| items.get(index)),
            _ => None,
        })
}

fn json_key_match_recursive(
    value: &serde_json::Value,
    field: &str,
    expected: &serde_json::Value,
) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, child)| {
            (key.eq_ignore_ascii_case(field) && json_value_matches(child, expected))
                || json_key_match_recursive(child, field, expected)
        }),
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| json_key_match_recursive(item, field, expected)),
        _ => false,
    }
}

fn json_value_matches(found: &serde_json::Value, expected: &serde_json::Value) -> bool {
    if matches!(expected, serde_json::Value::String(value) if value.is_empty()) {
        return true;
    }

    if found == expected {
        return true;
    }

    let found_text = match found {
        serde_json::Value::String(value) => value.clone(),
        _ => found.to_string(),
    };
    let expected_text = match expected {
        serde_json::Value::String(value) => value.clone(),
        _ => expected.to_string(),
    };

    found_text == expected_text
}

fn rule_protocol_matches(proto: &RuleProtocol, packet: &PacketInfo) -> bool {
    match proto {
        RuleProtocol::TCP => packet.protocol == Protocol::TCP,
        RuleProtocol::UDP => packet.protocol == Protocol::UDP,
        RuleProtocol::ICMP => packet.protocol == Protocol::ICMP,
        RuleProtocol::HTTP => {
            packet.full_url.is_some()
                || packet.hostname.is_some()
                || packet.dst_port == 80
                || packet.src_port == 80
        }
        RuleProtocol::HTTPS => {
            packet.tls_handshake || packet.dst_port == 443 || packet.src_port == 443
        }
        RuleProtocol::DNS => {
            packet.dns_query.is_some() || packet.dst_port == 53 || packet.src_port == 53
        }
        RuleProtocol::QUIC => {
            packet.protocol == Protocol::UDP && (packet.dst_port == 443 || packet.src_port == 443)
        }
        RuleProtocol::TLSSNI => packet.tls_handshake,
        RuleProtocol::ARP => matches!(packet.protocol, Protocol::Raw(0)),
        RuleProtocol::ANY => true,
    }
}

fn expand_ip_matcher(matcher: &mut IpMatcher) {
    for address in &mut matcher.addresses {
        *address = expand_environment_variables(address);
    }
    for cidr in &mut matcher.cidr_ranges {
        *cidr = expand_environment_variables(cidr);
    }
}

fn expand_domain_matcher(matcher: &mut DomainMatcher) {
    for domain in &mut matcher.domains {
        *domain = expand_environment_variables(domain);
    }
}

fn expand_url_matcher(matcher: &mut UrlMatcher) {
    for pattern in &mut matcher.patterns {
        *pattern = expand_environment_variables(pattern);
    }
}

fn expand_regex_matcher(matcher: &mut RegexMatcher) {
    matcher.pattern = expand_environment_variables(&matcher.pattern);
}

fn expand_content_match_data(data: &mut ContentMatchData) {
    data.pattern = expand_environment_variables(&data.pattern);
}

fn expand_traffic_routine(routine: &mut TrafficRoutine) {
    if let Some(from_ip) = &mut routine.from_ip {
        *from_ip = expand_environment_variables(from_ip);
    }
    if let Some(to_ip) = &mut routine.to_ip {
        *to_ip = expand_environment_variables(to_ip);
    }
}

fn expand_json_matcher(matcher: &mut JsonMatcher) {
    matcher.field = expand_environment_variables(&matcher.field);
    if let serde_json::Value::String(value) = &mut matcher.value {
        *value = expand_environment_variables(value);
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
    Loopback,
    PrivateA,
    PrivateB,
    PrivateC,
    Private,
    Any,
    #[default]
    All,
    None,
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
    #[serde(default)]
    pub is_regex: bool,
    #[serde(default)]
    pub encoding: ContentEncoding,
}

impl ContentMatchData {
    pub fn matches(&self, cache: &Arc<RwLock<HashMap<String, Regex>>>, data: &[u8]) -> bool {
        let Some(decoded) = self.encoding.decode(data) else {
            return false;
        };
        let text = String::from_utf8_lossy(&decoded);

        if self.is_regex {
            let p = if !self.pattern.starts_with("(?i)") {
                format!("(?i){}", self.pattern)
            } else {
                self.pattern.clone()
            };

            if let Ok(cache_map) = cache.read() {
                if let Some(re) = cache_map.get(&p) {
                    return re.is_match(&text);
                }
            }

            if let Ok(re) = Regex::new(&p) {
                if let Ok(mut cache_map) = cache.write() {
                    cache_map.insert(p.clone(), re.clone());
                }
                re.is_match(&text)
            } else {
                false
            }
        } else {
            text.to_lowercase().contains(&self.pattern.to_lowercase())
        }
    }
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
    #[serde(default, alias = "key")]
    pub field: String,
    pub value: serde_json::Value,
}

impl JsonMatcher {
    pub fn matches(&self, payload: &[u8]) -> bool {
        if self.field.trim().is_empty() || payload.is_empty() {
            return false;
        }

        decoded_json_candidates(payload)
            .into_iter()
            .any(|candidate| {
                serde_json::from_slice::<serde_json::Value>(&candidate)
                    .ok()
                    .is_some_and(|parsed| {
                        json_path_lookup(&parsed, &self.field)
                            .is_some_and(|found| json_value_matches(found, &self.value))
                            || json_key_match_recursive(&parsed, &self.field, &self.value)
                    })
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FirewallSdkFileTypeMatcher {
    #[serde(default)]
    pub file_types: Vec<String>,
}

impl FirewallSdkFileTypeMatcher {
    pub fn matches(&self, detected_type: Option<&str>) -> bool {
        if self.file_types.is_empty() {
            return true;
        }

        let Some(file_type) = detected_type else {
            return false;
        };

        let file_type_lower = file_type.to_lowercase();
        self.file_types
            .iter()
            .any(|entry| entry.to_lowercase() == file_type_lower)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FirewallSdkEntropyMatcher {
    #[serde(default, alias = "threshold")]
    pub min_entropy: f64,
}

impl FirewallSdkEntropyMatcher {
    pub fn matches(&self, entropy: Option<f64>) -> bool {
        entropy.is_some_and(|value| value >= self.min_entropy)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallSdkRuleAction {
    TrafficAttack,
    Block,
    #[default]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallSdkConditionLogic {
    #[default]
    And,
    Or,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", untagged)]
pub enum FirewallSdkCondition {
    And(Vec<FirewallSdkCondition>),
    Or(Vec<FirewallSdkCondition>),
    Protocol(RuleProtocol),
    SrcIp(IpMatcher),
    DstIp(IpMatcher),
    SrcPort(PortMatcher),
    DstPort(PortMatcher),
    Domain(DomainMatcher),
    Url(UrlMatcher),
    FileType(FirewallSdkFileTypeMatcher),
    Regex(RegexMatcher),
    Localhost(LocalhostType),
    ContentMatch(ContentMatchData),
    Entropy(FirewallSdkEntropyMatcher),
    SanctumDetected,
    Routine(TrafficRoutine),
    JsonMatch(JsonMatcher),
}

impl FirewallSdkCondition {
    pub fn matches_packet(
        &self,
        _cache: &Arc<RwLock<HashMap<String, Regex>>>,
        packet: &PacketInfo,
        payload: &[u8],
    ) -> bool {
        match self {
            FirewallSdkCondition::And(conds) => conds
                .iter()
                .all(|cond| cond.matches_packet(_cache, packet, payload)),
            FirewallSdkCondition::Or(conds) => conds
                .iter()
                .any(|cond| cond.matches_packet(_cache, packet, payload)),
            FirewallSdkCondition::Protocol(proto) => rule_protocol_matches(proto, packet),
            FirewallSdkCondition::SrcIp(matcher) => matcher.matches(packet.src_ip),
            FirewallSdkCondition::DstIp(matcher) => matcher.matches(packet.dst_ip),
            FirewallSdkCondition::SrcPort(matcher) => matcher.matches(packet.src_port),
            FirewallSdkCondition::DstPort(matcher) => matcher.matches(packet.dst_port),
            FirewallSdkCondition::Domain(matcher) => matcher.matches(packet.hostname.as_deref()),
            FirewallSdkCondition::Url(matcher) => matcher.matches(packet.full_url.as_deref()),
            FirewallSdkCondition::FileType(matcher) => {
                matcher.matches(packet.detected_file_type.as_deref())
            }
            FirewallSdkCondition::Regex(matcher) => matcher.matches(payload),
            FirewallSdkCondition::Localhost(localhost_type) => {
                if packet.outbound {
                    localhost_type.matches(packet.dst_ip)
                } else {
                    localhost_type.matches(packet.src_ip)
                }
            }
            FirewallSdkCondition::ContentMatch(data) => data
                .encoding
                .decode(payload)
                .is_some_and(|decoded| String::from_utf8_lossy(&decoded).contains(&data.pattern)),
            FirewallSdkCondition::Entropy(matcher) => matcher.matches(packet.payload_entropy),
            FirewallSdkCondition::SanctumDetected => true,
            FirewallSdkCondition::Routine(routine) => routine.matches(packet),
            FirewallSdkCondition::JsonMatch(matcher) => matcher.matches(payload),
        }
    }
}

impl NetworkRuleCondition {
    pub fn matches_packet(
        &self,
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        packet: &PacketInfo,
        payload: &[u8],
    ) -> bool {
        match self {
            NetworkRuleCondition::And(conds) => conds
                .iter()
                .all(|c| c.matches_packet(cache, packet, payload)),
            NetworkRuleCondition::Or(conds) => conds
                .iter()
                .any(|c| c.matches_packet(cache, packet, payload)),
            NetworkRuleCondition::Protocol(proto) => rule_protocol_matches(proto, packet),
            NetworkRuleCondition::SrcIp(matcher) => matcher.matches(packet.src_ip),
            NetworkRuleCondition::DstIp(matcher) => matcher.matches(packet.dst_ip),
            NetworkRuleCondition::SrcPort(matcher) => matcher.matches(packet.src_port),
            NetworkRuleCondition::DstPort(matcher) => matcher.matches(packet.dst_port),
            NetworkRuleCondition::Domain(matcher) => {
                matcher.matches(packet.hostname.as_deref())
                    || packet
                        .payload_domains
                        .iter()
                        .any(|d| matcher.matches(Some(d)))
            }
            NetworkRuleCondition::Url(matcher) => {
                matcher.matches(packet.full_url.as_deref())
                    || packet.payload_urls.iter().any(|u| matcher.matches(Some(u)))
            }
            NetworkRuleCondition::FileType(types) => {
                if let Some(ft) = &packet.detected_file_type {
                    let ft_lower = ft.to_lowercase();
                    types.iter().any(|t| t.to_lowercase() == ft_lower)
                } else {
                    false
                }
            }
            NetworkRuleCondition::Regex(matcher) => packet_payload_candidates(packet, payload)
                .iter()
                .any(|candidate| matcher.matches(candidate)),
            NetworkRuleCondition::Localhost(l_type) => l_type.matches(if packet.outbound {
                packet.dst_ip
            } else {
                packet.src_ip
            }),
            NetworkRuleCondition::ContentMatch(data) => packet_payload_candidates(packet, payload)
                .iter()
                .any(|candidate| {
                    data.encoding.decode(candidate).is_some_and(|decoded| {
                        String::from_utf8_lossy(&decoded).contains(&data.pattern)
                    })
                }),
            NetworkRuleCondition::Entropy(matcher) => packet
                .payload_entropy
                .map_or(false, |e| e >= matcher.threshold),
            NetworkRuleCondition::Routine(routine) => routine.matches(packet),
            NetworkRuleCondition::SanctumDetected => true,
            NetworkRuleCondition::JsonMatch(matcher) => packet_payload_candidates(packet, payload)
                .iter()
                .any(|candidate| matcher.matches(candidate)),
        }
    }
}

impl IpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        if self.addresses.is_empty() && self.cidr_ranges.is_empty() {
            return true;
        }
        let ip_str = ip.to_string();
        if self
            .addresses
            .iter()
            .any(|a| a == "*" || a == "any" || a == &ip_str)
        {
            return true;
        }
        self.cidr_ranges.iter().any(|c| ip_in_cidr(ip, c))
    }
}

impl DomainMatcher {
    pub fn matches(&self, hostname: Option<&str>) -> bool {
        let Some(host) = hostname else {
            return false;
        };
        if self.domains.is_empty() {
            return true;
        }
        let host_check = if self.case_insensitive {
            host.to_lowercase()
        } else {
            host.to_string()
        };
        self.domains.iter().any(|d| {
            let d_check = if self.case_insensitive {
                d.to_lowercase()
            } else {
                d.clone()
            };
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
        let Some(u) = url else {
            return false;
        };
        if self.patterns.is_empty() {
            return true;
        }
        let u_lower = u.to_lowercase();
        self.patterns
            .iter()
            .any(|p| wildcard_match(&p.to_lowercase(), &u_lower))
    }

    pub fn contains(pattern: String) -> Self {
        Self {
            patterns: vec![format!("*{}*", pattern)],
        }
    }
}

impl PortMatcher {
    pub fn matches(&self, port: u16) -> bool {
        if self.ports.is_empty() && self.ranges.is_empty() {
            return true;
        }
        if self.ports.contains(&port) {
            return true;
        }
        self.ranges.iter().any(|(s, e)| port >= *s && port <= *e)
    }
}

impl TrafficRoutine {
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        if let Some(ref f) = self.from_ip {
            if f != "*" && f != "any" && &packet.src_ip.to_string() != f {
                return false;
            }
        }
        if let Some(f) = self.from_port {
            if f != 0 && packet.src_port != f {
                return false;
            }
        }
        if let Some(ref t) = self.to_ip {
            if t != "*" && t != "any" && &packet.dst_ip.to_string() != t {
                return false;
            }
        }
        if let Some(t) = self.to_port {
            if t != 0 && packet.dst_port != t {
                return false;
            }
        }
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
                LocalhostType::PrivateB => {
                    ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31
                }
                LocalhostType::PrivateC => ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168,
                LocalhostType::Private => {
                    ipv4.octets()[0] == 10
                        || (ipv4.octets()[0] == 172
                            && ipv4.octets()[1] >= 16
                            && ipv4.octets()[1] <= 31)
                        || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168)
                }
                LocalhostType::Any => ipv4 == Ipv4Addr::new(0, 0, 0, 0),
                LocalhostType::All => {
                    ipv4.octets()[0] == 127
                        || ipv4.octets()[0] == 10
                        || (ipv4.octets()[0] == 172
                            && ipv4.octets()[1] >= 16
                            && ipv4.octets()[1] <= 31)
                        || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168)
                }
            },
            IpAddr::V6(ipv6) => match self {
                LocalhostType::None => true,
                LocalhostType::Loopback => ipv6.is_loopback(),
                LocalhostType::Private => ipv6.is_unique_local() || ipv6.is_unicast_link_local(),
                _ => {
                    ipv6.is_unique_local() || ipv6.is_unicast_link_local() || ipv6.is_unspecified()
                }
            },
        }
    }
}

impl RegexMatcher {
    pub fn matches(&self, data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(data);
        let p = if self.case_insensitive {
            format!("(?i){}", self.pattern)
        } else {
            self.pattern.clone()
        };
        Regex::new(&p).map_or(false, |re| re.is_match(&text))
    }
}

fn decode_relaxed_hex(data: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    if let Some(decoded) = decode_escaped_hex(text) {
        return Some(decoded);
    }

    let mut decoded = Vec::new();
    let mut saw_hex_cue = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let line = if let Some((hex_column, _ascii_column)) = line.split_once('|') {
            saw_hex_cue = true;
            hex_column
        } else {
            line
        };

        let tokens = line
            .split(|c: char| {
                c.is_whitespace() || matches!(c, ',' | ';' | '[' | ']' | '(' | ')' | '{' | '}')
            })
            .filter(|token| !token.trim().is_empty())
            .collect::<Vec<_>>();

        if tokens.is_empty() {
            continue;
        }

        let byte_tokens_after_first = tokens
            .iter()
            .skip(1)
            .filter_map(|token| clean_hex_token(token))
            .filter(|token| token.hex.len() == 2)
            .count();

        for (index, token) in tokens.iter().enumerate() {
            let Some(cleaned) = clean_hex_token(token) else {
                continue;
            };

            if cleaned.has_prefix {
                saw_hex_cue = true;
            }

            let looks_like_line_offset = index == 0
                && cleaned.hex.len() >= 4
                && (cleaned.has_offset_delimiter || byte_tokens_after_first >= 2);
            if looks_like_line_offset {
                saw_hex_cue = true;
                continue;
            }

            if !push_hex_pairs(&mut decoded, cleaned.hex) {
                return None;
            }
        }
    }

    if decoded.len() < 3 {
        return None;
    }

    if saw_hex_cue || source_looks_plain_hex(text) {
        Some(decoded)
    } else {
        None
    }
}

struct CleanHexToken<'a> {
    hex: &'a str,
    has_prefix: bool,
    has_offset_delimiter: bool,
}

fn clean_hex_token(token: &str) -> Option<CleanHexToken<'_>> {
    let token =
        token.trim_matches(|c: char| matches!(c, '"' | '\'' | '<' | '>' | '.' | '/' | '\\'));
    let has_offset_delimiter = token.ends_with(':');
    let token = token.trim_end_matches(':');
    let (token, has_prefix) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .map_or((token, false), |stripped| (stripped, true));
    let (token, has_slash_prefix) = token
        .strip_prefix("\\x")
        .or_else(|| token.strip_prefix("\\X"))
        .map_or((token, false), |stripped| (stripped, true));

    if token.is_empty()
        || token.len() % 2 != 0
        || !token.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }

    Some(CleanHexToken {
        hex: token,
        has_prefix: has_prefix || has_slash_prefix,
        has_offset_delimiter,
    })
}

fn decode_escaped_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0usize;

    while index + 3 < bytes.len() {
        if bytes[index] == b'\\'
            && (bytes[index + 1] == b'x' || bytes[index + 1] == b'X')
            && bytes[index + 2].is_ascii_hexdigit()
            && bytes[index + 3].is_ascii_hexdigit()
        {
            let hex = std::str::from_utf8(&bytes[index + 2..index + 4]).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 4;
        } else {
            index += 1;
        }
    }

    (decoded.len() >= 3).then_some(decoded)
}

fn push_hex_pairs(out: &mut Vec<u8>, hex: &str) -> bool {
    if hex.len() % 2 != 0 {
        return false;
    }

    for index in (0..hex.len()).step_by(2) {
        let Some(pair) = hex.get(index..index + 2) else {
            return false;
        };
        let Ok(byte) = u8::from_str_radix(pair, 16) else {
            return false;
        };
        out.push(byte);
    }

    true
}

fn source_looks_plain_hex(text: &str) -> bool {
    let compact = text
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, ',' | ';'))
        .collect::<String>();

    compact.len() >= 6
        && compact.len() % 2 == 0
        && compact.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

impl ContentEncoding {
    pub fn decode(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            ContentEncoding::Plain => Some(data.to_vec()),
            ContentEncoding::Base64 => {
                let text = String::from_utf8_lossy(data);
                STANDARD.decode(text.trim()).ok()
            }
            ContentEncoding::Base58 => {
                let text = String::from_utf8_lossy(data);
                bs58::decode(text.trim()).into_vec().ok()
            }
            ContentEncoding::Reverse => Some(data.iter().rev().cloned().collect()),
            ContentEncoding::Hex => decode_relaxed_hex(data),
        }
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        if let Ok(target_ip) = cidr.parse::<IpAddr>() {
            return ip == target_ip;
        }
        return false;
    }
    let Ok(prefix_len) = parts[1].parse::<u32>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            let Ok(net) = parts[0].parse::<Ipv4Addr>() else {
                return false;
            };
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                let shift = 32u32.checked_sub(prefix_len).unwrap_or(0);
                if shift >= 32 { 0 } else { !0u32 << shift }
            };
            (u32::from(v4) & mask) == (u32::from(net) & mask)
        }
        IpAddr::V6(v6) => {
            let Ok(net) = parts[0].parse::<Ipv6Addr>() else {
                return false;
            };
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                let shift = 128u32.checked_sub(prefix_len).unwrap_or(0);
                if shift >= 128 { 0 } else { !0u128 << shift }
            };
            (u128::from(v6) & mask) == (u128::from(net) & mask)
        }
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" || pattern == "any" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return text == pattern;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = text[pos..].find(part) {
            if i == 0 && found != 0 {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }
    pattern.ends_with('*') || pos == text.len()
}

pub fn matches_pattern(
    cache: &Arc<RwLock<HashMap<String, Regex>>>,
    pattern: &str,
    text: &str,
) -> bool {
    let p = pattern.to_lowercase();
    let t = text.to_lowercase();
    if p == "*" || p == "*.*" || p.is_empty() {
        return true;
    }
    if !p.contains('*') && !p.contains('?') {
        return t == p || t.contains(&p);
    }
    let rp = format!(
        "^{}$",
        regex::escape(&p).replace("\\*", ".*").replace("\\?", ".")
    );

    {
        if let Ok(cache_map) = cache.read() {
            if let Some(re) = cache_map.get(&rp) {
                return re.is_match(&t);
            }
        }
    }

    let Ok(mut cache_map) = cache.write() else {
        return false;
    };
    cache_map
        .entry(rp.clone())
        .or_insert_with(|| Regex::new(&rp).unwrap_or_else(|_| Regex::new(".*").unwrap()))
        .is_match(&t)
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
    JsonMatch(JsonMatcher),
}

// =============================================================================
// UNIFIED RESPONSE TYPES
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    #[serde(default)]
    pub terminate_process: bool,
    #[serde(default)]
    pub suspend_while_ask: bool,
    #[serde(default)]
    pub deny_while_ask: bool,
    #[serde(default)]
    pub suspend_process: bool,
    #[serde(default)]
    pub quarantine: bool,
    #[serde(default, alias = "deny_access", alias = "kernel_block")]
    pub status_access_denied: bool,
    #[serde(default)]
    pub kill_and_remove: bool,
    #[serde(default)]
    pub ask_user: bool,
    #[serde(default)]
    pub notify_user: bool,
    #[serde(default)]
    pub auto_revert: bool,
    #[serde(default)]
    pub record: bool,

    // Integrated Network Actions (from SdkRule)
    #[serde(default)]
    pub traffic_attack: bool,
    #[serde(default)]
    pub change_packet: bool,
    #[serde(default)]
    pub change_data: Option<String>,
    #[serde(default)]
    pub solve_packet: bool,
    #[serde(default)]
    pub change_request_body: Option<String>,
    #[serde(default)]
    pub change_response_body: Option<String>,
    #[serde(default)]
    pub use_regex_replacement: bool,
    #[serde(default)]
    pub search_pattern: Option<String>,
}

impl ResponseAction {
    pub fn normalize_prompt_defaults(&mut self) {
        if self.ask_user {
            self.deny_while_ask = true;
            self.status_access_denied = true;
        }
    }
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
pub struct ApiArgument {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    File {
        op: String,
        path_pattern: String,
    },
    Registry {
        op: String,
        key_pattern: String,
        value_name: Option<String>,
        expected_data: Option<String>,
    },
    Process {
        op: String,
        pattern: String,
    },
    Service {
        op: String,
        name_pattern: String,
    },
    Network {
        op: String,
        dest_pattern: Option<String>,
    },
    NetworkCondition(NetworkRuleCondition),
    Api {
        #[serde(default, alias = "name_pattern")]
        functions: Vec<String>,
        #[serde(default)]
        arguments: Vec<ApiArgument>,
        #[serde(default)]
        module_pattern: String,
    },
    Heuristic {
        metric: String,
        threshold: f64,
    },
    OperationCount {
        #[serde(alias = "operation")]
        op_type: String,
        #[serde(default)]
        path_pattern: Option<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },
    ExtensionPattern {
        patterns: Vec<String>,
        #[serde(default)]
        match_mode: MatchMode,
        op_type: String,
    },
    ByteThreshold {
        direction: String,
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },
    EntropyThreshold {
        metric: String,
        #[serde(default)]
        comparison: Comparison,
        threshold: f64,
    },
    FileCount {
        category: String,
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },
    Signature {
        #[serde(default)]
        is_trusted: Option<bool>,
        #[serde(default)]
        is_signed: Option<bool>,
        #[serde(default)]
        signer_pattern: Option<String>,
        #[serde(default)]
        signer_patterns: Vec<String>,
        #[serde(default)]
        signature_status: Option<String>,
        #[serde(default)]
        signature_statuses: Vec<String>,
        #[serde(default)]
        verification_failed: Option<bool>,
        #[serde(default)]
        no_signature: Option<bool>,
        #[serde(default)]
        signature_status_issues: Option<bool>,
        #[serde(default)]
        invalid_signature: Option<bool>,
        #[serde(default)]
        raw_hresult: Option<u32>,
        #[serde(default)]
        raw_hresults: Vec<u32>,
        #[serde(default)]
        status_text_pattern: Option<String>,
    },
    DirectorySpread {
        category: String,
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },
    DriveActivity {
        drive_type: String,
        op_type: String,
        #[serde(default)]
        comparison: Comparison,
        threshold: u32,
    },
    ProcessAncestry {
        ancestor_pattern: String,
        #[serde(default)]
        max_depth: Option<u32>,
    },
    ExtensionRatio {
        extensions: Vec<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: f32,
    },
    RateOfChange {
        metric: String,
        #[serde(default)]
        comparison: Comparison,
        threshold: f64,
    },
    SelfModification {
        modification_type: String,
    },
    CommandLineMatch {
        patterns: Vec<CommandLinePattern>,
        #[serde(default)]
        match_mode: MatchMode,
    },
    ProcessTree {
        #[serde(default)]
        parent_patterns: Vec<String>,
        #[serde(default)]
        child_patterns: Vec<String>,
        #[serde(default)]
        ancestor_patterns: Vec<String>,
        #[serde(default)]
        command_line_patterns: Vec<CommandLinePattern>,
        #[serde(default)]
        max_depth: Option<u32>,
        #[serde(default)]
        require_current_process: bool,
    },
    MultiCondition {
        conditions: Vec<RuleCondition>,
        #[serde(default)]
        operator: Option<String>,
        #[serde(default)]
        min_matches: Option<usize>,
        #[serde(default)]
        within_ms: Option<u64>,
        #[serde(default)]
        require_same_source_pid: bool,
    },
    SensitivePathAccess {
        patterns: Vec<String>,
        op_type: String,
        #[serde(default)]
        min_unique_paths: Option<u32>,
    },
    ClusterPattern {
        #[serde(default)]
        min_clusters: Option<usize>,
        #[serde(default)]
        max_clusters: Option<usize>,
    },
    TempDirectoryWrite {
        #[serde(default)]
        min_bytes: Option<u64>,
        #[serde(default)]
        min_files: Option<u32>,
    },
    ArchiveCreation {
        #[serde(default)]
        extensions: Vec<String>,
        #[serde(default)]
        min_size: Option<u64>,
        #[serde(default)]
        in_temp: bool,
    },
    DataExfiltrationPattern {
        source_patterns: Vec<String>,
        #[serde(default)]
        min_source_reads: Option<u32>,
        #[serde(default)]
        detect_temp_staging: bool,
        #[serde(default)]
        detect_archive: bool,
    },
    MemoryScan {
        #[serde(default)]
        patterns: Vec<String>,
        #[serde(default)]
        detect_pe_headers: bool,
        #[serde(default)]
        private_only: bool,
    },
    Amsi {
        #[serde(default)]
        risk_at_least: Option<String>,
        #[serde(default)]
        patterns: Vec<String>,
        #[serde(default)]
        cmdline_patterns: Vec<String>,
        #[serde(default)]
        source: Option<String>,
    },
    SanctumGhost {
        #[serde(default)]
        functions: Vec<String>,
        #[serde(default)]
        caller_address_patterns: Vec<String>,
        #[serde(default)]
        hex_patterns: Vec<String>,
        #[serde(default)]
        min_matches: usize,
    },
    /// Matches kernel-level hook, injection, and rootkit events from the
    /// Owlyshield driver (Communication.cpp). Covers IRP_USERMODE_HOOK_EVENT,
    /// IRP_KERNEL_* (remote thread, write/protect/create memory, queue APC,
    /// create/map section) and IRP_ROOTKIT_* categories.
    ///
    /// YAML example:
    /// ```yaml
    /// - type: KernelHook
    ///   event_types: ["IRP_KERNEL_WRITE_MEMORY", "IRP_KERNEL_PROTECT_MEMORY"]
    ///   target_pattern: "lsass.exe"
    /// ```
    KernelHook {
        /// One or more IRP event type strings to match, e.g.
        /// "IRP_USERMODE_HOOK_EVENT", "IRP_KERNEL_REMOTE_THREAD",
        /// "IRP_KERNEL_WRITE_MEMORY", "IRP_KERNEL_PROTECT_MEMORY",
        /// "IRP_KERNEL_CREATE_THREAD", "IRP_KERNEL_QUEUE_APC",
        /// "IRP_KERNEL_CREATE_SECTION", "IRP_KERNEL_MAP_SECTION",
        /// "IRP_ROOTKIT_SSDT_HOOK", "IRP_ROOTKIT_HIDDEN_PROCESS",
        /// "IRP_ROOTKIT_HIDDEN_DRIVER", "IRP_ROOTKIT_KERNEL_HOOK",
        /// "IRP_ROOTKIT_TERMINATE_PROCESS", "IRP_ROOTKIT_FILE_MOVE",
        /// "IRP_ROOTKIT_GENERIC".
        /// Empty list matches any of the above categories.
        #[serde(default)]
        event_types: Vec<String>,
        /// Wildcard/regex pattern matched against the API or event function
        /// name (e.g. "NtWriteVirtualMemory"). Empty = any.
        #[serde(default)]
        function_pattern: Option<String>,
        /// Wildcard/regex pattern matched against the source process image
        /// name or path. Empty = any.
        #[serde(default)]
        source_pattern: Option<String>,
        /// Wildcard/regex pattern matched against the target process image
        /// name or path. Empty = any.
        #[serde(default)]
        target_pattern: Option<String>,
        /// Minimum number of matching events required to satisfy the condition.
        /// Defaults to 1.
        #[serde(default)]
        min_count: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub name: String,
    pub conditions: Vec<RuleCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetectionCondition {
    And {
        and: Vec<DetectionCondition>,
    },
    Or {
        or: Vec<DetectionCondition>,
    },
    Not {
        not: Box<DetectionCondition>,
    },
    Named {
        condition: String,
    },
    AllOf {
        all_of: Vec<String>,
    },
    AnyOf {
        any_of: Vec<String>,
    },
    NOf {
        n_of: usize,
        conditions: Vec<String>,
    },
    AtLeast {
        at_least: usize,
        conditions: Vec<String>,
    },
    AllOfPattern {
        all_of_pattern: String,
    },
    AnyOfPattern {
        any_of_pattern: String,
    },
    Count {
        count: Vec<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: usize,
    },
    Percentage {
        percentage: Vec<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: f32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleMapping {
    And { and: Vec<RuleMapping> },
    Or { or: Vec<RuleMapping> },
    Not { not: Box<RuleMapping> },
    Stage { stage: String },
}

/// Condition on a single ML feature value recorded when the fast static ML
/// engine (fast_detect_file) fired. All bounds are inclusive.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MlFeatureCondition {
    /// For boolean features (is_obfuscated, parse_success, is_likely_packed):
    /// expected value (feature == 1.0 for true, == 0.0 for false).
    #[serde(default)]
    pub is_true: Option<bool>,
    /// Minimum value (inclusive) for numeric features.
    #[serde(default)]
    pub min: Option<f64>,
    /// Maximum value (inclusive) for numeric features.
    #[serde(default)]
    pub max: Option<f64>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NamedConditionGroup {
    #[serde(default)]
    pub apis: Vec<String>,
    #[serde(default = "default_zero")]
    pub api_threshold: usize,
    #[serde(default)]
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub file_operations: Vec<String>,
    #[serde(default)]
    pub require_same_file_read: bool,
    #[serde(default)]
    pub require_same_file_write: bool,
    #[serde(default)]
    pub require_same_file_rename: bool,
    #[serde(default)]
    pub require_same_stem_created_unknown_extension: bool,
    #[serde(default)]
    pub require_same_stem_written_unknown_extension: bool,
    #[serde(default)]
    pub registry_keys: Vec<String>,
    #[serde(default)]
    pub registry_keys_exclude: Vec<String>,
    #[serde(default)]
    pub registry_values: Vec<String>,
    #[serde(default)]
    pub registry_operations: Vec<String>,
    #[serde(default)]
    pub registry_value_data_patterns: Vec<String>,
    #[serde(default)]
    pub pipe_names: Vec<String>,
    #[serde(default)]
    pub pipe_operations: Vec<String>, // "create", "write"
    #[serde(default, alias = "opsets", alias = "op_set", alias = "operation_sets")]
    pub irp_operations: Vec<String>,
    #[serde(default, alias = "opcodes", alias = "irp_ops")]
    pub irp_opcodes: Vec<u32>,
    #[serde(default)]
    pub pipe_payloads: Vec<ContentMatchData>,
    #[serde(default)]
    pub network_indicators: Vec<String>,
    #[serde(default)]
    pub has_network_activity: bool,
    #[serde(default)]
    pub network_rules: Vec<NetworkRuleCondition>,
    #[serde(default)]
    pub network_domains: Vec<String>,
    #[serde(default)]
    pub dns_query_patterns: Vec<String>,
    #[serde(default)]
    pub network_ips: Vec<String>,
    #[serde(default)]
    pub firewall_blocked: Option<bool>,
    #[serde(default)]
    pub firewall_dst_ips: Vec<String>,
    #[serde(default)]
    pub firewall_dst_ports: Vec<u16>,
    #[serde(default)]
    pub firewall_hostnames: Vec<String>,
    #[serde(default)]
    pub firewall_block_reasons: Vec<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub parent_names: Vec<String>,
    #[serde(default)]
    pub terminated_processes: Vec<String>,
    #[serde(default)]
    pub created_processes: Vec<String>,
    #[serde(default)]
    pub is_acg_enabled: Option<bool>,
    #[serde(default)]
    pub detect_recently_written_payload_launch: bool,
    #[serde(default)]
    pub detect_self_termination: bool,
    #[serde(default)]
    pub detect_parent_image_delete: bool,
    #[serde(default)]
    pub detect_parent_image_rename: bool,
    #[serde(default)]
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub detect_extension_changes: bool,
    #[serde(default)]
    pub detect_known_to_unknown_extension_change: bool,
    #[serde(default, alias = "extension_allowlist")]
    pub extension_whitelist: Vec<String>,
    #[serde(default, alias = "detect_non_allowlisted_extensions")]
    pub detect_non_whitelisted_extensions: bool,
    #[serde(default)]
    pub file_actions: Vec<String>,
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub file_size_min: Option<u64>,
    #[serde(default)]
    pub file_size_max: Option<u64>,
    #[serde(default)]
    pub cmdline_patterns: Vec<CommandLinePattern>,
    #[serde(default)]
    pub cmdline_keywords: Vec<String>,
    #[serde(default)]
    pub script_file_patterns: Vec<String>,
    #[serde(default)]
    pub staging_paths: Vec<String>,
    #[serde(default)]
    pub browsed_paths: Vec<String>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    #[serde(default)]
    pub temp_writes: bool,
    #[serde(default)]
    pub persistence_locations: Vec<String>,
    #[serde(default)]
    pub autorun_keys: Vec<String>,
    #[serde(default)]
    pub scheduled_task_apis: Vec<String>,
    #[serde(default)]
    pub obfuscation_indicators: Vec<String>,
    #[serde(default)]
    pub anti_debug_apis: Vec<String>,
    #[serde(default)]
    pub anti_vm_apis: Vec<String>,
    #[serde(default)]
    pub requires_signed: Option<bool>,
    #[serde(default)]
    pub is_signed: Option<bool>,
    #[serde(default)]
    pub is_valid_signed: Option<bool>,
    #[serde(default)]
    pub is_executable: Option<bool>,
    #[serde(default)]
    pub is_catalog_signed: Option<bool>,
    #[serde(default)]
    pub is_attached_signed: Option<bool>,
    #[serde(default)]
    pub cloud_verdict: Option<u8>,
    #[serde(default)]
    pub cloud_available: Option<bool>,
    #[serde(default)]
    pub cloud_unknown: Option<bool>,
    // Fast static ML engine conditions (fast_detect_file). `ml_detection`
    // matches a specific detection name ("MaliciousJsScript",
    // "MaliciousPeExecutable"); `ml_detected` matches on whether any ML
    // detection was recorded for the process; `ml_features` matches the actual
    // ML feature vector (feature name -> value, e.g. is_obfuscated, entropy,
    // suspicious_score) recorded when an ML detection fired.
    #[serde(default)]
    pub ml_detection: Option<String>,
    #[serde(default)]
    pub ml_detected: Option<bool>,
    #[serde(default)]
    pub ml_features: HashMap<String, MlFeatureCondition>,
    #[serde(default)]
    pub signature_status: Option<String>,
    #[serde(default)]
    pub signature_statuses: Vec<String>,
    #[serde(default)]
    pub signature_verification_failed: Option<bool>,
    #[serde(default)]
    pub signature_no_signature: Option<bool>,
    #[serde(default)]
    pub signature_status_issues: Option<bool>,
    #[serde(default)]
    pub signature_invalid: Option<bool>,
    #[serde(default)]
    pub signature_hresult: Option<u32>,
    #[serde(default)]
    pub signature_hresults: Vec<u32>,
    #[serde(default)]
    pub signature_status_text_pattern: Option<String>,
    #[serde(default)]
    pub signer_pattern: Option<String>,
    #[serde(default)]
    pub signer_patterns: Vec<String>,
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    #[serde(default)]
    pub untrusted_signers: Vec<String>,

    // Hook/user-mode API error telemetry conditions. These match non-success
    // operation_status values without counting them as successful API behavior.
    #[serde(default)]
    pub hook_error_statuses: Vec<u32>,
    #[serde(default)]
    pub hook_error_api_patterns: Vec<String>,
    #[serde(default)]
    pub hook_error_raw_event_types: Vec<u32>,
    #[serde(default)]
    pub hook_error_min_count: Option<usize>,
    #[serde(default)]
    pub hook_error_exclude_benign: bool,
    #[serde(default = "default_zero")]
    pub min_matches: usize,
    #[serde(default)]
    pub json_match: Option<JsonMatcher>,

    // Sanctum EDR conditions
    #[serde(default)]
    pub sanctum_injection_score_min: Option<f32>,
    #[serde(default)]
    pub sanctum_syscall_count_min: Option<usize>,
    #[serde(default)]
    pub sanctum_shellcode_detected: Option<bool>,
    #[serde(default)]
    pub sanctum_suspicious_hits: Vec<String>,
    #[serde(default)]
    pub sanctum_detected: Option<bool>,

    // Rootkit generic condition tracking
    #[serde(default)]
    pub rootkit_event_types: Vec<String>,
    #[serde(default)]
    pub rootkit_event_min_count: Option<usize>,
    #[serde(default)]
    pub rootkit_total_min: Option<usize>,
    #[serde(default)]
    pub rootkit_description_contains: Vec<String>,

    // Self-defense telemetry from OpenEDR/Owlyshield kernel sensors. These
    // conditions observe tamper attempts and leave blocking to rule response or
    // user decision.
    #[serde(default)]
    pub self_defense_attack_types: Vec<String>,
    #[serde(default)]
    pub self_defense_categories: Vec<String>,
    #[serde(default)]
    pub self_defense_operations: Vec<String>,
    #[serde(default)]
    pub self_defense_target_patterns: Vec<String>,
    #[serde(default)]
    pub self_defense_attacker_patterns: Vec<String>,
    #[serde(default)]
    pub self_defense_sources: Vec<String>,
    #[serde(default)]
    pub self_defense_actions: Vec<String>,
    #[serde(default)]
    pub self_defense_min_count: Option<usize>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    #[serde(default)]
    pub rule_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub severity_score: Option<u8>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub browsed_paths: Vec<String>,
    #[serde(default)]
    pub accessed_paths: Vec<String>,
    #[serde(default)]
    pub staging_paths: Vec<String>,
    #[serde(default = "default_zero")]
    pub multi_access_threshold: usize,
    #[serde(default)]
    pub require_internet: bool,
    #[serde(default)]
    pub monitored_apis: Vec<String>,
    #[serde(default)]
    pub file_actions: Vec<String>,
    #[serde(default)]
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub suspicious_parents: Vec<String>,
    #[serde(default)]
    pub terminated_processes: Vec<String>,
    #[serde(default)]
    pub detect_self_termination: bool,
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub conditions_percentage: f32,
    #[serde(default)]
    pub named_conditions: HashMap<String, NamedConditionGroup>,
    #[serde(default)]
    pub detection_logic: Option<DetectionCondition>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub should_trust_comodo_cloud: bool,
    #[serde(default)]
    pub stages: Vec<AttackStage>,
    #[serde(default)]
    pub mapping: Option<RuleMapping>,
    #[serde(default)]
    pub min_stages_satisfied: usize,
    #[serde(default = "default_severity")]
    pub severity: u8,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub status: RuleStatus,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub level: DetectionLevel,
    #[serde(default)]
    pub mitre_attack: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub false_positives: Vec<String>,
    #[serde(default)]
    pub logsource: Option<LogSource>,
    #[serde(default)]
    pub response: ResponseAction,
    #[serde(default)]
    pub allowlisted_apps: Vec<AllowlistEntry>,
    #[serde(default)]
    pub proximity_log_threshold: f32,
    #[serde(default)]
    pub record_on_start: Vec<String>,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub memory_scan_config: Option<MemoryScanConfig>,
    #[serde(default)]
    pub protected_paths: ProtectedPaths,
    #[serde(default)]
    pub network_whitelist: Option<IpMatcher>,

    // Firewall SDK YAML compatibility fields
    #[serde(default, rename = "protocol")]
    pub sdk_protocol: Option<RuleProtocol>,
    #[serde(default, rename = "action")]
    pub sdk_action: Option<FirewallSdkRuleAction>,
    #[serde(default, rename = "condition_logic")]
    pub sdk_condition_logic: Option<FirewallSdkConditionLogic>,
    #[serde(default, rename = "encoding")]
    pub sdk_encoding: Option<ContentEncoding>,
    #[serde(default, rename = "src_ip")]
    pub sdk_src_ip: Option<IpMatcher>,
    #[serde(default, rename = "dst_ip")]
    pub sdk_dst_ip: Option<IpMatcher>,
    #[serde(default, rename = "src_port")]
    pub sdk_src_port: Option<PortMatcher>,
    #[serde(default, rename = "dst_port")]
    pub sdk_dst_port: Option<PortMatcher>,
    #[serde(default, rename = "domain")]
    pub sdk_domain: Option<DomainMatcher>,
    #[serde(default, rename = "url")]
    pub sdk_url: Option<UrlMatcher>,
    #[serde(default, rename = "file_type")]
    pub sdk_file_type: Option<FirewallSdkFileTypeMatcher>,
    #[serde(default, rename = "regex")]
    pub sdk_regex: Option<RegexMatcher>,
    #[serde(default, rename = "localhost_type")]
    pub sdk_localhost_type: Option<LocalhostType>,
    #[serde(default, rename = "routine")]
    pub sdk_routine: Option<TrafficRoutine>,
    #[serde(default, rename = "conditions")]
    pub sdk_conditions: Vec<FirewallSdkCondition>,
    #[serde(default, rename = "change_data")]
    pub sdk_change_data: Option<String>,
    #[serde(default, rename = "change_request_body")]
    pub sdk_change_request_body: Option<String>,
    #[serde(default, rename = "change_response_body")]
    pub sdk_change_response_body: Option<String>,
    #[serde(default, rename = "http_request_body")]
    pub sdk_http_request_body: Option<Vec<String>>,
    #[serde(default, rename = "http_response_body")]
    pub sdk_http_response_body: Option<Vec<String>>,
    #[serde(default, rename = "use_regex_replacement")]
    pub sdk_use_regex_replacement: bool,
    #[serde(default, rename = "search_pattern")]
    pub sdk_search_pattern: Option<String>,
    #[serde(default, rename = "json_match")]
    pub sdk_json_match: Option<JsonMatcher>,

    // Integrated high-perf network matcher triggers
    #[serde(default)]
    pub http_request_body_patterns: Vec<String>,
    #[serde(default)]
    pub http_response_body_patterns: Vec<String>,
    #[serde(default)]
    pub private_rules: Option<YamlValue>,
    #[serde(default)]
    pub is_private: bool,
}

impl BehaviorRule {
    fn has_firewall_sdk_compat_fields(&self) -> bool {
        self.sdk_protocol.is_some()
            || self.sdk_action.is_some()
            || self.sdk_condition_logic.is_some()
            || self.sdk_encoding.is_some()
            || self.sdk_src_ip.is_some()
            || self.sdk_dst_ip.is_some()
            || self.sdk_src_port.is_some()
            || self.sdk_dst_port.is_some()
            || self.sdk_domain.is_some()
            || self.sdk_url.is_some()
            || self.sdk_file_type.is_some()
            || self.sdk_regex.is_some()
            || self.sdk_localhost_type.is_some()
            || self.sdk_routine.is_some()
            || !self.sdk_conditions.is_empty()
            || self.sdk_change_data.is_some()
            || self.sdk_change_request_body.is_some()
            || self.sdk_change_response_body.is_some()
            || self
                .sdk_http_request_body
                .as_ref()
                .is_some_and(|patterns| !patterns.is_empty())
            || self
                .sdk_http_response_body
                .as_ref()
                .is_some_and(|patterns| !patterns.is_empty())
            || self.sdk_use_regex_replacement
            || self.sdk_search_pattern.is_some()
            || self.sdk_json_match.is_some()
    }

    fn firewall_sdk_condition_logic(&self) -> FirewallSdkConditionLogic {
        self.sdk_condition_logic.clone().unwrap_or_default()
    }

    fn firewall_sdk_encoding(&self) -> ContentEncoding {
        self.sdk_encoding.clone().unwrap_or_default()
    }

    fn matches_firewall_sdk_packet(
        &self,
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        packet: &PacketInfo,
        payload: &[u8],
    ) -> bool {
        if !self.has_firewall_sdk_compat_fields() {
            return false;
        }

        let raw_payload_candidates = packet_payload_candidates(packet, payload);
        let decoded_payload_candidates =
            decoded_packet_payload_candidates(packet, payload, &self.firewall_sdk_encoding());
        let mut checks = vec![rule_protocol_matches(
            &self.sdk_protocol.clone().unwrap_or_default(),
            packet,
        )];

        if let Some(matcher) = &self.sdk_src_ip {
            checks.push(matcher.matches(packet.src_ip));
        }
        if let Some(matcher) = &self.sdk_dst_ip {
            checks.push(matcher.matches(packet.dst_ip));
        }
        if let Some(matcher) = &self.sdk_src_port {
            checks.push(matcher.matches(packet.src_port));
        }
        if let Some(matcher) = &self.sdk_dst_port {
            checks.push(matcher.matches(packet.dst_port));
        }
        if let Some(matcher) = &self.sdk_domain {
            checks.push(matcher.matches(packet.hostname.as_deref()));
        }
        if let Some(matcher) = &self.sdk_url {
            checks.push(matcher.matches(packet.full_url.as_deref()));
        }
        if let Some(matcher) = &self.sdk_file_type {
            checks.push(matcher.matches(packet.detected_file_type.as_deref()));
        }
        if let Some(matcher) = &self.sdk_regex {
            checks.push(
                decoded_payload_candidates
                    .iter()
                    .any(|candidate| matcher.matches(candidate)),
            );
        }
        if let Some(localhost_type) = &self.sdk_localhost_type {
            checks.push(if packet.outbound {
                localhost_type.matches(packet.dst_ip)
            } else {
                localhost_type.matches(packet.src_ip)
            });
        }
        if let Some(routine) = &self.sdk_routine {
            checks.push(routine.matches(packet));
        }
        for condition in &self.sdk_conditions {
            checks.push(
                decoded_payload_candidates
                    .iter()
                    .any(|candidate| condition.matches_packet(cache, packet, candidate)),
            );
        }
        if self.entropy_threshold > 0.0 {
            checks.push(packet.payload_entropy.unwrap_or(0.0) >= self.entropy_threshold);
        }
        if let Some(patterns) = &self.sdk_http_request_body
            && !patterns.is_empty()
        {
            let body = packet.http_request_body.as_deref().unwrap_or("");
            checks.push(patterns.iter().any(|pattern| body.contains(pattern)));
        }
        if let Some(patterns) = &self.sdk_http_response_body
            && !patterns.is_empty()
        {
            let body = packet.http_response_body.as_deref().unwrap_or("");
            checks.push(patterns.iter().any(|pattern| body.contains(pattern)));
        }
        if let Some(matcher) = &self.sdk_json_match {
            checks.push(
                raw_payload_candidates
                    .iter()
                    .any(|candidate| matcher.matches(candidate)),
            );
        }

        match self.firewall_sdk_condition_logic() {
            FirewallSdkConditionLogic::And => checks.into_iter().all(|matched| matched),
            FirewallSdkConditionLogic::Or => checks.into_iter().any(|matched| matched),
        }
    }

    fn normalize_firewall_sdk_compat(&mut self) {
        if !self.has_firewall_sdk_compat_fields() {
            return;
        }

        if let Some(patterns) = &self.sdk_http_request_body {
            for pattern in patterns {
                if !self.http_request_body_patterns.contains(pattern) {
                    self.http_request_body_patterns.push(pattern.clone());
                }
            }
        }
        if let Some(patterns) = &self.sdk_http_response_body {
            for pattern in patterns {
                if !self.http_response_body_patterns.contains(pattern) {
                    self.http_response_body_patterns.push(pattern.clone());
                }
            }
        }

        match self.sdk_action.clone().unwrap_or_default() {
            FirewallSdkRuleAction::TrafficAttack => {
                self.response.traffic_attack = true;
            }
            FirewallSdkRuleAction::Block => {
                self.response.status_access_denied = true;
            }
            FirewallSdkRuleAction::Allow => {}
            FirewallSdkRuleAction::Ask => {
                self.response.ask_user = true;
            }
            FirewallSdkRuleAction::Terminate => {
                self.response.terminate_process = true;
            }
            FirewallSdkRuleAction::Quarantine => {
                self.response.quarantine = true;
            }
            FirewallSdkRuleAction::KillAndRemove => {
                self.response.kill_and_remove = true;
            }
            FirewallSdkRuleAction::ChangePacket => {
                self.response.change_packet = true;
                if self.response.change_data.is_none() {
                    self.response.change_data = self.sdk_change_data.clone();
                }
            }
            FirewallSdkRuleAction::SolvePacket => {
                self.response.solve_packet = true;
            }
            FirewallSdkRuleAction::ChangeRequestBody => {
                if self.response.change_request_body.is_none() {
                    self.response.change_request_body = self.sdk_change_request_body.clone();
                }
                self.response.use_regex_replacement |= self.sdk_use_regex_replacement;
                if self.response.search_pattern.is_none() {
                    self.response.search_pattern = self.sdk_search_pattern.clone();
                }
            }
            FirewallSdkRuleAction::ChangeResponseBody => {
                if self.response.change_response_body.is_none() {
                    self.response.change_response_body = self.sdk_change_response_body.clone();
                }
                self.response.use_regex_replacement |= self.sdk_use_regex_replacement;
                if self.response.search_pattern.is_none() {
                    self.response.search_pattern = self.sdk_search_pattern.clone();
                }
            }
        }
    }

    pub fn apply_replacement(&self, body: &str) -> String {
        if !self.response.use_regex_replacement {
            if self.response.change_request_body.is_some() {
                return self
                    .response
                    .change_request_body
                    .clone()
                    .unwrap_or_else(|| body.to_string());
            } else if self.response.change_response_body.is_some() {
                return self
                    .response
                    .change_response_body
                    .clone()
                    .unwrap_or_else(|| body.to_string());
            }
            return body.to_string();
        }

        let Some(search) = &self.response.search_pattern else {
            return body.to_string();
        };
        let replace_with = self
            .response
            .change_request_body
            .as_deref()
            .or(self.response.change_response_body.as_deref())
            .unwrap_or("");

        if let Ok(re) = Regex::new(search) {
            re.replace_all(body, replace_with).into_owned()
        } else {
            body.to_string()
        }
    }

    pub fn matches_packet(
        &self,
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        packet: &PacketInfo,
        payload: &[u8],
    ) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(whitelist) = &self.network_whitelist {
            if whitelist.matches(packet.dst_ip) || whitelist.matches(packet.src_ip) {
                return false;
            }
        }

        if self.matches_firewall_sdk_packet(cache, packet, payload) {
            return true;
        }

        let payload_candidates = packet_payload_candidates(packet, payload);

        // Match top-level HTTP body patterns if MITM is active
        for pattern in &self.http_request_body_patterns {
            if packet
                .http_request_body
                .as_deref()
                .is_some_and(|body| matches_pattern(cache, pattern, body))
                || payload_candidates.iter().any(|candidate| {
                    matches_pattern(cache, pattern, &String::from_utf8_lossy(candidate))
                })
            {
                return true;
            }
        }

        for pattern in &self.http_response_body_patterns {
            if packet
                .http_response_body
                .as_deref()
                .is_some_and(|body| matches_pattern(cache, pattern, body))
                || payload_candidates.iter().any(|candidate| {
                    matches_pattern(cache, pattern, &String::from_utf8_lossy(candidate))
                })
            {
                return true;
            }
        }

        // Match against named conditions that contain network rules
        for cond_group in self.named_conditions.values() {
            if let Some(matcher) = &cond_group.json_match {
                if payload_candidates
                    .iter()
                    .any(|candidate| matcher.matches(candidate))
                {
                    return true;
                }
            }

            for net_cond in &cond_group.network_rules {
                if net_cond.matches_packet(cache, packet, payload) {
                    return true;
                }
            }

            // Match classic domain/IP indicators in named conditions
            for domain in &cond_group.network_domains {
                if packet
                    .hostname
                    .as_ref()
                    .map_or(false, |h| h.contains(domain))
                {
                    return true;
                }
            }
            for ip in &cond_group.network_ips {
                if packet.dst_ip.to_string().contains(ip) || packet.src_ip.to_string().contains(ip)
                {
                    return true;
                }
            }
        }

        false
    }

    pub fn finalize_rich_fields(&mut self) {
        if let Some(score) = self.severity_score {
            self.severity = score;
        }

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
                    NetworkRuleCondition::And(conds) | NetworkRuleCondition::Or(conds) => {
                        for cond in conds {
                            match cond {
                                NetworkRuleCondition::SrcIp(m) | NetworkRuleCondition::DstIp(m) => {
                                    expand_ip_matcher(m)
                                }
                                NetworkRuleCondition::Domain(m) => expand_domain_matcher(m),
                                NetworkRuleCondition::Url(m) => expand_url_matcher(m),
                                NetworkRuleCondition::Regex(m) => expand_regex_matcher(m),
                                NetworkRuleCondition::ContentMatch(m) => {
                                    expand_content_match_data(m)
                                }
                                NetworkRuleCondition::Routine(routine) => {
                                    expand_traffic_routine(routine)
                                }
                                NetworkRuleCondition::JsonMatch(matcher) => {
                                    expand_json_matcher(matcher)
                                }
                                _ => {}
                            }
                        }
                    }
                    NetworkRuleCondition::SrcIp(m) | NetworkRuleCondition::DstIp(m) => {
                        expand_ip_matcher(m)
                    }
                    NetworkRuleCondition::Domain(m) => expand_domain_matcher(m),
                    NetworkRuleCondition::Url(m) => expand_url_matcher(m),
                    NetworkRuleCondition::Regex(m) => expand_regex_matcher(m),
                    NetworkRuleCondition::ContentMatch(m) => expand_content_match_data(m),
                    NetworkRuleCondition::Routine(routine) => expand_traffic_routine(routine),
                    NetworkRuleCondition::JsonMatch(matcher) => expand_json_matcher(matcher),
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
                AllowlistEntry::Complex {
                    pattern, signers, ..
                } => {
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
            expand_vec(&mut cond_group.hook_error_api_patterns);
            expand_network_rules(&mut cond_group.network_rules);
            expand_vec(&mut cond_group.registry_value_data_patterns);
            expand_vec(&mut cond_group.dns_query_patterns);
            expand_vec(&mut cond_group.self_defense_attack_types);
            expand_vec(&mut cond_group.self_defense_categories);
            expand_vec(&mut cond_group.self_defense_operations);
            expand_vec(&mut cond_group.self_defense_target_patterns);
            expand_vec(&mut cond_group.self_defense_attacker_patterns);
            expand_vec(&mut cond_group.self_defense_sources);
            expand_vec(&mut cond_group.self_defense_actions);
        }

        for stage in &mut self.stages {
            for condition in &mut stage.conditions {
                match condition {
                    RuleCondition::File { path_pattern, .. } => {
                        *path_pattern = expand_environment_variables(path_pattern)
                    }
                    RuleCondition::Registry {
                        key_pattern,
                        value_name,
                        expected_data,
                        ..
                    } => {
                        *key_pattern = expand_environment_variables(key_pattern);
                        expand_opt_string(value_name);
                        expand_opt_string(expected_data);
                    }
                    RuleCondition::Process { pattern, .. } => {
                        *pattern = expand_environment_variables(pattern)
                    }
                    RuleCondition::Service { name_pattern, .. } => {
                        *name_pattern = expand_environment_variables(name_pattern)
                    }
                    RuleCondition::Network { dest_pattern, .. } => expand_opt_string(dest_pattern),
                    RuleCondition::Api {
                        functions,
                        module_pattern,
                        ..
                    } => {
                        for func in functions {
                            *func = expand_environment_variables(func);
                        }
                        *module_pattern = expand_environment_variables(module_pattern);
                    }
                    RuleCondition::OperationCount { path_pattern, .. } => {
                        expand_opt_string(path_pattern)
                    }
                    RuleCondition::ExtensionPattern { patterns, .. } => expand_vec(patterns),
                    RuleCondition::Signature { signer_pattern, .. } => {
                        expand_opt_string(signer_pattern)
                    }
                    RuleCondition::ProcessAncestry {
                        ancestor_pattern, ..
                    } => *ancestor_pattern = expand_environment_variables(ancestor_pattern),
                    RuleCondition::CommandLineMatch { patterns, .. } => {
                        expand_cmd_patterns(patterns)
                    }
                    RuleCondition::ProcessTree {
                        parent_patterns,
                        child_patterns,
                        ancestor_patterns,
                        command_line_patterns,
                        ..
                    } => {
                        expand_vec(parent_patterns);
                        expand_vec(child_patterns);
                        expand_vec(ancestor_patterns);
                        expand_cmd_patterns(command_line_patterns);
                    }
                    RuleCondition::MultiCondition { conditions, .. } => {
                        for subcondition in conditions {
                            match subcondition {
                                RuleCondition::File { path_pattern, .. } => {
                                    *path_pattern = expand_environment_variables(path_pattern)
                                }
                                RuleCondition::Registry {
                                    key_pattern,
                                    value_name,
                                    expected_data,
                                    ..
                                } => {
                                    *key_pattern = expand_environment_variables(key_pattern);
                                    expand_opt_string(value_name);
                                    expand_opt_string(expected_data);
                                }
                                RuleCondition::Process { pattern, .. } => {
                                    *pattern = expand_environment_variables(pattern)
                                }
                                RuleCondition::Service { name_pattern, .. } => {
                                    *name_pattern = expand_environment_variables(name_pattern)
                                }
                                RuleCondition::Network { dest_pattern, .. } => {
                                    expand_opt_string(dest_pattern)
                                }
                                RuleCondition::Api {
                                    functions,
                                    module_pattern,
                                    ..
                                } => {
                                    for func in functions.iter_mut() {
                                        *func = expand_environment_variables(func);
                                    }
                                    *module_pattern = expand_environment_variables(module_pattern);
                                }
                                RuleCondition::OperationCount { path_pattern, .. } => {
                                    expand_opt_string(path_pattern)
                                }
                                RuleCondition::ExtensionPattern { patterns, .. } => {
                                    expand_vec(patterns)
                                }
                                RuleCondition::Signature { signer_pattern, .. } => {
                                    expand_opt_string(signer_pattern)
                                }
                                RuleCondition::ProcessAncestry {
                                    ancestor_pattern, ..
                                } => {
                                    *ancestor_pattern =
                                        expand_environment_variables(ancestor_pattern)
                                }
                                RuleCondition::CommandLineMatch { patterns, .. } => {
                                    expand_cmd_patterns(patterns)
                                }
                                RuleCondition::ProcessTree {
                                    parent_patterns,
                                    child_patterns,
                                    ancestor_patterns,
                                    command_line_patterns,
                                    ..
                                } => {
                                    expand_vec(parent_patterns);
                                    expand_vec(child_patterns);
                                    expand_vec(ancestor_patterns);
                                    expand_cmd_patterns(command_line_patterns);
                                }
                                RuleCondition::SensitivePathAccess { patterns, .. } => {
                                    expand_vec(patterns)
                                }
                                RuleCondition::ArchiveCreation { extensions, .. } => {
                                    expand_vec(extensions)
                                }
                                RuleCondition::DataExfiltrationPattern {
                                    source_patterns, ..
                                } => expand_vec(source_patterns),
                                RuleCondition::MemoryScan { patterns, .. } => expand_vec(patterns),
                                RuleCondition::SanctumGhost {
                                    functions,
                                    caller_address_patterns,
                                    hex_patterns,
                                    ..
                                } => {
                                    expand_vec(functions);
                                    expand_vec(caller_address_patterns);
                                    expand_vec(hex_patterns);
                                }
                                _ => {}
                            }
                        }
                    }
                    RuleCondition::SensitivePathAccess { patterns, .. } => expand_vec(patterns),
                    RuleCondition::ArchiveCreation { extensions, .. } => expand_vec(extensions),
                    RuleCondition::DataExfiltrationPattern {
                        source_patterns, ..
                    } => expand_vec(source_patterns),
                    RuleCondition::MemoryScan { patterns, .. } => expand_vec(patterns),
                    RuleCondition::SanctumGhost {
                        functions,
                        caller_address_patterns,
                        hex_patterns,
                        ..
                    } => {
                        expand_vec(functions);
                        expand_vec(caller_address_patterns);
                        expand_vec(hex_patterns);
                    }
                    _ => {}
                }
            }
        }

        if let Some(msc) = &mut self.memory_scan_config {
            expand_vec(&mut msc.target_processes);
        }

        if let Some(matcher) = &mut self.sdk_src_ip {
            expand_ip_matcher(matcher);
        }
        if let Some(matcher) = &mut self.sdk_dst_ip {
            expand_ip_matcher(matcher);
        }
        if let Some(matcher) = &mut self.sdk_domain {
            expand_domain_matcher(matcher);
        }
        if let Some(matcher) = &mut self.sdk_url {
            expand_url_matcher(matcher);
        }
        if let Some(matcher) = &mut self.sdk_regex {
            expand_regex_matcher(matcher);
        }
        if let Some(routine) = &mut self.sdk_routine {
            expand_traffic_routine(routine);
        }
        if let Some(matcher) = &mut self.sdk_json_match {
            expand_json_matcher(matcher);
        }
        for condition in &mut self.sdk_conditions {
            match condition {
                FirewallSdkCondition::And(conds) | FirewallSdkCondition::Or(conds) => {
                    for cond in conds {
                        match cond {
                            FirewallSdkCondition::SrcIp(m) | FirewallSdkCondition::DstIp(m) => {
                                expand_ip_matcher(m)
                            }
                            FirewallSdkCondition::Domain(m) => expand_domain_matcher(m),
                            FirewallSdkCondition::Url(m) => expand_url_matcher(m),
                            FirewallSdkCondition::Regex(m) => expand_regex_matcher(m),
                            FirewallSdkCondition::ContentMatch(m) => expand_content_match_data(m),
                            FirewallSdkCondition::Routine(routine) => {
                                expand_traffic_routine(routine)
                            }
                            FirewallSdkCondition::JsonMatch(matcher) => {
                                expand_json_matcher(matcher)
                            }
                            _ => {}
                        }
                    }
                }
                FirewallSdkCondition::SrcIp(m) | FirewallSdkCondition::DstIp(m) => {
                    expand_ip_matcher(m)
                }
                FirewallSdkCondition::Domain(m) => expand_domain_matcher(m),
                FirewallSdkCondition::Url(m) => expand_url_matcher(m),
                FirewallSdkCondition::Regex(m) => expand_regex_matcher(m),
                FirewallSdkCondition::ContentMatch(m) => expand_content_match_data(m),
                FirewallSdkCondition::Routine(routine) => expand_traffic_routine(routine),
                FirewallSdkCondition::JsonMatch(matcher) => expand_json_matcher(matcher),
                _ => {}
            }
        }
        expand_opt_string(&mut self.sdk_change_data);
        expand_opt_string(&mut self.sdk_change_request_body);
        expand_opt_string(&mut self.sdk_change_response_body);
        expand_opt_string(&mut self.sdk_search_pattern);
        if let Some(patterns) = &mut self.sdk_http_request_body {
            expand_vec(patterns);
        }
        if let Some(patterns) = &mut self.sdk_http_response_body {
            expand_vec(patterns);
        }
        self.normalize_firewall_sdk_compat();
        self.response.normalize_prompt_defaults();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_packet() -> PacketInfo {
        PacketInfo {
            timestamp: 0,
            protocol: Protocol::TCP,
            src_ip: "10.0.0.10".parse().unwrap(),
            dst_ip: "149.154.167.220".parse().unwrap(),
            src_port: 49152,
            dst_port: 443,
            size: 256,
            outbound: true,
            process_id: 4242,
            dns_query: None,
            hostname: Some("api.telegram.org".to_string()),
            full_url: Some("https://api.telegram.org/bot123/sendMessage".to_string()),
            tls_handshake: true,
            http_method: Some("POST".to_string()),
            http_path: Some("/bot123/sendMessage".to_string()),
            http_user_agent: Some("UnitTest".to_string()),
            http_content_type: Some("application/json".to_string()),
            http_referer: None,
            payload_entropy: Some(6.2),
            payload_sample: None,
            payload_urls: Vec::new(),
            payload_domains: Vec::new(),
            image_path: "C:\\test.exe".to_string(),
            detected_file_type: None,
            http_request_body: Some("{\"chat_id\":\"12345\",\"text\":\"hello\"}".to_string()),
            http_response_body: None,
            domain: "api.telegram.org".to_string(),
            url: "https://api.telegram.org/bot123/sendMessage".to_string(),
        }
    }

    #[test]
    fn firewall_sdk_ask_rule_maps_to_owlyshield_response() {
        let yaml = r#"
name: Block Telegram Bots
description: Prevent Telegram bot exfiltration
enabled: true
protocol: https
action: ask
condition_logic: and
domain:
  domains:
    - api.telegram.org
  case_insensitive: true
url:
  patterns:
    - "*/bot*/sendMessage*"
json_match:
  key: chat_id
  value: ""
"#;

        let mut rule: BehaviorRule = serde_yaml::from_str(yaml).unwrap();
        rule.finalize_rich_fields();

        assert!(rule.response.ask_user);
        assert!(rule.response.deny_while_ask);
        assert!(rule.response.status_access_denied);
        assert!(rule.matches_packet(&Arc::new(RwLock::new(HashMap::new())), &test_packet(), &[],));
    }

    #[test]
    fn plain_ask_user_rule_defaults_to_deny_while_ask() {
        let yaml = r#"
name: Ask User Default
response:
  ask_user: true
"#;

        let mut rule: BehaviorRule = serde_yaml::from_str(yaml).unwrap();
        rule.finalize_rich_fields();

        assert!(rule.response.ask_user);
        assert!(rule.response.deny_while_ask);
        assert!(rule.response.status_access_denied);
        assert!(!rule.response.suspend_while_ask);
    }

    #[test]
    fn plain_ask_user_rule_keeps_explicit_suspend_while_ask() {
        let yaml = r#"
name: Ask User Suspend
response:
  ask_user: true
  suspend_while_ask: true
"#;

        let mut rule: BehaviorRule = serde_yaml::from_str(yaml).unwrap();
        rule.finalize_rich_fields();

        assert!(rule.response.ask_user);
        assert!(rule.response.deny_while_ask);
        assert!(rule.response.status_access_denied);
        assert!(rule.response.suspend_while_ask);
    }

    #[test]
    fn firewall_sdk_regex_uses_top_level_encoding() {
        let yaml = r#"
name: Detect Encoded PowerShell
enabled: true
protocol: http
action: traffic_attack
encoding: base64
regex:
  pattern: "powershell.*-enc"
  case_insensitive: true
"#;

        let mut rule: BehaviorRule = serde_yaml::from_str(yaml).unwrap();
        rule.finalize_rich_fields();

        let mut packet = test_packet();
        packet.dst_port = 80;
        packet.tls_handshake = false;
        packet.full_url = Some("http://example.test/upload".to_string());
        packet.hostname = Some("example.test".to_string());
        packet.http_request_body = None;
        packet.payload_sample =
            Some(base64::engine::general_purpose::STANDARD.encode("powershell -enc test"));

        assert!(rule.response.traffic_attack);
        assert!(rule.matches_packet(&Arc::new(RwLock::new(HashMap::new())), &packet, &[],));
    }

    #[test]
    fn hex_encoding_accepts_full_packet_capture_hexdump() {
        let payload = br#"
00000000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  48 6f 73 74 3a 20 65 76 69 6c 2e 65 78 61 6d 70  |Host: evil.examp|
00000020  6c 65 0d 0a 0d 0a                                |le....|
"#;

        let decoded = ContentEncoding::Hex.decode(payload).unwrap();
        let decoded_text = String::from_utf8_lossy(&decoded);

        assert!(decoded_text.contains("GET / HTTP/1.1"));
        assert!(decoded_text.contains("Host: evil.example"));
    }

    #[test]
    fn firewall_regex_matches_hex_packet_capture_payload_sample() {
        let yaml = r#"
name: Detect Hex Encoded Evil Host
enabled: true
protocol: http
regex:
  pattern: "Host:\\s*evil\\.example"
  case_insensitive: true
"#;

        let mut rule: BehaviorRule = serde_yaml::from_str(yaml).unwrap();
        rule.finalize_rich_fields();

        let mut packet = test_packet();
        packet.dst_port = 80;
        packet.tls_handshake = false;
        packet.full_url = Some("http://evil.example/".to_string());
        packet.hostname = Some("evil.example".to_string());
        packet.http_request_body = None;
        packet.payload_sample = Some(
            r#"
00000000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a
00000010  48 6f 73 74 3a 20 65 76 69 6c 2e 65 78 61 6d 70
00000020  6c 65 0d 0a 0d 0a
"#
            .to_string(),
        );

        assert!(rule.matches_packet(&Arc::new(RwLock::new(HashMap::new())), &packet, &[],));
    }

    #[test]
    fn detection_logic_count_accepts_lowercase_comparison() {
        let yaml = r#"
name: Rootkit MultiVector
named_conditions:
  ssdt_finding:
    rootkit_event_types: ["ssdt_hook"]
  driver_finding:
    rootkit_event_types: ["hidden_driver"]
detection_logic:
  count:
    - "ssdt_finding"
    - "driver_finding"
  comparison: gte
  threshold: 2
"#;

        let rule: BehaviorRule = serde_yaml::from_str(yaml).unwrap();
        let DetectionCondition::Count {
            count,
            comparison,
            threshold,
        } = rule.detection_logic.unwrap()
        else {
            panic!("expected count detection logic");
        };

        assert_eq!(
            count,
            vec!["ssdt_finding".to_string(), "driver_finding".to_string()]
        );
        assert_eq!(comparison, Comparison::Gte);
        assert_eq!(threshold, 2);
    }
}
