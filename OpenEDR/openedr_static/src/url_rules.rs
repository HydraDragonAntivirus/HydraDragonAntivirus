//! Rust YAML-driven URL Threat Inspection Engine.
//! Evaluates protocol schemes, pattern regexes (Discord/Telegram webhooks,
//! droppers, phishing keywords), BinaryFuse16 whitelist overrides,
//! PyFunceble-style liveness, and ML model outputs into a final verdict.
//!
//! The rule set is **not** compiled in: it is read from
//! `url_rules/url_threat_rules.yaml` next to the engine resources and can also be
//! pushed at runtime through `openedr_static_load_url_rules`. Adding a host to
//! `unwhitelist_subdomains`, or a rule id to `deterministic_rules`, needs no
//! rebuild.

use std::collections::HashSet;
use std::path::Path;
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

/// Directory under the engine resource root holding the rule documents.
pub const URL_RULES_DIR: &str = "url_rules";

/// File name of the rule document inside [`URL_RULES_DIR`].
pub const URL_RULES_FILE: &str = "url_threat_rules.yaml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRuleFile {
    pub rules: Vec<UrlRuleDef>,
    #[serde(default)]
    pub unwhitelist_subdomains: Vec<String>,
    /// Rule ids kept as data. Declared here so the Telegram / Discord-webhook
    /// ids have one place to live; the embedded-URL layer does not read them.
    #[serde(default)]
    pub deterministic_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRuleDef {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub score: u32,
    #[serde(default)]
    pub override_whitelist: bool,
    #[serde(default)]
    pub skip_if_whitelisted: bool,
    pub conditions: UrlConditionsDef,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UrlConditionsDef {
    pub url_regex: Option<String>,
    pub path_regex: Option<String>,
    pub query_regex: Option<String>,
    pub body_regex: Option<String>,
    pub host_regex: Option<String>,
    pub scheme: Option<Vec<String>>,
    pub ports: Option<Vec<u16>>,
    pub tlds: Option<Vec<String>>,
    pub is_ip: Option<bool>,
    pub cidr_blacklisted: Option<bool>,
    /// Liveness labels this rule applies to (OR term like the rest):
    /// active, potentially_up, potentially_down, inactive, unknown.
    pub liveness: Option<Vec<String>>,
    /// True when the client-supplied page and the server-fetched page produced
    /// different findings. Set by difference scanning, never by single scans.
    /// Verdict/severity/score come from the YAML rule itself.
    pub content_difference: Option<bool>,
    /// Minimum content difference percent (0-100) for this rule to apply.
    /// Only consulted alongside `content_difference`; lets YAML demand an
    /// extremely high difference before calling it suspicious.
    pub min_difference_percent: Option<u8>,
    /// When true, the rule applies only if both sources agree on the HTTP
    /// status code (a 403-bot-block vs 200 comparison is apples to oranges
    /// and must never become a finding). Declared in YAML, not hardcoded.
    pub require_equal_status: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CompiledUrlRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub score: u32,
    pub override_whitelist: bool,
    pub skip_if_whitelisted: bool,
    pub url_re: Option<Regex>,
    pub path_re: Option<Regex>,
    pub query_re: Option<Regex>,
    pub body_re: Option<Regex>,
    pub host_re: Option<Regex>,
    pub schemes: Option<Vec<String>>,
    pub ports: Option<Vec<u16>>,
    pub tlds: Option<Vec<String>>,
    pub is_ip: Option<bool>,
    pub cidr_blacklisted: Option<bool>,
    pub liveness: Option<Vec<String>>,
    pub content_difference: Option<bool>,
    pub min_difference_percent: Option<u8>,
    pub require_equal_status: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRuleHit {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub score: u32,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlThreatReport {
    pub target_url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub is_ip: bool,
    pub whitelisted: bool,
    pub whitelist_bypassed: bool,
    pub bypass_reason: Option<String>,
    pub liveness: String,
    pub ml_probability: f32,
    pub detections: Vec<UrlRuleHit>,
    pub risk_score: u32,
    pub verdict: String,
    pub verdict_reason: String,
    pub fp_mitigated: bool,
    pub content_scanned: bool,
    pub unwhitelisted_for_ml: bool,
}

#[derive(Debug, Default)]
pub struct UrlThreatEngine {
    rules: Vec<CompiledUrlRule>,
    unwhitelist_subdomains: HashSet<String>,
    deterministic_rules: HashSet<String>,
}

/// Decomposed URL, shared by [`UrlThreatEngine::inspect`] and
/// [`UrlThreatEngine::match_deterministic_rules`] so both see identical
/// scheme/host/path.
struct UrlParts {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    query: String,
    is_ip: bool,
}

/// Accepts both absolute URLs and bare `host/path` input (prepending `https://`
/// for the parse, then reporting `unknown` as the scheme when it was absent).
fn parse_parts(url_str: &str) -> UrlParts {
    let parsed = Url::parse(url_str).or_else(|_| Url::parse(&format!("https://{}", url_str)));
    match parsed {
        Ok(u) => {
            let scheme = u.scheme().to_lowercase();
            let host = u.host_str().unwrap_or("").to_lowercase();
            let port = u.port().unwrap_or(if scheme == "https" { 443 } else { 80 });
            let clean_host = host
                .strip_prefix('[')
                .and_then(|x| x.strip_suffix(']'))
                .unwrap_or(&host)
                .to_string();
            UrlParts {
                is_ip: clean_host.parse::<std::net::IpAddr>().is_ok(),
                scheme,
                host,
                port,
                path: u.path().to_string(),
                query: u.query().unwrap_or("").to_string(),
            }
        }
        Err(_) => {
            let host = url_str
                .split('/')
                .next()
                .unwrap_or("")
                .to_lowercase();
            let clean_host = host
                .strip_prefix('[')
                .and_then(|x| x.strip_suffix(']'))
                .unwrap_or(&host)
                .to_string();
            UrlParts {
                scheme: "unknown".to_string(),
                is_ip: clean_host.parse::<std::net::IpAddr>().is_ok(),
                host,
                port: 80,
                path: String::new(),
                query: String::new(),
            }
        }
    }
}

/// Evaluate every condition on `rule` and report whether any of them matched.
/// Each condition is an OR term — that is the rule set's own semantics.
fn rule_matches(
    rule: &CompiledUrlRule,
    url_str: &str,
    p: &UrlParts,
    is_cidr_blacklisted: bool,
    page_content: Option<&str>,
    content_different: bool,
    live_label: &str,
) -> bool {
    let mut matched = false;

    if let Some(ref re) = rule.url_re {
        if re.is_match(url_str) {
            matched = true;
        }
    }
    if let Some(ref re) = rule.host_re {
        if re.is_match(&p.host) {
            matched = true;
        }
    }
    if let Some(ref re) = rule.path_re {
        if re.is_match(&p.path) {
            matched = true;
        }
    }
    if let Some(ref re) = rule.query_re {
        if re.is_match(&p.query) {
            matched = true;
        }
    }
    if let Some(ref schemes) = rule.schemes {
        if schemes.contains(&p.scheme) {
            matched = true;
        }
    }
    if let Some(ref ports) = rule.ports {
        if ports.contains(&p.port) {
            matched = true;
        }
    }
    if let Some(ref tlds) = rule.tlds {
        if tlds.iter().any(|tld| p.host.ends_with(tld)) {
            matched = true;
        }
    }
    if let Some(expected_ip) = rule.is_ip {
        if expected_ip == p.is_ip {
            matched = true;
        }
    }
    if let Some(expected_bl) = rule.cidr_blacklisted {
        if expected_bl == is_cidr_blacklisted {
            matched = true;
        }
    }
    if let Some(ref re) = rule.body_re {
        if let Some(content) = page_content {
            if re.is_match(content) {
                matched = true;
            }
        }
    }
    if let Some(expected_diff) = rule.content_difference {
        if expected_diff == content_different {
            matched = true;
        }
    }
    if let Some(ref labels) = rule.liveness {
        if labels.iter().any(|l| l == live_label) {
            matched = true;
        }
    }

    matched
}

/// Compile one rule definition. Shared by the replacing loader and the merging
/// one so both accept exactly the same rules.
fn compile_rule(def: UrlRuleDef) -> Result<CompiledUrlRule, String> {
    let compile = |pat: &Option<String>| -> Result<Option<Regex>, String> {
        match pat {
            Some(pat) => Regex::new(pat).map(Some).map_err(|e| format!("Regex error in {}: {e}", def.id)),
            None => Ok(None),
        }
    };
    let url_re = compile(&def.conditions.url_regex)?;
    let path_re = compile(&def.conditions.path_regex)?;
    let query_re = compile(&def.conditions.query_regex)?;
    let body_re = compile(&def.conditions.body_regex)?;
    let host_re = compile(&def.conditions.host_regex)?;
    Ok(CompiledUrlRule {
        id: def.id,
        title: def.title,
        description: def.description,
        severity: def.severity,
        score: def.score,
        override_whitelist: def.override_whitelist,
        skip_if_whitelisted: def.skip_if_whitelisted,
        url_re,
        path_re,
        query_re,
        body_re,
        host_re,
        schemes: def.conditions.scheme.map(|v| v.into_iter().map(|s| s.to_lowercase()).collect()),
        ports: def.conditions.ports,
        tlds: def.conditions.tlds.map(|v| v.into_iter().map(|s| s.to_lowercase()).collect()),
        is_ip: def.conditions.is_ip,
        cidr_blacklisted: def.conditions.cidr_blacklisted,
        liveness: def.conditions.liveness.map(|v| v.into_iter().map(|s| s.to_lowercase()).collect()),
        content_difference: def.conditions.content_difference,
        min_difference_percent: def.conditions.min_difference_percent,
        require_equal_status: def.conditions.require_equal_status,
    })
}

/// True when the rule declares at least one condition. A rule with none can
/// never match (`rule_matches` ORs the declared terms), so an analyst rule
/// like that is a mistake, not a no-op.
fn has_condition(c: &UrlConditionsDef) -> bool {
    c.url_regex.is_some()
        || c.path_regex.is_some()
        || c.query_regex.is_some()
        || c.body_regex.is_some()
        || c.host_regex.is_some()
        || c.scheme.as_ref().is_some_and(|v| !v.is_empty())
        || c.ports.as_ref().is_some_and(|v| !v.is_empty())
        || c.tlds.as_ref().is_some_and(|v| !v.is_empty())
        || c.is_ip.is_some()
        || c.cidr_blacklisted.is_some()
        || c.liveness.as_ref().is_some_and(|v| !v.is_empty())
        || c.content_difference.is_some()
}

/// Parse and check an analyst URL rule document; see [`validate_url_rules_yaml`].
fn parse_analyst_url_rules(src: &str) -> Result<UrlRuleFile, String> {
    let file: UrlRuleFile = serde_yaml::from_str(src).map_err(|e| format!("YAML parse error: {e}"))?;
    if file.rules.is_empty() && file.unwhitelist_subdomains.is_empty() && file.deterministic_rules.is_empty() {
        return Err("document contains no rules".to_string());
    }
    let mut seen = HashSet::new();
    for (idx, def) in file.rules.iter().enumerate() {
        let id = def.id.trim();
        if id.is_empty() {
            return Err(format!("rule #{}: missing `id`", idx + 1));
        }
        if id != def.id {
            return Err(format!("rule {id}: `id` has leading/trailing whitespace"));
        }
        if !seen.insert(id.to_string()) {
            return Err(format!("rule {id}: duplicate `id`"));
        }
        if def.title.trim().is_empty() {
            return Err(format!("rule {id}: missing `title`"));
        }
        // The verdict engine compares severity with `==`, so "malicious" or
        // "High" would load and then silently never count. Exact spelling only.
        if def.severity != "Malicious" && def.severity != "Suspicious" {
            return Err(format!(
                "rule {id}: `severity` must be exactly \"Malicious\" or \"Suspicious\", got {:?}",
                def.severity
            ));
        }
        if def.score > 100 {
            return Err(format!("rule {id}: `score` must be 0-100, got {}", def.score));
        }
        if !has_condition(&def.conditions) {
            return Err(format!("rule {id}: needs at least one condition"));
        }
        compile_rule(def.clone())?;
    }
    Ok(file)
}

/// Validate an analyst URL rule document with the same strictness as
/// [`UrlThreatEngine::load_yaml`] (all required fields present, every regex
/// compiles) plus: non-empty unique `id`, non-empty `title`, `severity`
/// exactly `Malicious` or `Suspicious`, `score` 0-100 and at least one
/// condition. Returns the rule count.
pub fn validate_url_rules_yaml(src: &str) -> Result<usize, String> {
    parse_analyst_url_rules(src).map(|f| f.rules.len())
}

impl UrlThreatEngine {
    /// An empty engine: no rules, no unwhitelist set, no deterministic ids.
    /// Callers load the rule document from disk via [`Self::load_from_file`] or
    /// [`Self::load_yaml`]; nothing is baked into the binary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read and compile the rule document at `path`. Thin wrapper over
    /// [`Self::load_yaml`] so callers do not each repeat the `read_to_string`.
    /// Returns the compiled rule count.
    pub fn load_from_file(&mut self, path: &Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.load_yaml(&text)
    }

    pub fn load_yaml(&mut self, yaml_str: &str) -> Result<usize, String> {
        let file: UrlRuleFile = serde_yaml::from_str(yaml_str)
            .map_err(|e| format!("YAML parse error: {e}"))?;

        // Replace, not merge. The two host/id lists are additive on the Rust
        // side (they're sets), so without this a runtime reload through
        // `openedr_static_load_url_rules` could only ever add hosts — it could
        // never retire one that the previous document declared. Clear first so
        // the document is the single source of truth.
        self.unwhitelist_subdomains.clear();
        self.deterministic_rules.clear();

        for sub in file.unwhitelist_subdomains {
            let clean = sub.trim().to_lowercase();
            if !clean.is_empty() {
                self.unwhitelist_subdomains.insert(clean);
            }
        }

        // Rule ids are matched case-insensitively against the rule definitions,
        // so a typo in the id list is a silent no-op rather than a match
        // against the wrong rule.
        for id in file.deterministic_rules {
            let clean = id.trim().to_string();
            if !clean.is_empty() {
                self.deterministic_rules.insert(clean);
            }
        }

        let mut compiled = Vec::new();
        for def in file.rules {
            compiled.push(compile_rule(def)?);
        }
        let count = compiled.len();
        self.rules = compiled;
        Ok(count)
    }

    /// Merge an analyst rule document into the loaded set instead of replacing
    /// it (contrast [`Self::load_yaml`]): the shipped rules stay, a rule whose
    /// `id` already exists is replaced in place (keeping its evaluation order),
    /// new ids are appended, and `unwhitelist_subdomains` / `deterministic_rules`
    /// are added to the existing sets.
    ///
    /// Validated in full ([`validate_url_rules_yaml`]) and compiled before
    /// anything changes, so a bad document leaves the engine untouched.
    /// Returns the number of rules in the document.
    pub fn merge_yaml(&mut self, yaml_str: &str) -> Result<usize, String> {
        let file = parse_analyst_url_rules(yaml_str)?;
        let mut compiled = Vec::with_capacity(file.rules.len());
        for def in file.rules {
            compiled.push(compile_rule(def)?);
        }
        let count = compiled.len();
        for rule in compiled {
            match self.rules.iter_mut().find(|r| r.id == rule.id) {
                Some(existing) => *existing = rule,
                None => self.rules.push(rule),
            }
        }
        for sub in file.unwhitelist_subdomains {
            self.add_unwhitelisted_subdomain(&sub);
        }
        for id in file.deterministic_rules {
            let clean = id.trim().to_string();
            if !clean.is_empty() {
                self.deterministic_rules.insert(clean);
            }
        }
        Ok(count)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn is_unwhitelisted(&self, host: &str) -> bool {
        let clean = host.to_lowercase();
        if self.unwhitelist_subdomains.contains(&clean) {
            return true;
        }
        for unwh in &self.unwhitelist_subdomains {
            if unwh.starts_with("*.") {
                let suffix = &unwh[2..];
                if clean == suffix || clean.ends_with(&format!(".{}", suffix)) {
                    return true;
                }
            }
        }
        for rule in &self.rules {
            if rule.override_whitelist {
                if let Some(ref re) = rule.host_re {
                    if re.is_match(&clean) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn add_unwhitelisted_subdomain(&mut self, host: &str) {
        let clean = host.trim().to_lowercase();
        if !clean.is_empty() {
            self.unwhitelist_subdomains.insert(clean);
        }
    }

    /// Number of ids listed in `deterministic_rules`.
    pub fn deterministic_rule_count(&self) -> usize {
        self.deterministic_rules.len()
    }

    /// Number of hosts in `unwhitelist_subdomains`.
    pub fn unwhitelisted_count(&self) -> usize {
        self.unwhitelist_subdomains.len()
    }

/// Evaluate **only** the rules named in the rule document's
/// `deterministic_rules` list against `raw_url`, returning the ids that matched,
/// in rule-set order.
///
/// Which rules those are is decided by data, not code: adding a Telegram or
/// webhook pattern here means editing the YAML, not this file. The list is
/// deliberately narrow — a URL carrying a bot token or a webhook id is a C2
/// endpoint whatever the rest of the string looks like, whereas the rest of the
/// rule set is tuned for a URL a person chose to visit and would fire on every
/// benign link inside a document.
///
/// Deliberately narrower than [`UrlThreatEngine::inspect`]: no page content, no
/// CIDR input, and `skip_if_whitelisted` is not consulted — the caller has
/// already decided the host is worth scoring.
pub fn match_deterministic_rules(&self, raw_url: &str) -> Vec<String> {
    if self.deterministic_rules.is_empty() {
        return Vec::new();
    }
    let url_str = raw_url.trim();
    let p = parse_parts(url_str);
    let mut hits = Vec::new();
    for rule in &self.rules {
        if !self
            .deterministic_rules
            .iter()
            .any(|id| id.eq_ignore_ascii_case(&rule.id))
        {
            continue;
        }
        // No page content and no CIDR input on this path: only the
        // url/host/path/query conditions can apply.
        if rule_matches(rule, url_str, &p, false, None, false, "unknown") {
            hits.push(rule.id.clone());
        }
    }
    hits
}

    /// Evaluate **only** rules carrying a `content_difference` condition, with the
    /// difference flag set. Called after two independent per-source scans disagree.
    /// Rules may additionally demand a minimum difference percent, so YAML can
    /// require an extremely high difference before judging. Severity, score and
    /// whitelist handling come from the YAML rule itself; this function only
    /// reports what the rules decided, each paired with its
    /// `override_whitelist` / `skip_if_whitelisted` flags for the caller to apply.
    pub fn match_difference_rules(
        &self,
        raw_url: &str,
        difference_percent: u8,
        client_status: Option<u16>,
        server_status: Option<u16>,
        liveness_code: i32,
    ) -> Vec<(UrlRuleHit, bool, bool)> {
        let url_str = raw_url.trim();
        let p = parse_parts(url_str);
        let live_label: &str = match liveness_code {
            1 => "active",
            2 => "inactive",
            3 => "potentially_up",
            4 => "potentially_down",
            _ => "unknown",
        };
        let mut hits = Vec::new();
        for rule in &self.rules {
            if rule.content_difference.is_none() {
                continue;
            }
            if let Some(min_pct) = rule.min_difference_percent {
                if difference_percent < min_pct {
                    continue;
                }
            }
            if rule.require_equal_status == Some(true) {
                let agreed = matches!((client_status, server_status), (Some(c), Some(s)) if s != 0 && c == s);
                if !agreed {
                    continue;
                }
            }
            if rule_matches(rule, url_str, &p, false, None, true, live_label) {
                hits.push((
                    UrlRuleHit {
                        rule_id: rule.id.clone(),
                        title: rule.title.clone(),
                        severity: rule.severity.clone(),
                        score: rule.score,
                        details: rule.description.clone(),
                    },
                    rule.override_whitelist,
                    rule.skip_if_whitelisted,
                ));
            }
        }
        hits
    }

/// Full inspection evaluating Rust YAML rules, whitelist, liveness and ML.
    /// liveness_code: 0 = unknown, 1 = active, 2 = inactive/dead
    pub fn inspect(
        &self,
        raw_url: &str,
        mut is_whitelisted: bool,
        is_cidr_blacklisted: bool,
        ml_prob: f32,
        liveness_code: i32,
        page_content: Option<&str>,
        content_different: bool,
    ) -> UrlThreatReport {
        let url_str = raw_url.trim();
        let p = parse_parts(url_str);
        let scheme = p.scheme.clone();
        let host = p.host.clone();
        let port = p.port;
        let is_ip = p.is_ip;
        let live_label: &str = match liveness_code {
            1 => "active",
            2 => "inactive",
            3 => "potentially_up",
            4 => "potentially_down",
            _ => "unknown",
        };

        let mut detections = Vec::new();
        let mut whitelist_bypassed = false;
        let mut bypass_reason = None;
        let mut unwhitelisted_for_ml = false;

        // Check unwhitelisted subdomain status
        if self.is_unwhitelisted(&host) {
            is_whitelisted = false;
            whitelist_bypassed = true;
            unwhitelisted_for_ml = true;
            bypass_reason = Some(format!("Host '{}' is unwhitelisted for ML inspection", host));
            detections.push(UrlRuleHit {
                rule_id: "UNWHITELISTED_SUBDOMAIN".to_string(),
                title: "Unwhitelisted for ML".to_string(),
                severity: "Informational".to_string(),
                score: 15,
                details: format!("Host '{}' is excluded from global whitelist to allow ML model classification.", host),
            });
        }

        // Evaluate all compiled YAML rules
        for rule in &self.rules {
            if rule.skip_if_whitelisted && is_whitelisted {
                continue;
            }

            if rule_matches(rule, url_str, &p, is_cidr_blacklisted, page_content, content_different, live_label) {
                if rule.override_whitelist && is_whitelisted {
                    is_whitelisted = false;
                    whitelist_bypassed = true;
                    bypass_reason = Some(format!("Whitelist overridden by threat rule {}", rule.id));
                }

                detections.push(UrlRuleHit {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity.clone(),
                    score: rule.score,
                    details: rule.description.clone(),
                });
            }
        }

        // Include ML model detection if high
        if ml_prob >= 0.50 {
            let score = (ml_prob * 100.0).round() as u32;
            detections.push(UrlRuleHit {
                rule_id: "LIGHTGBM_URL_MODEL".to_string(),
                title: "LightGBM URL Classification".to_string(),
                severity: if ml_prob >= 0.90 { "Malicious".to_string() } else { "Suspicious".to_string() },
                score,
                details: format!("Machine learning model malicious probability: {:.1}%", ml_prob * 100.0),
            });
        }

        // ==========================================
        // FINAL VERDICT RULE ENGINE
        // ==========================================
        let liveness_str = live_label.to_uppercase();

        let mut verdict;
        let mut risk_score;
        let mut verdict_reason;
        let fp_mitigated = false;

        let has_malicious_rule = detections.iter().any(|d| d.severity == "Malicious");
        // The model's own hit (pushed above as Suspicious for 0.50-0.90) is not a rule:
        // counting it made every mid-range ML score Suspicious, against the policy below.
        let has_suspicious_rule = detections.iter().any(|d| d.severity == "Suspicious" && d.rule_id != "LIGHTGBM_URL_MODEL");

        if has_malicious_rule && !is_whitelisted {
            verdict = "Malicious";
            risk_score = detections.iter().filter(|d| d.severity == "Malicious").map(|d| d.score).max().unwrap_or(90);
            verdict_reason = "Rule Decision (Malicious): Direct dropper payload, blacklisted CIDR, or critical threat pattern detected.".to_string();
        } else if is_whitelisted && !has_malicious_rule {
            verdict = "Clean";
            risk_score = 0;
            verdict_reason = "Whitelist Protection: Host matches Tranco 1M or benign CIDR subnet with no malicious override.".to_string();

        } else if ml_prob >= 0.90 {
            verdict = "Malicious";
            let max_score = detections.iter().map(|d| d.score).max().unwrap_or(80);
            risk_score = max_score.max((ml_prob * 100.0) as u32);
            verdict_reason = format!("ML Decision (Malicious): Machine learning model classified URL as high-confidence malicious ({:.1}%).", ml_prob * 100.0);
        } else if has_suspicious_rule {
            // Suspicious comes ONLY from YAML rule hits, never from the model
            // alone: mid-range ML noise without a supporting rule reports
            // Unknown instead (zero-FP policy).
            verdict = "Suspicious";
            let max_score = detections.iter().map(|d| d.score).max().unwrap_or(50);
            risk_score = max_score.max((ml_prob * 100.0) as u32);
            verdict_reason = format!("Rule Decision (Suspicious): Suspicious indicators detected ({risk_score}/100).");
        } else if ml_prob >= 0.50 {
            // Model alone, no rule hit: not enough to convict. Malicious only
            // above the high-confidence bar; mid-range model noise reports
            // Unknown instead of Suspicious (zero-FP policy).
            verdict = "Unknown";
            risk_score = (ml_prob * 100.0) as u32;
            verdict_reason = format!("Analysis Result (Unknown): Elevated model score ({:.1}%) with no supporting rule hit; not judged suspicious.", ml_prob * 100.0);
        } else if unwhitelisted_for_ml {
            verdict = "Unknown";
            risk_score = (ml_prob * 100.0) as u32;
            verdict_reason = format!("Analysis Result (Unknown): No malicious indicators detected, but domain is not in global verified whitelist (ML prob: {:.1}%).", ml_prob * 100.0);
        } else if !is_whitelisted {
            verdict = "Unknown";
            risk_score = 0;
            verdict_reason = "Analysis Result (Unknown): No malicious indicators detected, but domain is unverified / not in global whitelist.".to_string();
        } else {
            verdict = "Clean";
            risk_score = 0;
            verdict_reason = "Analysis Result (Clean): Whitelist verified benign domain with no threat indicators.".to_string();
        }

        // Safety net: Unknown must never stick to a whitelisted host.
        // If no malicious/suspicious/ML signal fired and the host is still
        // whitelisted at this point, report Clean instead of Unknown.
        if verdict == "Unknown" && is_whitelisted {
            verdict = "Clean";
            risk_score = 0;
            verdict_reason = "Whitelist Protection: Host matches Tranco 1M or benign CIDR subnet with no malicious override.".to_string();
        }

        UrlThreatReport {
            target_url: url_str.to_string(),
            scheme,
            host,
            port,
            is_ip,
            whitelisted: is_whitelisted,
            whitelist_bypassed,
            bypass_reason,
            liveness: liveness_str.to_string(),
            ml_probability: ml_prob,
            detections,
            risk_score,
            verdict: verdict.to_string(),
            verdict_reason,
            fp_mitigated,
            content_scanned: page_content.is_some(),
            unwhitelisted_for_ml,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: &str = r#"
rules:
  - id: SHIPPED_1
    title: "Shipped"
    description: "shipped rule"
    severity: Suspicious
    score: 40
    conditions:
      tlds: [".zip"]
unwhitelist_subdomains: ["a.example.com"]
"#;

    const ANALYST: &str = r#"
rules:
  - id: SHIPPED_1
    title: "Shipped, tightened"
    description: "analyst override"
    severity: Malicious
    score: 90
    conditions:
      tlds: [".zip"]
  - id: ANALYST_1
    title: "Paste site payload"
    description: "raw paste download"
    severity: Malicious
    score: 85
    conditions:
      url_regex: '(?i)pastebin\.com/raw/'
unwhitelist_subdomains: ["b.example.com"]
"#;

    #[test]
    fn validate_url_rules_accepts_valid_document() {
        assert_eq!(validate_url_rules_yaml(ANALYST), Ok(2));
    }

    #[test]
    fn validate_url_rules_rejects_bad_rules() {
        let bad_sev = "rules:\n  - id: X\n    title: T\n    description: d\n    severity: malicious\n    score: 50\n    conditions:\n      tlds: [\".x\"]\n";
        assert!(validate_url_rules_yaml(bad_sev).unwrap_err().contains("severity"));
        let bad_re = "rules:\n  - id: X\n    title: T\n    description: d\n    severity: Malicious\n    score: 50\n    conditions:\n      url_regex: \"(\"\n";
        assert!(validate_url_rules_yaml(bad_re).unwrap_err().contains("Regex error in X"));
        let no_cond = "rules:\n  - id: X\n    title: T\n    description: d\n    severity: Malicious\n    score: 50\n    conditions: {}\n";
        assert!(validate_url_rules_yaml(no_cond).unwrap_err().contains("condition"));
        let missing_score = "rules:\n  - id: X\n    title: T\n    description: d\n    severity: Malicious\n    conditions:\n      tlds: [\".x\"]\n";
        assert!(validate_url_rules_yaml(missing_score).is_err());
    }

    #[test]
    fn merge_yaml_keeps_shipped_and_replaces_by_id() {
        let mut e = UrlThreatEngine::new();
        assert_eq!(e.load_yaml(SHIPPED), Ok(1));
        assert_eq!(e.merge_yaml(ANALYST), Ok(2));
        assert_eq!(e.rule_count(), 2);
        assert!(e.is_unwhitelisted("a.example.com") && e.is_unwhitelisted("b.example.com"));
        let r = e.inspect("https://x.zip/", false, false, 0.0, 0, None, false);
        assert!(r.detections.iter().any(|d| d.rule_id == "SHIPPED_1" && d.severity == "Malicious"));
        // A rejected document changes nothing.
        assert!(e.merge_yaml("rules: [{id: Z, title: T, description: d, severity: High, score: 1, conditions: {is_ip: true}}]").is_err());
        assert_eq!(e.rule_count(), 2);
    }
}
