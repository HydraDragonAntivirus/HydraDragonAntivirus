//! Rust YAML-driven URL Threat Inspection Engine.
//! Evaluates protocol schemes, pattern regexes (Discord/Telegram webhooks,
//! droppers, phishing keywords), BinaryFuse16 whitelist overrides,
//! PyFunceble-style liveness, and ML model outputs into a final verdict.

use std::collections::HashSet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

pub const DEFAULT_URL_RULES_YAML: &str = include_str!("url_threat_rules.yaml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRuleFile {
    pub rules: Vec<UrlRuleDef>,
    #[serde(default)]
    pub unwhitelist_subdomains: Vec<String>,
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
}

impl UrlThreatEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            unwhitelist_subdomains: HashSet::new(),
        };
        let _ = engine.load_yaml(DEFAULT_URL_RULES_YAML);
        engine
    }

    pub fn load_yaml(&mut self, yaml_str: &str) -> Result<usize, String> {
        let file: UrlRuleFile = serde_yaml::from_str(yaml_str)
            .map_err(|e| format!("YAML parse error: {e}"))?;

        for sub in file.unwhitelist_subdomains {
            let clean = sub.trim().to_lowercase();
            if !clean.is_empty() {
                self.unwhitelist_subdomains.insert(clean);
            }
        }

        let mut compiled = Vec::new();
        for def in file.rules {
            let url_re = match def.conditions.url_regex {
                Some(ref pat) => Some(Regex::new(pat).map_err(|e| format!("Regex error in {}: {e}", def.id))?),
                None => None,
            };
            let path_re = match def.conditions.path_regex {
                Some(ref pat) => Some(Regex::new(pat).map_err(|e| format!("Regex error in {}: {e}", def.id))?),
                None => None,
            };
            let query_re = match def.conditions.query_regex {
                Some(ref pat) => Some(Regex::new(pat).map_err(|e| format!("Regex error in {}: {e}", def.id))?),
                None => None,
            };
            let body_re = match def.conditions.body_regex {
                Some(ref pat) => Some(Regex::new(pat).map_err(|e| format!("Regex error in {}: {e}", def.id))?),
                None => None,
            };
            let host_re = match def.conditions.host_regex {
                Some(ref pat) => Some(Regex::new(pat).map_err(|e| format!("Regex error in {}: {e}", def.id))?),
                None => None,
            };
            compiled.push(CompiledUrlRule {
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
            });
        }
        let count = compiled.len();
        self.rules = compiled;
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

    pub fn should_override_whitelist(&self, raw_url: &str, host: &str) -> bool {
        if self.is_unwhitelisted(host) {
            return true;
        }
        for rule in &self.rules {
            if rule.override_whitelist {
                if let Some(ref re) = rule.url_re {
                    if re.is_match(raw_url) {
                        return true;
                    }
                }
                if let Some(ref re) = rule.host_re {
                    if re.is_match(host) {
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
    ) -> UrlThreatReport {
        let url_str = raw_url.trim();
        let parsed = Url::parse(url_str).or_else(|_| {
            Url::parse(&format!("https://{}", url_str))
        });

        let (scheme, host, port, path, query, is_ip) = match parsed {
            Ok(ref u) => {
                let s = u.scheme().to_lowercase();
                let h = u.host_str().unwrap_or("").to_lowercase();
                let p = u.port().unwrap_or(if s == "https" { 443 } else { 80 });
                let path = u.path().to_string();
                let q = u.query().unwrap_or("").to_string();
                let clean_h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(&h);
                let is_ip = clean_h.parse::<std::net::IpAddr>().is_ok();
                (s, h, p, path, q, is_ip)
            }
            Err(_) => {
                let parts: Vec<&str> = url_str.split('/').collect();
                let h = parts.get(0).copied().unwrap_or("").to_lowercase();
                let clean_h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(&h);
                let is_ip = clean_h.parse::<std::net::IpAddr>().is_ok();
                ("unknown".to_string(), h, 80, "".to_string(), "".to_string(), is_ip)
            }
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

            let mut matched = false;

            if let Some(ref re) = rule.url_re {
                if re.is_match(url_str) {
                    matched = true;
                }
            }

            if let Some(ref re) = rule.host_re {
                if re.is_match(&host) {
                    matched = true;
                }
            }

            if let Some(ref re) = rule.path_re {
                if re.is_match(&path) {
                    matched = true;
                }
            }

            if let Some(ref re) = rule.query_re {
                if re.is_match(&query) {
                    matched = true;
                }
            }

            if let Some(ref schemes) = rule.schemes {
                if schemes.contains(&scheme) {
                    matched = true;
                }
            }

            if let Some(ref ports) = rule.ports {
                if ports.contains(&port) {
                    matched = true;
                }
            }

            if let Some(ref tlds) = rule.tlds {
                if tlds.iter().any(|tld| host.ends_with(tld)) {
                    matched = true;
                }
            }

            if let Some(expected_ip) = rule.is_ip {
                if expected_ip == is_ip {
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

            if matched {
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
                severity: if ml_prob >= 0.80 { "Malicious".to_string() } else { "Suspicious".to_string() },
                score,
                details: format!("Machine learning model malicious probability: {:.1}%", ml_prob * 100.0),
            });
        }

        // ==========================================
        // FINAL VERDICT RULE ENGINE
        // ==========================================
        let liveness_str = match liveness_code {
            1 => "ACTIVE",
            2 => "INACTIVE",
            _ => "UNKNOWN",
        };

        let verdict;
        let risk_score;
        let verdict_reason;
        let mut fp_mitigated = false;

        let has_malicious_rule = detections.iter().any(|d| d.severity == "Malicious");
        let has_webhook_c2 = detections.iter().any(|d| d.rule_id == "DISCORD_WEBHOOK_ABUSE" || d.rule_id == "TELEGRAM_BOT_API_ABUSE");
        let has_suspicious_rule = detections.iter().any(|d| d.severity == "Suspicious");

        if has_malicious_rule && !is_whitelisted {
            verdict = "Malicious";
            risk_score = detections.iter().filter(|d| d.severity == "Malicious").map(|d| d.score).max().unwrap_or(90);
            verdict_reason = "Rule Decision (Malicious): Direct dropper payload, blacklisted CIDR, or critical threat pattern detected.".to_string();
        } else if has_webhook_c2 {
            verdict = "Suspicious";
            risk_score = 75;
            verdict_reason = "Rule Decision (Suspicious): Discord Webhook or Telegram Bot API endpoint detected. Flagged as suspicious due to high C2 / stealer exfiltration abuse risk.".to_string();
        } else if is_whitelisted && !has_malicious_rule {
            verdict = "Clean";
            risk_score = 0;
            verdict_reason = "Whitelist Protection: Host matches Tranco 1M or benign CIDR subnet with no malicious override.".to_string();
        } else if liveness_code == 2 && !has_malicious_rule {
            verdict = "Clean";
            risk_score = 10;
            fp_mitigated = true;
            verdict_reason = "Liveness Protection: Domain is inactive / dead (NXDOMAIN). Score suppressed to mitigate false positive.".to_string();
        } else if ml_prob >= 0.80 {
            verdict = "Malicious";
            let max_score = detections.iter().map(|d| d.score).max().unwrap_or(80);
            risk_score = max_score.max((ml_prob * 100.0) as u32);
            verdict_reason = format!("ML Decision (Malicious): Machine learning model classified URL as high-confidence malicious ({:.1}%).", ml_prob * 100.0);
        } else if has_suspicious_rule || ml_prob >= 0.50 {
            verdict = "Suspicious";
            let max_score = detections.iter().map(|d| d.score).max().unwrap_or(50);
            risk_score = max_score.max((ml_prob * 100.0) as u32);
            verdict_reason = format!("Rule & ML Decision (Suspicious): Suspicious indicators or elevated ML risk score ({risk_score}/100) detected.");
        } else if unwhitelisted_for_ml {
            verdict = "Clean";
            risk_score = (ml_prob * 100.0) as u32;
            verdict_reason = format!("Analysis Result (Clean): No threat indicators detected (evaluated with ML model on unwhitelisted subdomain, prob: {:.1}%).", ml_prob * 100.0);
        } else {
            verdict = "Clean";
            risk_score = 0;
            verdict_reason = "Analysis Result (Clean): No threat indicators or suspicious patterns detected.".to_string();
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
