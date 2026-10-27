//! URL threat list: every URL a scan found malicious or suspicious, with when and how
//! often it was seen. Threat insights only hold files (SHA-256); URL scans went to the
//! live event feed alone (the last 2000 events, shared with file scans), so a URL threat
//! was gone from the dashboard after a busy hour.
//!
//! `url_insights.jsonl` (next to the executable) gets the whole entry again at each
//! sighting; at start the last line of a URL wins. A listed URL is updated by every later
//! scan, so one that turns clean shows as clean instead of keeping the old verdict. Clean
//! URLs that were never a threat are not stored: a line per clean page visit would grow
//! without bound.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

const FILE: &str = "url_insights.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlInsight {
    pub url: String,
    pub host: String,
    /// Engine verdict, lower case: malicious, suspicious, unknown, clean.
    pub verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub score: u32,
    /// ACTIVE, INACTIVE, POTENTIALLY_UP, ... at the last scan.
    #[serde(default)]
    pub liveness: String,
    pub first_seen: String,
    pub last_seen: String,
    pub seen_count: u64,
}

fn path() -> PathBuf {
    crate::config::app_dir().join(FILE)
}

fn map() -> &'static RwLock<HashMap<String, UrlInsight>> {
    static MAP: OnceLock<RwLock<HashMap<String, UrlInsight>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        if let Ok(f) = std::fs::File::open(path()) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(i) = serde_json::from_str::<UrlInsight>(&line) {
                    m.insert(i.url.clone(), i);
                }
            }
        }
        RwLock::new(m)
    })
}

fn is_threat(verdict: &str) -> bool {
    matches!(verdict, "malicious" | "suspicious")
}

/// One URL scan result. Not on the archive server (it only mirrors) and not in tests.
pub fn record(url: &str, host: &str, verdict: &str, threat: Option<&str>, reason: &str, score: u32, liveness: &str) {
    if cfg!(test) || crate::config::is_archive() {
        return;
    }
    let verdict = verdict.to_ascii_lowercase();
    let now = chrono::Utc::now().to_rfc3339();
    let entry = {
        let mut m = map().write().unwrap();
        if !is_threat(&verdict) && !m.contains_key(url) {
            return;
        }
        let e = m.entry(url.to_string()).or_insert_with(|| UrlInsight {
            url: url.to_string(),
            host: host.to_string(),
            verdict: String::new(),
            threat: None,
            reason: String::new(),
            score: 0,
            liveness: String::new(),
            first_seen: now.clone(),
            last_seen: String::new(),
            seen_count: 0,
        });
        e.verdict = verdict;
        e.threat = threat.map(str::to_string);
        e.reason = reason.to_string();
        e.score = score;
        e.liveness = liveness.to_string();
        e.last_seen = now;
        e.seen_count += 1;
        e.clone()
    };
    if let Ok(line) = serde_json::to_string(&entry) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path()) {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Counts per verdict and the URLs matching `query` (URL, host or threat name, any case)
/// and `verdict` ("" or "threat" = malicious + suspicious, "all", or one verdict), most
/// recently seen first, at most `limit`.
pub fn list(query: &str, verdict: &str, limit: usize) -> serde_json::Value {
    let m = map().read().unwrap();
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for i in m.values() {
        *counts.entry(i.verdict.as_str()).or_default() += 1;
    }
    let q = query.trim().to_lowercase();
    let mut items: Vec<&UrlInsight> = m
        .values()
        .filter(|i| match verdict {
            "" | "threat" => is_threat(&i.verdict),
            "all" => true,
            v => i.verdict == v,
        })
        .filter(|i| {
            q.is_empty()
                || i.url.to_lowercase().contains(&q)
                || i.host.to_lowercase().contains(&q)
                || i.threat.as_deref().is_some_and(|t| t.to_lowercase().contains(&q))
        })
        .collect();
    let matched = items.len();
    items.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    items.truncate(limit);
    serde_json::json!({
        "ok": true,
        "total": m.len(),
        "counts": counts,
        "matched": matched,
        "items": items,
    })
}
