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
//!
//! An analyst can review a listed URL (malicious, suspicious or clean). The human
//! verdict is what the list counts and what a later scan of the URL answers; the
//! engine verdict is still kept and updated next to it.

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
    /// Analyst verdict (`human_review::VERDICTS`); wins over `verdict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_threat: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub human_note: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub analyst: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
}

impl UrlInsight {
    /// The human verdict when there is one, else the engine verdict.
    pub fn effective(&self) -> &str {
        self.human_verdict.as_deref().unwrap_or(&self.verdict)
    }
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
            human_verdict: None,
            human_threat: None,
            human_note: String::new(),
            analyst: String::new(),
            reviewed_at: None,
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
    append(&entry);
}

fn append(entry: &UrlInsight) {
    if let Ok(line) = serde_json::to_string(entry) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path()) {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Analyst verdict for a listed URL; an empty `verdict` removes the review (the engine
/// verdict applies again).
pub fn review(url: &str, verdict: &str, threat: Option<&str>, note: &str, analyst: &str) -> Result<UrlInsight, String> {
    let verdict = verdict.trim().to_ascii_lowercase();
    if !verdict.is_empty() && !crate::human_review::VERDICTS.contains(&verdict.as_str()) {
        return Err("verdict must be malicious, suspicious or clean".into());
    }
    let entry = {
        let mut m = map().write().unwrap();
        let e = m.get_mut(url.trim()).ok_or("URL is not in the list")?;
        if verdict.is_empty() {
            e.human_verdict = None;
            e.human_threat = None;
            e.human_note.clear();
            e.analyst.clear();
            e.reviewed_at = None;
        } else {
            e.human_threat = threat.map(str::trim).filter(|t| !t.is_empty() && verdict != "clean").map(str::to_string);
            e.human_verdict = Some(verdict);
            e.human_note = note.trim().to_string();
            e.analyst = analyst.trim().to_string();
            e.reviewed_at = Some(chrono::Utc::now().to_rfc3339());
        }
        e.clone()
    };
    if !cfg!(test) && !crate::config::is_archive() {
        append(&entry);
    }
    Ok(entry)
}

/// (verdict, threat, note) an analyst gave `url`, if any.
pub fn human(url: &str) -> Option<(String, Option<String>, String)> {
    let m = map().read().unwrap();
    let e = m.get(url)?;
    Some((e.human_verdict.clone()?, e.human_threat.clone(), e.human_note.clone()))
}

/// Counts per (human first) verdict and the URLs matching `query` (URL, host or threat
/// name, any case) and `verdict` ("" or "threat" = malicious + suspicious, "unreviewed" =
/// threats no analyst has answered, "reviewed", "all", or one verdict), most recently
/// seen first, at most `limit`.
pub fn list(query: &str, verdict: &str, limit: usize) -> serde_json::Value {
    let m = map().read().unwrap();
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut reviewed = 0;
    for i in m.values() {
        *counts.entry(i.effective()).or_default() += 1;
        reviewed += i.human_verdict.is_some() as usize;
    }
    let q = query.trim().to_lowercase();
    let mut items: Vec<&UrlInsight> = m
        .values()
        .filter(|i| match verdict {
            "" | "threat" => is_threat(i.effective()),
            "unreviewed" => is_threat(&i.verdict) && i.human_verdict.is_none(),
            "reviewed" => i.human_verdict.is_some(),
            "all" => true,
            v => i.effective() == v,
        })
        .filter(|i| {
            q.is_empty()
                || i.url.to_lowercase().contains(&q)
                || i.host.to_lowercase().contains(&q)
                || i.threat.as_deref().is_some_and(|t| t.to_lowercase().contains(&q))
                || i.human_threat.as_deref().is_some_and(|t| t.to_lowercase().contains(&q))
        })
        .collect();
    let matched = items.len();
    items.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    items.truncate(limit);
    serde_json::json!({
        "ok": true,
        "total": m.len(),
        "counts": counts,
        "reviewed": reviewed,
        "matched": matched,
        "items": items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyst_verdict_wins_and_can_be_removed() {
        let url = "https://phish.example/login";
        map().write().unwrap().insert(
            url.to_string(),
            UrlInsight {
                url: url.to_string(),
                host: "phish.example".into(),
                verdict: "malicious".into(),
                threat: Some("Phishing".into()),
                reason: String::new(),
                score: 90,
                liveness: "ACTIVE".into(),
                first_seen: "2026-10-27T00:00:00Z".into(),
                last_seen: "2026-10-27T00:00:00Z".into(),
                seen_count: 1,
                human_verdict: None,
                human_threat: None,
                human_note: String::new(),
                analyst: String::new(),
                reviewed_at: None,
            },
        );
        assert_eq!(list("", "unreviewed", 10)["matched"], 1);
        assert!(review(url, "pua", None, "", "").is_err());
        assert!(review("https://not-listed.example/", "clean", None, "", "").is_err());

        let e = review(url, "Clean", Some("ignored for clean"), "bank's own login page", "ana").unwrap();
        assert_eq!((e.effective(), e.human_threat.as_deref()), ("clean", None));
        assert_eq!(human(url).unwrap().0, "clean");
        let l = list("", "all", 10);
        assert_eq!((l["counts"]["clean"].as_u64(), l["reviewed"].as_u64()), (Some(1), Some(1)));
        assert_eq!(list("", "threat", 10)["matched"], 0, "no longer counted as a threat");

        let e = review(url, "", None, "", "").unwrap();
        assert_eq!(e.effective(), "malicious", "engine verdict applies again");
        assert!(human(url).is_none());
    }
}
