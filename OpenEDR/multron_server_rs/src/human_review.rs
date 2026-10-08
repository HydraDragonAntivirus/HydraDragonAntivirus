//! Human analysis queue (Valkyrie-style).
//!
//! Every file the engine cannot settle (`unknown` / `suspicious` after a real scan) and
//! every hash a user asks about on the website goes into a queue. An analyst answers it
//! from the dashboard with a verdict, a public note and an optional internal note. A completed review overrides the
//! engine verdict everywhere (WebSocket clients, insights API, statistics) and its
//! response time (request -> verdict) is published.
//!
//! Stored apart from the engine rule folders, in `analyst_signatures/human_verdicts.jsonl`
//! next to the executable (see `analyst_dir`): the last line for a hash wins, a line with
//! `"deleted": true` removes it. Malicious verdicts must carry a threat name in the
//! VirusKov naming convention (see `naming.rs`), so they work as hash signatures.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Mutex, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cache::{parse_sha, Sha};

/// Upper bound for the pending queue so it cannot be flooded.
pub const MAX_PENDING: usize = 20_000;

pub const VERDICTS: [&str; 3] = ["malicious", "suspicious", "clean"];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Pending,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanReview {
    pub sha256: String,
    pub status: ReviewStatus,
    /// "auto" (engine could not decide), "user" (asked on the website) or "analyst".
    #[serde(default)]
    pub source: String,
    pub requested_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    /// Public note shown on the website.
    #[serde(default)]
    pub note: String,
    /// Internal note for analysts only: never in public JSON, client results or the website.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub internal_note: String,
    #[serde(default)]
    pub analyst: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    /// Seconds from request to verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

impl HumanReview {
    pub fn is_completed(&self) -> bool {
        self.status == ReviewStatus::Completed && self.verdict.is_some()
    }

    /// Dashboard JSON: the public fields plus the internal note.
    pub fn to_dashboard_json(&self) -> serde_json::Value {
        let mut v = self.to_public_json();
        v["internal_note"] = serde_json::json!(self.internal_note);
        v
    }

    /// Public JSON (website, client results). Never contains the internal note.
    pub fn to_public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sha256": self.sha256,
            "status": self.status,
            "source": self.source,
            "requested_at": self.requested_at,
            "engine_verdict": self.engine_verdict,
            "verdict": self.verdict,
            "threat_name": self.threat_name,
            "note": self.note,
            "analyst": self.analyst,
            "reviewed_at": self.reviewed_at,
            "response_secs": self.response_secs,
            "virustotal": virustotal_url(&self.sha256),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewStats {
    pub pending: usize,
    pub completed: usize,
    pub completed_24h: usize,
    pub avg_response_secs: Option<i64>,
    pub median_response_secs: Option<i64>,
    pub oldest_pending_secs: Option<i64>,
}

/// Folder for everything analysts write by hand (human verdicts, YARA rules). Kept
/// separate from the shipped rule folders so updates never overwrite analyst work.
pub fn analyst_dir() -> std::path::PathBuf {
    let dir = crate::config::app_dir().join("analyst_signatures");
    let _ = std::fs::create_dir_all(dir.join("yara"));
    dir
}

pub fn virustotal_url(sha256: &str) -> String {
    format!("https://www.virustotal.com/gui/file/{}", sha256.to_lowercase())
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

pub struct HumanReviewStore {
    map: RwLock<HashMap<Sha, HumanReview>>,
    file: Mutex<Option<File>>,
}

impl HumanReviewStore {
    pub fn new(path: &Path) -> Self {
        let mut map = HashMap::new();
        if let Ok(f) = File::open(path) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(r) = serde_json::from_str::<HumanReview>(&line) {
                    if let Some(sha) = parse_sha(&r.sha256) {
                        if r.deleted {
                            map.remove(&sha);
                        } else {
                            map.insert(sha, r);
                        }
                    }
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        if file.is_none() {
            eprintln!("[review] cannot open {} for writing; reviews will not persist", path.display());
        }
        Self { map: RwLock::new(map), file: Mutex::new(file) }
    }

    fn persist(&self, r: &HumanReview) {
        if let Ok(line) = serde_json::to_string(r) {
            if let Some(f) = self.file.lock().unwrap().as_mut() {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
    }

    pub fn get(&self, sha_hex: &str) -> Option<HumanReview> {
        let sha = parse_sha(sha_hex)?;
        self.map.read().unwrap().get(&sha).cloned()
    }

    /// Completed review for this hash, if any (overrides the engine).
    pub fn completed(&self, sha_hex: &str) -> Option<HumanReview> {
        self.get(sha_hex).filter(|r| r.is_completed())
    }

    /// Completed verdict by raw hash (used while counting statistics).
    pub fn completed_verdict_raw(&self, sha: &Sha) -> Option<String> {
        self.map.read().unwrap().get(sha).filter(|r| r.is_completed()).and_then(|r| r.verdict.clone())
    }

    /// Puts a hash in the queue. Existing entries (pending or completed) are returned as is.
    pub fn enqueue(
        &self,
        sha_hex: &str,
        source: &str,
        engine_verdict: Option<&str>,
        file_name: Option<&str>,
    ) -> Result<HumanReview, String> {
        let sha = parse_sha(sha_hex).ok_or("invalid sha256")?;
        let review = {
            let mut g = self.map.write().unwrap();
            if let Some(existing) = g.get(&sha) {
                return Ok(existing.clone());
            }
            let pending = g.values().filter(|r| r.status == ReviewStatus::Pending).count();
            if pending >= MAX_PENDING {
                return Err("the human analysis queue is full, try again later".into());
            }
            let r = HumanReview {
                sha256: sha_hex.to_lowercase(),
                status: ReviewStatus::Pending,
                source: source.to_string(),
                requested_at: Utc::now().to_rfc3339(),
                engine_verdict: engine_verdict.map(str::to_string),
                file_name: file_name.map(|n| n.chars().take(260).collect()),
                verdict: None,
                threat_name: None,
                note: String::new(),
                internal_note: String::new(),
                analyst: String::new(),
                reviewed_at: None,
                response_secs: None,
                deleted: false,
            };
            g.insert(sha, r.clone());
            r
        };
        self.persist(&review);
        Ok(review)
    }

    /// Analyst verdict. Works for queued hashes and for hashes reviewed directly.
    pub fn complete(
        &self,
        sha_hex: &str,
        verdict: &str,
        threat_name: Option<&str>,
        note: &str,
        internal_note: &str,
        analyst: &str,
    ) -> Result<HumanReview, String> {
        let sha = parse_sha(sha_hex).ok_or("invalid sha256")?;
        let verdict = verdict.trim().to_ascii_lowercase();
        if !VERDICTS.contains(&verdict.as_str()) {
            return Err("verdict must be malicious, suspicious or clean".into());
        }
        // Threat names follow Category.Platform.Family[.Variant]; required for malicious.
        let threat_name = match threat_name.map(str::trim).filter(|t| !t.is_empty()) {
            _ if verdict == "clean" => None,
            Some(t) => Some(crate::naming::normalize_threat_name(t)?),
            None if verdict == "malicious" => {
                return Err("a malicious verdict needs a threat name, e.g. Trojan.Win32.Remcos.A".into())
            }
            None => None,
        };
        let now = Utc::now();
        let review = {
            let mut g = self.map.write().unwrap();
            let r = g.entry(sha).or_insert_with(|| HumanReview {
                sha256: sha_hex.to_lowercase(),
                status: ReviewStatus::Pending,
                source: "analyst".into(),
                requested_at: now.to_rfc3339(),
                engine_verdict: None,
                file_name: None,
                verdict: None,
                threat_name: None,
                note: String::new(),
                internal_note: String::new(),
                analyst: String::new(),
                reviewed_at: None,
                response_secs: None,
                deleted: false,
            });
            let requested = parse_time(&r.requested_at).unwrap_or(now);
            r.status = ReviewStatus::Completed;
            r.verdict = Some(verdict);
            r.threat_name = threat_name;
            r.note = note.trim().chars().take(4000).collect();
            r.internal_note = internal_note.trim().chars().take(8000).collect();
            r.analyst = analyst.trim().chars().take(64).collect();
            r.reviewed_at = Some(now.to_rfc3339());
            // A re-review keeps the first response time.
            if r.response_secs.is_none() {
                r.response_secs = Some((now - requested).num_seconds().max(0));
            }
            r.clone()
        };
        self.persist(&review);
        Ok(review)
    }

    pub fn remove(&self, sha_hex: &str) -> bool {
        let Some(sha) = parse_sha(sha_hex) else { return false };
        let removed = self.map.write().unwrap().remove(&sha);
        if let Some(mut r) = removed {
            r.deleted = true;
            self.persist(&r);
            true
        } else {
            false
        }
    }

    /// Oldest first.
    pub fn pending(&self, limit: usize) -> Vec<HumanReview> {
        let g = self.map.read().unwrap();
        let mut v: Vec<HumanReview> = g.values().filter(|r| r.status == ReviewStatus::Pending).cloned().collect();
        v.sort_by(|a, b| a.requested_at.cmp(&b.requested_at));
        v.truncate(limit);
        v
    }

    /// Newest first.
    pub fn recent_completed(&self, limit: usize) -> Vec<HumanReview> {
        let g = self.map.read().unwrap();
        let mut v: Vec<HumanReview> = g.values().filter(|r| r.is_completed()).cloned().collect();
        v.sort_by(|a, b| b.reviewed_at.cmp(&a.reviewed_at));
        v.truncate(limit);
        v
    }

    pub fn stats(&self) -> ReviewStats {
        let g = self.map.read().unwrap();
        let now = Utc::now();
        let mut times: Vec<i64> = Vec::new();
        let (mut pending, mut completed, mut completed_24h) = (0usize, 0usize, 0usize);
        let mut oldest_pending: Option<DateTime<Utc>> = None;
        for r in g.values() {
            match r.status {
                ReviewStatus::Pending => {
                    pending += 1;
                    if let Some(t) = parse_time(&r.requested_at) {
                        oldest_pending = Some(oldest_pending.map_or(t, |o| o.min(t)));
                    }
                }
                ReviewStatus::Completed => {
                    completed += 1;
                    if let Some(s) = r.response_secs {
                        times.push(s);
                    }
                    if r.reviewed_at.as_deref().and_then(parse_time).is_some_and(|t| now - t < chrono::Duration::hours(24)) {
                        completed_24h += 1;
                    }
                }
            }
        }
        times.sort_unstable();
        let avg = if times.is_empty() { None } else { Some(times.iter().sum::<i64>() / times.len() as i64) };
        let median = if times.is_empty() { None } else { Some(times[times.len() / 2]) };
        ReviewStats {
            pending,
            completed,
            completed_24h,
            avg_response_secs: avg,
            median_response_secs: median,
            oldest_pending_secs: oldest_pending.map(|t| (now - t).num_seconds().max(0)),
        }
    }
}
