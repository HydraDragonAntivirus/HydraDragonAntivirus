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

pub const VERDICTS: [&str; 3] = ["malicious", "suspicious", "clean"];

/// Engine verdicts that put a file in the human analysis queue until an analyst
/// decides. Malicious is included so engine false positives get a human look too.
pub const AUTO_QUEUE_VERDICTS: [&str; 4] = ["malicious", "suspicious", "unknown", "possible_clean"];

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
    /// When an analyst pressed "Start analysis" (Valkyrie-style start date) and who.
    /// A verdict saved without it gets start = end and `timed` stays false, so quick
    /// and bulk verdicts do not drag the analysis-time statistics to zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub started_by: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timed: bool,
    /// Seconds waiting in the queue (request -> start) and analysing (start -> verdict).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

impl HumanReview {
    pub fn is_completed(&self) -> bool {
        self.status == ReviewStatus::Completed && self.verdict.is_some()
    }

    /// "pending", "in_progress" (an analyst started it) or "completed".
    pub fn stage(&self) -> &'static str {
        if self.is_completed() {
            "completed"
        } else if self.started_at.is_some() {
            "in_progress"
        } else {
            "pending"
        }
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
            "stage": self.stage(),
            "started_at": self.started_at,
            "started_by": self.started_by,
            "wait_secs": self.wait_secs,
            "analysis_secs": self.analysis_secs,
            "timed": self.timed,
            "virustotal": virustotal_url(&self.sha256),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewStats {
    pub pending: usize,
    /// Pending hashes an analyst has started.
    pub in_progress: usize,
    pub completed: usize,
    pub completed_24h: usize,
    /// Request -> verdict, every completed review.
    pub avg_response_secs: Option<i64>,
    pub median_response_secs: Option<i64>,
    pub oldest_pending_secs: Option<i64>,
    /// Request -> start and start -> verdict, reviews started with "Start analysis".
    pub avg_wait_secs: Option<i64>,
    pub median_wait_secs: Option<i64>,
    pub avg_analysis_secs: Option<i64>,
    pub median_analysis_secs: Option<i64>,
    /// Sum of analysis times (timed reviews).
    pub total_analysis_secs: i64,
    pub analysts: Vec<AnalystStats>,
    /// Last 14 days (UTC), oldest first.
    pub daily: Vec<DailyStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalystStats {
    pub analyst: String,
    pub completed: usize,
    pub completed_7d: usize,
    pub in_progress: usize,
    pub total_analysis_secs: i64,
    pub avg_analysis_secs: Option<i64>,
    pub avg_response_secs: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DailyStats {
    pub date: String,
    pub completed: usize,
    pub avg_response_secs: Option<i64>,
    pub avg_analysis_secs: Option<i64>,
}

fn avg(v: &[i64]) -> Option<i64> {
    if v.is_empty() { None } else { Some(v.iter().sum::<i64>() / v.len() as i64) }
}

fn median(v: &mut [i64]) -> Option<i64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
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
    /// Hashes an analyst removed from the queue (or whose review was deleted): the
    /// queue sync does not bring them back. A new real scan can still queue them.
    removed: RwLock<std::collections::HashSet<Sha>>,
    file: Mutex<Option<File>>,
}

impl HumanReviewStore {
    pub fn new(path: &Path) -> Self {
        let mut map = HashMap::new();
        let mut removed = std::collections::HashSet::new();
        if let Ok(f) = File::open(path) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(r) = serde_json::from_str::<HumanReview>(&line) {
                    if let Some(sha) = parse_sha(&r.sha256) {
                        if r.deleted {
                            map.remove(&sha);
                            removed.insert(sha);
                        } else {
                            removed.remove(&sha);
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
        Self { map: RwLock::new(map), removed: RwLock::new(removed), file: Mutex::new(file) }
    }

    fn persist(&self, r: &HumanReview) {
        if let Ok(line) = serde_json::to_string(r) {
            if let Some(f) = self.file.lock().unwrap().as_mut() {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
    }

    /// True when an analyst removed this hash from the queue / deleted its review.
    pub fn was_removed(&self, sha_hex: &str) -> bool {
        parse_sha(sha_hex).is_some_and(|sha| self.removed.read().unwrap().contains(&sha))
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
                started_at: None,
                started_by: String::new(),
                timed: false,
                wait_secs: None,
                analysis_secs: None,
                deleted: false,
            };
            g.insert(sha, r.clone());
            self.removed.write().unwrap().remove(&sha);
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
                started_at: None,
                started_by: String::new(),
                timed: false,
                wait_secs: None,
                analysis_secs: None,
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
            // A re-review keeps the first response, wait and analysis times.
            if r.response_secs.is_none() {
                r.response_secs = Some((now - requested).num_seconds().max(0));
                let started = r.started_at.as_deref().and_then(parse_time).filter(|_| r.timed).unwrap_or(now);
                if !r.timed {
                    r.started_at = Some(now.to_rfc3339());
                    r.started_by = r.analyst.clone();
                }
                r.wait_secs = Some((started - requested).num_seconds().max(0));
                r.analysis_secs = Some((now - started).num_seconds().max(0));
            }
            r.clone()
        };
        self.persist(&review);
        Ok(review)
    }

    /// "Start analysis": marks a queued (or new) hash as being analysed by `analyst`.
    /// A hash someone else already started is returned unchanged (`Err` with who),
    /// unless `take_over`.
    pub fn start(&self, sha_hex: &str, analyst: &str, take_over: bool) -> Result<HumanReview, String> {
        let sha = parse_sha(sha_hex).ok_or("invalid sha256")?;
        let analyst: String = analyst.trim().chars().take(64).collect();
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
                started_at: None,
                started_by: String::new(),
                timed: false,
                wait_secs: None,
                analysis_secs: None,
                deleted: false,
            });
            if r.is_completed() {
                return Err("this hash already has a verdict; edit it instead".into());
            }
            if r.started_at.is_some() && !take_over && !r.started_by.eq_ignore_ascii_case(&analyst) {
                return Err(format!(
                    "already in analysis by {}",
                    if r.started_by.is_empty() { "another analyst" } else { r.started_by.as_str() }
                ));
            }
            if r.started_at.is_none() || take_over {
                r.started_at = Some(now.to_rfc3339());
            }
            r.started_by = analyst;
            r.timed = true;
            r.clone()
        };
        self.persist(&review);
        Ok(review)
    }

    /// Puts a started hash back in the queue (the analyst stops working on it).
    pub fn release(&self, sha_hex: &str) -> Result<HumanReview, String> {
        let sha = parse_sha(sha_hex).ok_or("invalid sha256")?;
        let review = {
            let mut g = self.map.write().unwrap();
            let r = g.get_mut(&sha).ok_or("no review for this hash")?;
            if r.is_completed() {
                return Err("this hash already has a verdict".into());
            }
            r.started_at = None;
            r.started_by.clear();
            r.timed = false;
            r.clone()
        };
        self.persist(&review);
        Ok(review)
    }

    pub fn remove(&self, sha_hex: &str) -> bool {
        let Some(sha) = parse_sha(sha_hex) else { return false };
        let removed = self.map.write().unwrap().remove(&sha);
        self.removed.write().unwrap().insert(sha);
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

    /// (SHA-256, verdict) of every completed review.
    pub fn completed_verdicts(&self) -> Vec<(String, String)> {
        let g = self.map.read().unwrap();
        g.values().filter(|r| r.is_completed()).filter_map(|r| Some((r.sha256.clone(), r.verdict.clone()?))).collect()
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
        let (mut pending, mut in_progress, mut completed, mut completed_24h) = (0usize, 0usize, 0usize, 0usize);
        let mut oldest_pending: Option<DateTime<Utc>> = None;
        let (mut resp, mut wait, mut analysis) = (Vec::new(), Vec::new(), Vec::new());
        #[derive(Default)]
        struct Acc {
            completed: usize,
            completed_7d: usize,
            in_progress: usize,
            analysis: Vec<i64>,
            response: Vec<i64>,
        }
        let mut per: HashMap<String, (String, Acc)> = HashMap::new();
        let today = now.date_naive();
        let mut days: Vec<(chrono::NaiveDate, usize, Vec<i64>, Vec<i64>)> =
            (0..14).rev().map(|i| (today - chrono::Duration::days(i), 0, Vec::new(), Vec::new())).collect();
        for r in g.values() {
            match r.status {
                ReviewStatus::Pending => {
                    pending += 1;
                    if let Some(t) = parse_time(&r.requested_at) {
                        oldest_pending = Some(oldest_pending.map_or(t, |o| o.min(t)));
                    }
                    if r.started_at.is_some() {
                        in_progress += 1;
                        if !r.started_by.is_empty() {
                            per.entry(r.started_by.to_lowercase()).or_insert_with(|| (r.started_by.clone(), Acc::default())).1.in_progress += 1;
                        }
                    }
                }
                ReviewStatus::Completed => {
                    completed += 1;
                    let reviewed = r.reviewed_at.as_deref().and_then(parse_time);
                    if reviewed.is_some_and(|t| now - t < chrono::Duration::hours(24)) {
                        completed_24h += 1;
                    }
                    if let Some(s) = r.response_secs {
                        resp.push(s);
                    }
                    let timed_analysis = if r.timed { r.analysis_secs } else { None };
                    if r.timed {
                        wait.extend(r.wait_secs);
                        analysis.extend(r.analysis_secs);
                    }
                    let name = if r.analyst.is_empty() { "analyst".to_string() } else { r.analyst.clone() };
                    let acc = &mut per.entry(name.to_lowercase()).or_insert_with(|| (name, Acc::default())).1;
                    acc.completed += 1;
                    if reviewed.is_some_and(|t| now - t < chrono::Duration::days(7)) {
                        acc.completed_7d += 1;
                    }
                    acc.analysis.extend(timed_analysis);
                    acc.response.extend(r.response_secs);
                    if let Some(t) = reviewed {
                        if let Some(d) = days.iter_mut().find(|d| d.0 == t.date_naive()) {
                            d.1 += 1;
                            d.2.extend(r.response_secs);
                            d.3.extend(timed_analysis);
                        }
                    }
                }
            }
        }
        let mut analysts: Vec<AnalystStats> = per
            .into_values()
            .map(|(name, a)| AnalystStats {
                analyst: name,
                completed: a.completed,
                completed_7d: a.completed_7d,
                in_progress: a.in_progress,
                total_analysis_secs: a.analysis.iter().sum(),
                avg_analysis_secs: avg(&a.analysis),
                avg_response_secs: avg(&a.response),
            })
            .collect();
        analysts.sort_by(|a, b| b.completed.cmp(&a.completed).then(a.analyst.cmp(&b.analyst)));
        ReviewStats {
            pending,
            in_progress,
            completed,
            completed_24h,
            avg_response_secs: avg(&resp),
            median_response_secs: median(&mut resp),
            oldest_pending_secs: oldest_pending.map(|t| (now - t).num_seconds().max(0)),
            avg_wait_secs: avg(&wait),
            median_wait_secs: median(&mut wait),
            avg_analysis_secs: avg(&analysis),
            median_analysis_secs: median(&mut analysis),
            total_analysis_secs: analysis.iter().sum(),
            analysts,
            daily: days
                .into_iter()
                .map(|(d, n, r, a)| DailyStats {
                    date: d.to_string(),
                    completed: n,
                    avg_response_secs: avg(&r),
                    avg_analysis_secs: avg(&a),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn start_wait_analysis() {
        let path = std::env::temp_dir().join(format!("hr_test_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let st = HumanReviewStore::new(&path);
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        st.enqueue(&a, "auto", Some("unknown"), Some("x.exe")).unwrap();
        st.enqueue(&b, "auto", Some("unknown"), Some("y.exe")).unwrap();
        let r = st.start(&a, "emir", false).unwrap();
        assert_eq!(r.stage(), "in_progress");
        assert!(st.start(&a, "other", false).is_err());
        assert_eq!(st.stats().in_progress, 1);
        let done = st.complete(&a, "clean", None, "", "", "emir").unwrap();
        assert!(done.timed && done.analysis_secs.is_some() && done.wait_secs.is_some());
        // Quick verdict without start: start = end, not timed.
        let q = st.complete(&b, "clean", None, "", "", "emir").unwrap();
        assert!(!q.timed && q.analysis_secs == Some(0) && q.started_at == q.reviewed_at);
        let s = st.stats();
        assert_eq!(s.completed, 2);
        assert_eq!(s.analysts.len(), 1);
        assert_eq!(s.analysts[0].completed, 2);
        assert_eq!(s.daily.len(), 14);
        assert_eq!(s.daily[13].completed, 2);
        // A removed hash is remembered (the queue sync does not bring it back).
        assert!(st.remove(&b) && st.was_removed(&b));
        // Reload keeps the fields.
        drop(st);
        let st2 = HumanReviewStore::new(&path);
        assert!(st2.get(&a).unwrap().timed);
        assert!(st2.was_removed(&b) && !st2.was_removed(&a));
        let _ = std::fs::remove_file(&path);
    }
}
