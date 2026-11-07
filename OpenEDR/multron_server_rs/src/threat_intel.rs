use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::hexsha::HexSha;
use crate::istr::IStr;
use crate::stamp::Stamp;

use crate::cache::{parse_sha, Sha};
use crate::config::app_dir;
use crate::human_review::HumanReviewStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInsight {
    pub sha256: HexSha,
    pub first_seen: Stamp,
    pub last_seen: Stamp,
    pub seen_count: u64,
    pub verdict: IStr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<IStr>,
    pub file_names: Vec<IStr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    pub score: f64,
    /// Folders the file was seen in (at most 5), normalized by the client with
    /// environment placeholders (%USERPROFILE%, %APPDATA%, ...) so no user name is kept.
    /// Dashboard only: never put in public JSON (website, insights API, client results).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<IStr>,
    /// Full folder paths as sent by the client (user name included; at most 5), so
    /// several user profiles on one computer stay apart. Dashboard only, like `folders`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_folders: Vec<IStr>,
    /// Which client IP sent the file from which full path (at most `MAX_SIGHTINGS`
    /// IP/path pairs). Lets analysts count how many different sources a file came
    /// from and spot abuse. Dashboard only, like `folders`: never published.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sightings: Vec<Sighting>,
    /// Authenticode signer from the last engine scan (dashboard; None = not checked,
    /// e.g. a hash-only verdict or a non-PE file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Box<SignerSummary>>,
    /// Every signature that matched in the last engine scan of the stored verdict
    /// (engine layer + rule name), so analysts see the exact rules, not only the
    /// malware type. Dashboard only, like `folders`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detections: Vec<DetectionRef>,
    /// Since when the file waits for a new scan it could not get (a rescan or an
    /// engine change found no kept sample to scan): `verdict` is still the last one,
    /// shown as "not scanned" until a scan of the file comes; the client is asked for
    /// the file again meanwhile. It used to become "unknown", which hid known malware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_scanned_since: Option<IStr>,
    /// Hash checks answered "need upload" whose scan result has not come yet: the check
    /// already counted the sighting, so that result does not count it again.
    #[serde(skip)]
    pub pending_uploads: u32,
    /// Changed since it was last written to SQLite (the writer clears it).
    #[serde(skip)]
    pub dirty: bool,
}

/// One matched signature: the engine layer ("YARA", "ClamAV", "Analyst clamav", ...)
/// and the rule / signature name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionRef {
    pub layer: String,
    pub name: String,
}

/// One client IP + full path a file was sent from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sighting {
    pub ip: IStr,
    /// Full folder path as sent by the client (empty when the client sent none).
    #[serde(default, skip_serializing_if = "IStr::is_empty")]
    pub path: IStr,
    pub first_seen: Stamp,
    pub last_seen: Stamp,
    pub count: u64,
}

/// Most IP/path pairs kept per file.
pub const MAX_SIGHTINGS: usize = 100;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SignerSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub signed: bool,
    #[serde(default)]
    pub trusted: bool,
    #[serde(default)]
    pub catalog: bool,
    #[serde(default)]
    pub status: String,

    // Certificate identity, mirrored from `openedr_static::report::SignerDetails`.
    // Every field is defaulted so insight files written before these existed
    // still load; an absent field reads as "not reported", never as "clean".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub chain_len: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_time: Option<i64>,
}

fn is_zero(v: &usize) -> bool {
    *v == 0
}

impl SignerSummary {
    /// Certificate expired, or not yet valid, against the wall clock.
    ///
    /// `None` rather than `false` when no validity window was reported, so a
    /// file scanned before this field existed is not treated as a clean cert.
    pub fn validity_problem(&self, now: i64) -> Option<bool> {
        if self.not_before.is_some_and(|from| from > now) {
            return Some(true);
        }
        if self.not_after.is_some_and(|to| to < now) {
            // Timestamped while the certificate was valid: the signature still is
            // (Windows accepts it). A legacy countersignature has no time: accepted.
            let in_window = |t: i64| self.not_after.is_none_or(|to| t <= to) && self.not_before.is_none_or(|from| t >= from);
            if self.timestamped == Some(true) && self.timestamp_time.is_none_or(in_window) {
                return None;
            }
            return Some(true);
        }
        None
    }

    /// One line for the dashboard, or `None` when there is nothing to add
    /// beyond the publisher name already shown.
    pub fn certificate_detail(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(issuer) = self.issuer.as_deref().filter(|s| !s.trim().is_empty()) {
            parts.push(format!("issued by {issuer}"));
        }
        if let Some(tp) = self.thumbprint.as_deref().filter(|s| !s.trim().is_empty()) {
            parts.push(format!("cert {tp}"));
        }
        match self.timestamped {
            Some(true) => parts.push("timestamped".to_string()),
            Some(false) => parts.push("no countersignature".to_string()),
            None => {}
        }
        if let Some(tsa) = self
            .timestamp_signer
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            parts.push(format!("timestamped by {tsa}"));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }
}

impl ThreatInsight {
    pub fn prevalence(&self) -> &'static str {
        if self.seen_count >= 1000 {
            "very_high"
        } else if self.seen_count >= 100 {
            "high"
        } else if self.seen_count >= 10 {
            "moderate"
        } else if self.seen_count > 1 {
            "low"
        } else {
            "rare"
        }
    }
}

pub struct RestRateLimiter {
    quotas: std::sync::Mutex<HashMap<String, IpQuota>>,
}

struct IpQuota {
    tokens: f64,
    last_update: std::time::Instant,
    day_count: u32,
    day_start_secs: i64,
}

pub struct RateLimitHeader {
    pub limit: u32,
    pub remaining: u32,
}

impl RestRateLimiter {
    pub fn new() -> Self {
        Self {
            quotas: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 10 requests / minute burst, max 500 requests / day per IP.
    /// Returns Ok(RateLimitHeader) or Err(retry_after_seconds).
    pub fn check(&self, ip: &str, api_key: Option<&str>) -> Result<RateLimitHeader, u64> {
        // Commercial API key bypass / high tier (ready for monetization)
        if let Some(key) = api_key {
            if key.starts_with("vk_live_") || key.starts_with("viruskov_") {
                return Ok(RateLimitHeader {
                    limit: 1000,
                    remaining: 999,
                });
            }
        }

        let now_instant = std::time::Instant::now();
        let now_secs = chrono::Utc::now().timestamp();
        let mut guard = self.quotas.lock().unwrap();

        let quota = guard.entry(ip.to_string()).or_insert_with(|| IpQuota {
            tokens: 10.0,
            last_update: now_instant,
            day_count: 0,
            day_start_secs: now_secs,
        });

        // Daily reset (every 86400 seconds)
        if now_secs - quota.day_start_secs >= 86400 {
            quota.day_count = 0;
            quota.day_start_secs = now_secs;
        }

        if quota.day_count >= 500 {
            let retry_after = (86400 - (now_secs - quota.day_start_secs)).max(60) as u64;
            return Err(retry_after);
        }

        // Replenish tokens (10 tokens max, 1 token every 6 seconds = 10 per minute)
        let elapsed_secs = quota.last_update.elapsed().as_secs_f64();
        quota.tokens = (quota.tokens + elapsed_secs * (10.0 / 60.0)).min(10.0);
        quota.last_update = now_instant;

        if quota.tokens < 1.0 {
            let retry_after = ((1.0 - quota.tokens) * 6.0).ceil() as u64;
            return Err(retry_after.max(1));
        }

        quota.tokens -= 1.0;
        quota.day_count += 1;

        Ok(RateLimitHeader {
            limit: 10,
            remaining: quota.tokens.floor() as u32,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelStats {
    pub total_unique_hashes: usize,
    pub total_sightings: u64,
    pub malicious_count: usize,
    pub suspicious_count: usize,
    pub clean_count: usize,
    /// TLSH smart whitelist (`possible_clean`), counted apart from clean.
    pub possible_clean_count: usize,
    pub unknown_count: usize,
}

/// Records kept in memory besides the ones not written yet (see `ThreatIntelStore::hot`).
const HOT_MAX: usize = 50_000;
/// Hashes per `IN (...)` lookup.
const IN_CHUNK: usize = 500;
/// The final verdicts the statistics count by name; anything else is "unknown".
const KNOWN_VERDICTS: [&str; 4] = ["malicious", "suspicious", "clean", "possible_clean"];

/// Engine verdict counts of every record (`stats`), kept up to date by each change
/// instead of walking the table on every dashboard refresh.
#[derive(Debug, Default, Clone)]
struct Counts {
    hashes: u64,
    sightings: u64,
    by_verdict: HashMap<String, u64>,
}

impl Counts {
    fn add(&mut self, verdict: &str, n: i64) {
        let e = self.by_verdict.entry(verdict.to_string()).or_default();
        *e = (*e as i64 + n).max(0) as u64;
    }
}

pub struct ThreatIntelStore {
    /// Records changed and not written yet (`dirty`), and records read to be changed.
    /// Everything else lives only in SQLite: the writer drops written records once
    /// there are more than `HOT_MAX`, so memory does not grow with the number of hashes.
    hot: Arc<RwLock<HashMap<Sha, ThreatInsight>>>,
    counts: Arc<Mutex<Counts>>,
    writer: Option<mpsc::Sender<WriterMsg>>,
    /// `threat_insights.db` (the archive server: `threat_insights_archive.db`, filled
    /// from the mirrored `.jsonl`).
    db: Arc<crate::insight_db::InsightDb>,
    /// Human analysis queue and verdicts (override the engine verdict).
    pub reviews: HumanReviewStore,
    /// TLSH index of analysed files (smart whitelist, similar files).
    pub similarity: crate::similarity::SimilarityIndex,
}

impl ThreatIntelStore {
    pub fn new(persistence_file: Option<PathBuf>) -> Arc<Self> {
        let target_path = persistence_file.unwrap_or_else(|| app_dir().join("threat_insights.jsonl"));
        let archive = crate::config::is_archive();
        let db = open_db(&target_path, archive);
        let started = std::time::Instant::now();
        // The archive server fills its own database from the mirrored `.jsonl`
        // (`archive::spawn_reloader`); the main server moves its old `.jsonl` once.
        if !archive {
            migrate_jsonl(&db, &target_path);
        }
        // A standby must not write: the running server fills these after the hand-over.
        if !crate::config::is_standby() {
            fill_stale_columns(&db);
        }
        let counts = Arc::new(Mutex::new(recount(&db)));
        eprintln!(
            "[telemetry] {} hashes in {} ({:.1} s)",
            counts.lock().unwrap().hashes,
            db_path_for(&target_path, archive).display(),
            started.elapsed().as_secs_f64()
        );

        let reviews = HumanReviewStore::new(&crate::human_review::analyst_dir().join("human_verdicts.jsonl"));
        let hot = Arc::new(RwLock::new(HashMap::new()));
        let writer = Some(start_batch_writer(Arc::clone(&db), Arc::clone(&hot), Arc::clone(&counts)));

        Arc::new(Self {
            hot,
            counts,
            writer,
            db,
            reviews,
            similarity: crate::similarity::SimilarityIndex::load(),
        })
    }

    /// The SQLite store (change feed for the archive mirror and the seamless update).
    pub fn db(&self) -> &Arc<crate::insight_db::InsightDb> {
        &self.db
    }

    /// Writes every buffered insight to disk now (seamless update: before the hand-over;
    /// queries that read SQLite: before they read).
    pub fn flush(&self, timeout: Duration) -> bool {
        let Some(w) = &self.writer else { return true };
        let (tx, rx) = mpsc::sync_channel(1);
        w.send(WriterMsg::Flush(tx)).is_ok() && rx.recv_timeout(timeout).is_ok()
    }

    /// Before a query reads SQLite: the changes still in memory go first.
    fn flush_for_query(&self) {
        let _ = self.flush(Duration::from_secs(30));
    }

    /// A batch was imported (archive): written now and counted again.
    pub fn resync(&self) {
        resync(&self.db, &self.hot, &self.counts, false);
    }

    /// The running server wrote the database (seamless update standby): records in
    /// memory may be older than SQLite; after the hand-over, the columns it left out
    /// are filled. The counts are counted again.
    pub fn resync_external(&self) {
        if !crate::config::is_standby() {
            fill_stale_columns(&self.db);
        }
        resync(&self.db, &self.hot, &self.counts, true);
    }

    fn load(&self, sha: &Sha) -> Option<ThreatInsight> {
        let data = self.db.get(sha).ok().flatten()?;
        serde_json::from_slice(&data).ok()
    }

    /// Runs `f` on the record of `sha` with `true` when it was just created: read from
    /// SQLite into memory when it is not there, made by `create` when the hash is not
    /// known at all. `None` = not known and nothing to create. `f` sets `dirty` when it
    /// changed something.
    fn update<R>(
        &self,
        sha: Sha,
        create: Option<&dyn Fn() -> ThreatInsight>,
        f: impl FnOnce(&mut ThreatInsight, bool) -> R,
    ) -> Option<R> {
        let loaded = if self.hot.read().unwrap().contains_key(&sha) { None } else { self.load(&sha) };
        let mut g = self.hot.write().unwrap();
        let (entry, is_new) = match g.entry(sha) {
            std::collections::hash_map::Entry::Occupied(o) => (o.into_mut(), false),
            std::collections::hash_map::Entry::Vacant(v) => match loaded {
                Some(i) => (v.insert(i), false),
                None => (v.insert(create?()), true),
            },
        };
        Some(f(entry, is_new))
    }

    /// Records a sighting with its verdict (`seen_count` + 1), or the result of an
    /// upload a hash check asked for (`record_check`), which that check already counted.
    pub fn record(
        &self,
        sha256_hex: &str,
        verdict: &str,
        threat: Option<&str>,
        file_name: Option<&str>,
        file_size: Option<u64>,
        score: f64,
    ) {
        self.record_inner(sha256_hex, verdict, threat, file_name, file_size, score, false);
    }

    /// A hash check of a file the server has to scan: counts the sighting with an
    /// "unknown" placeholder; the scan result of the upload is not counted again.
    pub fn record_check(&self, sha256_hex: &str, file_name: Option<&str>, file_size: Option<u64>) {
        self.record_inner(sha256_hex, "unknown", None, file_name, file_size, 0.0, true);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_inner(
        &self,
        sha256_hex: &str,
        verdict: &str,
        threat: Option<&str>,
        file_name: Option<&str>,
        file_size: Option<u64>,
        score: f64,
        check: bool,
    ) {
        let Some(sha_bytes) = parse_sha(sha256_hex) else {
            return;
        };

        let now_str = Utc::now().to_rfc3339();
        let create = || ThreatInsight {
            sha256: sha256_hex.to_lowercase().into(),
            first_seen: now_str.as_str().into(),
            last_seen: now_str.as_str().into(),
            seen_count: 0,
            verdict: verdict.into(),
            threat_name: threat.map(IStr::from),
            file_names: Vec::new(),
            file_size,
            score,
            folders: Vec::new(),
            full_folders: Vec::new(),
            sightings: Vec::new(),
            signer: None,
            detections: Vec::new(),
            not_scanned_since: None,
            pending_uploads: 0,
            dirty: false,
        };

        let changed = self.update(sha_bytes, Some(&create), |entry, is_new| {
            let old_verdict = (!is_new).then(|| entry.verdict.to_string());
            let old_seen = entry.seen_count;

            // One sighting = one check or one upload, not both.
            if check {
                entry.seen_count += 1;
                entry.pending_uploads += 1;
            } else if entry.pending_uploads > 0 {
                entry.pending_uploads -= 1;
            } else {
                entry.seen_count += 1;
            }
            entry.last_seen = now_str.as_str().into();
            // Scanned again (an upload's result, not the check before it).
            if !check {
                entry.not_scanned_since = None;
            }

            // The latest real verdict wins, lower ones too: once malicious stayed malicious
            // before, so a false positive fixed in the engine (or a file now PUA /
            // suspicious) kept counting as malicious for every hash that was not kept here
            // to rescan. "unknown" (the `check` placeholder before the upload, scans
            // answered by a human verdict, scans that could not decide) never replaces a
            // real verdict, and any real verdict replaces it.
            if verdict != "unknown" && verdict != entry.verdict {
                entry.verdict = verdict.into();
                entry.threat_name = threat.map(IStr::from);
                entry.score = score;
            } else if verdict == entry.verdict {
                if let Some(t) = threat {
                    entry.threat_name.get_or_insert_with(|| t.into());
                }
                entry.score = score.max(entry.score);
            }

            if let Some(name) = file_name {
                let trimmed = name.trim();
                if !trimmed.is_empty() && !entry.file_names.iter().any(|n| n.eq_ignore_ascii_case(trimmed)) {
                    if entry.file_names.len() < 5 {
                        entry.file_names.push(trimmed.into());
                    }
                }
            }

            if file_size.is_some() && entry.file_size.is_none() {
                entry.file_size = file_size;
            }
            entry.dirty = true;

            let mut c = self.counts.lock().unwrap();
            match &old_verdict {
                None => {
                    c.hashes += 1;
                    c.add(&entry.verdict, 1);
                }
                Some(old) if old.as_str() != entry.verdict.as_str() => {
                    c.add(old, -1);
                    c.add(&entry.verdict, 1);
                }
                Some(_) => {}
            }
            c.sightings += entry.seen_count - old_seen;
            drop(c);

            // History: a new verdict (a first "unknown" placeholder is not one).
            let new_verdict = entry.verdict.as_str();
            let history = old_verdict.as_deref() != Some(new_verdict) && !(old_verdict.is_none() && new_verdict == "unknown");
            history.then(|| (old_verdict, entry.sha256.text().to_string(), entry.verdict.to_string(), entry.threat_name.as_ref().map(|t| t.to_string())))
        });
        let Some(Some((old_verdict, sha, new_verdict, threat_name))) = changed else { return };
        crate::verdict_history::record(&sha, "engine", old_verdict.as_deref(), &new_verdict, threat_name.as_deref(), "scan", "");
    }

    /// Adds a folder the file was seen in (see `ThreatInsight::folders`), its full
    /// path (`ThreatInsight::full_folders`) and the client IP it came from together
    /// with that full path (`ThreatInsight::sightings`). Only for hashes already
    /// recorded; empty or unusable paths are ignored (the IP is still counted).
    pub fn add_folder(&self, sha256_hex: &str, ip: &str, folder: &str, full: &str) {
        let folder = sanitize_folder(folder);
        let full = clean_full_folder(full);
        let ip: String = ip.trim().chars().filter(|c| !c.is_control()).take(64).collect();
        let Some(sha_bytes) = parse_sha(sha256_hex) else { return };
        self.update(sha_bytes, None, |entry, _| {
            for (list, item) in [(&mut entry.folders, folder), (&mut entry.full_folders, full.clone())] {
                if let Some(item) = item {
                    if list.len() < 5 && !list.iter().any(|f| f.eq_ignore_ascii_case(&item)) {
                        list.push(item.into());
                    }
                }
            }
            if !ip.is_empty() {
                add_sighting(&mut entry.sightings, &ip, full.as_deref().unwrap_or(""), &Utc::now().to_rfc3339());
            }
            entry.dirty = true;
        });
    }

    /// Stores the Authenticode signer the engine saw (after a real scan or rescan).
    pub fn set_signer(&self, sha256_hex: &str, signer: &SignerSummary) {
        let Some(sha_bytes) = parse_sha(sha256_hex) else { return };
        self.update(sha_bytes, None, |entry, _| {
            if entry.signer.as_deref() != Some(signer) {
                entry.signer = Some(Box::new(signer.clone()));
                entry.dirty = true;
            }
        });
    }

    /// Stores the signatures that matched. `force` (rescan): always replaces them, an
    /// empty list clears them. Otherwise only when the scan's verdict is the stored one
    /// (a weaker later scan does not replace the rules behind the stored verdict).
    pub fn set_detections(&self, sha256_hex: &str, verdict: &str, detections: &[DetectionRef], force: bool) {
        let Some(sha_bytes) = parse_sha(sha256_hex) else { return };
        self.update(sha_bytes, None, |entry, _| {
            if !force && (detections.is_empty() || entry.verdict != verdict) {
                return;
            }
            if entry.detections.as_slice() != detections {
                entry.detections = detections.to_vec();
                entry.dirty = true;
            }
        });
    }

    /// Sets the engine verdict after a rescan with the current engine (may lower it,
    /// unlike `record`). Not a sighting. A completed human review still overrides it.
    pub fn set_engine_verdict(&self, sha256_hex: &str, verdict: &str, threat: Option<&str>, score: f64) {
        self.set_engine_verdict_from(sha256_hex, verdict, threat, score, "rescan");
    }

    /// `set_engine_verdict` with the source written to the verdict history.
    pub fn set_engine_verdict_from(&self, sha256_hex: &str, verdict: &str, threat: Option<&str>, score: f64, source: &str) {
        let Some(sha_bytes) = parse_sha(sha256_hex) else { return };
        self.update(sha_bytes, None, |entry, _| {
            let had_extra = verdict == "unknown" && (entry.threat_name.is_some() || entry.score != 0.0 || !entry.detections.is_empty());
            let was_pending = entry.not_scanned_since.take().is_some();
            let old = std::mem::replace(&mut entry.verdict, verdict.into());
            entry.threat_name = threat.map(IStr::from);
            entry.score = score;
            if verdict == "unknown" {
                entry.detections.clear();
            }
            if old.as_str() == verdict && !had_extra && !was_pending {
                return;
            }
            entry.dirty = true;
            if old.as_str() != verdict {
                let mut c = self.counts.lock().unwrap();
                c.add(&old, -1);
                c.add(verdict, 1);
                drop(c);
                crate::verdict_history::record(&entry.sha256.text(), "engine", Some(&old), verdict, threat, source, "");
            }
        });
    }

    /// Hashes first seen on `date` (YYYY-MM-DD, UTC) with their effective verdict
    /// (a completed human review overrides the engine). Newest first, at most `limit`.
    pub fn first_seen_on(&self, date: &str, limit: usize) -> Vec<(ThreatInsight, String, bool)> {
        self.flush_for_query();
        // Every time on that day starts with it; '~' sorts after any character in them.
        let (lo, hi) = (date.to_string(), format!("{date}~"));
        let rows = self.db.scan(|c| {
            let mut st = c.prepare("SELECT data FROM insights WHERE first_seen >= ?1 AND first_seen < ?2 ORDER BY first_seen DESC LIMIT ?3")?;
            let rows = st.query_map(rusqlite::params![lo, hi, limit as i64], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        });
        log_err("first_seen_on", rows)
            .unwrap_or_default()
            .iter()
            .filter_map(|d| serde_json::from_slice::<ThreatInsight>(d).ok())
            .map(|i| {
                let human = parse_sha(&i.sha256.text()).and_then(|sha| self.reviews.completed_verdict_raw(&sha));
                let is_human = human.is_some();
                let v = human.unwrap_or_else(|| i.verdict.to_string());
                (i, v, is_human)
            })
            .collect()
    }

    /// (verdict, source "human" | "engine" | "unseen", threat name) for one hash.
    pub fn effective(&self, sha256_hex: &str) -> (String, String, Option<String>) {
        if let Some(r) = self.reviews.completed(sha256_hex) {
            return (r.verdict.clone().unwrap_or_default(), "human".into(), r.threat_name.clone());
        }
        match self.engine_verdict(sha256_hex) {
            Some((v, t)) => (v, "engine".into(), t),
            None => ("unknown".into(), "unseen".into(), None),
        }
    }

    /// Engine (verdict, threat name) of one hash, without reading the whole record.
    fn engine_verdict(&self, sha256_hex: &str) -> Option<(String, Option<String>)> {
        let sha = parse_sha(sha256_hex)?;
        if let Some(i) = self.hot.read().unwrap().get(&sha) {
            return Some((i.verdict.to_string(), i.threat_name.as_ref().map(|t| t.to_string())));
        }
        self.stored_verdict(&sha)
    }

    /// Marks a file as waiting for a new scan it cannot get now (no kept sample): the
    /// verdict stays the last one. Returns false for a hash that is not recorded.
    pub fn mark_not_scanned(&self, sha256_hex: &str, source: &str) -> bool {
        let Some(sha) = parse_sha(sha256_hex) else { return false };
        let old = self.update(sha, None, |entry, _| {
            if entry.not_scanned_since.is_some() {
                return None;
            }
            entry.not_scanned_since = Some(Utc::now().to_rfc3339().into());
            entry.dirty = true;
            Some(entry.verdict.to_string())
        });
        match old {
            Some(Some(v)) => {
                crate::verdict_history::record(&sha256_hex.to_ascii_lowercase(), "engine", Some(&v), "not_scanned", None, source, "");
                true
            }
            Some(None) => true,
            None => false,
        }
    }

    /// The file waits for a new scan (see `ThreatInsight::not_scanned_since`).
    pub fn is_not_scanned(&self, sha: &Sha) -> bool {
        if let Some(i) = self.hot.read().unwrap().get(sha) {
            return i.not_scanned_since.is_some();
        }
        self.stored_state(sha).is_some_and(|(_, not_scanned)| not_scanned)
    }

    pub fn needs_new_scan(&self, sha: &Sha) -> bool {
        if let Some(i) = self.hot.read().unwrap().get(sha) {
            return i.verdict == "unknown" || i.not_scanned_since.is_some();
        }
        match self.stored_state(sha) {
            Some((Some(v), not_scanned)) => v == "unknown" || not_scanned,
            Some((None, not_scanned)) => not_scanned || self.load(sha).is_some_and(|i| i.verdict == "unknown"),
            None => false,
        }
    }

    fn stored_state(&self, sha: &Sha) -> Option<(Option<String>, bool)> {
        let sha = *sha;
        let r = self.db.lookup(|c| {
            let mut st = c.prepare_cached(r#"SELECT verdict, instr(data, CAST('"not_scanned_since":' AS BLOB)) > 0 FROM insights WHERE sha = ?1"#)?;
            let mut rows = st.query([&sha[..]])?;
            match rows.next()? {
                Some(r) => Ok(Some((r.get::<_, Option<String>>(0)?, r.get::<_, bool>(1)?))),
                None => Ok(None),
            }
        });
        log_err("stored_state", r).flatten()
    }

    fn stored_verdict(&self, sha: &Sha) -> Option<(String, Option<String>)> {
        let sha = *sha;
        let cols = self.db.lookup(|c| {
            let mut st = c.prepare_cached("SELECT verdict, threat FROM insights WHERE sha = ?1")?;
            let mut rows = st.query([&sha[..]])?;
            match rows.next()? {
                Some(r) => Ok(Some((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?))),
                None => Ok(None),
            }
        });
        match log_err("effective", cols).flatten()? {
            (Some(v), t) => Some((v, t)),
            // Columns not filled yet (written by an older version): read the record.
            (None, _) => self.load(&sha).map(|i| (i.verdict.to_string(), i.threat_name.as_ref().map(|t| t.to_string()))),
        }
    }

    /// Engine verdicts of these hashes (the ones that are recorded): memory first, as
    /// it holds the newest state, then SQLite.
    fn engine_verdicts(&self, shas: &[Sha]) -> HashMap<Sha, String> {
        let mut out = HashMap::with_capacity(shas.len());
        let mut missing = Vec::new();
        {
            let g = self.hot.read().unwrap();
            for sha in shas {
                match g.get(sha) {
                    Some(i) => {
                        out.insert(*sha, i.verdict.to_string());
                    }
                    None => missing.push(*sha),
                }
            }
        }
        for chunk in missing.chunks(IN_CHUNK) {
            let sql = format!("SELECT sha, verdict FROM insights WHERE verdict IS NOT NULL AND sha IN ({})", vec!["?"; chunk.len()].join(","));
            let r = self.db.lookup(|c| {
                let mut st = c.prepare_cached(&sql)?;
                let rows = st.query_map(rusqlite::params_from_iter(chunk.iter().map(|s| &s[..])), |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
                })?;
                for row in rows {
                    let (sha, v) = row?;
                    if let Ok(sha) = Sha::try_from(sha.as_slice()) {
                        out.insert(sha, v);
                    }
                }
                Ok(())
            });
            log_err("engine_verdicts", r);
        }
        out
    }

    /// Calls `f(sha, engine verdict)` for every record with one of these engine
    /// verdicts. Reads only the verdict index (it holds the hash), never the records:
    /// `unknown` is most of the table, and reading every record's JSON made each queue
    /// page read the whole database.
    fn for_each_with_verdict(&self, verdicts: &[&str], mut f: impl FnMut(Sha, &str)) {
        self.flush_for_query();
        let sql = format!("SELECT sha, verdict FROM insights INDEXED BY insights_verdict WHERE verdict IN ({})", vec!["?"; verdicts.len()].join(","));
        let r = self.db.scan(|c| {
            let mut st = c.prepare(&sql)?;
            let mut rows = st.query(rusqlite::params_from_iter(verdicts.iter()))?;
            while let Some(row) = rows.next()? {
                let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                let v: String = row.get(1)?;
                f(sha, &v);
            }
            Ok(())
        });
        log_err("for_each_with_verdict", r);
    }

    /// First file name of each of these hashes (the ones that have one).
    fn first_names(&self, shas: &[Sha]) -> HashMap<Sha, String> {
        let mut out = HashMap::new();
        for chunk in shas.chunks(IN_CHUNK) {
            let sql = format!("SELECT sha, json_extract(data, '$.file_names[0]') FROM insights WHERE sha IN ({})", vec!["?"; chunk.len()].join(","));
            let r = self.db.lookup(|c| {
                let mut st = c.prepare_cached(&sql)?;
                let rows = st.query_map(rusqlite::params_from_iter(chunk.iter().map(|s| &s[..])), |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<String>>(1)?))
                })?;
                for row in rows {
                    if let (Ok(sha), Some(name)) = row.map(|(s, n)| (Sha::try_from(s.as_slice()), n))? {
                        out.insert(sha, name);
                    }
                }
                Ok(())
            });
            log_err("first_names", r);
        }
        out
    }

    /// The records of these hashes (SHA-256 hex, either case) that are known, by the
    /// lower-case hex: memory first, the rest from SQLite 500 at a time. For lists of
    /// many files, where one `get` each was one query each.
    pub fn get_many(&self, shas: &[&str]) -> HashMap<String, ThreatInsight> {
        let mut out = HashMap::with_capacity(shas.len());
        let mut missing: Vec<Sha> = Vec::new();
        {
            let g = self.hot.read().unwrap();
            for s in shas {
                let Some(sha) = parse_sha(s) else { continue };
                match g.get(&sha) {
                    Some(i) => {
                        out.insert(hex::encode(sha), i.clone());
                    }
                    None => missing.push(sha),
                }
            }
        }
        for chunk in missing.chunks(IN_CHUNK) {
            let sql = format!("SELECT sha, data FROM insights WHERE sha IN ({})", vec!["?"; chunk.len()].join(","));
            let r = self.db.lookup(|c| {
                let mut st = c.prepare_cached(&sql)?;
                let mut rows = st.query(rusqlite::params_from_iter(chunk.iter().map(|s| &s[..])))?;
                while let Some(row) = rows.next()? {
                    let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                    if let Ok(i) = serde_json::from_slice::<ThreatInsight>(row.get_ref(1)?.as_blob()?) {
                        out.insert(hex::encode(sha), i);
                    }
                }
                Ok(())
            });
            log_err("get_many", r);
        }
        out
    }

    /// Archive mode: lines the main server added to `threat_insights.jsonl` (a later
    /// line for the same hash replaces the earlier one). Nothing is removed: a rewritten
    /// file (`reset`) is read again and its lines replace what they cover. The counts
    /// follow with `resync` once a batch is written.
    pub fn archive_ingest(&self, lines: &[String], _reset: bool) {
        let mut g = self.hot.write().unwrap();
        for line in lines {
            if let Ok(mut item) = serde_json::from_str::<ThreatInsight>(line) {
                if let Some(sha) = parse_sha(&item.sha256.text()) {
                    item.dirty = true;
                    g.insert(sha, item);
                }
            }
        }
    }

    /// Every hash users sent (effective verdict: a completed human review first), for
    /// the public ML dataset numbers.
    pub fn user_files(&self) -> Vec<crate::dataset::UserFile> {
        self.flush_for_query();
        let mut out = Vec::new();
        let r = self.db.scan(|c| {
            let mut st = c.prepare("SELECT sha, verdict, json_extract(data, '$.file_names'), first_seen FROM insights WHERE verdict IS NOT NULL")?;
            let mut rows = st.query([])?;
            while let Some(row) = rows.next()? {
                let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                let verdict: String = row.get(1)?;
                let names: Vec<String> = row
                    .get::<_, Option<String>>(2)?
                    .and_then(|j| serde_json::from_str(&j).ok())
                    .unwrap_or_default();
                let first: String = row.get::<_, Option<String>>(3)?.unwrap_or_default();
                let human = self.reviews.completed_verdict_raw(&sha);
                out.push(crate::dataset::UserFile::new(&hex::encode(sha), human.as_deref().unwrap_or(&verdict), &names, &first));
            }
            Ok(())
        });
        log_err("user_files", r);
        out
    }

    pub fn get(&self, sha256_hex: &str) -> Option<ThreatInsight> {
        let sha_bytes = parse_sha(sha256_hex)?;
        if let Some(i) = self.hot.read().unwrap().get(&sha_bytes) {
            return Some(i.clone());
        }
        self.load(&sha_bytes)
    }

    /// Puts every hash whose effective verdict is still open (unknown, suspicious or
    /// possible_clean, no completed human review) into the human analysis queue if it
    /// is not there yet, so the queue matches the "Unknown" / "Suspicious" counts.
    /// Covers files recorded before auto-queueing existed and queue entries removed by
    /// hand. Only files kept on the server (`is_kept`, upper-case SHA-256): a hash
    /// without its file cannot be analysed. Returns how many were added.
    pub fn sync_review_queue(&self, is_kept: &dyn Fn(&str) -> bool) -> usize {
        let mut open: Vec<(Sha, String)> = Vec::new();
        self.for_each_with_verdict(&crate::human_review::AUTO_QUEUE_VERDICTS, |sha, verdict| {
            let hex = hex::encode(sha);
            if self.reviews.get(&hex).is_none() && !self.reviews.was_removed(&hex) && is_kept(&hex.to_ascii_uppercase()) {
                open.push((sha, verdict.to_string()));
            }
        });
        let names = self.first_names(&open.iter().map(|(s, _)| *s).collect::<Vec<_>>());
        open.iter()
            .filter(|(sha, verdict)| self.reviews.enqueue(&hex::encode(sha), "auto", Some(verdict), names.get(sha).map(String::as_str)).is_ok())
            .count()
    }

    /// Removes from the queue the pending files whose file is not kept on the server
    /// (never uploaded, dropped by the quota, offloaded): they cannot be analysed and
    /// may never come. Files an analyst has started stay. A file uploaded later is
    /// queued again by the scan. Returns how many were removed.
    pub fn prune_queue_without_file(&self, is_kept: &dyn Fn(&str) -> bool) -> usize {
        self.reviews
            .pending(usize::MAX)
            .into_iter()
            .filter(|r| r.started_by.is_empty() && !is_kept(&r.sha256.to_ascii_uppercase()))
            .filter(|r| self.reviews.remove(&r.sha256))
            .count()
    }

    /// Puts files with this engine verdict and no human review into the queue again,
    /// also the ones an analyst removed when `include_removed`. Only files kept on the
    /// server. Returns how many.
    pub fn requeue(&self, verdict: &str, include_removed: bool, is_kept: &dyn Fn(&str) -> bool) -> Result<usize, String> {
        let mut shas: Vec<Sha> = Vec::new();
        self.for_each_with_verdict(&[verdict], |sha, _| {
            let hex = hex::encode(sha);
            if self.reviews.get(&hex).is_none()
                && (include_removed || !self.reviews.was_removed(&hex))
                && is_kept(&hex.to_ascii_uppercase())
            {
                shas.push(sha);
            }
        });
        let mut names = self.first_names(&shas);
        let todo: Vec<(String, Option<String>)> = shas.iter().map(|s| (hex::encode(s), names.remove(s))).collect();
        let mut n = 0;
        for (sha, name) in &todo {
            match self.reviews.enqueue(sha, "requeue", Some(verdict), name.as_deref()) {
                Ok(_) => n += 1,
                Err(e) if n == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(n)
    }

    /// Why engine-flagged files are or are not in the human queue, per engine verdict:
    /// {verdict: {total, pending, done, removed, missing}}. `missing` should be 0 after
    /// `sync_review_queue`; anything else there is a bug or a full queue.
    pub fn queue_coverage(&self) -> serde_json::Value {
        let mut acc: HashMap<String, [u64; 5]> = crate::human_review::AUTO_QUEUE_VERDICTS.iter().map(|v| (v.to_string(), [0; 5])).collect();
        self.for_each_with_verdict(&crate::human_review::AUTO_QUEUE_VERDICTS, |sha, verdict| {
            let Some(a) = acc.get_mut(verdict) else { return };
            let hex = hex::encode(sha);
            a[0] += 1;
            match self.reviews.get(&hex) {
                Some(r) if r.is_completed() => a[2] += 1,
                Some(_) => a[1] += 1,
                None if self.reviews.was_removed(&hex) => a[3] += 1,
                None => a[4] += 1,
            }
        });
        let mut out = serde_json::Map::new();
        for v in crate::human_review::AUTO_QUEUE_VERDICTS {
            let [total, pending, done, removed, missing] = acc[v];
            out.insert(v.to_string(), serde_json::json!({"total": total, "pending": pending, "done": done, "removed": removed, "missing": missing}));
        }
        serde_json::Value::Object(out)
    }

    /// Client IPs that sent files (from `ThreatInsight::sightings`), most files first.
    /// `ip_q` / `path_q` are case-insensitive substrings of the IP / full path; with a
    /// path filter only the matching sightings are counted. Dashboard only.
    pub fn sources(&self, ip_q: &str, path_q: &str, limit: usize) -> Vec<serde_json::Value> {
        let ip_q = ip_q.trim().to_ascii_lowercase();
        let path_q = path_q.trim().to_lowercase();
        #[derive(Default)]
        struct Acc {
            files: u64,
            uploads: u64,
            paths: std::collections::HashSet<String>,
            first: String,
            last: String,
            verdicts: HashMap<String, u64>,
        }
        let mut acc: HashMap<String, Acc> = HashMap::new();
        self.flush_for_query();
        // Both tables in hash order (their keys), read side by side: the IPs counted
        // for one file are known while its rows pass, and no record is looked up one by
        // one (a join did that, a random read per sighting).
        let r = self.db.scan(|c| {
            let mut st = c.prepare("SELECT sha, ip, path, first_seen, last_seen, count FROM sightings ORDER BY sha")?;
            let mut vst = c.prepare("SELECT sha, verdict FROM insights ORDER BY sha")?;
            let mut rows = st.query([])?;
            let mut verdicts = vst.query([])?;
            let mut next_verdict: Option<(Sha, Option<String>)> = None;
            let mut cur: Option<Sha> = None;
            let mut seen_ips: Vec<String> = Vec::new();
            let mut verdict = String::new();
            let mut recorded = false;
            while let Some(row) = rows.next()? {
                let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                if cur != Some(sha) {
                    cur = Some(sha);
                    seen_ips.clear();
                    let mut engine = None;
                    recorded = false;
                    loop {
                        match &next_verdict {
                            Some((s, _)) if *s > sha => break,
                            Some((s, v)) if *s == sha => {
                                engine = v.clone();
                                recorded = true;
                                break;
                            }
                            _ => match verdicts.next()? {
                                Some(v) => {
                                    let s = Sha::try_from(v.get_ref(0)?.as_blob()?).unwrap_or([0; 32]);
                                    next_verdict = Some((s, v.get(1)?));
                                }
                                None => break,
                            },
                        }
                    }
                    verdict = self.reviews.completed_verdict_raw(&sha).or(engine).unwrap_or_default();
                }
                if !recorded {
                    continue;
                }
                let ip: String = row.get(1)?;
                let path: String = row.get(2)?;
                if !ip_q.is_empty() && !ip.to_ascii_lowercase().contains(&ip_q) {
                    continue;
                }
                if !path_q.is_empty() && !path.to_lowercase().contains(&path_q) {
                    continue;
                }
                let (first, last): (String, String) = (row.get(3)?, row.get(4)?);
                let a = acc.entry(ip.clone()).or_default();
                a.uploads += row.get::<_, i64>(5)?.max(0) as u64;
                if !path.is_empty() {
                    a.paths.insert(path.to_lowercase());
                }
                if a.first.is_empty() || first < a.first {
                    a.first = first;
                }
                if last > a.last {
                    a.last = last;
                }
                if !seen_ips.contains(&ip) {
                    seen_ips.push(ip);
                    a.files += 1;
                    *a.verdicts.entry(verdict.clone()).or_default() += 1;
                }
            }
            Ok(())
        });
        log_err("sources", r);
        let mut out: Vec<(u64, serde_json::Value)> = acc
            .into_iter()
            .map(|(ip, a)| {
                (a.files, serde_json::json!({
                    "ip": ip, "files": a.files, "uploads": a.uploads, "paths": a.paths.len(),
                    "first_seen": a.first, "last_seen": a.last, "verdicts": a.verdicts,
                }))
            })
            .collect();
        out.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1["last_seen"].as_str().cmp(&a.1["last_seen"].as_str())));
        out.into_iter().take(limit).map(|(_, v)| v).collect()
    }

    /// Files one client IP sent (exact IP), newest first, with the full paths it sent
    /// them from. `path_q` keeps only sightings whose path contains it. Dashboard only.
    pub fn files_from_ip(&self, ip: &str, path_q: &str, limit: usize) -> (usize, Vec<serde_json::Value>) {
        let ip = ip.trim();
        let path_q = path_q.trim().to_lowercase();
        self.flush_for_query();
        let mut out: Vec<(String, serde_json::Value)> = Vec::new();
        let r = self.db.scan(|c| {
            let mut st = c.prepare("SELECT data FROM insights WHERE sha IN (SELECT sha FROM sightings WHERE ip = ?1)")?;
            let mut rows = st.query([ip])?;
            while let Some(row) = rows.next()? {
                let Ok(i) = serde_json::from_slice::<ThreatInsight>(row.get_ref(0)?.as_blob()?) else { continue };
                let mine: Vec<&Sighting> = i
                    .sightings
                    .iter()
                    .filter(|s| s.ip == ip && (path_q.is_empty() || s.path.to_lowercase().contains(&path_q)))
                    .collect();
                if mine.is_empty() {
                    continue;
                }
                let last = mine.iter().map(|s| &s.last_seen).max().map(|t| t.to_string()).unwrap_or_default();
                let human = parse_sha(&i.sha256.text()).and_then(|sha| self.reviews.completed_verdict_raw(&sha));
                let v = serde_json::json!({
                    "sha256": i.sha256.to_ascii_lowercase(),
                    "file_names": i.file_names,
                    "file_size": i.file_size,
                    "verdict": human.clone().unwrap_or_else(|| i.verdict.to_string()),
                    "human": human.is_some(),
                    "threat": i.threat_name,
                    "detections": i.detections,
                    "seen_count": i.seen_count,
                    "sources": i.sightings.iter().map(|s| s.ip.as_str()).collect::<std::collections::HashSet<_>>().len(),
                    "sightings": mine,
                });
                out.push((last, v));
            }
            Ok(())
        });
        log_err("files_from_ip", r);
        let total = out.len();
        out.sort_by(|a, b| b.0.cmp(&a.0));
        (total, out.into_iter().take(limit).map(|(_, v)| v).collect())
    }

    /// Malicious and suspicious files by malware type: counts per category and the
    /// most common families, for all files and for the ones first seen in the last
    /// `recent_days`. `public` leaves out nothing sensitive: names only, no hashes.
    pub fn type_stats(&self, recent_days: i64) -> serde_json::Value {
        use std::collections::BTreeMap;
        let since = Stamp::new(&(Utc::now() - chrono::Duration::days(recent_days)).to_rfc3339());
        #[derive(Default)]
        struct Acc {
            categories: BTreeMap<&'static str, u64>,
            platforms: BTreeMap<&'static str, u64>,
            families: HashMap<(String, &'static str), u64>,
            /// Matched signatures (layer, rule) of the engine's last scan; dashboard only.
            signatures: HashMap<(String, String), u64>,
            total: u64,
            exact: u64,
        }
        let (mut all, mut recent) = (Acc::default(), Acc::default());
        let mut add = |threat: Option<&str>, first_seen: &str, detections: &[DetectionRef]| {
            let c = crate::naming::classify(threat.unwrap_or(""));
            let is_recent = Stamp::new(first_seen) >= since;
            for acc in std::iter::once(&mut all).chain(is_recent.then_some(&mut recent)) {
                acc.total += 1;
                acc.exact += c.exact as u64;
                *acc.categories.entry(c.category).or_default() += 1;
                if !c.platform.is_empty() {
                    *acc.platforms.entry(c.platform).or_default() += 1;
                }
                if !c.family.is_empty() {
                    *acc.families.entry((c.family.clone(), c.category)).or_default() += 1;
                }
                for d in detections {
                    *acc.signatures.entry((d.layer.clone(), d.name.clone())).or_default() += 1;
                }
            }
        };
        let detections_of = |j: Option<String>| -> Vec<DetectionRef> { j.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default() };
        self.flush_for_query();
        // Engine verdicts of the files no analyst answered...
        let r = self.db.scan(|c| {
            let mut st = c.prepare(
                "SELECT sha, threat, first_seen, json_extract(data, '$.detections') FROM insights WHERE verdict IN ('malicious', 'suspicious')",
            )?;
            let mut rows = st.query([])?;
            while let Some(row) = rows.next()? {
                let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                if self.reviews.completed_raw(&sha).is_some() {
                    continue;
                }
                let threat: Option<String> = row.get(1)?;
                let first: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
                add(threat.as_deref(), &first, &detections_of(row.get(3)?));
            }
            Ok(())
        });
        log_err("type_stats", r);
        // ...and the human verdicts, whatever the engine said.
        let human: Vec<(Sha, Option<String>)> = self
            .reviews
            .completed_overrides()
            .into_iter()
            .filter(|(_, v, _)| matches!(v.as_deref(), Some("malicious" | "suspicious")))
            .map(|(sha, _, t)| (sha, t))
            .collect();
        for chunk in human.chunks(IN_CHUNK) {
            let sql = format!(
                "SELECT sha, first_seen, json_extract(data, '$.detections') FROM insights WHERE sha IN ({})",
                vec!["?"; chunk.len()].join(",")
            );
            let threats: HashMap<Sha, Option<String>> = chunk.iter().cloned().collect();
            let r = self.db.scan(|c| {
                let mut st = c.prepare(&sql)?;
                let mut rows = st.query(rusqlite::params_from_iter(chunk.iter().map(|(s, _)| &s[..])))?;
                while let Some(row) = rows.next()? {
                    let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                    let first: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
                    add(threats.get(&sha).cloned().flatten().as_deref(), &first, &detections_of(row.get(2)?));
                }
                Ok(())
            });
            log_err("type_stats", r);
        }
        let out = |a: Acc| {
            let mut fam: Vec<_> = a.families.into_iter().collect();
            fam.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0 .0.cmp(&y.0 .0)));
            fam.truncate(20);
            let mut sig: Vec<_> = a.signatures.into_iter().collect();
            sig.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
            sig.truncate(30);
            serde_json::json!({
                "signatures": sig.into_iter().map(|((l, r), n)| serde_json::json!({"layer": l, "name": r, "count": n})).collect::<Vec<_>>(),
                "total": a.total,
                "exact": a.exact,
                "categories": a.categories,
                "platforms": a.platforms,
                "families": fam.into_iter().map(|((f, c), n)| serde_json::json!({"family": f, "category": c, "count": n})).collect::<Vec<_>>(),
            })
        };
        serde_json::json!({ "all": out(all), "recent": out(recent), "recent_days": recent_days })
    }

    /// (SHA-256 upper-case hex, verdict) of every hash whose engine verdict is one of
    /// `verdicts` and no analyst has answered (a completed human review is the verdict and
    /// stays as it is).
    pub fn engine_verdict_hashes(&self, verdicts: &[&str]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        self.for_each_with_verdict(verdicts, |sha, verdict| {
            if self.reviews.completed_verdict_raw(&sha).is_none() {
                out.push((hex::encode_upper(sha), verdict.to_string()));
            }
        });
        out
    }

    /// SHA-256 (upper-case hex) of every hash whose final verdict (human first) is
    /// unknown.
    pub fn unknown_hashes(&self) -> Vec<String> {
        self.flush_for_query();
        let known = |v: &str| KNOWN_VERDICTS.contains(&v);
        let mut out = Vec::new();
        // Engine verdict not a known one, unless an analyst gave a known one...
        let sql = format!(
            "SELECT sha FROM insights WHERE verdict NOT IN ({})",
            KNOWN_VERDICTS.iter().map(|v| format!("'{v}'")).collect::<Vec<_>>().join(",")
        );
        let r = self.db.scan(|c| {
            let mut st = c.prepare(&sql)?;
            let mut rows = st.query([])?;
            while let Some(row) = rows.next()? {
                let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                if !self.reviews.completed_verdict_raw(&sha).is_some_and(|h| known(&h)) {
                    out.push(hex::encode_upper(sha));
                }
            }
            Ok(())
        });
        log_err("unknown_hashes", r);
        // ...and recorded files an analyst answered with something else.
        let human: Vec<Sha> = self
            .reviews
            .completed_overrides()
            .into_iter()
            .filter_map(|(sha, v, _)| v.filter(|v| !known(v)).map(|_| sha))
            .collect();
        for (sha, engine) in self.engine_verdicts(&human) {
            if known(&engine) {
                out.push(hex::encode_upper(sha));
            }
        }
        out
    }

    pub fn stats(&self) -> ThreatIntelStats {
        let Counts { hashes, sightings, mut by_verdict } = self.counts.lock().unwrap().clone();
        // A completed human review overrides the engine verdict.
        let human: Vec<(Sha, String)> = self.reviews.completed_overrides().into_iter().filter_map(|(sha, v, _)| Some((sha, v?))).collect();
        let engine = self.engine_verdicts(&human.iter().map(|(s, _)| *s).collect::<Vec<_>>());
        for (sha, v) in &human {
            if let Some(e) = engine.get(sha) {
                if let Some(n) = by_verdict.get_mut(e) {
                    *n = n.saturating_sub(1);
                }
                *by_verdict.entry(v.clone()).or_default() += 1;
            }
        }
        let n = |v: &str| by_verdict.get(v).copied().unwrap_or(0) as usize;
        let named: usize = KNOWN_VERDICTS.iter().map(|v| n(v)).sum();
        ThreatIntelStats {
            total_unique_hashes: hashes as usize,
            total_sightings: sightings,
            malicious_count: n("malicious"),
            suspicious_count: n("suspicious"),
            clean_count: n("clean"),
            possible_clean_count: n("possible_clean"),
            unknown_count: (hashes as usize).saturating_sub(named),
        }
    }
}

/// The SHA-256 of an insight line without parsing it: the writer puts `sha256` first,
/// so a line starts with `{"sha256":"<64 hex>"`. `None` for any other shape.
fn line_sha_fast(line: &[u8]) -> Option<Sha> {
    const PREFIX: &[u8] = b"{\"sha256\":\"";
    let hex = line.strip_prefix(PREFIX)?.get(..64)?;
    (line.get(PREFIX.len() + 64) == Some(&b'"')).then_some(())?;
    parse_sha(std::str::from_utf8(hex).ok()?)
}

/// The SHA-256 of an insight line: the fast prefix, else the `sha256` field parsed.
fn line_sha(line: &[u8]) -> Option<Sha> {
    #[derive(Deserialize)]
    struct OnlySha {
        sha256: String,
    }
    line_sha_fast(line).or_else(|| parse_sha(&serde_json::from_slice::<OnlySha>(line).ok()?.sha256))
}

/// Calls `f(offset, line)` for every line of `path` (line without its line break).
fn for_each_line(path: &Path, mut f: impl FnMut(u64, &[u8])) -> std::io::Result<()> {
    let mut r = BufReader::with_capacity(8 << 20, File::open(path)?);
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut offset = 0u64;
    loop {
        buf.clear();
        let n = r.read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        let line = buf.strip_suffix(b"\n").unwrap_or(&buf);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        f(offset, line);
        offset += n as u64;
    }
}

/// The last valid entry of every hash in `threat_insights.jsonl`, the same result as
/// parsing every line in order and keeping the last one that parses, without parsing
/// every line: the file is append-only and every update writes the whole entry again,
/// so most lines are superseded (6.5 GB to parse at each start). The file is only read.
///
/// 1. one pass finds the offset of each hash's last line from the line prefix alone;
/// 2. a second pass takes those lines and parses them on all cores, a batch of
///    `LOAD_BATCH_BYTES` at a time (all of them raw at once, next to their parsed
///    copies, made the start the peak of the process: memory the heap kept after);
/// 3. a hash whose last line does not parse (cut short by a crash) gets its lines
///    parsed in order, keeping the last valid one, as before.
fn load_latest_insights(path: &Path) -> std::io::Result<HashMap<Sha, ThreatInsight>> {
    const LOAD_BATCH_BYTES: usize = 64 << 20;
    let mut last: HashMap<Sha, u64> = HashMap::new();
    for_each_line(path, |off, line| {
        if let Some(sha) = line_sha(line) {
            last.insert(sha, off);
        }
    })?;
    let mut map = HashMap::with_capacity(last.len());
    let mut wanted: std::collections::HashSet<u64> = last.into_values().collect();

    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(1, 16);
    let mut broken: std::collections::HashSet<Sha> = std::collections::HashSet::new();
    let mut parse_batch = |lines: &mut Vec<Vec<u8>>, map: &mut HashMap<Sha, ThreatInsight>| {
        let chunk = lines.len().div_ceil(threads).max(1);
        let parsed: Vec<Vec<Result<ThreatInsight, Option<Sha>>>> = std::thread::scope(|s| {
            let handles: Vec<_> = lines
                .chunks(chunk)
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .map(|l| serde_json::from_slice::<ThreatInsight>(l).map_err(|_| line_sha(l)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
        });
        lines.clear();
        for r in parsed.into_iter().flatten() {
            match r {
                Ok(item) => {
                    if let Some(sha) = parse_sha(&item.sha256.text()) {
                        map.insert(sha, item);
                    }
                }
                Err(Some(sha)) => {
                    broken.insert(sha);
                }
                Err(None) => {}
            }
        }
    };
    let (mut lines, mut bytes): (Vec<Vec<u8>>, usize) = (Vec::new(), 0);
    for_each_line(path, |off, line| {
        if wanted.remove(&off) {
            bytes += line.len();
            lines.push(line.to_vec());
            if bytes >= LOAD_BATCH_BYTES {
                parse_batch(&mut lines, &mut map);
                bytes = 0;
            }
        }
    })?;
    parse_batch(&mut lines, &mut map);
    drop((lines, wanted, parse_batch));
    if !broken.is_empty() {
        for_each_line(path, |_, line| {
            if line_sha(line).is_some_and(|s| broken.contains(&s)) {
                if let Ok(item) = serde_json::from_slice::<ThreatInsight>(line) {
                    if let Some(sha) = parse_sha(&item.sha256.text()) {
                        map.insert(sha, item);
                    }
                }
            }
        })?;
    }
    Ok(map)
}

/// `threat_insights.db` next to `threat_insights.jsonl`. The archive server keeps its
/// own `threat_insights_archive.db`, filled from the mirrored `.jsonl`.
fn db_path_for(jsonl_path: &Path, archive: bool) -> PathBuf {
    if archive {
        jsonl_path.with_file_name("threat_insights_archive.db")
    } else {
        jsonl_path.with_extension("db")
    }
}

fn open_db(jsonl_path: &Path, archive: bool) -> Arc<crate::insight_db::InsightDb> {
    let p = db_path_for(jsonl_path, archive);
    let opened = if crate::config::is_standby() { crate::insight_db::InsightDb::open(&p) } else { crate::insight_db::InsightDb::open_upgraded(&p) };
    match opened {
        Ok(db) => Arc::new(db),
        Err(e) => {
            // Telemetry still works for this run; nothing of it is kept.
            let tmp = std::env::temp_dir().join(format!("multron_threat_insights_{}.db", std::process::id()));
            eprintln!("[telemetry] opening SQLite {} failed: {e}; using {} for this run", p.display(), tmp.display());
            Arc::new(crate::insight_db::InsightDb::open(&tmp).expect("cannot open any threat insights database"))
        }
    }
}

/// The record as written to SQLite: its JSON and the columns copied from it.
fn insight_row(sha: Sha, item: &ThreatInsight) -> Option<crate::insight_db::InsightRow> {
    Some(crate::insight_db::InsightRow {
        sha,
        data: serde_json::to_vec(item).ok()?,
        verdict: item.verdict.to_string(),
        threat: item.threat_name.as_ref().map(|t| t.to_string()),
        first_seen: item.first_seen.to_string(),
        last_seen: item.last_seen.to_string(),
        seen_count: item.seen_count as i64,
        sightings: item
            .sightings
            .iter()
            .map(|s| crate::insight_db::SightingRow {
                ip: s.ip.to_string(),
                path: s.path.to_string(),
                first_seen: s.first_seen.to_string(),
                last_seen: s.last_seen.to_string(),
                count: s.count as i64,
            })
            .collect(),
    })
}

/// Logs a failed SQLite call; `None` then.
fn log_err<T>(what: &str, r: rusqlite::Result<T>) -> Option<T> {
    r.map_err(|e| eprintln!("[telemetry] SQLite {what} failed: {e}")).ok()
}

/// First start with SQLite: the records of the old `threat_insights.jsonl` are moved
/// in once (the file itself is left as it is).
fn migrate_jsonl(db: &crate::insight_db::InsightDb, jsonl_path: &Path) {
    if db.count().unwrap_or(1) != 0 || !jsonl_path.exists() {
        return;
    }
    eprintln!("[telemetry] SQLite is empty, migrating from {}...", jsonl_path.display());
    let map = match load_latest_insights(jsonl_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[telemetry] reading {} failed: {e}", jsonl_path.display());
            return;
        }
    };
    let rows: Vec<_> = map.iter().filter_map(|(sha, item)| insight_row(*sha, item)).collect();
    drop(map);
    for chunk in rows.chunks(2000) {
        log_err("migration", db.upsert_batch(chunk));
    }
    eprintln!("[telemetry] Migrated {} records into SQLite", rows.len());
}

/// Fills the columns of rows written without them (an older version, the server that
/// ran during a seamless update).
fn fill_stale_columns(db: &crate::insight_db::InsightDb) {
    let mut after: Sha = [0u8; 32];
    let mut n = 0usize;
    loop {
        let Some(batch) = log_err("stale_rows", db.stale_rows(&after, 5000)) else { return };
        let Some(last) = batch.last() else { break };
        after = last.0;
        let rows: Vec<_> = batch
            .iter()
            .map(|(sha, seq, data)| {
                let row = serde_json::from_slice::<ThreatInsight>(data).ok().and_then(|i| insight_row(*sha, &i));
                (*seq, *sha, row)
            })
            .collect();
        n += rows.len();
        log_err("fill_columns", db.fill_columns(&rows));
    }
    if n > 0 {
        eprintln!("[telemetry] filled the query columns of {n} records");
    }
}

/// Engine verdict counts of every record, from SQLite.
fn recount(db: &crate::insight_db::InsightDb) -> Counts {
    let mut c = Counts::default();
    let r = db.scan(|conn| {
        let mut st = conn.prepare(
            "SELECT verdict, COUNT(*), COALESCE(SUM(seen_count), 0) FROM insights WHERE verdict IS NOT NULL GROUP BY verdict",
        )?;
        let mut rows = st.query([])?;
        while let Some(row) = rows.next()? {
            let (v, n, s): (String, i64, i64) = (row.get(0)?, row.get(1)?, row.get(2)?);
            c.hashes += n as u64;
            c.sightings += s.max(0) as u64;
            c.by_verdict.insert(v, n as u64);
        }
        Ok(())
    });
    log_err("recount", r);
    c
}

/// Writes what is pending (not on a standby, which must not write) and counts again.
/// `drop_clean`: another process wrote the database (seamless update), so records in
/// memory that are not changes of ours may be older than SQLite. Holds the records
/// while it counts, so no change falls between the two.
fn resync(
    db: &crate::insight_db::InsightDb,
    hot: &RwLock<HashMap<Sha, ThreatInsight>>,
    counts: &Mutex<Counts>,
    drop_clean: bool,
) {
    let mut g = hot.write().unwrap();
    if !crate::config::is_standby() {
        let rows = rows_of(&take_dirty(&mut g));
        write_rows(db, &rows, &mut g);
    }
    if drop_clean {
        g.retain(|_, i| i.dirty);
    }
    *counts.lock().unwrap() = recount(db);
}

/// The records marked `dirty`, as rows to write; the mark is cleared.
fn take_dirty(g: &mut HashMap<Sha, ThreatInsight>) -> Vec<(Sha, ThreatInsight)> {
    g.iter_mut()
        .filter(|(_, i)| i.dirty)
        .map(|(sha, i)| {
            i.dirty = false;
            (*sha, i.clone())
        })
        .collect()
}

fn rows_of(taken: &[(Sha, ThreatInsight)]) -> Vec<crate::insight_db::InsightRow> {
    taken.iter().filter_map(|(sha, i)| insight_row(*sha, i)).collect()
}

/// Writes the rows; a batch that fails is marked `dirty` again (in `g`) so the next
/// round tries again. Returns the shas of failed batches.
fn write_rows(db: &crate::insight_db::InsightDb, rows: &[crate::insight_db::InsightRow], g: &mut HashMap<Sha, ThreatInsight>) {
    for sha in failed_rows(db, rows) {
        if let Some(i) = g.get_mut(&sha) {
            i.dirty = true;
        }
    }
}

fn failed_rows(db: &crate::insight_db::InsightDb, rows: &[crate::insight_db::InsightRow]) -> Vec<Sha> {
    let mut failed = Vec::new();
    for chunk in rows.chunks(WRITE_BATCH) {
        if log_err("upsert_batch", db.upsert_batch(chunk)).is_none() {
            failed.extend(chunk.iter().map(|r| r.sha));
        }
    }
    failed
}

/// Message to the insight writer: "write everything now and tell me". Changes are
/// marked on the records themselves (`dirty`); the writer writes them every 2 s.
enum WriterMsg {
    Flush(mpsc::SyncSender<()>),
}

/// Most records written in one transaction.
const WRITE_BATCH: usize = 8192;

fn start_batch_writer(
    db: Arc<crate::insight_db::InsightDb>,
    hot: Arc<RwLock<HashMap<Sha, ThreatInsight>>>,
    counts: Arc<Mutex<Counts>>,
) -> mpsc::Sender<WriterMsg> {
    let (tx, rx) = mpsc::channel::<WriterMsg>();

    std::thread::Builder::new()
        .name("threat_intel_writer".into())
        .spawn(move || {
            // A standby fills the columns the old server left out once it has taken over.
            let mut filled = !crate::config::is_standby();
            loop {
                let msg = rx.recv_timeout(Duration::from_secs(2));
                if !crate::config::is_standby() {
                    if !filled {
                        fill_stale_columns(&db);
                        resync(&db, &hot, &counts, true);
                        filled = true;
                    }
                    flush(&db, &hot);
                }
                match msg {
                    Ok(WriterMsg::Flush(done)) => {
                        let _ = done.send(());
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .expect("failed to spawn threat intel writer thread");

    tx
}

/// Writes the changed records (the records are not held while SQLite writes), then
/// drops written ones beyond `HOT_MAX` (records waiting for the upload a hash check
/// asked for stay while there is room: they carry `pending_uploads`, which is not
/// written).
fn flush(db: &crate::insight_db::InsightDb, hot: &RwLock<HashMap<Sha, ThreatInsight>>) {
    let taken = take_dirty(&mut hot.write().unwrap());
    let rows = rows_of(&taken);
    drop(taken);
    let failed = failed_rows(db, &rows);
    drop(rows);
    let mut g = hot.write().unwrap();
    for sha in failed {
        if let Some(i) = g.get_mut(&sha) {
            i.dirty = true;
        }
    }
    if g.len() > HOT_MAX {
        let excess = g.len() - HOT_MAX * 3 / 4;
        let evict: Vec<Sha> = g
            .iter()
            .filter(|(_, i)| !i.dirty && i.pending_uploads == 0)
            .map(|(sha, _)| *sha)
            .take(excess)
            .collect();
        for sha in evict {
            g.remove(&sha);
        }
    }
    if g.len() > 4 * HOT_MAX {
        g.retain(|_, i| i.dirty);
    }
    if g.capacity() > 4 * HOT_MAX && g.len() < HOT_MAX {
        g.shrink_to(HOT_MAX);
    }
}

/// Records one IP/path sighting (at most `MAX_SIGHTINGS` entries per file).
/// The engine result is recorded without a path and the client's check message with
/// one, so one upload must count once:
/// - no path: refreshes the IP's entry (counted only when that entry has no path
///   either, i.e. a client that never sends paths) or adds a pathless entry;
/// - a path: counts an exact IP+path match, otherwise fills the IP's pathless entry
///   (not counted again) or adds a new entry.
pub fn add_sighting(list: &mut Vec<Sighting>, ip: &str, path: &str, now: &str) {
    let (hit, count) = if path.is_empty() {
        match list.iter().position(|s| s.ip == ip) {
            Some(i) => (Some(i), list[i].path.is_empty()),
            None => (None, false),
        }
    } else if let Some(i) = list.iter().position(|s| s.ip == ip && s.path.eq_ignore_ascii_case(path)) {
        (Some(i), true)
    } else {
        (list.iter().position(|s| s.ip == ip && s.path.is_empty()), false)
    };
    if let Some(i) = hit {
        let s = &mut list[i];
        if s.path.is_empty() && !path.is_empty() {
            s.path = path.into();
        }
        if count {
            s.count += 1;
        }
        s.last_seen = now.into();
        return;
    }
    if list.len() < MAX_SIGHTINGS {
        list.push(Sighting { ip: ip.into(), path: path.into(), first_seen: now.into(), last_seen: now.into(), count: 1 });
    }
}

/// Server-side guard for client folder paths: the client already replaces the profile
/// path with %USERPROFILE%, this catches older or foreign clients. Keeps at most 260
/// characters, drops control characters and replaces a user name in
/// `X:\Users\<name>` / `/home/<name>` / `/Users/<name>` with a placeholder.
/// A full client folder path, kept as sent (user name included): control characters
/// removed, at most 1024 characters, no trailing separator.
pub fn clean_full_folder(path: &str) -> Option<String> {
    let f: String = path.trim().chars().filter(|c| !c.is_control()).take(1024).collect();
    let f = f.trim_end_matches(['\\', '/']).to_string();
    (!f.is_empty()).then_some(f)
}

pub fn sanitize_folder(folder: &str) -> Option<String> {
    let f: String = folder.trim().chars().filter(|c| !c.is_control()).take(260).collect();
    let f = f.trim_end_matches(['\\', '/']).to_string();
    if f.is_empty() {
        return None;
    }
    let lower = f.to_ascii_lowercase();
    // Windows: "C:\Users\name\..." (also forward slashes).
    let b = lower.as_bytes();
    if b.len() >= 9 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') && lower[3..].starts_with("users") && (b.len() == 8 || b[8] == b'\\' || b[8] == b'/') {
        let rest = &f[9.min(f.len())..];
        let (user, tail) = match rest.find(['\\', '/']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let u = user.to_ascii_lowercase();
        if u.is_empty() || u == "public" || u == "default" {
            return Some(f);
        }
        return Some(format!("%USERPROFILE%{tail}"));
    }
    for prefix in ["/home/", "/users/"] {
        if lower.starts_with(prefix) {
            let rest = &f[prefix.len()..];
            let tail = rest.find('/').map(|i| &rest[i..]).unwrap_or("");
            return Some(format!("~{tail}"));
        }
    }
    Some(f)
}

#[cfg(test)]
mod load_tests {
    use super::*;

    /// The old loader: parse every line in order, the last valid one wins.
    fn load_every_line(path: &Path) -> HashMap<Sha, ThreatInsight> {
        let mut m = HashMap::new();
        for line in BufReader::new(File::open(path).unwrap()).lines().map_while(Result::ok) {
            if let Ok(item) = serde_json::from_str::<ThreatInsight>(&line) {
                if let Some(sha) = parse_sha(&item.sha256.text()) {
                    m.insert(sha, item);
                }
            }
        }
        m
    }

    fn line(sha: char, verdict: &str, seen: u64) -> String {
        format!(r#"{{"sha256":"{}","first_seen":"a","last_seen":"b","seen_count":{seen},"verdict":"{verdict}","file_names":[],"score":0.0}}"#, sha.to_string().repeat(64))
    }

    fn same(a: &HashMap<Sha, ThreatInsight>, b: &HashMap<Sha, ThreatInsight>) {
        assert_eq!(a.len(), b.len());
        for (k, v) in a {
            assert_eq!(serde_json::to_string(v).unwrap(), serde_json::to_string(&b[k]).unwrap());
        }
    }

    #[test]
    fn latest_lines_equal_parsing_every_line() {
        let dir = std::env::temp_dir().join(format!("ti_load_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("threat_insights.jsonl");
        let reordered = r#"{"verdict":"clean","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","first_seen":"a","last_seen":"b","seen_count":7,"file_names":[],"score":0.0}"#;
        let body = [
            line('a', "unknown", 1),
            line('b', "clean", 1),
            line('a', "malicious", 2),
            "not json".to_string(),
            reordered.to_string(),
            line('b', "suspicious", 3),
            // Cut short (crash while writing): the earlier valid line of `b` must win.
            line('b', "clean", 9)[..40].to_string(),
        ]
        .join("\r\n");
        std::fs::write(&p, body).unwrap();
        let fast = load_latest_insights(&p).unwrap();
        same(&fast, &load_every_line(&p));
        assert_eq!(fast[&parse_sha(&"b".repeat(64)).unwrap()].verdict, "suspicious");
        assert_eq!(fast[&parse_sha(&"c".repeat(64)).unwrap()].seen_count, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The real file: `TI_FILE=...\threat_insights.jsonl cargo test --release -- --ignored real_file`.
    #[test]
    #[ignore]
    fn real_file_loads_the_same() {
        let Some(p) = std::env::var_os("TI_FILE") else { return };
        let p = PathBuf::from(p);
        let t = std::time::Instant::now();
        let fast = load_latest_insights(&p).unwrap();
        let fast_s = t.elapsed();
        let t = std::time::Instant::now();
        let slow = load_every_line(&p);
        eprintln!("fast {:?}, every line {:?}, {} hashes", fast_s, t.elapsed(), fast.len());
        same(&fast, &slow);
    }

    /// Every line of the real file written back gives the same JSON (the in-memory
    /// forms, `IStr` and `Stamp`, lose nothing):
    /// `TI_FILE=...\threat_insights.jsonl cargo test --release -- --ignored real_file_round_trip`.
    #[test]
    #[ignore]
    fn real_file_round_trip() {
        let Some(p) = std::env::var_os("TI_FILE") else { return };
        let (mut n, mut bad) = (0u64, 0u64);
        for_each_line(&PathBuf::from(p), |_, line| {
            let (Ok(orig), Ok(item)) = (serde_json::from_slice::<serde_json::Value>(line), serde_json::from_slice::<ThreatInsight>(line)) else { return };
            n += 1;
            if serde_json::to_value(&item).unwrap() != orig {
                if bad < 3 {
                    eprintln!("differs: {}", String::from_utf8_lossy(&line[..line.len().min(300)]));
                }
                bad += 1;
            }
        })
        .unwrap();
        eprintln!("{n} lines, {bad} differ");
        assert_eq!(bad, 0);
    }

    /// Process private bytes (Windows; 0 elsewhere).
    fn private_bytes() -> u64 {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("(Get-Process -Id {}).PrivateMemorySize64", std::process::id())])
            .output();
        out.ok().and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok()).unwrap_or(0)
    }

    /// Where the memory of the loaded insights goes, per field, and how many distinct
    /// values each has (what sharing them would save):
    /// `TI_FILE=...\threat_insights.jsonl cargo test --release -- --ignored real_file_memory --nocapture`.
    #[test]
    #[ignore]
    fn real_file_memory() {
        let Some(p) = std::env::var_os("TI_FILE") else { return };
        let before = private_bytes();
        let map = load_latest_insights(&PathBuf::from(p)).unwrap();
        let after = private_bytes();
        // Heap of a String: its capacity plus ~16 B allocator header; 24 B inline.
        let heap = |s: &str| s.len() as u64 + 16;
        #[derive(Default)]
        struct F { n: u64, inline: u64, heap: u64, distinct: std::collections::HashSet<String> }
        let mut f: std::collections::BTreeMap<&str, F> = Default::default();
        let mut add = |name: &'static str, s: &str| {
            let e = f.entry(name).or_default();
            e.n += 1;
            e.inline += 24;
            e.heap += heap(s);
            if e.distinct.len() < 20_000_000 {
                e.distinct.insert(s.to_string());
            }
        };
        let mut vec_hdr = 0u64;
        for i in map.values() {
            add("sha256", &i.sha256.text());
            add("first_seen", &i.first_seen.to_string());
            add("last_seen", &i.last_seen.to_string());
            add("verdict", &i.verdict);
            if let Some(t) = &i.threat_name { add("threat_name", t) }
            for x in &i.file_names { add("file_names", x) }
            for x in &i.folders { add("folders", x) }
            for x in &i.full_folders { add("full_folders", x) }
            for d in &i.detections { add("det.layer", &d.layer); add("det.name", &d.name) }
            for s in &i.sightings {
                add("sight.ip", &s.ip);
                add("sight.path", &s.path);
                add("sight.first_seen", &s.first_seen.to_string());
                add("sight.last_seen", &s.last_seen.to_string());
            }
            vec_hdr += 5 * 16 + (i.file_names.capacity() + i.folders.capacity() + i.full_folders.capacity()) as u64 * 24
                + i.detections.capacity() as u64 * 48 + i.sightings.capacity() as u64 * std::mem::size_of::<Sighting>() as u64;
        }
        let entry = (std::mem::size_of::<ThreatInsight>() + 32 + 8) as u64 * map.len() as u64;
        eprintln!("{} hashes; private bytes {} MB before, {} MB after (+{} MB)", map.len(), before >> 20, after >> 20, after.saturating_sub(before) >> 20);
        eprintln!("map entries (struct {} B + key + slot): {} MB; vec buffers/headers: {} MB", std::mem::size_of::<ThreatInsight>(), entry >> 20, vec_hdr >> 20);
        eprintln!("sizes: SignerSummary {} B, Option<SignerSummary> {} B, Sighting {} B, DetectionRef {} B; signed entries {}", std::mem::size_of::<SignerSummary>(), std::mem::size_of::<Option<SignerSummary>>(), std::mem::size_of::<Sighting>(), std::mem::size_of::<DetectionRef>(), map.values().filter(|i| i.signer.is_some()).count());
        eprintln!("{:<18} {:>11} {:>9} {:>9} {:>11}", "field", "strings", "heap MB", "inline MB", "distinct");
        let mut rows: Vec<_> = f.into_iter().collect();
        rows.sort_by(|a, b| b.1.heap.cmp(&a.1.heap));
        for (k, e) in rows {
            eprintln!("{:<18} {:>11} {:>9} {:>9} {:>11}", k, e.n, e.heap >> 20, e.inline >> 20, e.distinct.len());
        }
    }
}

#[cfg(test)]
mod folder_tests {
    use super::sanitize_folder;

    #[test]
    fn hides_user_names() {
        assert_eq!(sanitize_folder("C:\\Users\\emir\\Desktop\\x").as_deref(), Some("%USERPROFILE%\\Desktop\\x"));
        assert_eq!(sanitize_folder("c:/users/emir").as_deref(), Some("%USERPROFILE%"));
        assert_eq!(sanitize_folder("C:\\Users\\Public\\Downloads").as_deref(), Some("C:\\Users\\Public\\Downloads"));
        assert_eq!(sanitize_folder("%APPDATA%\\Foo\\").as_deref(), Some("%APPDATA%\\Foo"));
        assert_eq!(sanitize_folder("/home/bob/dl").as_deref(), Some("~/dl"));
        assert_eq!(sanitize_folder("C:\\Program Files\\A").as_deref(), Some("C:\\Program Files\\A"));
        assert_eq!(sanitize_folder("  ").as_deref(), None);
    }
}

#[cfg(test)]
mod sighting_tests {
    use super::*;

    #[test]
    fn one_upload_counts_once() {
        let mut l = Vec::new();
        // known hash: engine result first (no path), then the check message's path
        add_sighting(&mut l, "1.2.3.4", "", "t1");
        add_sighting(&mut l, "1.2.3.4", r"C:\Users\a\Downloads", "t1");
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].count, 1);
        assert_eq!(l[0].path, r"C:\Users\a\Downloads");
        // same file again from the same place
        add_sighting(&mut l, "1.2.3.4", "", "t2");
        add_sighting(&mut l, "1.2.3.4", r"c:\users\a\downloads", "t2");
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].count, 2);
        assert_eq!(l[0].last_seen, "t2");
        // another profile on the same computer, another IP
        add_sighting(&mut l, "1.2.3.4", r"C:\Users\b\Desktop", "t3");
        add_sighting(&mut l, "5.6.7.8", "", "t3");
        add_sighting(&mut l, "5.6.7.8", "", "t4");
        assert_eq!(l.len(), 3);
        assert_eq!(l[2].count, 2, "client without paths counts each upload");
    }

    #[test]
    fn check_and_its_upload_are_one_sighting() {
        let path = std::env::temp_dir().join(format!("ti_seen_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let ti = ThreatIntelStore::new(Some(path.clone()));
        let sha = "ab".repeat(32);
        let seen = || ti.get(&sha).unwrap().seen_count;
        // Unknown file: hash check (needs upload), then the scan result of the upload.
        ti.record_check(&sha, Some("a.exe"), Some(10));
        ti.record(&sha, "malicious", Some("Trojan.Win32.X"), Some("a.exe"), Some(10), 1.0);
        assert_eq!(seen(), 1);
        assert_eq!(ti.get(&sha).unwrap().verdict, "malicious");
        // Later: answered from the hash (no upload) and a direct upload without a check.
        ti.record(&sha, "malicious", None, Some("a.exe"), Some(10), 1.0);
        ti.record(&sha, "malicious", None, Some("a.exe"), Some(10), 1.0);
        assert_eq!(seen(), 3);
        // Two clients check before either uploads; one upload, one waiter.
        ti.record_check(&sha, None, None);
        ti.record_check(&sha, None, None);
        ti.record(&sha, "malicious", None, None, None, 1.0);
        ti.record(&sha, "malicious", None, None, None, 1.0);
        assert_eq!(seen(), 5);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    fn store(tag: &str) -> (Arc<ThreatIntelStore>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ti_store_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("threat_insights.jsonl");
        (ThreatIntelStore::new(Some(path)), dir)
    }

    fn sha(i: usize) -> String {
        format!("{:064x}", i as u128 * 0x9e37_79b9_7f4a_7c15 + 1)
    }

    const VERDICTS: [&str; 5] = ["malicious", "suspicious", "clean", "possible_clean", "unknown"];

    /// A file that cannot be rescanned keeps its last verdict, marked not scanned
    /// (the counts do not move), until a new scan result clears the mark.
    #[test]
    fn not_scanned_keeps_the_last_verdict() {
        let (ti, dir) = store("notscanned");
        ti.record(&sha(1), "malicious", Some("Trojan.Win32.Agent"), Some("a.exe"), Some(10), 1.0);
        assert!(ti.mark_not_scanned(&sha(1), "unkept"));
        let i = ti.get(&sha(1)).unwrap();
        assert_eq!((i.verdict.as_str(), i.not_scanned_since.is_some()), ("malicious", true));
        assert_eq!(ti.stats().malicious_count, 1, "still counted as malicious");
        assert!(ti.is_not_scanned(&parse_sha(&sha(1)).unwrap()));
        // Read back from SQLite with the mark.
        assert!(ti.flush(Duration::from_secs(30)));
        ti.hot.write().unwrap().clear();
        assert!(ti.is_not_scanned(&parse_sha(&sha(1)).unwrap()), "read from SQLite");
        assert!(ti.needs_new_scan(&parse_sha(&sha(1)).unwrap()));
        assert!(ti.get(&sha(1)).unwrap().not_scanned_since.is_some());
        // A check (before an upload) does not clear it; the scan result does.
        ti.record_check(&sha(1), None, None);
        assert!(ti.get(&sha(1)).unwrap().not_scanned_since.is_some());
        ti.record(&sha(1), "clean", None, None, None, 0.0);
        let i = ti.get(&sha(1)).unwrap();
        assert_eq!((i.verdict.as_str(), i.not_scanned_since.is_none()), ("clean", true));
        assert!(!ti.mark_not_scanned(&sha(99), "unkept"), "unknown hash");
        ti.record(&sha(2), "clean", None, Some("\"not_scanned_since\":x.exe"), None, 0.0);
        assert!(ti.flush(Duration::from_secs(30)));
        ti.hot.write().unwrap().clear();
        for n in [1, 2] {
            let s = parse_sha(&sha(n)).unwrap();
            assert!(!ti.is_not_scanned(&s) && !ti.needs_new_scan(&s), "record {n} from SQLite");
        }
        drop(ti);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// More records than stay in memory: what is not there any more is read back from
    /// SQLite, and the counts, lists and IP pages agree with what was recorded.
    #[test]
    fn records_beyond_memory_are_read_back_and_counted() {
        let (ti, dir) = store("big");
        let n = HOT_MAX + 10_000;
        for i in 0..n {
            let v = VERDICTS[i % VERDICTS.len()];
            ti.record(&sha(i), v, (v == "malicious").then_some("Trojan.Win32.Agent"), Some(&format!("f{i}.exe")), Some(100), 1.0);
            ti.add_folder(&sha(i), &format!("10.0.0.{}", i % 7), "", &format!("C:\\Users\\a\\dir{}", i % 3));
        }
        // One file seen twice from one IP, once from another.
        ti.record(&sha(0), "malicious", None, None, None, 1.0);
        ti.add_folder(&sha(0), "10.0.0.0", "", "C:\\Users\\a\\dir0");
        ti.add_folder(&sha(0), "192.168.1.1", "", "");
        assert!(ti.flush(Duration::from_secs(60)));
        assert!(ti.hot.read().unwrap().len() <= HOT_MAX, "written records leave memory");

        let st = ti.stats();
        assert_eq!(st.total_unique_hashes, n);
        assert_eq!(st.total_sightings, n as u64 + 1);
        assert_eq!(st.malicious_count, n.div_ceil(5));
        assert_eq!(st.unknown_count, (0..n).filter(|i| i % 5 == 4).count());

        // The counts kept on the way equal the ones SQLite gives.
        ti.resync();
        let again = ti.stats();
        assert_eq!((again.total_unique_hashes, again.total_sightings, again.malicious_count, again.clean_count), (st.total_unique_hashes, st.total_sightings, st.malicious_count, st.clean_count));

        // The first record left memory long ago.
        let first = ti.get(&sha(0)).expect("read back from SQLite");
        assert_eq!((first.seen_count, first.verdict.as_str()), (2, "malicious"));
        assert_eq!(first.sightings.len(), 2);
        assert_eq!(ti.effective(&sha(0)).0, "malicious");
        assert_eq!(ti.effective(&sha(n + 5)).1, "unseen");

        // A change to a record that is only in SQLite.
        ti.set_engine_verdict(&sha(0), "clean", None, 0.0);
        assert_eq!(ti.stats().malicious_count, st.malicious_count - 1);
        assert_eq!(ti.get(&sha(0)).unwrap().seen_count, 2, "loaded, not replaced");

        let unknown = ti.unknown_hashes();
        assert_eq!(unknown.len(), st.unknown_count);
        assert_eq!(ti.engine_verdict_hashes(&["suspicious"]).len(), st.suspicious_count);
        assert_eq!(ti.first_seen_on(&Utc::now().format("%Y-%m-%d").to_string(), 10).len(), 10);

        let src = ti.sources("", "", 100);
        let ip0 = src.iter().find(|v| v["ip"] == "10.0.0.0").unwrap();
        assert_eq!(ip0["files"], n.div_ceil(7));
        assert_eq!(ip0["paths"], 3);
        let (total, files) = ti.files_from_ip("192.168.1.1", "", 10);
        assert_eq!((total, files.len()), (1, 1));
        assert_eq!(files[0]["sha256"], sha(0));

        let types = ti.type_stats(7);
        assert_eq!(types["all"]["total"], (st.malicious_count - 1 + st.suspicious_count) as u64);

        drop(ti);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore]
    fn check_path_speed() {
        let (ti, dir) = store("speed");
        let n = HOT_MAX + 50_000;
        for i in 0..n {
            ti.record(&sha(i), "clean", None, Some("f.exe"), Some(100), 0.0);
            ti.add_folder(&sha(i), "10.0.0.1", "", "C:\\Users\\a\\dir");
        }
        assert!(ti.flush(Duration::from_secs(60)));
        let hot: Vec<String> = (0..n).map(sha).filter(|s| ti.hot.read().unwrap().contains_key(&parse_sha(s).unwrap())).take(20_000).collect();
        let cold: Vec<String> = (0..n).map(sha).filter(|s| !ti.hot.read().unwrap().contains_key(&parse_sha(s).unwrap())).take(20_000).collect();
        for (label, set) in [("hot", &hot), ("cold", &cold)] {
            let t = std::time::Instant::now();
            for s in set.iter() {
                std::hint::black_box(ti.get(s).is_some_and(|i| i.verdict == "unknown"));
            }
            let get = t.elapsed().as_secs_f64();
            let t = std::time::Instant::now();
            for s in set.iter() {
                std::hint::black_box(ti.needs_new_scan(&parse_sha(s).unwrap()));
            }
            let quick = t.elapsed().as_secs_f64();
            let t = std::time::Instant::now();
            for s in set.iter() {
                ti.record(s, "clean", None, Some("f.exe"), Some(100), 0.0);
                ti.set_detections(s, "clean", &[], false);
                ti.add_folder(s, "10.0.0.2", "", "");
                ti.add_folder(s, "10.0.0.2", "dir", "C:\\Users\\b\\dir");
            }
            let rest = t.elapsed().as_secs_f64();
            let per = |secs: f64| set.len() as f64 / secs;
            println!("{label:<5} get {:>9.0}/s  needs_new_scan {:>9.0}/s  record+detections+2 folders {:>9.0}/s", per(get), per(quick), per(rest));
            assert!(ti.flush(Duration::from_secs(60)));
        }
        drop(ti);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Process memory with many records written (Windows):
    /// `cargo test --release -- --ignored store_memory --nocapture`.
    #[test]
    #[ignore]
    fn store_memory() {
        let private = || {
            let out = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &format!("(Get-Process -Id {}).PrivateMemorySize64", std::process::id())])
                .output();
            out.ok().and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok()).unwrap_or(0) >> 20
        };
        let (ti, dir) = store("mem");
        let before = private();
        let n: usize = std::env::var("TI_RECORDS").ok().and_then(|v| v.parse().ok()).unwrap_or(500_000);
        let t = std::time::Instant::now();
        for i in 0..n {
            ti.record(&sha(i), VERDICTS[i % 5], Some("Trojan.Win32.Agent"), Some(&format!("some_installer_{i}.exe")), Some(1 << 20), 1.0);
            for k in 0..3 {
                ti.add_folder(&sha(i), &format!("10.{}.{}.{}", k, i % 250, i % 13), "", &format!("C:\\Users\\user{}\\Downloads\\folder{}", i % 50, i % 1000));
            }
            if i % 100_000 == 0 {
                eprintln!("{i} records, private {} MB", private());
            }
        }
        let wrote = std::time::Instant::now();
        let peak = private();
        while !ti.flush(Duration::from_secs(600)) {}
        eprintln!("peak private {peak} MB while writing; the writer caught up {:.1} s after the last record", wrote.elapsed().as_secs_f64());
        eprintln!(
            "{n} records in {:.1} s; private {} MB before, {} MB after; {} in memory",
            t.elapsed().as_secs_f64(),
            before,
            private(),
            ti.hot.read().unwrap().len()
        );
        let t = std::time::Instant::now();
        let st = ti.stats();
        eprintln!("stats {:?} in {:?}", st.total_unique_hashes, t.elapsed());
        let t = std::time::Instant::now();
        let s = ti.sources("", "", 50);
        eprintln!("sources {} ips in {:?}", s.len(), t.elapsed());
        let t = std::time::Instant::now();
        let ty = ti.type_stats(7);
        eprintln!("type_stats total {} in {:?}; private {} MB", ty["all"]["total"], t.elapsed(), private());
        drop(ti);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
