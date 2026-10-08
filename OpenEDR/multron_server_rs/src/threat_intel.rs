use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::cache::{parse_sha, Sha};
use crate::config::app_dir;
use crate::human_review::HumanReviewStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInsight {
    pub sha256: String,
    pub first_seen: String,
    pub last_seen: String,
    pub seen_count: u64,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    pub file_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    pub score: f64,
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
    pub retry_after: u64,
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
                    retry_after: 0,
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
            retry_after: 0,
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

pub struct ThreatIntelStore {
    map: RwLock<HashMap<Sha, ThreatInsight>>,
    writer: Option<mpsc::Sender<ThreatInsight>>,
    /// Human analysis queue and verdicts (override the engine verdict).
    pub reviews: HumanReviewStore,
    /// TLSH index of analysed files (smart whitelist, similar files).
    pub similarity: crate::similarity::SimilarityIndex,
}

impl ThreatIntelStore {
    pub fn new(persistence_file: Option<PathBuf>) -> Arc<Self> {
        let mut initial_map = HashMap::new();
        let target_path = persistence_file.unwrap_or_else(|| app_dir().join("threat_insights.jsonl"));

        if target_path.exists() {
            if let Ok(file) = File::open(&target_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(item) = serde_json::from_str::<ThreatInsight>(&line) {
                        if let Some(sha_bytes) = parse_sha(&item.sha256) {
                            initial_map.insert(sha_bytes, item);
                        }
                    }
                }
            }
        }

        let reviews = HumanReviewStore::new(&crate::human_review::analyst_dir().join("human_verdicts.jsonl"));
        let writer = start_batch_writer(target_path);

        Arc::new(Self {
            map: RwLock::new(initial_map),
            writer: Some(writer),
            reviews,
            similarity: crate::similarity::SimilarityIndex::load(),
        })
    }

    pub fn record(
        &self,
        sha256_hex: &str,
        verdict: &str,
        threat: Option<&str>,
        file_name: Option<&str>,
        file_size: Option<u64>,
        score: f64,
    ) {
        let Some(sha_bytes) = parse_sha(sha256_hex) else {
            return;
        };

        let now_str = Utc::now().to_rfc3339();

        let updated_insight = {
            let mut guard = self.map.write().unwrap();
            let entry = guard.entry(sha_bytes).or_insert_with(|| ThreatInsight {
                sha256: sha256_hex.to_lowercase(),
                first_seen: now_str.clone(),
                last_seen: now_str.clone(),
                seen_count: 0,
                verdict: verdict.to_string(),
                threat_name: threat.map(str::to_string),
                file_names: Vec::new(),
                file_size,
                score,
            });

            entry.seen_count += 1;
            entry.last_seen = now_str;

            // Upgrade verdict if a better analysis emerged. A placeholder "unknown"
            // (recorded by `check` before the upload) is replaced by any real verdict,
            // so files that turn out clean leave the unknown bucket.
            let rank = |v: &str| match v {
                "malicious" => 3,
                "suspicious" => 2,
                "clean" => 2,
                "possible_clean" => 1,
                _ => 0,
            };
            if rank(verdict) > rank(&entry.verdict) {
                entry.verdict = verdict.to_string();
                if let Some(t) = threat {
                    entry.threat_name = Some(t.to_string());
                }
                entry.score = score.max(entry.score);
            }

            if let Some(name) = file_name {
                let trimmed = name.trim();
                if !trimmed.is_empty() && !entry.file_names.iter().any(|n| n.eq_ignore_ascii_case(trimmed)) {
                    if entry.file_names.len() < 5 {
                        entry.file_names.push(trimmed.to_string());
                    }
                }
            }

            if file_size.is_some() && entry.file_size.is_none() {
                entry.file_size = file_size;
            }

            entry.clone()
        };

        if let Some(writer) = &self.writer {
            let _ = writer.send(updated_insight);
        }
    }

    /// Hashes first seen on `date` (YYYY-MM-DD, UTC) with their effective verdict
    /// (a completed human review overrides the engine). Newest first, at most `limit`.
    pub fn first_seen_on(&self, date: &str, limit: usize) -> Vec<(ThreatInsight, String, bool)> {
        let guard = self.map.read().unwrap();
        let mut out: Vec<(ThreatInsight, String, bool)> = guard
            .iter()
            .filter(|(_, i)| i.first_seen.starts_with(date))
            .map(|(sha, i)| {
                let human = self.reviews.completed_verdict_raw(sha);
                let is_human = human.is_some();
                (i.clone(), human.unwrap_or_else(|| i.verdict.clone()), is_human)
            })
            .collect();
        out.sort_by(|a, b| b.0.first_seen.cmp(&a.0.first_seen));
        out.truncate(limit);
        out
    }

    /// (verdict, source "human" | "engine" | "unseen", threat name) for one hash.
    pub fn effective(&self, sha256_hex: &str) -> (String, String, Option<String>) {
        if let Some(r) = self.reviews.completed(sha256_hex) {
            return (r.verdict.clone().unwrap_or_default(), "human".into(), r.threat_name.clone());
        }
        match self.get(sha256_hex) {
            Some(i) => (i.verdict.clone(), "engine".into(), i.threat_name.clone()),
            None => ("unknown".into(), "unseen".into(), None),
        }
    }

    pub fn get(&self, sha256_hex: &str) -> Option<ThreatInsight> {
        let sha_bytes = parse_sha(sha256_hex)?;
        self.map.read().unwrap().get(&sha_bytes).cloned()
    }

    pub fn stats(&self) -> ThreatIntelStats {
        let guard = self.map.read().unwrap();
        let mut total_sightings = 0u64;
        let mut malicious_count = 0;
        let mut suspicious_count = 0;
        let mut clean_count = 0;
        let mut possible_clean_count = 0;
        let mut unknown_count = 0;

        for (sha, item) in guard.iter() {
            total_sightings += item.seen_count;
            // A completed human review overrides the engine verdict.
            let human = self.reviews.completed_verdict_raw(sha);
            match human.as_deref().unwrap_or(item.verdict.as_str()) {
                "malicious" => malicious_count += 1,
                "suspicious" => suspicious_count += 1,
                "clean" => clean_count += 1,
                "possible_clean" => possible_clean_count += 1,
                _ => unknown_count += 1,
            }
        }

        ThreatIntelStats {
            total_unique_hashes: guard.len(),
            total_sightings,
            malicious_count,
            suspicious_count,
            clean_count,
            possible_clean_count,
            unknown_count,
        }
    }
}

fn start_batch_writer(path: PathBuf) -> mpsc::Sender<ThreatInsight> {
    let (tx, rx) = mpsc::channel::<ThreatInsight>();

    std::thread::Builder::new()
        .name("threat_intel_writer".into())
        .spawn(move || {
            let mut buffer: Vec<ThreatInsight> = Vec::with_capacity(128);
            let mut last_flush = std::time::Instant::now();

            loop {
                // Wake up at least every 2 s so a lone update is not left unflushed
                // until the next one arrives (it would be lost on restart).
                match rx.recv_timeout(Duration::from_secs(2)) {
                    Ok(item) => buffer.push(item),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if !buffer.is_empty() {
                            flush_insights(&path, &mut buffer);
                            last_flush = std::time::Instant::now();
                        }
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }

                // Drain remaining queued items non-blockingly
                while let Ok(more) = rx.try_recv() {
                    buffer.push(more);
                    if buffer.len() >= 512 {
                        break;
                    }
                }

                if buffer.len() >= 64 || last_flush.elapsed() >= Duration::from_secs(2) {
                    flush_insights(&path, &mut buffer);
                    last_flush = std::time::Instant::now();
                }
            }

            if !buffer.is_empty() {
                flush_insights(&path, &mut buffer);
            }
        })
        .expect("failed to spawn threat intel writer thread");

    tx
}

fn flush_insights(path: &Path, buffer: &mut Vec<ThreatInsight>) {
    if buffer.is_empty() {
        return;
    }

    let Ok(file) = OpenOptions::new().create(true).append(true).open(path) else {
        buffer.clear();
        return;
    };

    let mut writer = BufWriter::new(file);
    for item in buffer.drain(..) {
        if let Ok(serialized) = serde_json::to_string(&item) {
            let _ = writeln!(writer, "{}", serialized);
        }
    }
    let _ = writer.flush();
}
