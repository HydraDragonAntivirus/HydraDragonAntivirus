//! Verdict history: every change of a file's engine verdict or human verdict.
//!
//! `verdict_changes.jsonl` (next to the executable) gets one line per change as it
//! happens: a new engine verdict from a scan or a rescan, an analyst verdict, a
//! removed analyst verdict. `verdict_changes_backfill.jsonl` is written once, in the
//! background, from the history the older files already hold (`threat_insights.jsonl`
//! and `human_verdicts.jsonl` are append-only, so every past verdict is still there).
//! Both are read into memory at start; the insights APIs return a file's history.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

const LIVE: &str = "verdict_changes.jsonl";
const BACKFILL: &str = "verdict_changes_backfill.jsonl";
/// Entries kept in memory per file (the oldest go first).
const MAX_PER_FILE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub sha256: String,
    /// RFC 3339 time of the change.
    pub at: String,
    /// "engine" or "human".
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The new verdict; "removed" when an analyst verdict was deleted.
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    /// scan, rescan, analyst, backfill
    pub source: String,
    /// Analyst name for human changes (never in the public API), empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by: String,
}

fn path(name: &str) -> PathBuf {
    crate::config::app_dir().join(name)
}

fn map() -> &'static RwLock<HashMap<String, Vec<Change>>> {
    static MAP: OnceLock<RwLock<HashMap<String, Vec<Change>>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m: HashMap<String, Vec<Change>> = HashMap::new();
        for name in [BACKFILL, LIVE] {
            if let Ok(f) = std::fs::File::open(path(name)) {
                for line in BufReader::new(f).lines().map_while(Result::ok) {
                    if let Ok(c) = serde_json::from_str::<Change>(&line) {
                        push(&mut m, c);
                    }
                }
            }
        }
        RwLock::new(m)
    })
}

fn push(m: &mut HashMap<String, Vec<Change>>, c: Change) {
    let v = m.entry(c.sha256.clone()).or_default();
    v.push(c);
    if v.len() > MAX_PER_FILE {
        v.remove(0);
    }
}

/// Records one change. Not on the archive server (it only mirrors) and not in tests.
pub fn record(sha: &str, kind: &str, from: Option<&str>, to: &str, threat: Option<&str>, source: &str, by: &str) {
    if from == Some(to) || cfg!(test) || crate::config::is_archive() {
        return;
    }
    let c = Change {
        sha256: sha.to_ascii_lowercase(),
        at: chrono::Utc::now().to_rfc3339(),
        kind: kind.into(),
        from: from.map(str::to_string),
        to: to.into(),
        threat: threat.map(str::to_string),
        source: source.into(),
        by: by.into(),
    };
    if let Ok(line) = serde_json::to_string(&c) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path(LIVE)) {
            let _ = writeln!(f, "{line}");
        }
    }
    push(&mut map().write().unwrap(), c);
}

/// History of one file, oldest first.
pub fn get(sha: &str) -> Vec<Change> {
    let mut v = map().read().unwrap().get(&sha.to_ascii_lowercase()).cloned().unwrap_or_default();
    v.sort_by(|a, b| a.at.cmp(&b.at));
    v
}

/// Public form: analyst names become "human" / "ai".
pub fn public_json(changes: &[Change]) -> Vec<serde_json::Value> {
    let ai = crate::human_review::ai_analyst_names();
    changes
        .iter()
        .map(|c| {
            let by = match c.kind.as_str() {
                "human" if ai.contains(&c.by.to_lowercase()) => "ai",
                "human" => "human",
                _ => "engine",
            };
            serde_json::json!({ "at": c.at, "kind": c.kind, "from": c.from, "to": c.to, "threat": c.threat, "source": c.source, "by": by })
        })
        .collect()
}

#[derive(Deserialize)]
struct InsightLine {
    sha256: String,
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    threat_name: Option<String>,
    #[serde(default)]
    last_seen: String,
}

#[derive(Deserialize)]
struct ReviewLine {
    sha256: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    threat_name: Option<String>,
    #[serde(default)]
    analyst: String,
    #[serde(default)]
    reviewed_at: Option<String>,
    #[serde(default)]
    requested_at: String,
    #[serde(default)]
    deleted: bool,
}

/// Writes `verdict_changes_backfill.jsonl` from the append-only insight and review
/// logs, once (skipped when it exists). Runs on a background thread at start; the
/// history of a file shows up in the API after the next restart.
pub fn backfill_if_missing() {
    if crate::config::is_archive() || path(BACKFILL).exists() {
        return;
    }
    let _ = std::thread::Builder::new().name("verdict_history_backfill".into()).spawn(|| {
        let t = std::time::Instant::now();
        let tmp = path("verdict_changes_backfill.jsonl.part");
        let Ok(out) = std::fs::File::create(&tmp) else { return };
        let mut out = std::io::BufWriter::new(out);
        let mut n = 0usize;
        let mut emit = |c: Change, out: &mut std::io::BufWriter<std::fs::File>| {
            if let Ok(line) = serde_json::to_string(&c) {
                let _ = writeln!(out, "{line}");
                n += 1;
            }
        };
        // Engine: every change of the verdict between consecutive insight lines.
        let mut last: HashMap<String, String> = HashMap::new();
        if let Ok(f) = std::fs::File::open(path("threat_insights.jsonl")) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let Ok(i) = serde_json::from_str::<InsightLine>(&line) else { continue };
                let sha = i.sha256.to_ascii_lowercase();
                let prev = last.get(&sha).cloned();
                if prev.as_deref() != Some(i.verdict.as_str()) && !(prev.is_none() && i.verdict == "unknown") {
                    emit(Change { sha256: sha.clone(), at: i.last_seen, kind: "engine".into(), from: prev, to: i.verdict.clone(), threat: i.threat_name, source: "backfill".into(), by: String::new() }, &mut out);
                }
                last.insert(sha, i.verdict);
            }
        }
        drop(last);
        // Human: completed verdicts that differ from the previous one, and deletions.
        let mut last: HashMap<String, String> = HashMap::new();
        if let Ok(f) = std::fs::File::open(crate::human_review::analyst_dir().join("human_verdicts.jsonl")) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let Ok(r) = serde_json::from_str::<ReviewLine>(&line) else { continue };
                let sha = r.sha256.to_ascii_lowercase();
                let prev = last.get(&sha).cloned();
                if r.deleted {
                    if let Some(p) = prev {
                        emit(Change { sha256: sha.clone(), at: r.reviewed_at.unwrap_or(r.requested_at), kind: "human".into(), from: Some(p), to: "removed".into(), threat: None, source: "backfill".into(), by: r.analyst }, &mut out);
                        last.remove(&sha);
                    }
                    continue;
                }
                let (true, Some(v)) = (r.status == "completed", r.verdict) else { continue };
                if prev.as_deref() != Some(v.as_str()) {
                    emit(Change { sha256: sha.clone(), at: r.reviewed_at.unwrap_or(r.requested_at), kind: "human".into(), from: prev, to: v.clone(), threat: r.threat_name, source: "backfill".into(), by: r.analyst }, &mut out);
                }
                last.insert(sha, v);
            }
        }
        if out.flush().is_ok() && std::fs::rename(&tmp, path(BACKFILL)).is_ok() {
            eprintln!("[history] verdict history backfilled: {n} changes in {} s (shown after the next restart)", t.elapsed().as_secs());
        }
    });
}
