//! Verdict history: every change of a file's engine verdict or human verdict.
//!
//! `verdict_changes.jsonl` (next to the executable) gets one line per change as it
//! happens: a new engine verdict from a scan or a rescan, an analyst verdict, a
//! removed analyst verdict. `verdict_changes_backfill.jsonl` is written once, in the
//! background, from the history the older files already hold (`threat_insights.jsonl`
//! and `human_verdicts.jsonl` are append-only, so every past verdict is still there).
//!
//! The two files stay the record (the archive mirrors them). `verdict_history.db`
//! (SQLite, `verdict_history_archive.db` on the archive server) is an index of them by
//! hash, so a file's history is read from disk instead of every change of every hash
//! being held in memory. A background thread adds the lines past the position it
//! keeps for each file every few seconds (a line already there is ignored); changes
//! recorded since its last pass are kept in memory until then.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const LIVE: &str = "verdict_changes.jsonl";
const BACKFILL: &str = "verdict_changes_backfill.jsonl";
/// Changes returned per file (the newest ones).
const MAX_PER_FILE: usize = 64;
/// How often new lines are added to the index.
const IMPORT_EVERY: Duration = Duration::from_secs(2);
/// Lines per transaction while adding.
const IMPORT_BATCH: usize = 20_000;

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

impl Change {
    /// Same change (the index key).
    fn same(&self, o: &Change) -> bool {
        (&self.sha256, &self.at, &self.kind, &self.to, &self.source) == (&o.sha256, &o.at, &o.kind, &o.to, &o.source)
    }
}

fn path(name: &str) -> PathBuf {
    crate::config::app_dir().join(name)
}

fn db_path() -> PathBuf {
    path(if crate::config::is_archive() { "verdict_history_archive.db" } else { "verdict_history.db" })
}

struct Store {
    /// Reads of one file's history; None when the index could not be opened.
    read: Mutex<Option<Connection>>,
    /// Recorded here but maybe not in the index yet.
    pending: Mutex<Vec<Change>>,
}

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| Store { read: Mutex::new(None), pending: Mutex::new(Vec::new()) })
}

fn open(p: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(p)?;
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.pragma_update(None, "cache_size", -4096)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "journal_size_limit", crate::insight_db::WAL_SIZE_LIMIT)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS changes (
             sha    TEXT NOT NULL,
             at     TEXT NOT NULL,
             kind   TEXT NOT NULL,
             to_v   TEXT NOT NULL,
             source TEXT NOT NULL,
             line   TEXT NOT NULL,
             PRIMARY KEY (sha, at, kind, to_v, source)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS positions (file TEXT PRIMARY KEY, offset INTEGER NOT NULL);",
    )?;
    Ok(conn)
}

/// Opens the index, adds what the files hold beyond it, then keeps adding on a
/// background thread. Called once at start (the archive server too: its mirror
/// appends to the files).
pub fn start() {
    let p = db_path();
    let conn = match open(&p) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[history] opening SQLite {} failed: {e}; verdict history shows only this run's changes", p.display());
            return;
        }
    };
    match open(&p) {
        Ok(r) => *store().read.lock().unwrap() = Some(r),
        Err(e) => eprintln!("[history] opening SQLite {} for reading failed: {e}", p.display()),
    }
    let _ = std::thread::Builder::new().name("verdict_history".into()).spawn(move || {
        let t = std::time::Instant::now();
        let n = import_all(&conn);
        if n > 0 {
            eprintln!("[history] {n} verdict changes indexed in {} s", t.elapsed().as_secs());
        }
        let _ = crate::insight_db::truncate_wal(&conn, Duration::from_secs(5));
        let mut last_truncate = std::time::Instant::now();
        loop {
            std::thread::sleep(IMPORT_EVERY);
            import_all(&conn);
            // The reader would otherwise keep the WAL from ever being rewound.
            if last_truncate.elapsed() >= Duration::from_secs(60)
                && crate::insight_db::truncate_wal(&conn, Duration::from_millis(500)).unwrap_or(false)
            {
                last_truncate = std::time::Instant::now();
            }
        }
    });
}

/// Adds the new lines of both files. Every change kept in memory when the pass
/// started is in the live file already, so those leave memory once it succeeded.
fn import_all(conn: &Connection) -> usize {
    let recorded = store().pending.lock().unwrap().len();
    let mut n = 0;
    let mut ok = true;
    for name in [BACKFILL, LIVE] {
        match import(conn, &path(name), name) {
            Ok(k) => n += k,
            Err(e) => {
                ok = false;
                eprintln!("[history] indexing {name} failed: {e}");
            }
        }
    }
    if ok && recorded > 0 {
        let mut p = store().pending.lock().unwrap();
        let k = recorded.min(p.len());
        p.drain(..k);
        p.shrink_to(256);
    }
    n
}

/// Adds the full lines of `file` past the position kept under `key`. A file shorter
/// than that position was replaced and is read again from the start.
fn import(conn: &Connection, file: &Path, key: &str) -> rusqlite::Result<usize> {
    let Ok(f) = std::fs::File::open(file) else { return Ok(0) };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut pos: u64 = conn
        .query_row("SELECT offset FROM positions WHERE file = ?1", [key], |r| r.get::<_, i64>(0))
        .optional()?
        .map_or(0, |v| v as u64);
    if pos > len {
        pos = 0;
    }
    if pos == len {
        return Ok(0);
    }
    let mut r = BufReader::with_capacity(1 << 20, f);
    if r.seek(SeekFrom::Start(pos)).is_err() {
        return Ok(0);
    }
    let mut total = 0;
    let mut line = Vec::new();
    loop {
        let tx = conn.unchecked_transaction()?;
        let mut lines = 0;
        {
            let mut ins = tx.prepare_cached("INSERT OR IGNORE INTO changes (sha, at, kind, to_v, source, line) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
            while lines < IMPORT_BATCH {
                line.clear();
                match r.read_until(b'\n', &mut line) {
                    Ok(k) if k > 0 && line.ends_with(b"\n") => {}
                    _ => break, // the end, or a line still being written
                }
                pos += line.len() as u64;
                lines += 1;
                let Ok(mut c) = serde_json::from_slice::<Change>(&line) else { continue };
                c.sha256.make_ascii_lowercase();
                if let Ok(json) = serde_json::to_string(&c) {
                    total += ins.execute(params![c.sha256, c.at, c.kind, c.to, c.source, json])?;
                }
            }
        }
        tx.execute("INSERT OR REPLACE INTO positions (file, offset) VALUES (?1, ?2)", params![key, pos as i64])?;
        tx.commit()?;
        if lines < IMPORT_BATCH {
            return Ok(total);
        }
    }
}

/// The newest `MAX_PER_FILE` changes of one file in the index, oldest first.
fn query(conn: &Connection, sha: &str) -> rusqlite::Result<Vec<Change>> {
    let mut st = conn.prepare_cached("SELECT line FROM changes WHERE sha = ?1 ORDER BY at DESC LIMIT ?2")?;
    let rows = st.query_map(params![sha, MAX_PER_FILE as i64], |r| r.get::<_, String>(0))?;
    let mut v: Vec<Change> = rows.filter_map(|l| l.ok().and_then(|l| serde_json::from_str(&l).ok())).collect();
    v.reverse();
    Ok(v)
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
    // Appended and kept under one lock, so the indexer never counts a kept change
    // whose line is not in the file yet.
    let mut pending = store().pending.lock().unwrap();
    if let Ok(line) = serde_json::to_string(&c) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path(LIVE)) {
            let _ = writeln!(f, "{line}");
        }
    }
    pending.push(c);
}

/// History of one file, oldest first.
pub fn get(sha: &str) -> Vec<Change> {
    let sha = sha.to_ascii_lowercase();
    let mut v = match store().read.lock().unwrap().as_ref() {
        Some(conn) => query(conn, &sha).unwrap_or_else(|e| {
            eprintln!("[history] reading {sha} failed: {e}");
            Vec::new()
        }),
        None => Vec::new(),
    };
    for c in store().pending.lock().unwrap().iter().filter(|c| c.sha256 == sha) {
        if !v.iter().any(|o| o.same(c)) {
            v.push(c.clone());
        }
    }
    v.sort_by(|a, b| a.at.cmp(&b.at));
    let extra = v.len().saturating_sub(MAX_PER_FILE);
    v.drain(..extra);
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
/// indexer adds it a few seconds after it is written.
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
            eprintln!("[history] verdict history backfilled: {n} changes in {} s", t.elapsed().as_secs());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(sha: &str, i: usize) -> String {
        let c = Change { sha256: sha.into(), at: format!("2026-01-01T00:00:{:02}.{:06}Z", i / 1000 % 60, i), kind: "engine".into(), from: None, to: format!("v{i}"), threat: None, source: "scan".into(), by: String::new() };
        serde_json::to_string(&c).unwrap() + "\n"
    }

    #[test]
    fn index_follows_the_file() {
        let dir = std::env::temp_dir().join(format!("vh_index_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(LIVE);
        let conn = open(&dir.join("verdict_history.db")).unwrap();
        let append = |s: &str| {
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&file).unwrap();
            f.write_all(s.as_bytes()).unwrap();
        };

        // Upper-case hashes are stored lower-case; a half-written line waits.
        append(&(line("AA", 1) + &line("bb", 2)));
        let half = line("aa", 3);
        append(&half[..10]);
        assert_eq!(import(&conn, &file, LIVE).unwrap(), 2);
        assert_eq!(query(&conn, "aa").unwrap().len(), 1);
        append(&half[10..]);
        assert_eq!(import(&conn, &file, LIVE).unwrap(), 1);
        assert_eq!(query(&conn, "aa").unwrap().iter().map(|c| c.to.as_str()).collect::<Vec<_>>(), ["v1", "v3"]);
        assert_eq!(import(&conn, &file, LIVE).unwrap(), 0);

        // A replaced (shorter) file is read again; what is indexed already is ignored.
        std::fs::write(&file, line("aa", 1)).unwrap();
        assert_eq!(import(&conn, &file, LIVE).unwrap(), 0);

        // Only the newest changes of a file, oldest first.
        let many: String = (10..10 + MAX_PER_FILE + 20).map(|i| line("cc", i)).collect();
        append(&many);
        assert_eq!(import(&conn, &file, LIVE).unwrap(), MAX_PER_FILE + 20);
        let h = query(&conn, "cc").unwrap();
        assert_eq!(h.len(), MAX_PER_FILE);
        assert_eq!(h[0].to, "v30");
        assert_eq!(h.last().unwrap().to, format!("v{}", 10 + MAX_PER_FILE + 19));

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
