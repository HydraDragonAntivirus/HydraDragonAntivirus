//! Uploads the unknown-process kill chain telemetry that edrsvc records in training
//! mode (`%ProgramData%\edrsvc\training_data\unknown_killchain_YYYYMMDD.jsonl`, one
//! event per line) to the Multron server, so the kill chain model gets benign / unknown
//! behavior and not only the detections the behavior endpoint already receives.
//!
//! The raw stream is far too big to send as is (one idle machine writes ~290k events a
//! day, ~6.6 KB each), and almost all of it repeats: the same process doing the same
//! thing. Each event is reduced to its *shape*, the feature set
//! `OpenEDR/scripts/train_kc_hybrid.py` extracts from it (`event_features`, a port of
//! its `extract_features`), keyed together with the normalized executable path. Only
//! the first event of each (exe, shape) is sent in full; later ones only bump that
//! key's count. On the 2026-09-12 sample that is 4,241 events / 28.1 MB -> 454 records
//! / 0.12 MB brotli-compressed.
//!
//! Nothing here deletes or rewrites edrsvc's files: progress is a byte offset per file
//! (`upload_state\offsets.json`), and the keys already sent are kept in
//! `upload_state\seen.bin`. A batch is committed (offsets and keys saved) only after the
//! server accepted it, so a failed upload is retried from the same place next round.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::logging::Logging;

/// Server route the batches go to.
pub const KILLCHAIN_PATH: &str = "/api/v1/edr/telemetry/killchain";

const FIRST_ROUND_DELAY: Duration = Duration::from_secs(120);
const ROUND_INTERVAL: Duration = Duration::from_secs(30 * 60);
const BATCH_SPACING: Duration = Duration::from_secs(3);
/// Bytes of new log read per file per round (the rest waits for the next round).
const MAX_READ_PER_ROUND: u64 = 64 * 1024 * 1024;
/// A batch is sent once it holds this many new records or this much record JSON.
const MAX_BATCH_RECORDS: usize = 2000;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
/// Keys remembered as sent. Past this, new keys are still sent but no longer
/// remembered (the server merges a repeated key into its count).
const MAX_SEEN_KEYS: usize = 4_000_000;

// ------------------------------------------------------------------ features
// Port of train_kc_hybrid.py's extract_features (dt_prev not given: "dt_prev~none").
// The key only decides what counts as a repeat; the trainer recomputes the features
// from the raw event it receives, so a small mismatch costs dedupe precision only.

const IDENTITY_KEYS: [&str; 6] = ["imagefile", "imagepath", "cmdline", "commandline", "exepath", "appname"];
const EXCLUDE_SUB: [&str; 6] = ["verdict", "threat", "hash", "ticktime", "creationtime", "accesstime"];
const EXCLUDE_SUB_LITERAL: &str = "$$";
const EXCLUDE_EQ: [&str; 5] = ["id", "pid", "gid", "sid", "time"];
const DATA_KEYS: [&str; 6] = ["data", "content", "blob", "script", "scripttext", "value"];
const MAX_FEATURES: usize = 2000;

fn key_excluded(kl: &str) -> bool {
    EXCLUDE_EQ.contains(&kl)
        || kl.ends_with("_id")
        || kl.ends_with(".id")
        || EXCLUDE_SUB.iter().any(|s| kl.contains(s))
        || kl.contains(EXCLUDE_SUB_LITERAL)
}

fn dirclass(p: &str) -> &'static str {
    let l = p.to_lowercase().replace('/', "\\");
    if l.is_empty() {
        return "none";
    }
    if l.contains("startup") {
        return "startup";
    }
    if l.contains("\\system32") || l.contains("\\syswow64") || l.starts_with("%systemroot%") {
        return "system32";
    }
    if l.contains("programdata") {
        return "programdata";
    }
    if l.contains("\\temp\\") || l.contains("\\tmp\\") {
        return "temp";
    }
    if l.contains("appdata") {
        return "appdata";
    }
    if l.starts_with("\\\\.\\pipe\\") {
        return "pipe";
    }
    if l.contains("harddisk") {
        return "device";
    }
    if l.contains("\\windows\\") {
        return "windows_other";
    }
    if l.contains("program files") {
        return "progfiles";
    }
    if l.contains("\\users\\") {
        return "user";
    }
    "other"
}

fn ext_of(p: &str) -> String {
    let l = p.to_lowercase();
    if let Some(pos) = l.rfind('.') {
        let tail = &l[pos + 1..];
        let n = tail.chars().count();
        if (1..=5).contains(&n) && tail.chars().all(|c| c.is_alphanumeric()) {
            return tail.to_string();
        }
    }
    "none".to_string()
}

fn is_pathy(s: &str) -> bool {
    (s.contains('\\') || s.contains('/') || s.starts_with('%')) && s.chars().count() > 3
}

fn logbucket(x: f64) -> String {
    if !x.is_finite() || x <= 0.0 {
        return "0".to_string();
    }
    ((x + 1.0).log10().floor() as i64).to_string()
}

fn trim_prefix(prefix: &str) -> &str {
    prefix.strip_suffix('.').unwrap_or(prefix)
}

type Features = BTreeMap<String, f32>;

fn put(f: &mut Features, k: String, v: f32) {
    f.insert(k, v);
}

fn flatten(prefix: &str, val: &serde_json::Value, f: &mut Features, depth: usize) {
    use serde_json::Value;
    if depth > 4 || f.len() > MAX_FEATURES {
        return;
    }
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let kl = k.to_lowercase();
                if key_excluded(&kl) || kl.contains("kernelstack") {
                    continue;
                }
                if DATA_KEYS.contains(&kl.as_str()) {
                    put(f, format!("{prefix}{kl}_present"), 1.0);
                    let length = match v {
                        Value::String(s) => s.chars().count(),
                        other => other.to_string().chars().count(),
                    };
                    put(f, format!("{prefix}{kl}_len~{}", logbucket(length as f64)), 1.0);
                    continue;
                }
                if IDENTITY_KEYS.iter().any(|idk| kl.contains(idk)) {
                    put(f, format!("has_{prefix}{kl}"), 1.0);
                    continue;
                }
                flatten(&format!("{prefix}{kl}."), v, f, depth + 1);
            }
        }
        Value::Array(items) => {
            put(f, format!("len_{}={}", trim_prefix(prefix), logbucket(items.len() as f64)), 1.0);
            for item in items.iter().take(5) {
                flatten(prefix, item, f, depth + 1);
            }
        }
        Value::Bool(b) => put(f, format!("{}={}", trim_prefix(prefix), u8::from(*b)), 1.0),
        Value::Number(n) => {
            put(f, format!("{}~{}", trim_prefix(prefix), logbucket(n.as_f64().unwrap_or(0.0))), 1.0)
        }
        Value::String(s) => {
            if s.is_empty() || s == "<undefined>" || s == "null" {
                return;
            }
            if is_pathy(s) {
                put(f, format!("{prefix}dir={}", dirclass(s)), 1.0);
                put(f, format!("{prefix}ext={}", ext_of(s)), 1.0);
                put(f, format!("{prefix}len~{}", logbucket(s.chars().count() as f64)), 1.0);
            } else if s.chars().count() > 80 {
                put(f, format!("{prefix}longlen~{}", logbucket(s.chars().count() as f64)), 1.0);
            } else {
                put(f, format!("{}={}", trim_prefix(prefix), s.to_lowercase()), 1.0);
            }
        }
        Value::Null => {}
    }
}

fn kstack_features(raw: &serde_json::Value, f: &mut Features) {
    for key in ["kernelStackSymbols", "kernelstacksymbols", "kernelStack", "kernelstack"] {
        let Some(s) = raw.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
            continue;
        };
        let mut mods = std::collections::BTreeSet::new();
        let mut nframes = 0usize;
        for p in s.split([';', ',']) {
            let p = p.trim().to_lowercase();
            if p.is_empty() || p.chars().all(|c| c == '0') {
                continue;
            }
            nframes += 1;
            let first = p.split('+').next().unwrap_or("").split('!').next().unwrap_or("");
            let first = first.replace('/', "\\");
            let base = first.rsplit('\\').next().unwrap_or("");
            if !base.is_empty() && base.chars().count() < 64 {
                mods.insert(base.to_string());
            }
        }
        for m in mods {
            put(f, format!("kstack_mod={m}"), 1.0);
        }
        put(f, format!("kstack_frames~{}", logbucket(nframes as f64)), 1.0);
        break;
    }
}

/// The feature set train_kc_hybrid.py's `extract_features(event, details, raw)` gives.
pub fn event_features(event: &str, details: &str, raw: &serde_json::Value) -> Features {
    let mut f = Features::new();
    put(&mut f, format!("event={event}"), 1.0);
    const TAGS: [(&str, &str); 4] = [("[File:", "File"), ("[Reg:", "Reg"), ("[API:", "API"), ("[Net:", "Net")];
    for (tag, name) in TAGS {
        if details.starts_with(&format!(" {tag}")) || details.starts_with(tag) {
            put(&mut f, format!("det={name}"), 1.0);
        }
    }
    let best = TAGS.iter().filter_map(|(tag, _)| details.find(tag)).min();
    if let Some(pos) = best {
        let after = &details[pos..];
        if let Some(colon) = after.find(':') {
            let val = after[colon + 1..].trim_start();
            if let Some(end) = val.find(']') {
                let val = &val[..end];
                if is_pathy(val) {
                    put(&mut f, format!("detdir={}", dirclass(val)), 1.0);
                    put(&mut f, format!("detext={}", ext_of(val)), 1.0);
                } else if let Some((m, func)) = val.split_once('!') {
                    put(&mut f, format!("detmod={}", m.to_lowercase()), 1.0);
                    put(&mut f, format!("detfn={}", func.to_lowercase()), 1.0);
                }
            }
        }
    }
    flatten("raw.", raw, &mut f, 0);
    kstack_features(raw, &mut f);
    put(&mut f, "dt_prev~none".to_string(), 1.0);
    put(&mut f, "has_net".to_string(), if details.contains("[Net:") { 1.0 } else { 0.0 });
    put(&mut f, "has_target".to_string(), if raw.get("target").is_some_and(|v| v.is_object()) { 1.0 } else { 0.0 });
    put(&mut f, "has_thread".to_string(), if raw.get("thread").is_some_and(|v| v.is_object()) { 1.0 } else { 0.0 });
    let has_stack = raw.get("kernelStackSymbols").is_some_and(|v| !v.is_null());
    put(&mut f, "has_stack".to_string(), if has_stack { 1.0 } else { 0.0 });
    match raw.get("accessMask") {
        Some(acc) if !acc.is_null() => put(&mut f, format!("access={}", py_scalar(acc)), 1.0),
        _ => put(&mut f, "access=None".to_string(), 1.0),
    }
    f
}

/// Python's str() of a JSON scalar (`access={acc}`).
fn py_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        other => other.to_string(),
    }
}

/// The executable path with the user profile name replaced, so the same program
/// under two accounts (or on two machines) is one key.
pub fn normalize_exe(exe: &str) -> String {
    let l = exe.to_lowercase().replace('/', "\\");
    if let Some(pos) = l.find("\\users\\") {
        let rest = &l[pos + "\\users\\".len()..];
        if let Some(slash) = rest.find('\\') {
            return format!("{}\\users\\*{}", &l[..pos], &rest[slash..]);
        }
    }
    l
}

/// Dedupe key of an event: the normalized exe and the event's feature set.
pub fn shape_key(exe: &str, f: &Features) -> u64 {
    let mut h = Sha256::new();
    h.update(normalize_exe(exe).as_bytes());
    for (k, v) in f {
        h.update(b"\n");
        h.update(k.as_bytes());
        h.update(b"=");
        h.update(v.to_string().as_bytes());
    }
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().expect("8 bytes"))
}

// ------------------------------------------------------------------ uploader

#[derive(Serialize)]
struct UploadRecord {
    key: String,
    /// The log file's day (`YYYYMMDD`) and the event's time of day.
    date: String,
    time: String,
    exe: String,
    event: String,
    details: String,
    raw: serde_json::Value,
    count: u64,
}

#[derive(Serialize)]
struct UploadBatch<'a> {
    machine_id: &'a str,
    /// Events whose key was new: the first one in full, with how often it occurred.
    records: Vec<UploadRecord>,
    /// Repeats of keys sent in an earlier batch: key -> occurrences.
    counts: BTreeMap<String, u64>,
}

fn key_hex(k: u64) -> String {
    format!("{k:016x}")
}

struct State {
    dir: PathBuf,
    offsets: HashMap<String, u64>,
    seen: HashSet<u64>,
}

impl State {
    fn load(dir: PathBuf) -> Self {
        let offsets = std::fs::read(dir.join("offsets.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut seen = HashSet::new();
        if let Ok(b) = std::fs::read(dir.join("seen.bin")) {
            for c in b.chunks_exact(8) {
                seen.insert(u64::from_le_bytes(c.try_into().expect("8 bytes")));
            }
        }
        Self { dir, offsets, seen }
    }

    /// Saves the offsets (atomically) and appends `new_keys` to seen.bin.
    fn commit(&mut self, offsets: &HashMap<String, u64>, new_keys: &[u64]) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let mut room = MAX_SEEN_KEYS.saturating_sub(self.seen.len());
        let mut bytes = Vec::with_capacity(new_keys.len().min(room) * 8);
        for &k in new_keys {
            if room == 0 {
                break;
            }
            if self.seen.insert(k) {
                bytes.extend_from_slice(&k.to_le_bytes());
                room -= 1;
            }
        }
        if !bytes.is_empty() {
            std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("seen.bin"))?.write_all(&bytes)?;
        }
        self.offsets.extend(offsets.iter().map(|(k, v)| (k.clone(), *v)));
        let tmp = self.dir.join("offsets.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&self.offsets).unwrap_or_default())?;
        std::fs::rename(&tmp, self.dir.join("offsets.json"))
    }
}

/// One batch being filled from the logs.
#[derive(Default)]
struct Pending {
    records: Vec<UploadRecord>,
    index: HashMap<u64, usize>,
    counts: BTreeMap<u64, u64>,
    bytes: usize,
    /// Offsets reached by the lines this batch holds.
    offsets: HashMap<String, u64>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.records.is_empty() && self.counts.is_empty()
    }
    fn full(&self) -> bool {
        self.records.len() >= MAX_BATCH_RECORDS || self.bytes >= MAX_BATCH_BYTES
    }
}

/// Adds one log line to the batch. `date` is the file's day.
fn add_line(p: &mut Pending, seen: &HashSet<u64>, date: &str, line: &str) {
    let Ok(d) = serde_json::from_str::<serde_json::Value>(line) else {
        return;
    };
    let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (exe, event, details) = (s("exe"), s("event"), s("details"));
    let raw = d.get("raw").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
    let key = shape_key(&exe, &event_features(&event, &details, &raw));
    if seen.contains(&key) {
        *p.counts.entry(key).or_default() += 1;
    } else if let Some(&i) = p.index.get(&key) {
        p.records[i].count += 1;
    } else {
        p.bytes += line.len();
        p.index.insert(key, p.records.len());
        p.records.push(UploadRecord {
            key: key_hex(key),
            date: date.to_string(),
            time: s("time"),
            exe,
            event,
            details,
            raw,
            count: 1,
        });
    }
}

/// Sends the batch; true when the server accepted it.
fn send(p: &Pending) -> bool {
    let machine_id = crate::edr_feedback::get_machine_guid();
    let batch = UploadBatch {
        machine_id: &machine_id,
        records: Vec::new(),
        counts: p.counts.iter().map(|(k, c)| (key_hex(*k), *c)).collect(),
    };
    // Serialize records by reference: build the JSON by hand around them.
    let mut body = match serde_json::to_value(&batch) {
        Ok(v) => v,
        Err(_) => return false,
    };
    body["records"] = match serde_json::to_value(&p.records) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let json = match serde_json::to_vec(&body) {
        Ok(j) => j,
        Err(_) => return false,
    };
    let packed = match crate::edr_feedback::compress_brotli(&json) {
        Ok(b) => b,
        Err(_) => return false,
    };
    match crate::edr_feedback::post_to_server(KILLCHAIN_PATH, "application/json", Some("br"), &packed) {
        Ok((200, _)) => {
            Logging::info(&format!(
                "[KillChain Upload] sent {} new event shapes, {} repeat counts ({} KB -> {} KB)",
                p.records.len(),
                p.counts.len(),
                json.len() / 1024,
                packed.len() / 1024
            ));
            // The server allows one EDR telemetry request per 2 s per address.
            std::thread::sleep(BATCH_SPACING);
            true
        }
        Ok((status, resp)) => {
            Logging::warning(&format!(
                "[KillChain Upload] server returned HTTP {status}: {}",
                String::from_utf8_lossy(&resp[..resp.len().min(300)])
            ));
            false
        }
        Err(e) => {
            Logging::warning(&format!("[KillChain Upload] upload failed: {e}"));
            false
        }
    }
}

/// `unknown_killchain_YYYYMMDD.jsonl` files in `dir`, oldest first, with their day.
fn log_files(dir: &Path) -> Vec<(PathBuf, String, String)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let date = name.strip_prefix("unknown_killchain_")?.strip_suffix(".jsonl")?.to_string();
            Some((e.path(), name, date))
        })
        .collect();
    v.sort_by(|a, b| a.1.cmp(&b.1));
    v
}

/// One upload round over every log file. Returns false when an upload failed (the
/// round stops there; nothing past the last accepted batch is committed).
fn round(state: &mut State, log_dir: &Path) -> bool {
    let mut p = Pending::default();
    for (path, name, date) in log_files(log_dir) {
        let start = state.offsets.get(&name).copied().unwrap_or(0);
        let Ok(mut file) = std::fs::File::open(&path) else { continue };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len <= start || file.seek(SeekFrom::Start(start)).is_err() {
            continue;
        }
        let mut buf = Vec::new();
        if file.take(MAX_READ_PER_ROUND).read_to_end(&mut buf).is_err() {
            continue;
        }
        // Only whole lines: edrsvc may be writing the last one right now.
        let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') else { continue };
        let mut pos = 0usize;
        while pos <= last_nl {
            let end = pos + buf[pos..=last_nl].iter().position(|&b| b == b'\n').expect("newline");
            if let Ok(line) = std::str::from_utf8(&buf[pos..end]) {
                let line = line.trim_end_matches('\r');
                if !line.is_empty() {
                    add_line(&mut p, &state.seen, &date, line);
                }
            }
            pos = end + 1;
            p.offsets.insert(name.clone(), start + pos as u64);
            if p.full() {
                if !send(&p) {
                    return false;
                }
                let keys: Vec<u64> = p.index.keys().copied().collect();
                if let Err(e) = state.commit(&p.offsets, &keys) {
                    Logging::warning(&format!("[KillChain Upload] could not save upload state: {e}"));
                }
                p = Pending::default();
            }
        }
    }
    if !p.is_empty() {
        if !send(&p) {
            return false;
        }
        let keys: Vec<u64> = p.index.keys().copied().collect();
        if let Err(e) = state.commit(&p.offsets, &keys) {
            Logging::warning(&format!("[KillChain Upload] could not save upload state: {e}"));
        }
    } else if !p.offsets.is_empty() {
        // Only blank / unparsable lines: still move past them.
        let _ = state.commit(&p.offsets, &[]);
    }
    true
}

fn training_data_dir() -> Option<PathBuf> {
    let pd = std::env::var_os("ProgramData")?;
    Some(PathBuf::from(pd).join("edrsvc").join("training_data"))
}

// ------------------------------------------------------------------ in-memory feed
//
// edrsvc hands every training event straight to `submit` (FFI
// `owlyshield_killchain_submit`) instead of appending it to a .jsonl file: the
// file cost one open/append/close per event (hundreds of thousands a day, ~6.6 KB
// each) only for this uploader to read it back. Events are reduced to their
// shape here, in memory, and uploaded every round or as soon as a batch is full.
// A failed upload stays pending and is retried. Keys already sent are remembered
// in memory only: after a restart a repeat is sent once more as a record, which
// the server merges into its count.

/// Pending events are capped at this multiple of a full batch; past it new events
/// are dropped (and counted) until the next upload drains the queue.
const LIVE_CAP_FACTOR: usize = 2;

#[derive(Default)]
struct Live {
    pending: Pending,
    seen: HashSet<u64>,
    dropped: u64,
}

fn live() -> &'static (std::sync::Mutex<Live>, std::sync::Condvar) {
    static LIVE: std::sync::OnceLock<(std::sync::Mutex<Live>, std::sync::Condvar)> = std::sync::OnceLock::new();
    LIVE.get_or_init(|| (std::sync::Mutex::new(Live::default()), std::sync::Condvar::new()))
}

/// One training event from edrsvc: `{"time","exe","event","details","raw"}` (the
/// line format of the old .jsonl files). Its day is the local date it arrives on,
/// as the old file name was.
pub fn submit(line: &str) {
    start();
    let date = chrono::Local::now().format("%Y%m%d").to_string();
    let (lock, wake) = live();
    let Ok(mut g) = lock.lock() else { return };
    if g.pending.records.len() >= MAX_BATCH_RECORDS * LIVE_CAP_FACTOR
        || g.pending.bytes >= MAX_BATCH_BYTES * LIVE_CAP_FACTOR
    {
        g.dropped += 1;
        return;
    }
    let Live { pending, seen, .. } = &mut *g;
    add_line(pending, seen, &date, line);
    if g.pending.full() {
        wake.notify_one();
    }
}

/// Puts a batch that failed to upload back in front of what arrived meanwhile.
fn requeue(failed: Pending, live: &mut Live) {
    let newer = std::mem::replace(&mut live.pending, failed);
    let p = &mut live.pending;
    for rec in newer.records {
        let key = u64::from_str_radix(&rec.key, 16).unwrap_or_default();
        if let Some(&i) = p.index.get(&key) {
            p.records[i].count += rec.count;
        } else {
            p.index.insert(key, p.records.len());
            p.bytes += rec.raw.to_string().len();
            p.records.push(rec);
        }
    }
    for (k, c) in newer.counts {
        *p.counts.entry(k).or_default() += c;
    }
}

/// Uploads what `submit` collected; returns false when the upload failed.
fn send_live() -> bool {
    let (lock, _) = live();
    let (batch, dropped) = {
        let Ok(mut g) = lock.lock() else { return false };
        (std::mem::take(&mut g.pending), std::mem::take(&mut g.dropped))
    };
    if dropped > 0 {
        Logging::warning(&format!(
            "[KillChain Upload] {dropped} training event(s) dropped: the in-memory queue was full"
        ));
    }
    if batch.is_empty() {
        return true;
    }
    let ok = send(&batch);
    let Ok(mut g) = lock.lock() else { return ok };
    if ok {
        let room = MAX_SEEN_KEYS.saturating_sub(g.seen.len());
        let keys: Vec<u64> = batch.index.keys().copied().take(room).collect();
        g.seen.extend(keys);
    } else {
        requeue(batch, &mut g);
    }
    ok
}

/// Starts the background uploader (once). Set `OWLY_KILLCHAIN_UPLOAD=0` to turn it off.
pub fn start() {
    static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if std::env::var("OWLY_KILLCHAIN_UPLOAD").is_ok_and(|v| v.trim() == "0") {
        return;
    }
    if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let _ = std::thread::Builder::new().name("killchain-upload".into()).spawn(move || {
        std::thread::sleep(FIRST_ROUND_DELAY);
        // .jsonl files edrsvc wrote before it handed events over directly: drained
        // once more each round until nothing new is left in them.
        let log_dir = training_data_dir();
        let mut state = log_dir.as_ref().map(|d| State::load(d.join("upload_state")));
        loop {
            // Several batches when a full one woke us early.
            while send_live() {
                let (lock, _) = live();
                if !lock.lock().map(|g| g.pending.full()).unwrap_or(false) {
                    break;
                }
            }
            if let (Some(dir), Some(st)) = (log_dir.as_ref(), state.as_mut()) {
                if dir.is_dir() {
                    round(st, dir);
                }
            }
            // Sleep until the next round, or until a batch fills up.
            let (lock, wake) = live();
            if let Ok(g) = lock.lock() {
                let _ = wake.wait_timeout_while(g, ROUND_INTERVAL, |g| !g.pending.full());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_batch_is_requeued_ahead_of_newer_events() {
        let line = |exe: &str| {
            format!(r#"{{"time":"10:00:00.000","exe":"{exe}","event":"LLE_FILE_CREATE","details":"","raw":{{}}}}"#)
        };
        let seen = HashSet::new();
        let mut failed = Pending::default();
        add_line(&mut failed, &seen, "20261114", &line("C:\\\\a.exe"));
        add_line(&mut failed, &seen, "20261114", &line("C:\\\\a.exe"));
        assert_eq!(failed.records.len(), 1);
        assert_eq!(failed.records[0].count, 2);

        let mut l = Live::default();
        add_line(&mut l.pending, &seen, "20261114", &line("C:\\\\a.exe"));
        add_line(&mut l.pending, &seen, "20261114", &line("C:\\\\b.exe"));
        requeue(failed, &mut l);
        assert_eq!(l.pending.records.len(), 2, "same shape merged, new shape kept");
        let a = l.pending.records.iter().find(|r| r.exe.ends_with("a.exe")).unwrap();
        assert_eq!(a.count, 3);
        assert_eq!(l.pending.index.len(), 2);
    }

    #[test]
    fn features_follow_the_python_extractor() {
        let raw = serde_json::json!({
            "accessMask": 2,
            "file": {"path": "C:\\Windows\\System32\\x.dll", "id": 5, "size": 2560, "isAsciiText": false},
            "process": {"cmdLine": "x", "pid": 4},
            "kernelStackSymbols": "ntoskrnl.exe!Foo+0x10;fltmgr.sys!Bar+0x2"
        });
        let f = event_features("LLE_FILE_MAP_READ", " [File: C:\\Windows\\System32\\x.dll]", &raw);
        for k in [
            "event=LLE_FILE_MAP_READ",
            "det=File",
            "detdir=system32",
            "detext=dll",
            "raw.file.path.dir=system32",
            "raw.file.path.ext=dll",
            "raw.file.size~3",
            "raw.file.isasciitext=0",
            "has_raw.process.cmdline",
            "kstack_mod=ntoskrnl.exe",
            "kstack_mod=fltmgr.sys",
            "kstack_frames~0",
            "access=2",
            "dt_prev~none",
        ] {
            assert!(f.contains_key(k), "missing {k}: {f:?}");
        }
        assert!(!f.keys().any(|k| k.contains(".id") || k.contains("pid")), "ids are excluded");
        assert_eq!(f["has_stack"], 1.0);
        assert_eq!(f["has_net"], 0.0);
    }

    /// Feature-by-feature parity with train_kc_hybrid.py over a real log. Needs a file
    /// of `{"line": <log line>, "feats": {name: value}}` rows from the Python side:
    /// `KC_PARITY_FILE=... cargo test --lib killchain_upload -- --ignored`.
    #[test]
    #[ignore]
    fn parity_with_python_on_a_real_log() {
        let path = std::env::var("KC_PARITY_FILE").expect("KC_PARITY_FILE");
        let text = std::fs::read_to_string(path).expect("parity file");
        let (mut n, mut bad) = (0, 0);
        for row in text.lines() {
            let row: serde_json::Value = serde_json::from_str(row).expect("row");
            let d: serde_json::Value = serde_json::from_str(row["line"].as_str().expect("line")).expect("log line");
            let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let raw = d.get("raw").cloned().unwrap_or_default();
            let ours = event_features(&s("event"), &s("details"), &raw);
            let py: Features = row["feats"]
                .as_object()
                .expect("feats")
                .iter()
                .map(|(k, v)| (k.clone(), v.as_f64().unwrap_or(0.0) as f32))
                .collect();
            n += 1;
            if ours != py {
                bad += 1;
                if bad <= 3 {
                    let only_rust: Vec<_> = ours.keys().filter(|k| !py.contains_key(*k)).collect();
                    let only_py: Vec<_> = py.keys().filter(|k| !ours.contains_key(*k)).collect();
                    eprintln!("line {n}: only rust {only_rust:?}
  only python {only_py:?}");
                }
            }
        }
        assert_eq!(bad, 0, "{bad} of {n} events differ from the Python features");
    }

    #[test]
    fn same_shape_same_key_across_users() {
        let raw = serde_json::json!({"file": {"path": "C:\\Users\\a\\AppData\\x.tmp", "id": 1}});
        let raw2 = serde_json::json!({"file": {"path": "C:\\Users\\b\\AppData\\y.tmp", "id": 2}});
        let k1 = shape_key("C:\\Users\\a\\app.exe", &event_features("E", "", &raw));
        let k2 = shape_key("C:\\Users\\b\\app.exe", &event_features("E", "", &raw2));
        assert_eq!(k1, k2, "ids and user names do not split a shape");
        let k3 = shape_key("C:\\Users\\b\\other.exe", &event_features("E", "", &raw2));
        assert_ne!(k1, k3);
    }

    #[test]
    fn repeats_collapse_and_seen_keys_become_counts() {
        let line = r#"{"time":"1","exe":"a.exe","event":"E","details":"","raw":{"x":1}}"#;
        let other = r#"{"time":"2","exe":"b.exe","event":"E","details":"","raw":{"x":1}}"#;
        let mut p = Pending::default();
        let mut seen = HashSet::new();
        for _ in 0..3 {
            add_line(&mut p, &seen, "20261114", line);
        }
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.records[0].count, 3);
        seen.insert(shape_key("b.exe", &event_features("E", "", &serde_json::json!({"x": 1}))));
        add_line(&mut p, &seen, "20261114", other);
        add_line(&mut p, &seen, "20261114", other);
        assert_eq!(p.records.len(), 1, "a key sent before is not sent again");
        assert_eq!(p.counts.values().sum::<u64>(), 2);
    }
}
