use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub type Sha = [u8; 32];

pub fn parse_sha(hex_str: &str) -> Option<Sha> {
    let s = hex_str.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVerdict {
    #[serde(rename = "v")]
    pub verdict: String,
    #[serde(rename = "t", default, skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(rename = "sc", default)]
    pub score: f64,
    /// Unix seconds when the engine produced this verdict.
    #[serde(rename = "ts")]
    pub at: i64,
}

#[derive(Serialize, Deserialize)]
struct Line {
    s: String,
    #[serde(flatten)]
    v: CachedVerdict,
}

/// SHA-256 -> verdict of every file the engine has scanned. Shared by all clients, so a
/// file one client uploaded is answered for everybody else from its hash alone.
/// Bounded (oldest dropped first) and appended to a JSON-lines file so it survives restarts.
pub struct VerdictCache {
    inner: Mutex<Inner>,
    max: usize,
    ttl_secs: i64,
    unknown_ttl_secs: i64,
    writer: Option<mpsc::Sender<String>>,
}

struct Inner {
    map: HashMap<Sha, CachedVerdict>,
    order: VecDeque<Sha>,
}

impl VerdictCache {
    pub fn new(max: usize, ttl_days: i64, unknown_ttl_hours: i64, file: Option<PathBuf>) -> Self {
        let mut c = Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            max: max.max(1000),
            ttl_secs: ttl_days.max(0) * 86400,
            unknown_ttl_secs: unknown_ttl_hours.max(0) * 3600,
            writer: None,
        };
        if let Some(path) = file {
            let lines = c.load(&path);
            // Rewrite the file when it is mostly stale or duplicate lines.
            let live = c.len();
            if lines > live * 2 + 10_000 {
                c.compact(&path);
            }
            c.writer = start_writer(path);
        }
        c
    }

    fn ttl_for(&self, verdict: &str) -> i64 {
        if verdict == "unknown" {
            self.unknown_ttl_secs
        } else {
            self.ttl_secs
        }
    }

    fn load(&self, path: &Path) -> usize {
        let Ok(f) = File::open(path) else { return 0 };
        let now = now_secs();
        let mut lines = 0;
        let mut g = self.inner.lock().unwrap();
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            lines += 1;
            let Ok(l) = serde_json::from_str::<Line>(&line) else { continue };
            let Some(sha) = parse_sha(&l.s) else { continue };
            if now - l.v.at > self.ttl_for(&l.v.verdict) {
                continue;
            }
            if g.map.insert(sha, l.v).is_none() {
                g.order.push_back(sha);
            }
            while g.order.len() > self.max {
                if let Some(old) = g.order.pop_front() {
                    g.map.remove(&old);
                }
            }
        }
        lines
    }

    fn compact(&self, path: &Path) {
        let tmp = path.with_extension("jsonl.tmp");
        let ok = (|| -> std::io::Result<()> {
            let mut w = BufWriter::new(File::create(&tmp)?);
            let g = self.inner.lock().unwrap();
            for sha in &g.order {
                if let Some(v) = g.map.get(sha) {
                    let line = Line { s: hex::encode_upper(sha), v: v.clone() };
                    writeln!(w, "{}", serde_json::to_string(&line).unwrap_or_default())?;
                }
            }
            w.flush()
        })();
        if ok.is_ok() {
            let _ = std::fs::rename(&tmp, path);
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    }

    pub fn get(&self, sha: &Sha) -> Option<CachedVerdict> {
        let mut g = self.inner.lock().unwrap();
        let v = g.map.get(sha)?;
        if now_secs() - v.at > self.ttl_for(&v.verdict) {
            g.map.remove(sha);
            return None;
        }
        Some(v.clone())
    }

    pub fn put(&self, sha: Sha, v: CachedVerdict) {
        if let Some(w) = &self.writer {
            let line = Line { s: hex::encode_upper(sha), v: v.clone() };
            if let Ok(s) = serde_json::to_string(&line) {
                let _ = w.send(s);
            }
        }
        let mut g = self.inner.lock().unwrap();
        if g.map.insert(sha, v).is_none() {
            g.order.push_back(sha);
        }
        while g.order.len() > self.max {
            if let Some(old) = g.order.pop_front() {
                g.map.remove(&old);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }
}

fn start_writer(path: PathBuf) -> Option<mpsc::Sender<String>> {
    let file = OpenOptions::new().create(true).append(true).open(&path).ok()?;
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::Builder::new()
        .name("cache-writer".into())
        .spawn(move || {
            let mut w = BufWriter::new(file);
            loop {
                match rx.recv_timeout(Duration::from_secs(2)) {
                    Ok(line) => {
                        let _ = writeln!(w, "{line}");
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let _ = w.flush();
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = w.flush();
                        break;
                    }
                }
            }
        })
        .ok()?;
    Some(tx)
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
