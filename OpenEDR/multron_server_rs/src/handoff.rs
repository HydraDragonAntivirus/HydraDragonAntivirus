//! Seamless update ("getting updated" mode): the new version of the server starts next
//! to the running one and takes over in a few seconds, instead of the old way (close the
//! server, replace the exe, start it again and wait minutes for the engine to load).
//!
//! 1. Multron Updater renames the running exe (Windows allows that), puts the new one in
//!    its place and starts it with `--handoff`.
//! 2. The new process (standby) tells the running one (`POST /api/handoff/begin` on its
//!    dashboard), which switches to "getting updated": scans go on as usual, health and
//!    the dashboard say the server is being updated. The standby repeats the call every
//!    few seconds; when it stops (the new version crashed), the old server leaves the
//!    mode by itself after `BEAT_TIMEOUT`.
//! 3. The standby loads the engine and the data WITHOUT touching anything the running
//!    server owns (no leftover clean-up, no dataset indexing, no listener, no writes) and
//!    follows what the running server appends to `threat_insights.jsonl`,
//!    `human_verdicts.jsonl` and `tlsh_index.jsonl`.
//! 4. Ready: `POST /api/handoff/release`. The old server refuses new scans for a moment
//!    ("switching"), lets the scans in progress finish (at most `--handoff-drain-secs`),
//!    closes its sessions, waits for its writers to flush and exits.
//! 5. The standby binds the dashboard port as soon as it is free (= the old process is
//!    gone), reads the last appended lines, and starts the scan listener at once.
//!
//! Clients see a closed connection and a few seconds of "try again" instead of minutes.
//! A running server without these endpoints (an older version) answers 404: the
//! standby then exits with `EXIT_UNSUPPORTED` and the updater falls back to the old way.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::archive::{Tail, TailRead};
use crate::config::app_dir;
use crate::scan_server::ScanServer;
use crate::threat_intel::ThreatIntelStore;

/// The old server leaves "getting updated" when the standby has not called for this long.
pub const BEAT_TIMEOUT: Duration = Duration::from_secs(45);
/// How often the standby calls the old server.
pub const BEAT_EVERY: Duration = Duration::from_secs(5);
/// Exit code of a standby whose running server does not support the handoff.
pub const EXIT_UNSUPPORTED: i32 = 3;

// ----------------------------------------------------------------------------- old side

#[derive(Debug, Clone, Copy)]
struct Standby {
    pid: u32,
    since: Instant,
    last_beat: Instant,
    /// Maintenance mode before "getting updated" (put back when the update is abandoned).
    prev_mode: u8,
}

/// Running server: the standby that will take over, if any.
#[derive(Default)]
pub struct OldSide {
    standby: Mutex<Option<Standby>>,
}

impl OldSide {
    /// A standby announced itself (or called again). Returns true the first time.
    pub fn begin(&self, server: &ScanServer, pid: u32) -> bool {
        let mut g = self.standby.lock().unwrap();
        let now = Instant::now();
        match g.as_mut() {
            Some(s) if s.pid == pid => {
                s.last_beat = now;
                false
            }
            _ => {
                let prev = server.maintenance.load(std::sync::atomic::Ordering::Relaxed);
                // Normal maintenance stays (scans are refused anyway); otherwise scans go
                // on and clients are told the server is being updated.
                let prev_mode = if prev == 3 { g.map_or(0, |s| s.prev_mode) } else { prev };
                if matches!(prev, 0 | 3) {
                    server.set_maintenance("getting_updated");
                }
                *g = Some(Standby { pid, since: now, last_beat: now, prev_mode });
                true
            }
        }
    }

    /// The standby went quiet or gave up: leave "getting updated". Returns its pid.
    pub fn abandon(&self, server: &ScanServer, only_if_stale: bool) -> Option<u32> {
        let mut g = self.standby.lock().unwrap();
        let s = (*g)?;
        if only_if_stale && s.last_beat.elapsed() < BEAT_TIMEOUT {
            return None;
        }
        *g = None;
        if server.maintenance_mode() == "getting_updated" {
            server.maintenance.store(s.prev_mode, std::sync::atomic::Ordering::Relaxed);
        }
        Some(s.pid)
    }

    pub fn standby_pid(&self) -> Option<u32> {
        self.standby.lock().unwrap().map(|s| s.pid)
    }

    pub fn status_json(&self) -> serde_json::Value {
        match *self.standby.lock().unwrap() {
            Some(s) => serde_json::json!({
                "standbyPid": s.pid,
                "sinceSecs": s.since.elapsed().as_secs(),
                "lastBeatSecs": s.last_beat.elapsed().as_secs(),
            }),
            None => serde_json::Value::Null,
        }
    }
}

// ----------------------------------------------------------------------------- new side

/// Loopback address to reach a dashboard bound to `ui` (0.0.0.0 -> 127.0.0.1).
pub fn local_addr(ui: SocketAddr) -> SocketAddr {
    if ui.ip().is_unspecified() {
        let ip = if ui.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() };
        SocketAddr::new(ip, ui.port())
    } else {
        ui
    }
}

/// Minimal HTTP/1.1 call to the local dashboard (no HTTP client crate in this server).
/// Returns the status code and the JSON body (Null when it is not JSON).
pub async fn call(addr: SocketAddr, method: &str, path: &str, body: Option<&serde_json::Value>, timeout: Duration) -> Result<(u16, serde_json::Value), String> {
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Multron-Dashboard: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
        parse_response(&raw)
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| "timed out".to_string())?
}

fn parse_response(raw: &[u8]) -> Result<(u16, serde_json::Value), String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no HTTP header")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("bad status line")?;
    let mut body = raw[split + 4..].to_vec();
    if head.lines().any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked")) {
        body = dechunk(&body);
    }
    Ok((status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)))
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = b.windows(2).position(|w| w == b"\r\n") {
        let size = std::str::from_utf8(&b[..eol]).ok().and_then(|s| usize::from_str_radix(s.split(';').next()?.trim(), 16).ok());
        let Some(size) = size.filter(|&n| n > 0) else { break };
        let start = eol + 2;
        let Some(chunk) = b.get(start..start + size) else { break };
        out.extend_from_slice(chunk);
        b = b.get(start + size + 2..).unwrap_or(&[]);
    }
    out
}

/// What the running server answered to `begin`.
pub enum Begin {
    /// It switched to "getting updated" (or already was, for this standby).
    Accepted { pid: u32 },
    /// No server answers on the dashboard address: start normally.
    NoServer,
    /// It answers but does not know the handoff (older version).
    Unsupported,
}

pub async fn begin(ui: SocketAddr) -> Begin {
    let body = serde_json::json!({ "pid": std::process::id() });
    match call(local_addr(ui), "POST", "/api/handoff/begin", Some(&body), Duration::from_secs(5)).await {
        Ok((200, v)) => Begin::Accepted { pid: v["pid"].as_u64().unwrap_or(0) as u32 },
        Ok(_) => Begin::Unsupported,
        Err(_) => Begin::NoServer,
    }
}

/// The running server was told to hand over; `listening` = its scan listener was up.
pub struct Released {
    pub listening: bool,
}

pub async fn release(ui: SocketAddr, drain_secs: u64) -> Result<Released, String> {
    let body = serde_json::json!({ "pid": std::process::id(), "drainSeconds": drain_secs });
    let wait = Duration::from_secs(drain_secs + 30);
    match call(local_addr(ui), "POST", "/api/handoff/release", Some(&body), wait).await {
        Ok((200, v)) if v["released"].as_bool() == Some(true) => Ok(Released { listening: v["listening"].as_bool().unwrap_or(true) }),
        Ok((code, v)) => Err(format!("release refused ({code}): {}", v["error"].as_str().unwrap_or(""))),
        Err(e) => Err(e),
    }
}

/// The standby gives up (it could not finish loading): the old server leaves the mode.
pub async fn cancel(ui: SocketAddr) {
    let body = serde_json::json!({ "pid": std::process::id() });
    let _ = call(local_addr(ui), "POST", "/api/handoff/cancel", Some(&body), Duration::from_secs(5)).await;
}

/// Binds `addr` as soon as the old process has let it go.
pub async fn bind_when_free(addr: SocketAddr, limit: Duration) -> Result<tokio::net::TcpListener, String> {
    let started = Instant::now();
    loop {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => return Ok(l),
            Err(e) if started.elapsed() >= limit => return Err(format!("{addr} is still in use after {} s: {e}", limit.as_secs())),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Lengths of the files the standby loads and then follows, taken BEFORE loading them.
pub struct Lengths {
    insights: u64,
    reviews: u64,
    tlsh: u64,
}

fn files() -> (PathBuf, PathBuf, PathBuf) {
    (
        app_dir().join("threat_insights.jsonl"),
        crate::human_review::analyst_dir().join("human_verdicts.jsonl"),
        app_dir().join("tlsh_index.jsonl"),
    )
}

fn sig_paths() -> Vec<PathBuf> {
    vec![app_dir().join("tlsh_signatures"), crate::human_review::analyst_dir()]
}

pub fn lengths() -> Lengths {
    let len = |p: &PathBuf| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let (a, b, c) = files();
    Lengths { insights: len(&a), reviews: len(&b), tlsh: len(&c) }
}

/// Standby: follows what the running server appends after the standby loaded the files.
pub struct Follow {
    insights: Tail,
    reviews: Tail,
    tlsh: Tail,
    sig_fp: Vec<(PathBuf, u64, u128)>,
}

impl Follow {
    pub fn new(l: Lengths) -> Self {
        let (a, b, c) = files();
        Follow {
            insights: Tail::after(a, l.insights),
            reviews: Tail::after(b, l.reviews),
            tlsh: Tail::after(c, l.tlsh),
            sig_fp: crate::archive::fingerprint(&sig_paths()),
        }
    }

    /// Reads what was appended since the last call. Returns the number of lines.
    pub fn catch_up(&mut self, ti: &ThreatIntelStore) -> usize {
        let mut n = 0;
        let mut feed = |t: &mut Tail, f: &dyn Fn(&[String], bool)| match t.read() {
            TailRead::Same => {}
            TailRead::New(l) => {
                n += l.len();
                f(&l, false)
            }
            TailRead::Reset(l) => {
                n += l.len();
                f(&l, true)
            }
        };
        feed(&mut self.insights, &|l, r| ti.archive_ingest(l, r));
        feed(&mut self.reviews, &|l, r| ti.reviews.archive_ingest(l, r));
        feed(&mut self.tlsh, &|l, r| ti.similarity.archive_ingest_index(l, r));
        let fp = crate::archive::fingerprint(&sig_paths());
        if fp != self.sig_fp {
            ti.similarity.reload_known_malware();
            ti.similarity.reload_corpus_refs();
            ti.similarity.reload_analyst_sigs();
            self.sig_fp = fp;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_response_parsing() {
        let (code, v) = parse_response(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 13\r\n\r\n{\"pid\":12345}").unwrap();
        assert_eq!(code, 200);
        assert_eq!(v["pid"], 12345);
        let (code, v) = parse_response(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n").unwrap();
        assert_eq!((code, v["a"].as_i64()), (200, Some(1)));
        let (code, v) = parse_response(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").unwrap();
        assert_eq!((code, v), (404, serde_json::Value::Null));
        assert!(parse_response(b"garbage").is_err());
    }

    #[test]
    fn loopback_for_unspecified() {
        assert_eq!(local_addr("0.0.0.0:9440".parse().unwrap()), "127.0.0.1:9440".parse().unwrap());
        assert_eq!(local_addr("127.0.0.1:9440".parse().unwrap()), "127.0.0.1:9440".parse().unwrap());
    }

    #[test]
    fn tail_after_reads_only_new_lines() {
        let d = std::env::temp_dir().join(format!("handoff_tail_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("a.jsonl");
        std::fs::write(&p, "one\ntwo\nthr").unwrap(); // "thr" is a line being written
        let len = std::fs::metadata(&p).unwrap().len();
        let mut t = Tail::after(p.clone(), len);
        assert!(matches!(t.read(), TailRead::Same), "nothing complete after the loaded part");
        std::fs::write(&p, "one\ntwo\nthree\nfour\n").unwrap();
        match t.read() {
            TailRead::New(l) => assert_eq!(l, vec!["three", "four"], "the half-written line is read again whole"),
            _ => panic!("expected new lines"),
        }
        // Empty file: everything is new.
        let q = d.join("b.jsonl");
        let mut t = Tail::after(q.clone(), 0);
        std::fs::write(&q, "x\n").unwrap();
        assert!(matches!(t.read(), TailRead::New(l) if l == vec!["x"]));
        std::fs::remove_dir_all(&d).ok();
    }
}
