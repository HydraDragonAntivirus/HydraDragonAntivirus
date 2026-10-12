//! Total running time across restarts (`uptime.json` next to the server): when the
//! server first started, how long it has run in all, and how many times it started.
//! Saved every minute, so a crash loses at most the last minute.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Saved {
    first_start: DateTime<Utc>,
    /// Seconds run before this start.
    total_secs: u64,
    /// Starts so far, this one included.
    starts: u64,
    #[serde(default)]
    last_seen: Option<DateTime<Utc>>,
}

struct State {
    path: PathBuf,
    saved: Saved,
    started: Instant,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn load(path: PathBuf) -> State {
    let now = Utc::now();
    let mut saved = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Saved>(&t).ok())
        .unwrap_or(Saved { first_start: now, total_secs: 0, starts: 0, last_seen: None });
    saved.starts += 1;
    State { path, saved, started: Instant::now() }
}

fn snapshot(st: &State) -> Saved {
    let mut s = st.saved.clone();
    s.total_secs += st.started.elapsed().as_secs();
    s.last_seen = Some(Utc::now());
    s
}

fn save(st: &State) {
    let text = serde_json::to_string_pretty(&snapshot(st)).unwrap_or_default();
    let tmp = st.path.with_extension("json.tmp");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, &st.path);
    }
}

/// Call once at startup: counts this start and saves every minute.
pub fn start() {
    let st = STATE.get_or_init(|| Mutex::new(load(crate::config::app_dir().join("uptime.json"))));
    save(&st.lock().unwrap());
    let _ = std::thread::Builder::new().name("uptime".into()).spawn(|| loop {
        std::thread::sleep(Duration::from_secs(60));
        if let Some(st) = STATE.get() {
            save(&st.lock().unwrap());
        }
    });
}

/// Saves now (on shutdown, so a normal stop or an update loses nothing).
pub fn save_now() {
    if let Some(st) = STATE.get() {
        save(&st.lock().unwrap());
    }
}

/// {totalUptimeSecs, since, restarts, availability (% of the time since the first start)}.
pub fn json() -> serde_json::Value {
    let Some(st) = STATE.get() else { return serde_json::Value::Null };
    let s = snapshot(&st.lock().unwrap());
    let span = (Utc::now() - s.first_start).num_seconds().max(1) as f64;
    serde_json::json!({
        "totalUptimeSecs": s.total_secs,
        "since": s.first_start.to_rfc3339(),
        "restarts": s.starts.saturating_sub(1),
        "availability": ((s.total_secs as f64 / span) * 100.0).min(100.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_across_restarts() {
        let path = std::env::temp_dir().join(format!("uptime_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let a = load(path.clone());
        assert_eq!(a.saved.starts, 1);
        let mut s = snapshot(&a);
        s.total_secs = 100;
        std::fs::write(&path, serde_json::to_string(&s).unwrap()).unwrap();
        let b = load(path.clone());
        assert_eq!((b.saved.starts, b.saved.total_secs, b.saved.first_start), (2, 100, a.saved.first_start));
        let _ = std::fs::remove_file(&path);
    }
}
