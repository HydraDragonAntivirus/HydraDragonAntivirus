use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn log_path() -> Option<PathBuf> {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .map(|path| path.join("edrsvc").join("log").join("openedr_static_engine.log"))
}

pub fn log(event: &str, detail: &str) {
    let Some(path) = log_path() else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }

    let _guard = LOG_LOCK.get_or_init(|| Mutex::new(())).lock().ok();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let detail = detail.replace(['\r', '\n'], " ");
        let _ = writeln!(file, "unix_ms={timestamp} [{event}] {detail}");
    }
}
