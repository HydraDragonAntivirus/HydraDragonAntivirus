use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Multron Cloud Scan Server in Rust")]
pub struct CliArgs {
    /// Start scanning right away on this address, e.g. 127.0.0.1:9443
    #[arg(long, default_value = "")]
    pub listen: String,

    /// WebSocket endpoint path used with --listen (default: /scan)
    #[arg(long, default_value = "")]
    pub path: String,

    /// Address of the dashboard (keep it on 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1:9440")]
    pub ui: String,

    /// Do not open the dashboard in the browser at startup
    #[arg(long)]
    pub no_browser: bool,

    /// Rules/database folder for the engine (default: next to exe, then current folder)
    #[arg(long, default_value = "")]
    pub rules: String,

    /// Files scanned by the engine at the same time (all clients together)
    #[arg(long, default_value_t = default_workers())]
    pub workers: usize,

    /// Files one client may have uploading or in analysis at the same time
    #[arg(long, default_value_t = 8)]
    pub pipeline: usize,

    /// Maximum simultaneous client connections
    #[arg(long, default_value_t = 64)]
    pub max_conns: usize,

    /// Largest accepted file in MB
    #[arg(long, default_value_t = 100)]
    pub max_mb: i64,

    /// Memory for files waiting for or in analysis (all clients together), in MB
    #[arg(long, default_value_t = 1024)]
    pub max_inflight_mb: i64,

    /// Answer repeated files (same SHA-256) from memory instead of asking for upload again
    #[arg(long)]
    pub cache: bool,

    /// Folder where uploaded files are kept only while scanned
    #[arg(long, default_value = "")]
    pub work_dir: String,

    /// Never write uploaded files to disk (faster, but signatures are not checked)
    #[arg(long)]
    pub memory_only: bool,
}

fn default_workers() -> usize {
    let cpus = num_cpus();
    (cpus / 2).max(2)
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSettings {
    pub host: String,
    pub port: u16,
    pub path: String,
    #[serde(default)]
    pub autostart: bool,
}

impl Default for SavedSettings {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 9443,
            path: "/scan".to_string(),
            autostart: false,
        }
    }
}

pub fn app_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.to_path_buf();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
