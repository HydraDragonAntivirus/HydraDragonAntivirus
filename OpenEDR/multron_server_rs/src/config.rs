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

    /// Engine threads: files scanned at the same time (all clients together)
    #[arg(long, default_value_t = default_workers())]
    pub workers: usize,

    /// Stack size of one engine thread in MB (deep archives / emulation need a big stack)
    #[arg(long, default_value_t = 64)]
    pub worker_stack_mb: usize,

    /// Files one client may have uploading or in analysis at the same time
    #[arg(long, default_value_t = 4)]
    pub pipeline: usize,

    /// Maximum simultaneous client connections
    #[arg(long, default_value_t = 2048)]
    pub max_conns: usize,

    /// Maximum simultaneous connections from one IP address (0 = no limit)
    #[arg(long, default_value_t = 8)]
    pub max_per_ip: usize,

    /// Shared secret the client must send in hello (empty = no token)
    #[arg(long, default_value = "")]
    pub token: String,

    /// Largest accepted file in MB (never more than 100)
    #[arg(long, default_value_t = MAX_FILE_MB)]
    pub max_mb: i64,

    /// New connections one IP may open per minute
    #[arg(long, default_value_t = 20)]
    pub connects_per_min: u32,

    /// MB one IP may upload per hour (files answered by hash do not count)
    #[arg(long, default_value_t = 2048)]
    pub upload_mb_per_hour: u32,

    /// Messages one connection may send per second
    #[arg(long, default_value_t = 100)]
    pub msgs_per_sec: u32,

    /// Hashes one connection may check per second
    #[arg(long, default_value_t = 3000)]
    pub checks_per_sec: u32,

    /// Limit violations before an IP is blocked
    #[arg(long, default_value_t = 3)]
    pub ban_strikes: u32,

    /// Minutes an IP stays blocked
    #[arg(long, default_value_t = 15)]
    pub ban_minutes: u64,

    /// Memory for uploaded files waiting for or in analysis (all clients together), in MB
    #[arg(long, default_value_t = 768)]
    pub max_inflight_mb: i64,

    /// Hashes one client may ask about in a single check message
    #[arg(long, default_value_t = 512)]
    pub max_check_batch: usize,

    /// Do not answer known files (same SHA-256) from the verdict cache
    #[arg(long)]
    pub no_cache: bool,

    /// Verdicts kept in memory (oldest are dropped first)
    #[arg(long, default_value_t = 500_000)]
    pub cache_entries: usize,

    /// Days a clean/malicious/suspicious verdict stays valid
    #[arg(long, default_value_t = 14)]
    pub cache_days: i64,

    /// Hours an "unknown" verdict stays valid (rules get updated, so recheck sooner)
    #[arg(long, default_value_t = 24)]
    pub unknown_cache_hours: i64,

    /// Do not save the verdict cache to multron_cache.jsonl (lost on restart)
    #[arg(long)]
    pub no_cache_file: bool,

    /// Do not answer from the engine's SHA-256 whitelist without an upload
    #[arg(long)]
    pub no_hash_whitelist: bool,

    /// Folder where uploaded files are kept only while scanned
    #[arg(long, default_value = "")]
    pub work_dir: String,

    /// Never write uploaded files to disk (faster, but signatures are not checked)
    #[arg(long)]
    pub memory_only: bool,

    /// Do not keep files the engine could not classify (unknown) in the work folder
    #[arg(long)]
    pub no_keep_unknown: bool,

    /// Disk space for kept unknown files in GB; no more are kept above it
    #[arg(long, default_value_t = 20)]
    pub keep_unknown_gb: u64,
}

/// Hard ceiling for one uploaded file. --max-mb can lower it, never raise it.
pub const MAX_FILE_MB: i64 = 100;

impl CliArgs {
    pub fn cache(&self) -> bool {
        !self.no_cache
    }

    /// Clamps values that would let one client use too much memory or disk.
    pub fn enforce_limits(&mut self) {
        if self.max_mb > MAX_FILE_MB || self.max_mb < 1 {
            eprintln!("[config] --max-mb {} not allowed, using {}", self.max_mb, MAX_FILE_MB);
            self.max_mb = self.max_mb.clamp(1, MAX_FILE_MB);
        }
        self.max_inflight_mb = self.max_inflight_mb.clamp(self.max_mb, 8192);
        self.pipeline = self.pipeline.clamp(1, 16);
        self.max_check_batch = self.max_check_batch.clamp(1, 1024);
        self.msgs_per_sec = self.msgs_per_sec.max(1);
        self.checks_per_sec = self.checks_per_sec.max(1);
        self.ban_strikes = self.ban_strikes.max(1);
    }
}

fn default_workers() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    cpus.saturating_sub(1).max(2)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSettings {
    pub host: String,
    pub port: u16,
    pub path: String,
    #[serde(default)]
    pub autostart: bool,
    /// Limits edited in the dashboard; None until they are changed there once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<crate::limits::LimitSettings>,
}

impl Default for SavedSettings {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 9443,
            path: "/scan".to_string(),
            autostart: false,
            limits: None,
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
