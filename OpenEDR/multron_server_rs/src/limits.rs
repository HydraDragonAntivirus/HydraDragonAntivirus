use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

use crate::config::{CliArgs, MAX_FILE_MB};

/// Limits that can be changed from the dashboard while the server runs.
/// Saved in multron_server.json; the command-line flags are only the first defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitSettings {
    pub max_mb: i64,
    pub max_inflight_mb: i64,
    pub max_conns: usize,
    pub max_per_ip: usize,
    pub pipeline: usize,
    pub max_check_batch: usize,
    pub connects_per_min: u32,
    pub upload_mb_per_hour: u32,
    pub msgs_per_sec: u32,
    pub checks_per_sec: u32,
    pub ban_strikes: u32,
    pub ban_minutes: u64,
}

impl LimitSettings {
    pub fn from_args(a: &CliArgs) -> Self {
        Self {
            max_mb: a.max_mb,
            max_inflight_mb: a.max_inflight_mb,
            max_conns: a.max_conns,
            max_per_ip: a.max_per_ip,
            pipeline: a.pipeline,
            max_check_batch: a.max_check_batch,
            connects_per_min: a.connects_per_min,
            upload_mb_per_hour: a.upload_mb_per_hour,
            msgs_per_sec: a.msgs_per_sec,
            checks_per_sec: a.checks_per_sec,
            ban_strikes: a.ban_strikes,
            ban_minutes: a.ban_minutes,
        }
    }

    /// Keeps every value in a safe range. The 100 MB file ceiling cannot be raised.
    pub fn clamped(mut self) -> Self {
        self.max_mb = self.max_mb.clamp(1, MAX_FILE_MB);
        self.max_inflight_mb = self.max_inflight_mb.clamp(self.max_mb, 8192);
        self.max_conns = self.max_conns.clamp(1, 100_000);
        self.max_per_ip = self.max_per_ip.min(10_000);
        self.pipeline = self.pipeline.clamp(1, 16);
        self.max_check_batch = self.max_check_batch.clamp(1, 1024);
        self.connects_per_min = self.connects_per_min.clamp(1, 10_000);
        self.upload_mb_per_hour = self.upload_mb_per_hour.clamp(1, 1_000_000);
        self.msgs_per_sec = self.msgs_per_sec.clamp(1, 100_000);
        self.checks_per_sec = self.checks_per_sec.clamp(1, 1_000_000);
        self.ban_strikes = self.ban_strikes.clamp(1, 1000);
        self.ban_minutes = self.ban_minutes.clamp(1, 7 * 24 * 60);
        self
    }
}

/// The current limits, read on every use, so a change applies at once
/// (pipeline and check batch size apply to new connections).
pub struct LiveLimits {
    max_mb: AtomicI64,
    max_inflight_mb: AtomicI64,
    max_conns: AtomicUsize,
    max_per_ip: AtomicUsize,
    pipeline: AtomicUsize,
    max_check_batch: AtomicUsize,
    connects_per_min: AtomicU32,
    upload_mb_per_hour: AtomicU32,
    msgs_per_sec: AtomicU32,
    checks_per_sec: AtomicU32,
    ban_strikes: AtomicU32,
    ban_minutes: AtomicU64,
}

const R: Ordering = Ordering::Relaxed;

impl LiveLimits {
    pub fn new(s: LimitSettings) -> Self {
        let s = s.clamped();
        Self {
            max_mb: AtomicI64::new(s.max_mb),
            max_inflight_mb: AtomicI64::new(s.max_inflight_mb),
            max_conns: AtomicUsize::new(s.max_conns),
            max_per_ip: AtomicUsize::new(s.max_per_ip),
            pipeline: AtomicUsize::new(s.pipeline),
            max_check_batch: AtomicUsize::new(s.max_check_batch),
            connects_per_min: AtomicU32::new(s.connects_per_min),
            upload_mb_per_hour: AtomicU32::new(s.upload_mb_per_hour),
            msgs_per_sec: AtomicU32::new(s.msgs_per_sec),
            checks_per_sec: AtomicU32::new(s.checks_per_sec),
            ban_strikes: AtomicU32::new(s.ban_strikes),
            ban_minutes: AtomicU64::new(s.ban_minutes),
        }
    }

    pub fn set(&self, s: LimitSettings) -> LimitSettings {
        let s = s.clamped();
        self.max_mb.store(s.max_mb, R);
        self.max_inflight_mb.store(s.max_inflight_mb, R);
        self.max_conns.store(s.max_conns, R);
        self.max_per_ip.store(s.max_per_ip, R);
        self.pipeline.store(s.pipeline, R);
        self.max_check_batch.store(s.max_check_batch, R);
        self.connects_per_min.store(s.connects_per_min, R);
        self.upload_mb_per_hour.store(s.upload_mb_per_hour, R);
        self.msgs_per_sec.store(s.msgs_per_sec, R);
        self.checks_per_sec.store(s.checks_per_sec, R);
        self.ban_strikes.store(s.ban_strikes, R);
        self.ban_minutes.store(s.ban_minutes, R);
        s
    }

    pub fn get(&self) -> LimitSettings {
        LimitSettings {
            max_mb: self.max_mb(),
            max_inflight_mb: self.max_inflight_mb(),
            max_conns: self.max_conns(),
            max_per_ip: self.max_per_ip(),
            pipeline: self.pipeline(),
            max_check_batch: self.max_check_batch(),
            connects_per_min: self.connects_per_min(),
            upload_mb_per_hour: self.upload_mb_per_hour(),
            msgs_per_sec: self.msgs_per_sec(),
            checks_per_sec: self.checks_per_sec(),
            ban_strikes: self.ban_strikes(),
            ban_minutes: self.ban_minutes(),
        }
    }

    pub fn max_mb(&self) -> i64 { self.max_mb.load(R) }
    pub fn max_bytes(&self) -> i64 { self.max_mb() * 1024 * 1024 }
    pub fn max_inflight_mb(&self) -> i64 { self.max_inflight_mb.load(R) }
    pub fn max_conns(&self) -> usize { self.max_conns.load(R) }
    pub fn max_per_ip(&self) -> usize { self.max_per_ip.load(R) }
    pub fn pipeline(&self) -> usize { self.pipeline.load(R) }
    pub fn max_check_batch(&self) -> usize { self.max_check_batch.load(R) }
    pub fn connects_per_min(&self) -> u32 { self.connects_per_min.load(R) }
    pub fn upload_mb_per_hour(&self) -> u32 { self.upload_mb_per_hour.load(R) }
    pub fn msgs_per_sec(&self) -> u32 { self.msgs_per_sec.load(R) }
    pub fn checks_per_sec(&self) -> u32 { self.checks_per_sec.load(R) }
    pub fn ban_strikes(&self) -> u32 { self.ban_strikes.load(R) }
    pub fn ban_minutes(&self) -> u64 { self.ban_minutes.load(R) }
}
