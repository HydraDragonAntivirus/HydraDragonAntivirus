use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::limits::LiveLimits;

/// Token bucket. Capacity and refill rate are passed on every call, so a limit changed in
/// the dashboard applies to existing buckets right away.
pub struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub fn full(cap: f64) -> Self {
        Self { tokens: cap, last: Instant::now() }
    }

    /// `cap` tokens at most, refilled at `rate` per second.
    pub fn take(&mut self, n: f64, cap: f64, rate: f64) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * rate).min(cap);
        self.last = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

struct IpState {
    connects: Bucket,
    upload_bytes: Bucket,
    strikes: u32,
    banned_until: Option<Instant>,
    last_seen: Instant,
}

/// Per-IP limits shared by all connections: connection rate, uploaded bytes per hour,
/// and a temporary ban for addresses that keep breaking the limits.
pub struct RateLimiter {
    map: Mutex<HashMap<String, IpState>>,
    limits: Arc<LiveLimits>,
    calls: AtomicU64,
    pub blocked: AtomicI64,
    pub bans: AtomicI64,
}

impl RateLimiter {
    pub fn new(limits: Arc<LiveLimits>) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            limits,
            calls: AtomicU64::new(0),
            blocked: AtomicI64::new(0),
            bans: AtomicI64::new(0),
        }
    }

    fn connect_cap(&self) -> f64 {
        self.limits.connects_per_min() as f64
    }

    fn upload_cap(&self) -> f64 {
        self.limits.upload_mb_per_hour() as f64 * 1024.0 * 1024.0
    }

    fn with<T>(&self, ip: &str, f: impl FnOnce(&mut IpState) -> T) -> T {
        let mut g = self.map.lock().unwrap();
        if self.calls.fetch_add(1, Ordering::Relaxed) % 4096 == 0 {
            let now = Instant::now();
            g.retain(|_, s| {
                s.banned_until.is_some_and(|t| t > now)
                    || now.duration_since(s.last_seen) < Duration::from_secs(3600)
            });
        }
        let (conn_cap, up_cap) = (self.connect_cap(), self.upload_cap());
        let s = g.entry(ip.to_string()).or_insert_with(|| IpState {
            connects: Bucket::full(conn_cap),
            upload_bytes: Bucket::full(up_cap),
            strikes: 0,
            banned_until: None,
            last_seen: Instant::now(),
        });
        s.last_seen = Instant::now();
        f(s)
    }

    /// Before the WebSocket upgrade: refuses banned addresses and connection floods.
    pub fn on_connect(&self, ip: &str) -> Result<(), &'static str> {
        let cap = self.connect_cap();
        let r = self.with(ip, |s| {
            if s.banned_until.is_some_and(|t| t > Instant::now()) {
                return Err("temporarily blocked: too many requests");
            }
            if !s.connects.take(1.0, cap, cap / 60.0) {
                s.strikes += 1;
                return Err("too many connections, slow down");
            }
            Ok(())
        });
        if r.is_err() {
            self.blocked.fetch_add(1, Ordering::Relaxed);
            self.check_ban(ip);
        }
        r
    }

    /// Before asking for an upload: bytes this address may still send this hour.
    pub fn take_upload(&self, ip: &str, bytes: i64) -> bool {
        let cap = self.upload_cap();
        let ok = self.with(ip, |s| s.upload_bytes.take(bytes.max(0) as f64, cap, cap / 3600.0));
        if !ok {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// A broken limit or protocol rule; after `ban_strikes` the address is banned.
    pub fn strike(&self, ip: &str) {
        self.with(ip, |s| s.strikes += 1);
        self.blocked.fetch_add(1, Ordering::Relaxed);
        self.check_ban(ip);
    }

    fn check_ban(&self, ip: &str) {
        let strikes = self.limits.ban_strikes();
        let minutes = self.limits.ban_minutes();
        let banned = self.with(ip, |s| {
            if s.strikes >= strikes && s.banned_until.is_none_or(|t| t <= Instant::now()) {
                s.banned_until = Some(Instant::now() + Duration::from_secs(minutes * 60));
                s.strikes = 0;
                true
            } else {
                false
            }
        });
        if banned {
            self.bans.fetch_add(1, Ordering::Relaxed);
            eprintln!("[limit] {ip} blocked for {minutes} min");
        }
    }

    /// Lifts every ban (dashboard button).
    pub fn unban_all(&self) -> usize {
        let mut n = 0;
        for s in self.map.lock().unwrap().values_mut() {
            if s.banned_until.take().is_some() {
                n += 1;
            }
            s.strikes = 0;
        }
        n
    }

    pub fn banned_now(&self) -> Vec<String> {
        let now = Instant::now();
        self.map
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| s.banned_until.is_some_and(|t| t > now))
            .map(|(ip, _)| ip.clone())
            .collect()
    }
}
