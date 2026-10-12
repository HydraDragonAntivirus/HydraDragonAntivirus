//! Analyst IP bans (bots, abuse): exact addresses or CIDR ranges, permanent or with an
//! end time, kept in `ip_bans.json` next to the server. Banned addresses get 403 on
//! every public route (WebSocket included) and their open sessions are closed.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::app_dir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBan {
    /// "203.0.113.9", "203.0.113.0/24" or "2001:db8::/32" (normalized).
    pub rule: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub analyst: String,
    pub created: String,
    /// RFC 3339 end time; None = until removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Requests refused since the ban was added (not saved on every hit).
    #[serde(default)]
    pub hits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().map_err(|_| format!("not an IP address: {a}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().ok().filter(|n| *n <= max).ok_or_else(|| format!("bad prefix /{p} (0-{max})"))?,
            None => max,
        };
        // A whole address family can not be banned by accident.
        let min = if addr.is_ipv4() { 8 } else { 16 };
        if prefix < min {
            return Err(format!("range too wide: at least /{min}"));
        }
        Ok(Self { addr: mask(addr, prefix), prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        // IPv4-mapped IPv6 (::ffff:1.2.3.4) is checked as IPv4.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == self.addr
    }

    fn text(&self) -> String {
        let max = if self.addr.is_ipv4() { 32 } else { 128 };
        if self.prefix == max { self.addr.to_string() } else { format!("{}/{}", self.addr, self.prefix) }
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

fn expired(b: &IpBan, now: DateTime<Utc>) -> bool {
    b.expires
        .as_deref()
        .and_then(|e| DateTime::parse_from_rfc3339(e).ok())
        .is_some_and(|e| e.with_timezone(&Utc) <= now)
}

pub struct BanList {
    path: PathBuf,
    list: RwLock<Vec<(Net, IpBan)>>,
}

impl BanList {
    pub fn load() -> Self {
        Self::load_from(app_dir().join("ip_bans.json"))
    }

    pub fn load_from(path: PathBuf) -> Self {
        let mut list = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Vec<IpBan>>(&text) {
                Ok(items) => {
                    for b in items {
                        match Net::parse(&b.rule) {
                            Ok(n) => list.push((n, b)),
                            Err(e) => eprintln!("[bans] skipped {}: {e}", b.rule),
                        }
                    }
                }
                Err(e) => eprintln!("[bans] {} unreadable: {e}", path.display()),
            }
        }
        if !list.is_empty() {
            eprintln!("[bans] {} IP bans loaded", list.len());
        }
        Self { path, list: RwLock::new(list) }
    }

    fn save(&self, list: &[(Net, IpBan)]) -> Result<(), String> {
        let items: Vec<&IpBan> = list.iter().map(|(_, b)| b).collect();
        let text = serde_json::to_string_pretty(&items).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("{}: {e}", self.path.display()))
    }

    /// The ban that covers `ip`, if any (expired bans are ignored). Counts the hit.
    pub fn check(&self, ip: &str) -> Option<IpBan> {
        let ip: IpAddr = ip.trim().parse().ok()?;
        let now = Utc::now();
        let hit = {
            let g = self.list.read().unwrap();
            g.iter().position(|(n, b)| n.contains(ip) && !expired(b, now))
        }?;
        let mut g = self.list.write().unwrap();
        let (_, b) = g.get_mut(hit)?;
        b.hits += 1;
        Some(b.clone())
    }

    pub fn is_banned(&self, ip: &str) -> bool {
        let Ok(ip) = ip.trim().parse::<IpAddr>() else { return false };
        let now = Utc::now();
        self.list.read().unwrap().iter().any(|(n, b)| n.contains(ip) && !expired(b, now))
    }

    /// Adds or replaces a ban. `minutes` 0 = permanent. Returns the normalized rule.
    pub fn add(&self, rule: &str, reason: &str, analyst: &str, minutes: u64) -> Result<IpBan, String> {
        let net = Net::parse(rule)?;
        let now = Utc::now();
        let ban = IpBan {
            rule: net.text(),
            reason: reason.trim().chars().take(500).collect(),
            analyst: analyst.trim().chars().take(80).collect(),
            created: now.to_rfc3339(),
            expires: (minutes > 0).then(|| (now + chrono::Duration::minutes(minutes.min(10 * 365 * 24 * 60) as i64)).to_rfc3339()),
            hits: 0,
        };
        let mut g = self.list.write().unwrap();
        g.retain(|(n, _)| *n != net);
        g.push((net, ban.clone()));
        self.save(&g)?;
        Ok(ban)
    }

    /// Removes the ban with this rule (as listed). True when one was removed.
    pub fn remove(&self, rule: &str) -> Result<bool, String> {
        let net = Net::parse(rule)?;
        let mut g = self.list.write().unwrap();
        let before = g.len();
        g.retain(|(n, _)| *n != net);
        if g.len() == before {
            return Ok(false);
        }
        self.save(&g)?;
        Ok(true)
    }

    /// All bans, newest first, with `active` (not expired).
    pub fn list(&self) -> Vec<serde_json::Value> {
        let now = Utc::now();
        let mut v: Vec<serde_json::Value> = self
            .list
            .read()
            .unwrap()
            .iter()
            .map(|(_, b)| {
                let mut j = serde_json::to_value(b).unwrap_or_default();
                j["active"] = serde_json::json!(!expired(b, now));
                j
            })
            .collect();
        v.sort_by(|a, b| b["created"].as_str().cmp(&a["created"].as_str()));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ipbans_{}_{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("ip_bans.json")
    }
    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn exact_cidr_v6_and_persist() {
        let p = tmp();
        let b = BanList::load_from(p.clone());
        assert_eq!(b.add("203.0.113.77/24", "bot", "a", 0).unwrap().rule, "203.0.113.0/24");
        b.add("2001:db8::1", "bot6", "a", 0).unwrap();
        assert!(b.is_banned("203.0.113.5"));
        assert!(b.is_banned("::ffff:203.0.113.200"));
        assert!(!b.is_banned("203.0.114.5"));
        assert!(b.is_banned("2001:db8::1"));
        assert!(!b.is_banned("2001:db8::2"));
        assert!(b.check("203.0.113.9").is_some());
        assert!(BanList::load_from(p.clone()).is_banned("203.0.113.1"), "saved to disk");
        assert!(b.remove("203.0.113.0/24").unwrap());
        assert!(!b.is_banned("203.0.113.5"));
        assert!(!BanList::load_from(p).is_banned("203.0.113.5"));
        assert!(b.add("10.0.0.0/4", "", "", 0).is_err(), "too wide");
        assert!(b.add("nope", "", "", 0).is_err());
    }

    #[test]
    fn expired_ban_is_ignored() {
        let b = BanList::load_from(tmp());
        b.add("198.51.100.4", "", "", 0).unwrap();
        b.list.write().unwrap()[0].1.expires = Some("2000-01-01T00:00:00+00:00".into());
        assert!(!b.is_banned("198.51.100.4"));
        assert_eq!(b.list()[0]["active"], false);
    }
}
