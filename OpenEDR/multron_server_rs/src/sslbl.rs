//! Abuse.ch SSLBL (SSL Certificate Blacklist) Manager for Multron Server.
//! Stores and serves SHA-1 fingerprints of malicious SSL certificates used by botnet C2s.
//!
//! Two layers, like the other signature folders next to the executable:
//! - `firewall_signatures/*.csv` — shipped feeds (Abuse.ch `sslblacklist.csv`),
//!   read-only, loaded at start-up and never rewritten by the server.
//! - `analyst_signatures/sslbl.jsonl` — what analysts add or import from the
//!   dashboard; it overlays the shipped layer.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const SSLBL_FILE: &str = "sslbl.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslblEntry {
    pub sha1: String,
    pub reason: String,
    pub added_at: String,
    #[serde(default)]
    pub analyst: String,
    /// Shipped in `firewall_signatures/` (not persisted to `sslbl.jsonl`, and
    /// not removable from the dashboard: edit the shipped feed instead).
    #[serde(default, skip_deserializing)]
    pub builtin: bool,
}

/// Shipped firewall signatures: `firewall_signatures/` next to the executable
/// (Abuse.ch SSLBL feed as `*.csv`, firewall rules as `*.yaml`).
pub fn firewall_signatures_dir() -> PathBuf {
    crate::config::app_dir().join("firewall_signatures")
}

/// Parses an Abuse.ch SSLBL CSV (`Listingdate,SHA1,Listingreason`, `#` comments)
/// into `(sha1, reason)` pairs; malformed lines are skipped.
fn parse_abusech_csv(csv_text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in csv_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.len() < 2 {
            continue;
        }
        let Some(sha1) = as_cert_sha1(parts[1]) else {
            continue;
        };
        let reason = if parts.len() >= 3 {
            format!("Abuse.ch SSLBL: {}", parts[2..].join(",").trim())
        } else {
            "Abuse.ch SSLBL Malicious Certificate".to_string()
        };
        out.push((sha1, reason));
    }
    out
}

#[derive(Default)]
pub struct SslblStore {
    entries: RwLock<HashMap<String, SslblEntry>>,
}

static STORE: OnceLock<SslblStore> = OnceLock::new();

pub fn sslbl_store() -> &'static SslblStore {
    STORE.get_or_init(|| {
        let store = SslblStore::default();
        store.load();
        store
    })
}

impl SslblStore {
    fn file_path() -> PathBuf {
        crate::human_review::analyst_dir().join(SSLBL_FILE)
    }

    /// Loads every `*.csv` feed of `firewall_signatures/` as built-in entries.
    fn load_shipped(&self) {
        let dir = firewall_signatures_dir();
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut map = self.entries.write().unwrap();
        let mut loaded = 0usize;
        for e in rd.flatten() {
            let p = e.path();
            let is_csv = p
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("csv"));
            if !is_csv {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            let added_at = std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339())
                .unwrap_or_default();
            for (sha1, reason) in parse_abusech_csv(&text) {
                map.insert(sha1.clone(), SslblEntry {
                    sha1,
                    reason,
                    added_at: added_at.clone(),
                    analyst: "abuse.ch_feed".to_string(),
                    builtin: true,
                });
                loaded += 1;
            }
        }
        tracing::info!("[sslbl] Loaded {} shipped SSL blacklist entries from {:?}", loaded, dir);
    }

    pub fn load(&self) {
        // Shipped feeds first; the analyst file overlays them below.
        self.load_shipped();
        let p = Self::file_path();
        let Ok(file) = File::open(&p) else {
            return;
        };
        let reader = BufReader::new(file);
        let mut map = self.entries.write().unwrap();
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<SslblEntry>(trimmed) {
                map.insert(entry.sha1.to_ascii_lowercase(), entry);
            }
        }
        tracing::info!("[sslbl] Loaded {} SSL blacklist entries from {:?}", map.len(), p);
    }

    pub fn save(&self) -> std::io::Result<()> {
        let p = Self::file_path();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut file = File::create(&p)?;
        let map = self.entries.read().unwrap();
        // Shipped entries live in `firewall_signatures/`, never in this file.
        for entry in map.values().filter(|e| !e.builtin) {
            if let Ok(json) = serde_json::to_string(entry) {
                writeln!(file, "{}", json)?;
            }
        }
        Ok(())
    }

    pub fn add(&self, sha1: &str, reason: &str, analyst: &str) -> Result<SslblEntry, String> {
        let clean_sha1 = sha1.trim().replace(':', "").to_ascii_lowercase();
        if clean_sha1.len() != 40 || !clean_sha1.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid SHA-1 fingerprint (must be 40 hex characters)".into());
        }
        let entry = SslblEntry {
            sha1: clean_sha1.clone(),
            reason: reason.trim().to_string(),
            added_at: Utc::now().to_rfc3339(),
            analyst: analyst.trim().to_string(),
            builtin: false,
        };
        {
            let mut map = self.entries.write().unwrap();
            map.insert(clean_sha1, entry.clone());
        }
        let _ = self.save();
        Ok(entry)
    }

    pub fn remove(&self, sha1: &str) -> bool {
        let clean_sha1 = sha1.trim().replace(':', "").to_ascii_lowercase();
        let removed = {
            let mut map = self.entries.write().unwrap();
            // A shipped entry would come back on the next start: it is
            // removed by editing the feed in `firewall_signatures/`.
            if map.get(&clean_sha1).is_some_and(|e| e.builtin) {
                false
            } else {
                map.remove(&clean_sha1).is_some()
            }
        };
        if removed {
            let _ = self.save();
        }
        removed
    }

    /// Blacklist entry for a certificate SHA-1 (any case, optional colons).
    pub fn lookup(&self, sha1: &str) -> Option<SslblEntry> {
        let clean = sha1.trim().replace(':', "").to_ascii_lowercase();
        self.entries.read().unwrap().get(&clean).cloned()
    }

    pub fn list(&self) -> Vec<SslblEntry> {
        let map = self.entries.read().unwrap();
        let mut list: Vec<SslblEntry> = map.values().cloned().collect();
        list.sort_by(|a, b| b.added_at.cmp(&a.added_at));
        list
    }

    pub fn import_abusech_csv(&self, csv_text: &str) -> usize {
        let mut added = 0;
        let mut map = self.entries.write().unwrap();
        let now_str = Utc::now().to_rfc3339();
        for (sha1, reason) in parse_abusech_csv(csv_text) {
            // Already shipped in `firewall_signatures/`: nothing to store.
            if map.get(&sha1).is_some_and(|e| e.builtin) {
                continue;
            }
            map.insert(sha1.clone(), SslblEntry {
                sha1,
                reason,
                added_at: now_str.clone(),
                analyst: "abuse.ch_feed".to_string(),
                builtin: false,
            });
            added += 1;
        }
        drop(map);
        if added > 0 {
            let _ = self.save();
        }
        added
    }
}

/// `Some(lowercase sha1)` when `target` is a bare certificate fingerprint
/// (40 hex chars, optionally colon-separated) rather than a URL / host / IP.
pub fn as_cert_sha1(target: &str) -> Option<String> {
    let clean = target.trim().replace(':', "").to_ascii_lowercase();
    (clean.len() == 40 && clean.chars().all(|c| c.is_ascii_hexdigit())).then_some(clean)
}

// ---------------- REST API Handlers ----------------

pub async fn handle_get_sslbl() -> impl IntoResponse {
    let list = sslbl_store().list();
    Json(serde_json::json!({
        "ok": true,
        "count": list.len(),
        "entries": list,
    }))
}

#[derive(Deserialize)]
pub struct SslblAddBody {
    pub sha1: String,
    #[serde(default = "default_reason")]
    pub reason: String,
    #[serde(default)]
    pub analyst: String,
}

fn default_reason() -> String {
    "Malicious C2 Certificate".into()
}

pub async fn handle_add_sslbl(Json(body): Json<SslblAddBody>) -> Response {
    match sslbl_store().add(&body.sha1, &body.reason, &body.analyst) {
        Ok(entry) => Json(serde_json::json!({ "ok": true, "entry": entry })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct SslblDeleteBody {
    pub sha1: String,
}

pub async fn handle_delete_sslbl(Json(body): Json<SslblDeleteBody>) -> impl IntoResponse {
    let removed = sslbl_store().remove(&body.sha1);
    Json(serde_json::json!({ "ok": true, "removed": removed }))
}

#[derive(Deserialize)]
pub struct SslblImportBody {
    pub csv: String,
}

pub async fn handle_import_abusech_sslbl(Json(body): Json<SslblImportBody>) -> impl IntoResponse {
    let count = sslbl_store().import_abusech_csv(&body.csv);
    Json(serde_json::json!({ "ok": true, "imported": count, "total": sslbl_store().list().len() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_abusech_csv_lines() {
        let csv = "# Listingdate,SHA1,Listingreason\n\
                   2026-09-21 16:26:12,ADCFF1C66A3BA1C9446886EB9F6EFDBEC4F17688,ACRStealer C&C\n\
                   garbage line\n\
                   2026-09-21 15:49:25,nothex,AsyncRAT C&C\n";
        let got = parse_abusech_csv(csv);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "adcff1c66a3ba1c9446886eb9f6efdbec4f17688");
        assert_eq!(got[0].1, "Abuse.ch SSLBL: ACRStealer C&C");
    }

    /// The feed shipped in `OpenMalwareScannerPortable/firewall_signatures/`
    /// must stay parseable: every data line yields an entry.
    #[test]
    fn shipped_feed_parses_completely() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../OpenMalwareScannerPortable/firewall_signatures/sslblacklist.csv");
        let text = std::fs::read_to_string(&p).expect("shipped sslblacklist.csv");
        let data_lines = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .count();
        assert!(data_lines > 1000);
        assert_eq!(parse_abusech_csv(&text).len(), data_lines);
    }
}
