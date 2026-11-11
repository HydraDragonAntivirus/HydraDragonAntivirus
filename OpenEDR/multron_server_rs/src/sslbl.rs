//! Abuse.ch SSLBL (SSL Certificate Blacklist) Manager for Multron Server.
//! Stores and serves SHA-1 fingerprints of malicious SSL certificates used by botnet C2s.

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

    pub fn load(&self) {
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
        for entry in map.values() {
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
            map.remove(&clean_sha1).is_some()
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
        for line in csv_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // CSV format: Listingdate,SHA1,Listingreason
            let parts: Vec<&str> = trimmed.split(',').collect();
            if parts.len() >= 2 {
                let sha1_raw = parts[1].trim().replace(':', "").to_ascii_lowercase();
                if sha1_raw.len() == 40 && sha1_raw.chars().all(|c| c.is_ascii_hexdigit()) {
                    let reason = if parts.len() >= 3 {
                        format!("Abuse.ch SSLBL: {}", parts[2..].join(",").trim())
                    } else {
                        "Abuse.ch SSLBL Malicious Certificate".to_string()
                    };
                    map.insert(sha1_raw.clone(), SslblEntry {
                        sha1: sha1_raw,
                        reason,
                        added_at: now_str.clone(),
                        analyst: "abuse.ch_feed".to_string(),
                    });
                    added += 1;
                }
            }
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
