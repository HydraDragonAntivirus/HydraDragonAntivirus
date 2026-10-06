use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const EVENT_HISTORY: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: i64,
    pub time: DateTime<Utc>,
    pub kind: String, // info, connect, disconnect, result, error, rejected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_type: Option<String>,
}

impl Event {
    pub fn console_line(&self) -> String {
        let client = self.client.as_deref().unwrap_or("server");
        let session = self.session.unwrap_or(0);
        match self.kind.as_str() {
            "connect" => format!("[{} #{}] connected", client, session),
            "disconnect" => format!(
                "[{} #{}] disconnected ({})",
                client,
                session,
                self.message.as_deref().unwrap_or("")
            ),
            "result" => {
                let verdict = self.verdict.as_deref().unwrap_or("unknown");
                let file = self.file.as_deref().unwrap_or("");
                let size_str = format_size(self.size.unwrap_or(0));
                let ms = self.ms.unwrap_or(0);
                let mut line = format!("[{} #{}] {:<10} {} ({}, {} ms)", client, session, verdict, file, size_str, ms);
                if let Some(t) = &self.threat {
                    if !t.is_empty() {
                        line.push_str(" -> ");
                        line.push_str(t);
                    }
                }
                if let Some(m) = &self.message {
                    if !m.is_empty() {
                        line.push_str(" [");
                        line.push_str(m);
                        line.push(']');
                    }
                }
                line
            }
            "extracted" => {
                let verdict = self.verdict.as_deref().unwrap_or("unknown");
                let file = self.file.as_deref().unwrap_or("");
                let size_str = format_size(self.size.unwrap_or(0));
                let origin = self.origin_type.as_deref().unwrap_or("Extracted");
                let mut line = format!("[{} #{}] {:<10} ↳ [{}] {} ({})", client, session, verdict, origin, file, size_str);
                if let Some(t) = &self.threat {
                    if !t.is_empty() {
                        line.push_str(" -> ");
                        line.push_str(t);
                    }
                }
                line
            }
            "error" | "rejected" => {
                let file = self.file.as_deref().unwrap_or("");
                let msg = self.message.as_deref().unwrap_or("");
                format!("[{} #{}] {:<10} {}: {}", client, session, self.kind, file, msg)
            }
            _ => self.message.clone().unwrap_or_default(),
        }
    }

    /// Convert event to Elastic Common Schema (ECS 8.x) JSON format for Elasticsearch.
    pub fn to_ecs_lite_json(&self) -> serde_json::Value {
        let is_threat = self.verdict.as_deref() == Some("malicious") || self.verdict.as_deref() == Some("suspicious");
        let raw_verdict = self.verdict.as_deref().unwrap_or("unknown");
        let mut obj = serde_json::json!({
            "@timestamp": self.time.to_rfc3339(),
            "ecs": { "version": "9.5.4" },
            "event": {
                "sequence": self.seq,
                "kind": if is_threat { "alert" } else { "event" },
                "category": if self.kind == "connect" || self.kind == "disconnect" { vec!["network"] } else { vec!["malware", "file"] },
                "type": if is_threat { vec!["info", "indicator"] } else { vec!["info"] },
                "action": self.kind.clone(),
                "duration": self.ms.unwrap_or(0) * 1_000_000,
            },
            "host": {
                "name": "multron-server"
            },
            "antivirus": {
                "engine": "VirusKov",
                "verdict": raw_verdict,
            }
        });

        if let Some(ref client) = self.client {
            obj["client"] = serde_json::json!({ "address": client });
            obj["source"] = serde_json::json!({ "address": client });
        }
        let mut multron = serde_json::Map::new();
        if let Some(session) = self.session {
            multron.insert("session_id".to_string(), serde_json::json!(session));
        }

        if let Some(ref verdict) = self.verdict {
            multron.insert("verdict".to_string(), serde_json::json!(verdict));
            obj["rule"] = serde_json::json!({ "verdict": verdict });
        }
        if let Some(ref threat) = self.threat {
            let mut ind = serde_json::json!({
                "type": "file",
                "name": threat,
            });
            if let Some(ref sha) = self.sha256 {
                ind["file"] = serde_json::json!({ "hash": { "sha256": sha } });
            }
            obj["threat"] = serde_json::json!({ "indicator": ind });
            if let Some(rule) = obj.get_mut("rule").and_then(|r| r.as_object_mut()) {
                rule.insert("name".to_string(), serde_json::json!(threat));
            } else {
                obj["rule"] = serde_json::json!({ "name": threat, "category": self.kind });
            }
        }
        if let Some(ref file) = self.file {
            let mut file_obj = serde_json::Map::new();
            file_obj.insert("name".to_string(), serde_json::json!(file));
            if let Some(size) = self.size {
                file_obj.insert("size".to_string(), serde_json::json!(size));
            }
            if let Some(ref sha) = self.sha256 {
                file_obj.insert("hash".to_string(), serde_json::json!({ "sha256": sha }));
            }
            obj["file"] = serde_json::Value::Object(file_obj);
        }
        if let Some(ms) = self.ms {
            multron.insert("scan_ms".to_string(), serde_json::json!(ms));
            if let Some(av) = obj.get_mut("antivirus").and_then(|a| a.as_object_mut()) {
                av.insert("scan_time_ms".to_string(), serde_json::json!(ms));
            }
        }
        if let Some(ref detail) = self.detail {
            multron.insert("detail".to_string(), serde_json::json!(detail));
        }
        if let Some(ref origin) = self.origin_type {
            multron.insert("origin_type".to_string(), serde_json::json!(origin));
        }
        if !multron.is_empty() {
            obj["multron"] = serde_json::Value::Object(multron);
        }
        if let Some(ref msg) = self.message {
            obj["message"] = serde_json::json!(msg);
        } else {
            obj["message"] = serde_json::json!(self.console_line());
        }

        obj
    }
}

pub struct EventLog {
    inner: Mutex<EventLogInner>,
    pub verbose: bool,
}

struct EventLogInner {
    seq: i64,
    events: Vec<Event>,
}

impl EventLog {
    pub fn new(verbose: bool) -> Self {
        Self {
            inner: Mutex::new(EventLogInner {
                seq: 0,
                events: Vec::with_capacity(EVENT_HISTORY),
            }),
            verbose,
        }
    }

    pub fn add(&self, mut event: Event) {
        let is_error_or_warning = event.kind == "error" || event.kind == "rejected";
        let event_kind = event.kind.to_uppercase();

        let (line, ecs_json) = {
            let mut guard = self.inner.lock().unwrap();
            guard.seq += 1;
            event.seq = guard.seq;
            event.time = Utc::now();
            let line = event.console_line();
            let ecs_json = event.to_ecs_lite_json();
            guard.events.push(event);
            let len = guard.events.len();
            if len > EVENT_HISTORY {
                guard.events.drain(0..len - EVENT_HISTORY);
            }
            (line, ecs_json)
        };

        if self.verbose {
            if let Ok(json_str) = serde_json::to_string(&ecs_json) {
                eprintln!("{}", json_str);
            } else {
                eprintln!("{}", line);
            }
        } else if is_error_or_warning {
            eprintln!("[{}] {}", event_kind, line);
        }

        // Append to multron_events.ecs.jsonl (Elasticsearch ECS Lite format)
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(crate::config::app_dir().join("multron_events.ecs.jsonl"))
        {
            use std::io::Write;
            if let Ok(json_line) = serde_json::to_string(&ecs_json) {
                let _ = writeln!(file, "{}", json_line);
            }
        }
    }

    pub fn since(&self, seq: i64) -> (Vec<Event>, i64) {
        let guard = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for e in guard.events.iter().rev() {
            if e.seq > seq && out.len() < 500 {
                out.push(e.clone());
            } else if e.seq <= seq {
                break;
            }
        }
        out.reverse();
        (out, guard.seq)
    }

    pub fn since_ecs(&self, seq: i64) -> (Vec<serde_json::Value>, i64) {
        let guard = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for e in guard.events.iter().rev() {
            if e.seq > seq && out.len() < 500 {
                out.push(e.to_ecs_lite_json());
            } else if e.seq <= seq {
                break;
            }
        }
        out.reverse();
        (out, guard.seq)
    }
}

fn format_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
