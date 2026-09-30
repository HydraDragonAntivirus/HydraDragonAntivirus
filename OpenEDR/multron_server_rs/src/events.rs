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
            "error" | "rejected" => {
                let file = self.file.as_deref().unwrap_or("");
                let msg = self.message.as_deref().unwrap_or("");
                format!("[{} #{}] {:<10} {}: {}", client, session, self.kind, file, msg)
            }
            _ => self.message.clone().unwrap_or_default(),
        }
    }
}

pub struct EventLog {
    inner: Mutex<EventLogInner>,
}

struct EventLogInner {
    seq: i64,
    events: Vec<Event>,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(EventLogInner {
                seq: 0,
                events: Vec::with_capacity(EVENT_HISTORY),
            }),
        }
    }

    pub fn add(&self, mut event: Event) {
        let line = {
            let mut guard = self.inner.lock().unwrap();
            guard.seq += 1;
            event.seq = guard.seq;
            event.time = Utc::now();
            let line = event.console_line();
            guard.events.push(event);
            let len = guard.events.len();
            if len > EVENT_HISTORY {
                guard.events.drain(0..len - EVENT_HISTORY);
            }
            line
        };
        eprintln!("{}", line);
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
