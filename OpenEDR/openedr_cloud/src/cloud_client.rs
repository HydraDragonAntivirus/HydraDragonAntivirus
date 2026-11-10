use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionItem {
    pub name: String,
    pub category: String,
    pub engine: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanReport {
    pub file_path: String,
    pub verdict: String, // "Clean" | "Malicious" | "Suspicious" | "Unknown"
    pub detections: Vec<DetectionItem>,
    pub sha256: String,
    pub file_size: u64,
    pub scanned_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanReport {
    pub pid: u32,
    pub verdict: String, // "Clean" | "Malicious" | "Suspicious" | "Unknown"
    pub detections: Vec<DetectionItem>,
    pub sha256: String,
    pub bytes_scanned: usize,
    pub scanned_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlScanReport {
    pub target_url: String,
    pub verdict: String, // "Clean" | "Malicious"
    pub malware_probability: f64,
    pub is_malicious: bool,
    pub whitelisted: bool,
    pub blacklisted: bool,
}

#[derive(Debug, Clone)]
pub struct CloudConfig {
    pub url: String,
    pub token: String,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self::load()
    }
}

impl CloudConfig {
    pub fn load() -> Self {
        let mut url = std::env::var("OPENEDR_CLOUD_URL")
            .unwrap_or_else(|_| "wss://api.viruskov.com/ws".to_string());
        let mut token = std::env::var("OPENEDR_CLOUD_TOKEN").unwrap_or_default();

        let mut config_paths = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                config_paths.push(parent.join("openedr_cloud.json"));
            }
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            config_paths.push(PathBuf::from(pf).join("HydraDragonAntivirus").join("OpenEDR").join("openedr_cloud.json"));
        }
        if let Ok(pd) = std::env::var("ProgramData") {
            config_paths.push(PathBuf::from(pd).join("HydraDragon").join("openedr_cloud.json"));
        }

        for path in config_paths {
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(u) = v.get("url").and_then(|x| x.as_str()) {
                            if !u.is_empty() {
                                url = u.to_string();
                            }
                        }
                        if let Some(t) = v.get("token").and_then(|x| x.as_str()) {
                            token = t.to_string();
                        }
                        break;
                    }
                }
            }
        }

        // Auto-upgrade legacy host to API tunnel endpoint
        if url == "wss://viruskov.com/ws" || url == "ws://viruskov.com/ws" {
            url = "wss://api.viruskov.com/ws".to_string();
        }

        Self { url, token }
    }
}

type WsStream = WebSocket<MaybeTlsStream<TcpStream>>;

struct CloudSession {
    socket: Option<WsStream>,
    config: CloudConfig,
    next_id: AtomicI64,
    last_failure: Option<Instant>,
}

impl CloudSession {
    fn new() -> Self {
        Self {
            socket: None,
            config: CloudConfig::load(),
            next_id: AtomicI64::new(1),
            last_failure: None,
        }
    }

    fn next_request_id(&self) -> i64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn ensure_connected(&mut self) -> Result<&mut WsStream, String> {
        if let Some(last_fail) = self.last_failure {
            if last_fail.elapsed() < Duration::from_secs(3) {
                return Err("Throttled after recent connection failure".to_string());
            }
        }

        if self.socket.is_some() {
            return Ok(self.socket.as_mut().unwrap());
        }

        let connect_url = &self.config.url;
        let (mut socket, _resp) = match tungstenite::connect(connect_url) {
            Ok(pair) => pair,
            Err(e) => {
                self.last_failure = Some(Instant::now());
                return Err(format!("Cloud connection failed ({}): {}", connect_url, e));
            }
        };

        // Handshake: send hello (v3)
        let hello_msg = serde_json::json!({
            "type": "hello",
            "version": 3,
            "client": "OpenEDRCloud/1.0",
            "token": self.config.token,
        });

        if let Err(e) = socket.send(Message::Text(hello_msg.to_string().into())) {
            self.last_failure = Some(Instant::now());
            return Err(format!("Failed to send hello to cloud: {}", e));
        }

        // Wait for hello_ok
        let mut hello_ok = false;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match socket.read() {
                Ok(Message::Text(txt)) => {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
                        let msg_type = val.get("type").and_then(|x| x.as_str()).unwrap_or("");
                        if msg_type == "hello_ok" {
                            hello_ok = true;
                            break;
                        } else if msg_type == "error" {
                            let msg = val.get("message").and_then(|x| x.as_str()).unwrap_or("unknown error");
                            self.last_failure = Some(Instant::now());
                            return Err(format!("Cloud rejected handshake: {}", msg));
                        }
                    }
                }
                Ok(Message::Ping(p)) => {
                    let _ = socket.send(Message::Pong(p));
                }
                Ok(_) => {}
                Err(e) => {
                    self.last_failure = Some(Instant::now());
                    return Err(format!("Failed reading hello_ok from cloud: {}", e));
                }
            }
        }

        if !hello_ok {
            self.last_failure = Some(Instant::now());
            return Err("Timed out waiting for hello_ok from cloud".to_string());
        }

        self.last_failure = None;
        self.socket = Some(socket);
        Ok(self.socket.as_mut().unwrap())
    }

    fn drop_connection(&mut self) {
        self.socket = None;
        self.last_failure = Some(Instant::now());
    }
}

static CLIENT: Mutex<Option<CloudSession>> = Mutex::new(None);

fn with_client<F, R>(f: F) -> R
where
    F: FnOnce(&mut CloudSession) -> R,
{
    let mut guard = CLIENT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(CloudSession::new());
    }
    f(guard.as_mut().unwrap())
}

/// Computes SHA256 hex string for a given reader.
pub fn compute_sha256<R: Read>(mut reader: R) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total_bytes += n as u64;
    }

    let hash = hasher.finalize();
    Ok((hex::encode(hash), total_bytes))
}

fn parse_result_verdict(val: &serde_json::Value) -> (String, Vec<DetectionItem>) {
    let mut raw_verdict = val.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
    if raw_verdict.is_empty() {
        if let Some(av) = val.get("antivirus") {
            raw_verdict = av.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        }
    }

    let title_verdict = match raw_verdict.to_ascii_lowercase().as_str() {
        "malicious" => "Malicious",
        "clean" | "possible_clean" => "Clean",
        "suspicious" => "Suspicious",
        _ => "Unknown",
    };

    let mut detections = Vec::new();
    if title_verdict == "Malicious" || title_verdict == "Suspicious" {
        let mut threat_name = None;
        if let Some(t) = val.get("threat") {
            threat_name = t.get("name").and_then(|n| n.as_str());
        }
        if threat_name.is_none() {
            if let Some(r) = val.get("rule") {
                threat_name = r.get("name").and_then(|n| n.as_str());
            }
        }
        if threat_name.is_none() {
            if let Some(av) = val.get("antivirus") {
                threat_name = av.get("detail").and_then(|d| d.as_str());
            }
        }
        if threat_name.is_none() {
            if let Some(dets) = val.get("detections").and_then(|d| d.as_array()) {
                threat_name = dets.first().and_then(|d| d.get("name")).and_then(|n| n.as_str());
            }
        }

        let name = threat_name
            .unwrap_or(if title_verdict == "Malicious" {
                "Malware.CloudDetection"
            } else {
                "Suspicious.CloudDetection"
            })
            .to_string();

        detections.push(DetectionItem {
            name,
            category: "cloud".to_string(),
            engine: "viruskov".to_string(),
        });
    }

    (title_verdict.to_string(), detections)
}

/// Scans a file on disk via viruskov.com cloud WebSocket.
pub fn scan_file(path: &Path) -> FileScanReport {
    let path_str = path.to_string_lossy().to_string();
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return FileScanReport {
                file_path: path_str,
                verdict: "Error(gone)".to_string(),
                detections: Vec::new(),
                sha256: String::new(),
                file_size: 0,
                scanned_at: chrono_now_iso(),
                note: Some("File not found or unreadable".to_string()),
            };
        }
    };

    let (sha256_hex, file_size) = match compute_sha256(file) {
        Ok(res) => res,
        Err(_) => {
            return FileScanReport {
                file_path: path_str,
                verdict: "Error(locked_or_gone)".to_string(),
                detections: Vec::new(),
                sha256: String::new(),
                file_size: 0,
                scanned_at: chrono_now_iso(),
                note: Some("Failed to read file contents for hashing".to_string()),
            };
        }
    };

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "sample.bin".to_string());

    let res = with_client(|session| {
        let req_id = session.next_request_id();

        let socket = match session.ensure_connected() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        // 1. Send check
        let check_req = serde_json::json!({
            "type": "check",
            "items": [
                {
                    "id": req_id,
                    "sha256": sha256_hex,
                    "name": file_name,
                    "size": file_size,
                    "path": path_str,
                    "rescan": false
                }
            ]
        });

        if let Err(e) = socket.send(Message::Text(check_req.to_string().into())) {
            session.drop_connection();
            return Err(format!("Socket write error: {}", e));
        }

        // Wait for result or need_upload
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(12) {
                return Err("Cloud query timed out".to_string());
            }

            let msg = match socket.read() {
                Ok(m) => m,
                Err(e) => {
                    session.drop_connection();
                    return Err(format!("Socket read error: {}", e));
                }
            };

            match msg {
                Message::Text(txt) => {
                    let val: serde_json::Value = match serde_json::from_str(&txt) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let msg_id = val.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                    let msg_type = val.get("type").and_then(|x| x.as_str()).unwrap_or("");

                    if msg_id == req_id {
                        if msg_type == "result" {
                            let (verdict, detections) = parse_result_verdict(&val);
                            return Ok((verdict, detections));
                        } else if msg_type == "need_upload" {
                            // Upload file
                            let scan_req = serde_json::json!({
                                "type": "scan",
                                "id": req_id,
                                "sha256": sha256_hex,
                                "name": file_name,
                                "size": file_size
                            });
                            if let Err(e) = socket.send(Message::Text(scan_req.to_string().into())) {
                                session.drop_connection();
                                return Err(format!("Upload request error: {}", e));
                            }
                        } else if msg_type == "send_file" {
                            let file_bytes = match std::fs::read(path) {
                                Ok(b) => b,
                                Err(e) => return Err(format!("Failed reading file for upload: {}", e)),
                            };
                            if let Err(e) = socket.send(Message::Binary(file_bytes.into())) {
                                session.drop_connection();
                                return Err(format!("File upload binary error: {}", e));
                            }
                        } else if msg_type == "error" {
                            let err_msg = val.get("message").and_then(|m| m.as_str()).unwrap_or("cloud error");
                            return Err(err_msg.to_string());
                        }
                    }
                }
                Message::Ping(p) => {
                    let _ = socket.send(Message::Pong(p));
                }
                _ => {}
            }
        }
    });

    match res {
        Ok((verdict, detections)) => FileScanReport {
            file_path: path_str,
            verdict,
            detections,
            sha256: sha256_hex,
            file_size,
            scanned_at: chrono_now_iso(),
            note: None,
        },
        Err(e) => FileScanReport {
            file_path: path_str,
            verdict: "Unknown".to_string(),
            detections: Vec::new(),
            sha256: sha256_hex,
            file_size,
            scanned_at: chrono_now_iso(),
            note: Some(format!("Cloud scan deferred: {}", e)),
        },
    }
}

/// Scans in-memory bytes (memory dumps or buffer) via viruskov.com cloud WebSocket.
pub fn scan_bytes(data: &[u8], name: &str) -> (String, Vec<DetectionItem>, String) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256_hex = hex::encode(hasher.finalize());
    let size = data.len() as u64;

    let res = with_client(|session| {
        let req_id = session.next_request_id();

        let socket = match session.ensure_connected() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let check_req = serde_json::json!({
            "type": "check",
            "items": [
                {
                    "id": req_id,
                    "sha256": sha256_hex,
                    "name": name,
                    "size": size,
                    "path": name,
                    "rescan": false
                }
            ]
        });

        if let Err(e) = socket.send(Message::Text(check_req.to_string().into())) {
            session.drop_connection();
            return Err(format!("Socket write error: {}", e));
        }

        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(12) {
                return Err("Cloud query timed out".to_string());
            }

            let msg = match socket.read() {
                Ok(m) => m,
                Err(e) => {
                    session.drop_connection();
                    return Err(format!("Socket read error: {}", e));
                }
            };

            match msg {
                Message::Text(txt) => {
                    let val: serde_json::Value = match serde_json::from_str(&txt) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let msg_id = val.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                    let msg_type = val.get("type").and_then(|x| x.as_str()).unwrap_or("");

                    if msg_id == req_id {
                        if msg_type == "result" {
                            let (verdict, detections) = parse_result_verdict(&val);
                            return Ok((verdict, detections));
                        } else if msg_type == "need_upload" {
                            let scan_req = serde_json::json!({
                                "type": "scan",
                                "id": req_id,
                                "sha256": sha256_hex,
                                "name": name,
                                "size": size
                            });
                            if let Err(e) = socket.send(Message::Text(scan_req.to_string().into())) {
                                session.drop_connection();
                                return Err(format!("Upload request error: {}", e));
                            }
                        } else if msg_type == "send_file" {
                            if let Err(e) = socket.send(Message::Binary(data.to_vec().into())) {
                                session.drop_connection();
                                return Err(format!("Binary upload error: {}", e));
                            }
                        } else if msg_type == "error" {
                            let err_msg = val.get("message").and_then(|m| m.as_str()).unwrap_or("cloud error");
                            return Err(err_msg.to_string());
                        }
                    }
                }
                Message::Ping(p) => {
                    let _ = socket.send(Message::Pong(p));
                }
                _ => {}
            }
        }
    });

    match res {
        Ok((verdict, detections)) => (verdict, detections, sha256_hex),
        Err(_) => ("Unknown".to_string(), Vec::new(), sha256_hex),
    }
}

/// Scans a URL via viruskov.com cloud WebSocket.
pub fn scan_url(url: &str) -> UrlScanReport {
    let res = with_client(|session| {
        let req_id = session.next_request_id();

        let socket = match session.ensure_connected() {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let url_req = serde_json::json!({
            "type": "scan_url",
            "id": req_id,
            "url": url
        });

        if let Err(e) = socket.send(Message::Text(url_req.to_string().into())) {
            session.drop_connection();
            return Err(format!("Socket write error: {}", e));
        }

        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(8) {
                return Err("Cloud URL query timed out".to_string());
            }

            let msg = match socket.read() {
                Ok(m) => m,
                Err(e) => {
                    session.drop_connection();
                    return Err(format!("Socket read error: {}", e));
                }
            };

            match msg {
                Message::Text(txt) => {
                    let val: serde_json::Value = match serde_json::from_str(&txt) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let msg_id = val.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
                    let msg_type = val.get("type").and_then(|x| x.as_str()).unwrap_or("");

                    if msg_id == req_id && msg_type == "url_result" {
                        let res_obj = val.get("result").cloned().unwrap_or(serde_json::Value::Null);
                        let is_mal = res_obj.get("is_malicious").and_then(|m| m.as_bool()).unwrap_or(false);
                        let prob = res_obj.get("malware_probability").and_then(|p| p.as_f64()).unwrap_or(0.0);
                        let white = res_obj.get("whitelisted").and_then(|w| w.as_bool()).unwrap_or(!is_mal);
                        let black = res_obj.get("blacklisted").and_then(|b| b.as_bool()).unwrap_or(is_mal);
                        return Ok((is_mal, prob, white, black));
                    } else if msg_id == req_id && msg_type == "error" {
                        let err_msg = val.get("message").and_then(|m| m.as_str()).unwrap_or("cloud error");
                        return Err(err_msg.to_string());
                    }
                }
                Message::Ping(p) => {
                    let _ = socket.send(Message::Pong(p));
                }
                _ => {}
            }
        }
    });

    match res {
        Ok((is_mal, prob, white, black)) => UrlScanReport {
            target_url: url.to_string(),
            verdict: if is_mal { "Malicious".to_string() } else { "Clean".to_string() },
            malware_probability: prob,
            is_malicious: is_mal,
            whitelisted: white,
            blacklisted: black,
        },
        Err(_) => UrlScanReport {
            target_url: url.to_string(),
            verdict: "Clean".to_string(),
            malware_probability: 0.0,
            is_malicious: false,
            whitelisted: true,
            blacklisted: false,
        },
    }
}

fn chrono_now_iso() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}-01-01T00:00:00Z", now) // Lightweight fallback
}
