use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, RwLock, Semaphore};
use tower_http::cors::{Any, CorsLayer};

use crate::budget::ByteBudget;
use crate::cache::{now_secs, parse_sha, CachedVerdict, Sha, VerdictCache};
use crate::config::{app_dir, CliArgs};
use crate::engine_adapter::{EngineAdapter, ResultMessage, ENGINE_NAME};
use crate::events::{Event, EventLog};
use crate::limits::{LimitSettings, LiveLimits};
use crate::ratelimit::{Bucket, RateLimiter};
use crate::scheduler::FairScheduler;
use crate::threat_intel::{RestRateLimiter, ThreatIntelStore};

/// Largest single WebSocket message. Files arrive in 256 KiB chunks and JSON stays small,
/// so nobody can make the server buffer a 100 MB frame.
const MAX_WS_MESSAGE: usize = 1024 * 1024;
/// Uploads slower than this are cut off (stops connections that trickle bytes to hold memory).
const MIN_UPLOAD_BYTES_PER_SEC: i64 = 64 * 1024;
/// Upload window per client = pipeline × this (see `session_loop`).
const UPLOAD_WINDOW_FACTOR: usize = 4;

/// 3 = hash-first: the client sends `check` batches of SHA-256s and uploads only the
/// files the server answers with `need_upload`. Version 2 clients (scan only) still work.
pub const PROTOCOL_VERSION: i32 = 3;
const MIN_PROTOCOL_VERSION: i32 = 2;

#[derive(Debug, Deserialize)]
struct ClientMessage {
    pub r#type: String,
    #[serde(default)]
    pub version: i32,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub items: Vec<CheckItem>,
}

#[derive(Debug, Deserialize)]
struct CheckItem {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
pub struct UrlScanRequest {
    pub url: String,
    #[serde(default)]
    pub content: Option<String>,
    /// HTTP status the client saw when it fetched the content (if it did).
    /// Used as a gate: difference rules only run when both sides agree.
    #[serde(default)]
    pub content_status: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct UrlScanQuery {
    pub url: String,
}

#[derive(Debug, Serialize)]
struct ErrorMessage<'a> {
    pub r#type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub message: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub id: i64,
    pub address: String,
    pub app: String,
    #[serde(rename = "connectedAt")]
    pub connected_at: chrono::DateTime<Utc>,
    pub scanned: i64,
    pub threats: i64,
    #[serde(rename = "inFlight")]
    pub in_flight: usize,
    pub uploads: i64,
}

type Out = mpsc::UnboundedSender<Message>;

/// A client that asked about a file another client is uploading right now.
/// It gets the verdict when that scan finishes instead of uploading the same bytes.
struct Waiter {
    tx: Out,
    id: i64,
    session: Arc<SessionHandle>,
    name: String,
    size: i64,
}

struct InflightEntry {
    token: u64,
    waiters: Vec<Waiter>,
}

enum Outcome {
    Done(ResultMessage),
    EngineError(String),
    UploadFailed,
}

#[derive(Default)]
pub struct Stats {
    pub checked: AtomicI64,
    pub cache_hits: AtomicI64,
    pub whitelist_hits: AtomicI64,
    pub hash_sig_hits: AtomicI64,
    pub shared_hits: AtomicI64,
    pub uploads: AtomicI64,
    pub bytes_uploaded: AtomicI64,
    pub engine_scans: AtomicI64,
    pub engine_crashes: AtomicI64,
    pub rejected_auth: AtomicI64,
}

pub struct ScanServer {
    pub cfg: CliArgs,
    pub engine: Arc<EngineAdapter>,
    pub scheduler: Arc<FairScheduler>,
    pub budget: Arc<ByteBudget>,
    pub events: Arc<EventLog>,
    pub cache: VerdictCache,
    pub stats: Stats,
    pub limiter: RateLimiter,
    pub limits: Arc<LiveLimits>,
    pub threat_intel: Arc<ThreatIntelStore>,
    pub rest_limiter: RestRateLimiter,

    inflight: StdMutex<HashMap<Sha, InflightEntry>>,
    next_token: AtomicU64,
    per_ip: StdMutex<HashMap<String, usize>>,
    pub sessions: RwLock<HashMap<i64, Arc<SessionHandle>>>,

    pub next_session_id: AtomicI64,
    pub total_connections: AtomicI64,
    pub total_scanned: AtomicI64,
    pub total_threats: AtomicI64,
    pub total_errors: AtomicI64,
    pub active_connections: AtomicUsize,
    /// Maintenance mode: the listener stays up (health answers), but new
    /// scans are refused with a message while in-flight work finishes.
    /// Unlike stop, clients get an answer instead of a refused connection.
    pub maintenance: AtomicBool,
    /// Process boot time for uptime reporting.
    pub boot_time: std::time::Instant,
}

pub struct SessionHandle {
    pub id: i64,
    pub address: String,
    pub app: RwLock<String>,
    pub connected_at: chrono::DateTime<Utc>,
    pub scanned: AtomicI64,
    pub threats: AtomicI64,
    pub uploads: AtomicI64,
    pub in_flight: AtomicUsize,
    pub abort_tx: mpsc::Sender<()>,
}

impl ScanServer {
    pub fn new(
        cfg: CliArgs,
        engine: Arc<EngineAdapter>,
        events: Arc<EventLog>,
        threat_intel: Arc<ThreatIntelStore>,
    ) -> Arc<Self> {
        let scheduler = FairScheduler::new(cfg.workers, cfg.worker_stack_mb);
        let budget = ByteBudget::new(cfg.max_inflight_mb * 1024 * 1024);
        let cache_file: Option<PathBuf> = if cfg.cache() && !cfg.no_cache_file {
            Some(app_dir().join("multron_cache.jsonl"))
        } else {
            None
        };
        let cache = VerdictCache::new(cfg.cache_entries, cfg.cache_days, cfg.unknown_cache_hours, cache_file);
        if cache.len() > 0 {
            eprintln!("[cache] {} verdicts loaded", cache.len());
        }

        let limits = Arc::new(LiveLimits::new(LimitSettings::from_args(&cfg)));
        let limiter = RateLimiter::new(Arc::clone(&limits));
        let rest_limiter = RestRateLimiter::new();

        Arc::new(Self {
            limiter,
            limits,
            threat_intel,
            rest_limiter,
            cfg,
            engine,
            scheduler,
            budget,
            events,
            cache,
            stats: Stats::default(),
            inflight: StdMutex::new(HashMap::new()),
            next_token: AtomicU64::new(1),
            per_ip: StdMutex::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicI64::new(0),
            total_connections: AtomicI64::new(0),
            total_scanned: AtomicI64::new(0),
            total_threats: AtomicI64::new(0),
            total_errors: AtomicI64::new(0),
            active_connections: AtomicUsize::new(0),
            maintenance: AtomicBool::new(false),
            boot_time: std::time::Instant::now(),
        })
    }

    /// Seconds since the server process started.
    pub fn uptime_secs(&self) -> u64 {
        self.boot_time.elapsed().as_secs()
    }

    /// Maintenance flag: true while the operator holds new scans for updates.
    pub fn maintenance(&self) -> bool {
        self.maintenance.load(Ordering::Relaxed)
    }

    /// Flip maintenance mode. In-flight scans finish; new ones are refused
    /// with a message until it is switched back off.
    pub fn set_maintenance(&self, on: bool) {
        self.maintenance.store(on, Ordering::Relaxed);
    }

    pub fn router(self: &Arc<Self>, path: &str) -> Router {
        let normalized_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        Router::new()
            .route(&normalized_path, get(ws_handler))
            .route("/health", get(Self::handle_health))
            .route("/api/v1/insights/:sha256", get(handle_hash_insights))
            .route("/api/v1/insights/stats", get(handle_insights_stats))
            .route("/api/v1/scan/url", post(handle_scan_url).get(handle_scan_url_get))
            .layer(cors)
            .with_state(Arc::clone(self))
    }

async fn handle_health(State(server): State<Arc<ScanServer>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": if server.maintenance() { "maintenance" } else { "ok" },
        "maintenance": server.maintenance(),
        "uptimeSecs": server.uptime_secs(),
        "engine": ENGINE_NAME,
        "protocol": PROTOCOL_VERSION,
    }))
}

    pub async fn get_clients(&self) -> Vec<ClientInfo> {
        let guard = self.sessions.read().await;
        let mut list = Vec::with_capacity(guard.len());
        for sess in guard.values() {
            let app_name = sess.app.read().await.clone();
            list.push(ClientInfo {
                id: sess.id,
                address: sess.address.clone(),
                app: app_name,
                connected_at: sess.connected_at,
                scanned: sess.scanned.load(Ordering::Relaxed),
                threats: sess.threats.load(Ordering::Relaxed),
                in_flight: sess.in_flight.load(Ordering::Relaxed),
                uploads: sess.uploads.load(Ordering::Relaxed),
            });
        }
        list.sort_by_key(|c| c.id);
        list
    }

    pub async fn close_all_sessions(&self) {
        let guard = self.sessions.read().await;
        for sess in guard.values() {
            let _ = sess.abort_tx.try_send(());
        }
    }

    pub fn inflight_files(&self) -> usize {
        self.inflight.lock().unwrap().len()
    }

    /// Verdict without the file: shared verdict cache, then hash signatures / whitelist.
    fn known(&self, sha: &Sha, sha_hex: &str) -> Option<ResultMessage> {
        if self.cfg.cache() {
            if let Some(v) = self.cache.get(sha) {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                let is_threat = v.verdict == "malicious" || v.verdict == "suspicious";
                let ecs = serde_json::json!({
                    "@timestamp": chrono::Utc::now().to_rfc3339(),
                    "ecs": { "version": "9.5.4" },
                    "event": {
                        "kind": if is_threat { "alert" } else { "event" },
                        "category": ["malware", "file"],
                        "type": if is_threat { vec!["info", "indicator"] } else { vec!["info"] },
                        "action": "cache_lookup",
                        "outcome": "success",
                        "duration": 0,
                    },
                    "file": {
                        "hash": {
                            "sha256": sha_hex,
                        }
                    },
                    "antivirus": {
                        "engine": ENGINE_NAME,
                        "verdict": v.verdict,
                        "score": v.score,
                        "source": "cache",
                        "detail": v.detail,
                    },
                    "rule": {
                        "name": v.threat.as_deref().unwrap_or(v.detail.as_deref().unwrap_or("")),
                        "verdict": v.verdict,
                    }
                });
                let threat_indicator = if is_threat {
                    Some(serde_json::json!({
                        "indicator": {
                            "type": "file",
                            "name": v.threat.as_deref().unwrap_or(""),
                            "confidence": v.score,
                            "file": {
                                "hash": {
                                    "sha256": sha_hex,
                                }
                            }
                        }
                    }))
                } else {
                    None
                };
                return Some(ResultMessage {
                    r#type: "result".into(),
                    id: 0,
                    timestamp: ecs.get("@timestamp").and_then(|t| t.as_str()).map(|s| s.to_string()),
                    ecs: Some(serde_json::json!({ "version": "9.5.4" })),
                    event: ecs.get("event").cloned(),
                    file: ecs.get("file").cloned(),
                    antivirus: ecs.get("antivirus").cloned(),
                    threat_indicator,
                    rule: ecs.get("rule").cloned(),
                    verdict: v.verdict,
                    threat: v.threat,
                    detail: v.detail,
                    score: v.score,
                    sha256: sha_hex.to_string(),
                    scan_ms: 0,
                    source: "cache".into(),
                    extracted_objects: Vec::new(),
                });
            }
        }
        let r = self.engine.hash_lookup(sha, sha_hex)?;
        if r.source == "whitelist" {
            self.stats.whitelist_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.hash_sig_hits.fetch_add(1, Ordering::Relaxed);
        }
        Some(r)
    }

    fn remember(&self, sha: Sha, res: &ResultMessage) {
        if !self.cfg.cache() {
            return;
        }
        self.cache.put(
            sha,
            CachedVerdict {
                verdict: res.verdict.clone(),
                threat: res.threat.clone(),
                detail: res.detail.clone(),
                score: res.score,
                at: now_secs(),
            },
        );
    }

    /// Called once by the session that uploaded a file; answers every client waiting on it.
    fn finish_inflight(&self, sha: &Sha, token: u64, outcome: &Outcome) {
        let waiters = {
            let mut g = self.inflight.lock().unwrap();
            match g.get(sha) {
                Some(e) if e.token == token => g.remove(sha).map(|e| e.waiters).unwrap_or_default(),
                _ => return,
            }
        };
        for w in waiters {
            w.session.in_flight.fetch_sub(1, Ordering::Relaxed);
            match outcome {
                Outcome::Done(res) => {
                    let mut r = res.clone();
                    r.id = w.id;
                    r.scan_ms = 0;
                    r.source = "shared".into();
                    self.stats.shared_hits.fetch_add(1, Ordering::Relaxed);
                    record_result(self, &w.session, &r, &w.name, w.size);
                    send_json(&w.tx, &r);
                }
                Outcome::EngineError(msg) => {
                    send_error(&w.tx, Some(w.id), &format!("scan failed: {msg}"));
                }
                Outcome::UploadFailed => {
                    send_json(&w.tx, &serde_json::json!({"type": "need_upload", "id": w.id}));
                }
            }
        }
    }

    /// Applies limits edited in the dashboard; returns them as stored (clamped).
    pub fn apply_limits(&self, s: LimitSettings) -> LimitSettings {
        let s = self.limits.set(s);
        self.budget.resize(s.max_inflight_mb * 1024 * 1024);
        s
    }

    fn acquire_ip(&self, ip: &str) -> bool {
        let max = self.limits.max_per_ip();
        let mut g = self.per_ip.lock().unwrap();
        let n = g.entry(ip.to_string()).or_insert(0);
        if max > 0 && *n >= max {
            return false;
        }
        *n += 1;
        true
    }

    fn release_ip(&self, ip: &str) {
        let mut g = self.per_ip.lock().unwrap();
        if let Some(n) = g.get_mut(ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.remove(ip);
            }
        }
    }
}

/// Marks a file as "being uploaded/scanned" so identical checks from other clients wait
/// for it. Dropping it without `complete` (disconnect, bad upload) tells them to upload.
struct InflightGuard {
    server: Arc<ScanServer>,
    sha: Sha,
    token: u64,
    owner: bool,
    done: bool,
}

impl InflightGuard {
    fn claim(server: &Arc<ScanServer>, sha: Sha) -> Self {
        let token = server.next_token.fetch_add(1, Ordering::Relaxed);
        let owner = {
            let mut g = server.inflight.lock().unwrap();
            if g.contains_key(&sha) {
                false
            } else {
                g.insert(sha, InflightEntry { token, waiters: Vec::new() });
                true
            }
        };
        Self { server: Arc::clone(server), sha, token, owner, done: false }
    }

    fn complete(mut self, outcome: Outcome) {
        self.done = true;
        if self.owner {
            self.server.finish_inflight(&self.sha, self.token, &outcome);
        }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if !self.done && self.owner {
            self.server.finish_inflight(&self.sha, self.token, &Outcome::UploadFailed);
        }
    }
}

fn extract_client_ip(addr: SocketAddr, headers: &HeaderMap) -> String {
    let mut client_ip = addr.ip().to_string();
    if addr.ip().is_loopback() {
        if let Some(cf) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
            let cf = cf.trim();
            if !cf.is_empty() && cf.len() <= 64 && cf.parse::<std::net::IpAddr>().is_ok() {
                client_ip = cf.to_string();
            }
        }
    }
    client_ip
}

async fn handle_hash_insights(
    Path(sha256): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(server): State<Arc<ScanServer>>,
) -> Response {
    let client_ip = extract_client_ip(addr, &headers);
    let api_key = headers
        .get("x-api-key")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok());

    match server.rest_limiter.check(&client_ip, api_key) {
        Ok(header) => {
            let sha_clean = sha256.trim().to_lowercase();
            if sha_clean.len() != 64 || !sha_clean.chars().all(|c| c.is_ascii_hexdigit()) {
                let err = serde_json::json!({
                    "status": "error",
                    "error": "Invalid SHA-256 hash format. Expected 64 hexadecimal characters."
                });
                return (
                    StatusCode::BAD_REQUEST,
                    [
                        ("Content-Type", "application/json"),
                        ("Access-Control-Allow-Origin", "*"),
                    ],
                    serde_json::to_string(&err).unwrap(),
                ).into_response();
            }

            if let Some(insight) = server.threat_intel.get(&sha_clean) {
                let response = serde_json::json!({
                    "status": "success",
                    "sha256": insight.sha256,
                    "verdict": insight.verdict,
                    "threat_name": insight.threat_name,
                    "first_seen": insight.first_seen,
                    "last_seen": insight.last_seen,
                    "seen_count": insight.seen_count,
                    "prevalence": insight.prevalence(),
                    "file_names": insight.file_names,
                    "file_size": insight.file_size,
                    "score": insight.score,
                    "threat_intelligence": {
                        "engine": ENGINE_NAME,
                        "feed": "VirusKov Community Telemetry",
                        "prevalence_level": insight.prevalence()
                    }
                });

                (
                    StatusCode::OK,
                    [
                        ("Content-Type", "application/json"),
                        ("Access-Control-Allow-Origin", "*"),
                        ("X-RateLimit-Limit", &header.limit.to_string()),
                        ("X-RateLimit-Remaining", &header.remaining.to_string()),
                    ],
                    serde_json::to_string_pretty(&response).unwrap(),
                ).into_response()
            } else {
                let response = serde_json::json!({
                    "status": "not_found",
                    "sha256": sha_clean,
                    "verdict": "unknown",
                    "seen_count": 0,
                    "prevalence": "not_seen",
                    "message": "Hash has not been observed in VirusKov telemetry",
                    "threat_intelligence": {
                        "engine": ENGINE_NAME,
                        "feed": "VirusKov Community Telemetry"
                    }
                });

                (
                    StatusCode::NOT_FOUND,
                    [
                        ("Content-Type", "application/json"),
                        ("Access-Control-Allow-Origin", "*"),
                        ("X-RateLimit-Limit", &header.limit.to_string()),
                        ("X-RateLimit-Remaining", &header.remaining.to_string()),
                    ],
                    serde_json::to_string_pretty(&response).unwrap(),
                ).into_response()
            }
        }
        Err(retry_after) => {
            let error_json = serde_json::json!({
                "status": "error",
                "error": "Too Many Requests",
                "message": "VirusKov Threat Insights rate limit exceeded (10 requests/min). Please slow down.",
                "retry_after_seconds": retry_after
            });

            (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    ("Content-Type", "application/json"),
                    ("Access-Control-Allow-Origin", "*"),
                    ("Retry-After", &retry_after.to_string()),
                    ("X-RateLimit-Limit", "10"),
                    ("X-RateLimit-Remaining", "0"),
                ],
                serde_json::to_string(&error_json).unwrap(),
            ).into_response()
        }
    }
}

async fn handle_insights_stats(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(server): State<Arc<ScanServer>>,
) -> Response {
    let client_ip = extract_client_ip(addr, &headers);
    let api_key = headers
        .get("x-api-key")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok());

    match server.rest_limiter.check(&client_ip, api_key) {
        Ok(header) => {
            let stats = server.threat_intel.stats();
            let response = serde_json::json!({
                "status": "success",
                "engine": ENGINE_NAME,
                "feed": "VirusKov Community Telemetry",
                "telemetry": {
                    "total_unique_hashes": stats.total_unique_hashes,
                    "total_sightings": stats.total_sightings,
                    "verdicts": {
                        "malicious": stats.malicious_count,
                        "suspicious": stats.suspicious_count,
                        "clean": stats.clean_count,
                        "unknown": stats.unknown_count,
                    }
                }
            });

            (
                StatusCode::OK,
                [
                    ("Content-Type", "application/json"),
                    ("Access-Control-Allow-Origin", "*"),
                    ("X-RateLimit-Limit", &header.limit.to_string()),
                    ("X-RateLimit-Remaining", &header.remaining.to_string()),
                ],
                serde_json::to_string_pretty(&response).unwrap(),
            ).into_response()
        }
        Err(retry_after) => {
            let error_json = serde_json::json!({
                "status": "error",
                "error": "Too Many Requests",
                "message": "VirusKov Threat Insights rate limit exceeded. Please slow down.",
                "retry_after_seconds": retry_after
            });

            (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    ("Content-Type", "application/json"),
                    ("Access-Control-Allow-Origin", "*"),
                    ("Retry-After", &retry_after.to_string()),
                    ("X-RateLimit-Limit", "10"),
                    ("X-RateLimit-Remaining", "0"),
                ],
                serde_json::to_string(&error_json).unwrap(),
            ).into_response()
        }
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(server): State<Arc<ScanServer>>,
) -> Response {
    let client_ip = extract_client_ip(addr, &headers);

    // Banned addresses and connection floods are refused before the upgrade (cheap 429).
    if let Err(msg) = server.limiter.on_connect(&client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    ws.max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |socket| handle_socket(socket, server, client_ip))
}

async fn reject(mut socket: WebSocket, msg: &str) {
    let err = ErrorMessage { r#type: "error", id: None, message: msg };
    let _ = socket
        .send(Message::Text(serde_json::to_string(&err).unwrap_or_default()))
        .await;
    let _ = socket.close().await;
}

async fn handle_socket(socket: WebSocket, server: Arc<ScanServer>, client_ip: String) {
    let current = server.active_connections.fetch_add(1, Ordering::SeqCst);
    if current >= server.limits.max_conns() {
        server.active_connections.fetch_sub(1, Ordering::SeqCst);
        reject(socket, "server busy, try again later").await;
        return;
    }
    if !server.acquire_ip(&client_ip) {
        server.active_connections.fetch_sub(1, Ordering::SeqCst);
        reject(socket, "too many connections from this address").await;
        return;
    }

    let session_id = server.next_session_id.fetch_add(1, Ordering::SeqCst) + 1;
    server.total_connections.fetch_add(1, Ordering::Relaxed);

    let (abort_tx, mut abort_rx) = mpsc::channel(1);
    let session_handle = Arc::new(SessionHandle {
        id: session_id,
        address: client_ip.clone(),
        app: RwLock::new(String::new()),
        connected_at: Utc::now(),
        scanned: AtomicI64::new(0),
        threats: AtomicI64::new(0),
        uploads: AtomicI64::new(0),
        in_flight: AtomicUsize::new(0),
        abort_tx,
    });

    server
        .sessions
        .write()
        .await
        .insert(session_id, Arc::clone(&session_handle));

    server.events.add(simple_event("connect", Some(session_id), Some(client_ip.clone()), None));

    let run_res = tokio::select! {
        res = run_session(socket, Arc::clone(&server), Arc::clone(&session_handle)) => res,
        _ = abort_rx.recv() => Ok(()),
    };

    server.active_connections.fetch_sub(1, Ordering::SeqCst);
    server.release_ip(&client_ip);
    server.sessions.write().await.remove(&session_id);

    let mut msg = format!(
        "{} file(s) answered, {} uploaded",
        session_handle.scanned.load(Ordering::Relaxed),
        session_handle.uploads.load(Ordering::Relaxed)
    );
    if let Err(e) = run_res {
        msg.push_str(&format!(", {}", e));
    }
    server
        .events
        .add(simple_event("disconnect", Some(session_id), Some(client_ip), Some(msg)));
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn run_session(
    socket: WebSocket,
    server: Arc<ScanServer>,
    session: Arc<SessionHandle>,
) -> Result<(), String> {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (out, mut outgoing_rx) = mpsc::unbounded_channel::<Message>();

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = outgoing_rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    // Keeps proxies / the Cloudflare tunnel from closing an idle connection.
    let ping_tx = out.clone();
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(20));
        loop {
            interval.tick().await;
            if ping_tx.send(Message::Ping(Vec::new())).is_err() {
                break;
            }
        }
    });

    let result = session_loop(&mut ws_rx, &out, &server, &session).await;

    ping_task.abort();
    drop(out);
    // Scans still in the engine hold their own sender clone; wait for them a while.
    let _ = tokio::time::timeout(Duration::from_secs(600), writer_task).await;
    result
}

async fn session_loop(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    out: &Out,
    server: &Arc<ScanServer>,
    session: &Arc<SessionHandle>,
) -> Result<(), String> {
    // 1. Handshake
    let hello = match tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => match serde_json::from_str::<ClientMessage>(&t) {
            Ok(m) => m,
            Err(e) => {
                server.limiter.strike(&session.address);
                return Err(format!("invalid hello JSON: {}", e));
            }
        },
        _ => {
            return Err("handshake timeout or connection closed".to_string());
        }
    };

    if hello.r#type != "hello" {
        send_error(out, None, "expected hello");
        return Err(format!("unexpected first message: {}", hello.r#type));
    }
    if hello.version < MIN_PROTOCOL_VERSION || hello.version > PROTOCOL_VERSION {
        let err = format!(
            "unsupported protocol version {} (server speaks {}), please update Multron Win Cleaner",
            hello.version, PROTOCOL_VERSION
        );
        send_error(out, None, &err);
        return Err(err);
    }
    if !server.cfg.token.is_empty()
        && !constant_time_eq(hello.token.as_bytes(), server.cfg.token.as_bytes())
    {
        server.stats.rejected_auth.fetch_add(1, Ordering::Relaxed);
        server.limiter.strike(&session.address);
        send_error(out, None, "invalid token");
        return Err("invalid token".into());
    }
    if !server.engine.ready() {
        send_error(out, None, "the scan engine is still loading, try again in a minute");
        return Err("engine not ready".into());
    }

    *session.app.write().await = hello.client.chars().take(64).collect();
    let pipeline = server.limits.pipeline().max(1);

    send_json(
        out,
        &serde_json::json!({
            "type": "hello_ok",
            "version": PROTOCOL_VERSION,
            "engine": ENGINE_NAME,
            "pipeline": pipeline,
            "checkBatch": server.limits.max_check_batch(),
            "maxMB": server.limits.max_mb(),
        }),
    );

    // `window`: files one client may have uploading or waiting for a result. It is wider
    // than `scan_slots` so the next uploads stream in while earlier files are being
    // scanned (before, the upload of file N+1 waited for a scan to finish, which made the
    // upload rate look like ~0.3 MB/s). Memory stays bounded by the shared budget.
    let slots = Arc::new(Semaphore::new(pipeline * UPLOAD_WINDOW_FACTOR));
    // `scan_slots`: files one client may have in the engine at the same time.
    let scan_slots = Arc::new(Semaphore::new(pipeline));

    // Per-connection flood limits (one second of burst headroom on top of the rate).
    // Rates are read on every message, so a change in the dashboard applies at once.
    let msg_rate = || server.limits.msgs_per_sec() as f64;
    let check_rate = || server.limits.checks_per_sec() as f64;
    let mut msg_bucket = Bucket::full(msg_rate() * 2.0);
    let mut check_bucket = Bucket::full(check_rate() * 2.0);
    let flood = |what: &str| {
        server.limiter.strike(&session.address);
        send_error(out, None, &format!("too many {what}, slow down"));
        Err(format!("flood: too many {what}"))
    };

    // 2. Requests
    loop {
        let msg = match tokio::time::timeout(Duration::from_secs(600), ws_rx.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                if !msg_bucket.take(1.0, msg_rate() * 2.0, msg_rate()) {
                    return flood("messages");
                }
                match serde_json::from_str::<ClientMessage>(&t) {
                    Ok(m) => m,
                    Err(e) => {
                        server.limiter.strike(&session.address);
                        return Err(format!("invalid JSON message: {}", e));
                    }
                }
            }
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {
                if !msg_bucket.take(1.0, msg_rate() * 2.0, msg_rate()) {
                    return flood("messages");
                }
                continue;
            }
            Ok(Some(Ok(Message::Binary(_)))) => {
                server.limiter.strike(&session.address);
                send_error(out, None, "unexpected binary data");
                return Err("binary data without send_file".into());
            }
            Ok(Some(Err(e))) => return Err(e.to_string()),
            Err(_) => return Err("idle timeout".into()),
        };

        match msg.r#type.as_str() {
            "check" => {
                if !check_bucket.take(msg.items.len().max(1) as f64, check_rate() * 2.0, check_rate()) {
                    return flood("hash checks");
                }
                handle_check(server, session, out, msg.items, server.limits.max_bytes())?
            }
            "scan" => {
                if server.maintenance() {
                    send_error(out, Some(msg.id), "server in maintenance mode, retry later");
                } else {
                    handle_scan(ws_rx, out, server, session, &slots, &scan_slots, msg, server.limits.max_bytes()).await?;
                }
            }
            "scan_url" => {
                if server.maintenance() {
                    send_error(out, Some(msg.id), "server in maintenance mode, retry later");
                    continue;
                }
                let target_url = msg.url.unwrap_or(msg.name);
                match execute_url_scan(server, &target_url, None, None).await {
                    Ok(ecs_val) => {
                        let res_msg = serde_json::json!({
                            "type": "url_result",
                            "id": msg.id,
                            "result": ecs_val,
                        });
                        send_json(out, &res_msg);
                    }
                    Err(err) => send_error(out, Some(msg.id), &err),
                }
            }
            other => {
                server.limiter.strike(&session.address);
                send_error(out, None, "unknown message type");
                return Err(format!("unexpected message: {other}"));
            }
        }
    }
    Ok(())
}

/// Answers a batch of hashes: `result` when the verdict is already known, nothing yet
/// when another client is uploading the same file, `need_upload` otherwise.
fn handle_check(
    server: &Arc<ScanServer>,
    session: &Arc<SessionHandle>,
    out: &Out,
    items: Vec<CheckItem>,
    max_bytes: i64,
) -> Result<(), String> {
    if items.len() > server.limits.max_check_batch() {
        send_error(out, None, "check batch too large");
        return Err(format!("check batch of {} items", items.len()));
    }
    for it in items {
        if it.id <= 0 {
            continue;
        }
        server.stats.checked.fetch_add(1, Ordering::Relaxed);
        let sha_hex = it.sha256.trim().to_ascii_uppercase();
        let Some(sha) = parse_sha(&sha_hex) else {
            send_error(out, Some(it.id), "invalid sha256");
            continue;
        };
        let name: String = it.name.chars().take(260).collect();

        if let Some(mut r) = server.known(&sha, &sha_hex) {
            r.id = it.id;
            record_result(server, session, &r, &name, it.size);
            send_json(out, &r);
            continue;
        }

        if it.size < 0 || it.size > max_bytes {
            reject_file(server, session, out, it.id, &name, it.size, &sha_hex,
                &format!("file too large (limit {} MB)", server.limits.max_mb()));
            continue;
        }

        {
            let mut g = server.inflight.lock().unwrap();
            if let Some(entry) = g.get_mut(&sha) {
                session.in_flight.fetch_add(1, Ordering::Relaxed);
                entry.waiters.push(Waiter {
                    tx: out.clone(),
                    id: it.id,
                    session: Arc::clone(session),
                    name,
                    size: it.size,
                });
                continue;
            }
        }

        server.threat_intel.record(
            &sha_hex,
            "unknown",
            None,
            if name.is_empty() { None } else { Some(&name) },
            if it.size > 0 { Some(it.size as u64) } else { None },
            0.0,
        );
        send_json(out, &serde_json::json!({"type": "need_upload", "id": it.id}));
    }
    Ok(())
}

async fn handle_scan(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    out: &Out,
    server: &Arc<ScanServer>,
    session: &Arc<SessionHandle>,
    slots: &Arc<Semaphore>,
    scan_slots: &Arc<Semaphore>,
    msg: ClientMessage,
    max_bytes: i64,
) -> Result<(), String> {
    if msg.id <= 0 {
        send_error(out, None, "scan request without id");
        return Err("scan request without id".to_string());
    }
    let id = msg.id;
    let name: String = msg.name.chars().take(260).collect();
    let sha_hex = msg.sha256.trim().to_ascii_uppercase();
    let Some(sha) = parse_sha(&sha_hex) else {
        send_error(out, Some(id), "invalid sha256");
        return Ok(());
    };

    if let Some(mut r) = server.known(&sha, &sha_hex) {
        r.id = id;
        record_result(server, session, &r, &name, msg.size);
        send_json(out, &r);
        return Ok(());
    }

    if msg.size < 0 || msg.size > max_bytes {
        reject_file(server, session, out, id, &name, msg.size, &sha_hex,
            &format!("file too large (limit {} MB)", server.limits.max_mb()));
        return Ok(());
    }
    let size = msg.size;

    if !server.limiter.take_upload(&session.address, size) {
        reject_file(server, session, out, id, &name, size, &sha_hex,
            "upload limit for this hour reached, try again later");
        return Ok(());
    }

    let slot = Arc::clone(slots).acquire_owned().await.map_err(|e| e.to_string())?;
    let budget = server.budget.acquire(size).await;
    let guard = InflightGuard::claim(server, sha);

    send_json(out, &serde_json::json!({"type": "send_file", "id": id}));

    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(60 + (size / MIN_UPLOAD_BYTES_PER_SEC) as u64);
    let mut data: Vec<u8> = Vec::with_capacity(size as usize);
    while (data.len() as i64) < size {
        let wait = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .min(Duration::from_secs(120));
        if wait.is_zero() {
            server.limiter.strike(&session.address);
            send_error(out, Some(id), "upload too slow");
            return Err("upload too slow".into());
        }
        match tokio::time::timeout(wait, ws_rx.next()).await {
            Ok(Some(Ok(Message::Binary(bin)))) => {
                if data.len() as i64 + bin.len() as i64 > size {
                    server.limiter.strike(&session.address);
                    send_error(out, Some(id), "more bytes than announced");
                    return Err("upload larger than announced size".into());
                }
                data.extend_from_slice(&bin);
            }
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => continue,
            _ => return Err("upload timeout or connection dropped".into()),
        }
    }

    let calculated: String = Sha256::digest(&data).encode_hex_upper();
    if calculated != sha_hex {
        server.limiter.strike(&session.address);
        reject_file(server, session, out, id, &name, size, &sha_hex,
            "sha256 of the uploaded bytes does not match");
        return Ok(());
    }

    server.stats.uploads.fetch_add(1, Ordering::Relaxed);
    server.stats.bytes_uploaded.fetch_add(size, Ordering::Relaxed);
    session.uploads.fetch_add(1, Ordering::Relaxed);
    session.in_flight.fetch_add(1, Ordering::Relaxed);

    let (rtx, rrx) = oneshot::channel();
    let engine = Arc::clone(&server.engine);
    let (job_name, job_sha) = (name.clone(), sha_hex.clone());
    let scan_slots = Arc::clone(scan_slots);

    let srv = Arc::clone(server);
    let sess = Arc::clone(session);
    let out = out.clone();
    tokio::spawn(async move {
        // Wait for a scan slot here, not in the session loop, so the connection keeps
        // accepting uploads while this file waits for the engine.
        let scan_slot = scan_slots.acquire_owned().await.ok();
        let session_id = sess.id;
        srv.scheduler.submit(
            session_id,
            Box::new(move || {
                let r = engine.scan_blocking(&data, &job_name, &job_sha);
                drop(data);
                let _ = rtx.send(r);
            }),
        );
        let outcome = rrx.await;
        drop(budget);
        drop(scan_slot);
        drop(slot);
        sess.in_flight.fetch_sub(1, Ordering::Relaxed);

        let res = match outcome {
            Ok(Ok(r)) => {
                srv.stats.engine_scans.fetch_add(1, Ordering::Relaxed);
                Ok(r)
            }
            // The scan thread panicked: remember the file so it is never scanned again.
            Err(_) => {
                srv.stats.engine_crashes.fetch_add(1, Ordering::Relaxed);
                Ok(ResultMessage {
                    r#type: "result".into(),
                    id: 0,
                    timestamp: Some(chrono::Utc::now().to_rfc3339()),
                    ecs: Some(serde_json::json!({ "version": "9.5.4" })),
                    event: Some(serde_json::json!({ "action": "static_analysis", "kind": "event", "category": ["malware", "file"], "outcome": "failure" })),
                    file: Some(serde_json::json!({ "name": name, "size": size, "hash": { "sha256": sha_hex } })),
                    antivirus: Some(serde_json::json!({ "engine": ENGINE_NAME, "verdict": "error", "detail": "The scan engine crashed on this file" })),
                    threat_indicator: None,
                    rule: None,
                    verdict: "error".into(),
                    threat: None,
                    detail: Some("The scan engine crashed on this file".into()),
                    score: 0.0,
                    sha256: sha_hex.clone(),
                    scan_ms: 0,
                    source: "scan".into(),
                    extracted_objects: Vec::new(),
                })
            }
            Ok(Err(e)) => Err(e),
        };

        match res {
            Ok(mut r) => {
                srv.remember(sha, &r);
                r.id = id;
                record_result(&srv, &sess, &r, &name, size);
                send_json(&out, &r);
                guard.complete(Outcome::Done(r));
            }
            Err(e) => {
                sess.scanned.fetch_add(1, Ordering::Relaxed);
                srv.total_scanned.fetch_add(1, Ordering::Relaxed);
                srv.total_errors.fetch_add(1, Ordering::Relaxed);
                let mut ev = simple_event("error", Some(sess.id), Some(sess.address.clone()), Some(e.clone()));
                ev.file = Some(name);
                ev.size = Some(size);
                ev.sha256 = Some(sha_hex);
                srv.events.add(ev);
                send_error(&out, Some(id), &format!("scan failed: {}", e));
                guard.complete(Outcome::EngineError(e));
            }
        }
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reject_file(
    server: &ScanServer,
    session: &SessionHandle,
    out: &Out,
    id: i64,
    name: &str,
    size: i64,
    sha_hex: &str,
    reason: &str,
) {
    let mut ev = simple_event("rejected", Some(session.id), Some(session.address.clone()), Some(reason.to_string()));
    ev.file = Some(name.to_string());
    ev.size = Some(size);
    ev.sha256 = Some(sha_hex.to_string());
    server.events.add(ev);
    send_error(out, Some(id), reason);
}

/// Counts every answer. Files answered from their hash are only counted, not written to
/// the live feed (there are far too many), except threats.
fn record_result(server: &ScanServer, session: &SessionHandle, res: &ResultMessage, file_name: &str, size: i64) {
    session.scanned.fetch_add(1, Ordering::Relaxed);
    server.total_scanned.fetch_add(1, Ordering::Relaxed);

    server.threat_intel.record(
        &res.sha256,
        &res.verdict,
        res.threat.as_deref(),
        if file_name.is_empty() { None } else { Some(file_name) },
        if size > 0 { Some(size as u64) } else { None },
        res.score,
    );

    let threat = res.verdict == "malicious" || res.verdict == "suspicious";
    if threat {
        session.threats.fetch_add(1, Ordering::Relaxed);
        server.total_threats.fetch_add(1, Ordering::Relaxed);
    }
    if res.source != "scan" && !threat {
        return;
    }

    server.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "result".to_string(),
        session: Some(session.id),
        client: Some(session.address.clone()),
        verdict: Some(res.verdict.clone()),
        file: Some(file_name.to_string()),
        size: Some(size),
        ms: Some(res.scan_ms),
        threat: res.threat.clone(),
        detail: res.detail.clone(),
        sha256: Some(res.sha256.clone()),
        message: if res.source == "scan" { None } else { Some(res.source.clone()) },
        origin_type: None,
    });

    // Record each extracted object as a sub-event in the live feed
    for obj in &res.extracted_objects {
        let sub_threat_name = obj.detections.first().map(|d| d.name.clone());
        let sub_detail = if !obj.detections.is_empty() {
            let d_names: Vec<String> = obj.detections.iter().take(4).map(|d| format!("{} ({})", d.name, d.layer)).collect();
            Some(d_names.join(", "))
        } else {
            Some(format!("Unpacked payload ({:.1} KB)", (obj.size as f64) / 1024.0))
        };

        server.events.add(Event {
            seq: 0,
            time: Utc::now(),
            kind: "extracted".to_string(),
            session: Some(session.id),
            client: Some(session.address.clone()),
            verdict: Some(obj.verdict.to_lowercase()),
            file: Some(format!("↳ {}", obj.name)),
            size: Some(obj.size as i64),
            ms: None,
            threat: sub_threat_name,
            detail: sub_detail,
            sha256: Some(obj.sha256.clone()),
            message: Some(obj.origin_type.clone()),
            origin_type: Some(obj.origin_type.clone()),
        });
    }
}

fn simple_event(kind: &str, session: Option<i64>, client: Option<String>, message: Option<String>) -> Event {
    Event {
        seq: 0,
        time: Utc::now(),
        kind: kind.to_string(),
        session,
        client,
        verdict: None,
        file: None,
        size: None,
        ms: None,
        threat: None,
        detail: None,
        sha256: None,
        message,
        origin_type: None,
    }
}

fn send_json<T: Serialize>(tx: &Out, v: &T) {
    if let Ok(s) = serde_json::to_string(v) {
        let _ = tx.send(Message::Text(s));
    }
}

fn send_error(tx: &Out, id: Option<i64>, msg: &str) {
    send_json(tx, &ErrorMessage { r#type: "error", id, message: msg });
}

/// Merge two independent per-source URL reports: the server-fetched copy vs the
/// client-supplied copy. Detections are unioned with their origin noted. When
/// the two sides disagree, YAML rules carrying a `content_difference` condition
/// judge it -- severity, score and whitelist handling come from the rules, this
/// function only records the facts and applies what the rules decided.
/// Difference percentage (0-100) between two page sources via shingle Jaccard:
/// 0 = identical, 100 = nothing in common. Line-based, falling back to 1 KiB
/// chunks for minified single-line bodies. Capped work, approximation only.
fn content_difference_percent(a: &str, b: &str) -> u8 {
    use std::collections::HashSet;

    fn shingles(text: &str) -> HashSet<&str> {
        const CAP: usize = 50_000;
        const CHUNK: usize = 1024;
        let mut set = HashSet::new();
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.len() >= 10 {
            for l in lines {
                if set.len() >= CAP {
                    break;
                }
                set.insert(l.trim());
            }
        } else {
            let bytes = text.as_bytes();
            let mut i = 0;
            while i < bytes.len() && set.len() < CAP {
                let end = (i + CHUNK).min(bytes.len());
                // str slices: step on UTF-8 boundaries only
                let mut e = end;
                while e > i && !text.is_char_boundary(e) {
                    e -= 1;
                }
                if e <= i {
                    break;
                }
                set.insert(&text[i..e]);
                i = end;
            }
        }
        set
    }

    if a == b {
        return 0;
    }
    let sa = shingles(a);
    let sb = shingles(b);
    if sa.is_empty() && sb.is_empty() {
        return 0;
    }
    let inter = sa.intersection(&sb).count();
    let union = sa.union(&sb).count().max(1);
    ((1.0 - inter as f64 / union as f64) * 100.0).round().clamp(0.0, 100.0) as u8
}

fn merge_url_reports(
    engine: &crate::engine_adapter::EngineAdapter,
    url_trimmed: &str,
    difference_percent: u8,
    client_status: Option<u16>,
    server_status: Option<u16>,
    liveness_code: i32,
    mut server: openedr_static::url_rules::UrlThreatReport,
    client: openedr_static::url_rules::UrlThreatReport,
) -> Result<openedr_static::url_rules::UrlThreatReport, String> {
    use std::collections::HashSet;

    fn verdict_rank(v: &str) -> u8 {
        match v {
            "Malicious" => 3,
            "Suspicious" => 2,
            "Unknown" => 1,
            "Clean" => 0,
            _ => 1,
        }
    }

    let server_ids: HashSet<String> = server.detections.iter().map(|d| d.rule_id.clone()).collect();
    let client_ids: HashSet<String> = client.detections.iter().map(|d| d.rule_id.clone()).collect();

    let mut server_only: Vec<String> = Vec::new();
    let mut client_only: Vec<String> = Vec::new();

    for d in server.detections.iter_mut() {
        if !client_ids.contains(d.rule_id.as_str()) {
            server_only.push(d.rule_id.clone());
            d.details.push_str(" [seen in server fetch only]");
        }
    }
    for mut d in client.detections.into_iter() {
        if !server_ids.contains(d.rule_id.as_str()) {
            client_only.push(d.rule_id.clone());
            d.details.push_str(" [seen in client content only]");
            server.detections.push(d);
        }
    }

    let differed = server.verdict != client.verdict
        || !server_only.is_empty()
        || !client_only.is_empty();

    // Worst verdict across both single-source scans wins.
    let (mut verdict, mut risk_score, mut verdict_reason) =
        if verdict_rank(&client.verdict) >= verdict_rank(&server.verdict) {
            (client.verdict.clone(), client.risk_score, client.verdict_reason.clone())
        } else {
            (server.verdict.clone(), server.risk_score, server.verdict_reason.clone())
        };

    // Difference judgment comes from YAML rules, never from hardcoded logic.
    // Each rule declares its own gates (minimum percent, equal status);
    // here the facts are only recorded for the rules to judge.
    if differed {
        let facts = format!(
            "Content difference: {}%. Client status: {} vs server status: {}. Client-supplied content verdict: {} vs server-fetched verdict: {}. Rules seen only in server fetch: [{}]; rules seen only in client content: [{}].",
            difference_percent,
            client_status.map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string()),
            server_status.map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
            client.verdict,
            server.verdict,
            server_only.join(", "),
            client_only.join(", "),
        );
        for (mut hit, override_wl, skip_wl) in engine.match_difference_rules(url_trimmed, difference_percent, client_status, server_status, liveness_code)? {
            if skip_wl && server.whitelisted {
                continue;
            }
            if override_wl && server.whitelisted {
                server.whitelisted = false;
                server.whitelist_bypassed = true;
                server.bypass_reason = Some(format!("Whitelist overridden by threat rule {}", hit.rule_id));
            }
            hit.details.push_str(&format!(" {}", facts));
            // Rule-driven escalation only: Malicious or Suspicious difference-rule
            // hits can raise the verdict; model noise alone never does.
            if (hit.severity == "Malicious" || hit.severity == "Suspicious")
                && verdict_rank(&hit.severity) > verdict_rank(&verdict)
            {
                verdict = hit.severity.clone();
                risk_score = risk_score.max(hit.score);
                verdict_reason = format!("{}: {}", hit.title, hit.details);
            }
            server.detections.push(hit);
        }
    }

    server.whitelisted = server.whitelisted && client.whitelisted;
    server.whitelist_bypassed = server.whitelist_bypassed || client.whitelist_bypassed;
    if server.bypass_reason.is_none() {
        server.bypass_reason = client.bypass_reason.clone();
    }
    server.ml_probability = server.ml_probability.max(client.ml_probability);
    server.fp_mitigated = server.fp_mitigated && client.fp_mitigated;
    server.content_scanned = true;
    server.unwhitelisted_for_ml = server.unwhitelisted_for_ml || client.unwhitelisted_for_ml;
    server.verdict = verdict;
    server.risk_score = risk_score;
    server.verdict_reason = verdict_reason;
    Ok(server)
}

pub async fn execute_url_scan(
    server: &Arc<ScanServer>,
    raw_url: &str,
    page_content: Option<&str>,
    content_status: Option<u16>,
) -> Result<serde_json::Value, String> {
    let started = std::time::Instant::now();
    let url_trimmed = raw_url.trim();
    if url_trimmed.is_empty() {
        return Err("URL cannot be empty".to_string());
    }

    // Step 1: PyFunceble-style asynchronous liveness check (DNS / Host resolution)
    let (dns_code, _) = crate::liveness::check_liveness(url_trimmed).await;

    // Step 2: Fetch each content source SEPARATELY for difference scanning.
    // Client-supplied HTML (what the user sees) and the server-fetched copy
    // (what the scanner sees) are never merged: cloaking pages serve benign
    // bytes to scanners and malicious bytes to victims, so any difference
    // between the two is handed to the YAML rules for judgment.
    let fetched_body: Option<(u16, String)>;
    let (server_status, server_content): (Option<u16>, Option<&str>) =
        if dns_code == crate::liveness::LIVENESS_ACTIVE {
            fetched_body = crate::liveness::fetch_page_content_safe(url_trimmed).await;
            match &fetched_body {
                Some((st, body)) => (Some(*st), Some(body.as_str())),
                None => (None, None),
            }
        } else {
            (None, None)
        };

    // Step 1b: refine DNS liveness with the HTTP status, PyFunceble-style.
    // DNS-dead stays dead; DNS-alive is classified ACTIVE / POTENTIALLY_UP /
    // POTENTIALLY_DOWN from the fetched status code.
    let (liveness_code, liveness_str) =
        crate::liveness::classify_with_http(dns_code, server_status);

    // Step 3: OpenEDR Static Engine inspection per source, then merge.
    // (Evaluates Whitelist -> Deterministic Rules -> CIDR -> Liveness Protection -> ML Gating -> HTML / JS YARA)
    // Single source -> single scan, unchanged behaviour. Both sources ->
    // independent scans; when they differ, YAML difference rules judge it.
    let mut difference_percent: Option<u8> = None;
    let report = match (page_content, server_content) {
        (Some(client_body), Some(server_body)) => {
            let pct = content_difference_percent(client_body, server_body);
            difference_percent = Some(pct);
            let server_report = server.engine.inspect_url(url_trimmed, liveness_code, Some(server_body))?;
            let client_report = server.engine.inspect_url(url_trimmed, liveness_code, Some(client_body))?;
            merge_url_reports(&server.engine, url_trimmed, pct, content_status, server_status, liveness_code, server_report, client_report)?
        }
        (Some(client_body), None) => {
            server.engine.inspect_url(url_trimmed, liveness_code, Some(client_body))?
        }
        (None, server_body) => {
            server.engine.inspect_url(url_trimmed, liveness_code, server_body)?
        }
    };
    let scan_ms = started.elapsed().as_millis() as i64;

    // Record event in live event feed
    server.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "url_scan".to_string(),
        session: None,
        client: Some("api".to_string()),
        verdict: Some(report.verdict.to_lowercase()),
        file: Some(report.target_url.clone()),
        size: None,
        ms: Some(scan_ms),
        threat: if report.verdict != "Clean" {
            report.detections.first().map(|d| d.title.clone())
        } else {
            None
        },
        detail: Some(report.verdict_reason.clone()),
        sha256: None,
        message: Some(format!("Liveness: {}", liveness_str)),
        origin_type: Some("url".to_string()),
    });

    let detections_json: Vec<serde_json::Value> = report.detections.iter().map(|d| {
        serde_json::json!({
            "rule_id": d.rule_id,
            "title": d.title,
            "severity": d.severity,
            "score": d.score,
            "details": d.details,
        })
    }).collect();

    let ecs = serde_json::json!({
        "@timestamp": Utc::now().to_rfc3339(),
        "ecs": { "version": "8.11.0" },
        "event": {
            "action": "url_scan",
            "category": ["network", "threat"],
            "kind": "alert",
            "outcome": if report.verdict == "Malicious" { "failure" } else { "success" },
            "duration": scan_ms * 1_000_000
        },
        "url": {
            "original": report.target_url,
            "scheme": report.scheme,
            "domain": report.host,
            "port": report.port,
        },
        "antivirus": {
            "engine": ENGINE_NAME,
            "verdict": report.verdict.to_lowercase(),
            "reason": report.verdict_reason,
            "risk_score": report.risk_score,
            "fp_mitigated": report.fp_mitigated,
        },
        "threat": {
            "indicator": {
                "type": "url",
                "url": { "original": report.target_url },
                "liveness": report.liveness,
                "whitelisted": report.whitelisted,
                "whitelist_bypassed": report.whitelist_bypassed,
                "ml_probability": report.ml_probability,
                "content_difference_percent": difference_percent,
                "content_status_client": content_status,
                "content_status_server": server_status,
                "detections": detections_json,
            }
        }
    });

    Ok(ecs)
}

async fn handle_scan_url(
    State(server): State<Arc<ScanServer>>,
    axum::Json(req): axum::Json<UrlScanRequest>,
) -> Response {
    if server.maintenance() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "error": "server in maintenance mode, retry later" })),
        )
            .into_response();
    }
    match execute_url_scan(&server, &req.url, req.content.as_deref(), req.content_status).await {
        Ok(ecs_val) => (StatusCode::OK, axum::Json(ecs_val)).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": err })),
        ).into_response(),
    }
}

async fn handle_scan_url_get(
    State(server): State<Arc<ScanServer>>,
    axum::extract::Query(query): axum::extract::Query<UrlScanQuery>,
) -> Response {
    if server.maintenance() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "error": "server in maintenance mode, retry later" })),
        )
            .into_response();
    }
    match execute_url_scan(&server, &query.url, None, None).await {
        Ok(ecs_val) => (StatusCode::OK, axum::Json(ecs_val)).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": err })),
        ).into_response(),
    }
}
