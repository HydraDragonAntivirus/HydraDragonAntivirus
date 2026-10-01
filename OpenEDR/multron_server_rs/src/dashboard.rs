use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::HeaderMap;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use serde::Deserialize;
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::config::{app_dir, CliArgs, SavedSettings};
use crate::engine_adapter::EngineAdapter;
use crate::events::EventLog;
use crate::scan_server::ScanServer;

static DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[derive(Deserialize)]
struct StateQuery {
    #[serde(default)]
    since: i64,
}

pub struct AppState {
    pub cfg: CliArgs,
    pub engine: Arc<EngineAdapter>,
    pub events: Arc<EventLog>,
    pub scan_server: Arc<ScanServer>,
    pub settings: RwLock<SavedSettings>,
    pub settings_path: PathBuf,
    pub listener_handle: Mutex<Option<ListenerControl>>,
    pub listen_err: RwLock<String>,
    pub started_at: RwLock<Option<chrono::DateTime<Utc>>>,
}

pub struct ListenerControl {
    pub shutdown_tx: mpsc::Sender<()>,
}

impl AppState {
    pub async fn new(
        cfg: CliArgs,
        engine: Arc<EngineAdapter>,
        events: Arc<EventLog>,
        scan_server: Arc<ScanServer>,
    ) -> Arc<Self> {
        let mut settings = SavedSettings::default();
        let settings_path = app_dir().join("multron_server.json");
        if let Ok(data) = std::fs::read(&settings_path) {
            if let Ok(saved) = serde_json::from_slice::<SavedSettings>(&data) {
                settings = saved;
            }
        }

        // CLI --listen overrides saved address
        if !cfg.listen.is_empty() {
            if let Ok(addr) = cfg.listen.parse::<SocketAddr>() {
                settings.host = addr.ip().to_string();
                settings.port = addr.port();
                settings.autostart = true;
            }
        }
        if !cfg.path.is_empty() {
            settings.path = cfg.path.clone();
        }

        Arc::new(Self {
            cfg,
            engine,
            events,
            scan_server,
            settings: RwLock::new(settings),
            settings_path,
            listener_handle: Mutex::new(None),
            listen_err: RwLock::new(String::new()),
            started_at: RwLock::new(None),
        })
    }

    pub async fn save_settings(&self) {
        let guard = self.settings.read().await;
        if let Ok(data) = serde_json::to_vec_pretty(&*guard) {
            let _ = std::fs::write(&self.settings_path, data);
        }
    }

    pub async fn start_listener(self: &Arc<Self>, mut s: SavedSettings) -> Result<(), String> {
        s.host = s.host.trim().to_string();
        if s.host.is_empty() {
            s.host = "127.0.0.1".to_string();
        }
        if s.port == 0 {
            return Err("invalid port".to_string());
        }

        let mut path = s.path.trim().to_string();
        if !path.starts_with('/') {
            path = format!("/{}", path);
        }
        if path == "/" || path == "/health" {
            return Err("path must be something like /scan".to_string());
        }
        s.path = path.clone();

        let mut handle_guard = self.listener_handle.lock().await;
        if handle_guard.is_some() {
            return Err("the server is already running, stop it first".to_string());
        }

        let bind_addr = format!("{}:{}", s.host, s.port);
        let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                let err_str = e.to_string();
                *self.listen_err.write().await = err_str.clone();
                return Err(err_str);
            }
        };

        let scan_router = self.scan_server.router(&path);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        let app_ref = Arc::clone(self);
        tokio::spawn(async move {
            let serve_res = axum::serve(
                listener,
                scan_router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
            })
            .await;

            if let Err(e) = serve_res {
                *app_ref.listen_err.write().await = e.to_string();
                app_ref.events.add(crate::events::Event {
                    seq: 0,
                    time: Utc::now(),
                    kind: "info".to_string(),
                    session: None,
                    client: None,
                    verdict: None,
                    file: None,
                    size: None,
                    ms: None,
                    threat: None,
                    detail: None,
                    sha256: None,
                    message: Some(format!("listener stopped: {}", e)),
                });
            }
        });

        *handle_guard = Some(ListenerControl { shutdown_tx });
        *self.listen_err.write().await = String::new();
        *self.started_at.write().await = Some(Utc::now());

        s.autostart = true;
        *self.settings.write().await = s.clone();
        self.save_settings().await;

        self.events.add(crate::events::Event {
            seq: 0,
            time: Utc::now(),
            kind: "info".to_string(),
            session: None,
            client: None,
            verdict: None,
            file: None,
            size: None,
            ms: None,
            threat: None,
            detail: None,
            sha256: None,
            message: Some(format!("listening on ws://{}{}", bind_addr, path)),
        });

        Ok(())
    }

    pub async fn stop_listener(&self, remember: bool) {
        let mut handle_guard = self.listener_handle.lock().await;
        if let Some(ctrl) = handle_guard.take() {
            let _ = ctrl.shutdown_tx.send(()).await;
            self.scan_server.close_all_sessions().await;
            *self.started_at.write().await = None;

            if remember {
                let mut settings_guard = self.settings.write().await;
                settings_guard.autostart = false;
                drop(settings_guard);
                self.save_settings().await;
            }

            self.events.add(crate::events::Event {
                seq: 0,
                time: Utc::now(),
                kind: "info".to_string(),
                session: None,
                client: None,
                verdict: None,
                file: None,
                size: None,
                ms: None,
                threat: None,
                detail: None,
                sha256: None,
                message: Some("server stopped".to_string()),
            });
        }
    }
}

pub fn dashboard_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(handle_index))
        .route("/api/state", get(handle_state))
        .route("/api/start", post(handle_start))
        .route("/api/stop", post(handle_stop))
        .layer(middleware::from_fn(guard_middleware))
        .with_state(state)
}

async fn guard_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    let headers = req.headers();

    // Check Host header: must be localhost or loopback
    if let Some(host_val) = headers.get("host").and_then(|h| h.to_str().ok()) {
        let host = host_val.split(':').next().unwrap_or(host_val);
        if host != "localhost" && host != "127.0.0.1" && host != "::1" {
            return (
                StatusCode::FORBIDDEN,
                "dashboard is only available on this computer",
            )
                .into_response();
        }
    }

    // State-changing calls need X-Multron-Dashboard header
    if req.method() == Method::POST {
        if headers.get("X-Multron-Dashboard").and_then(|v| v.to_str().ok()) != Some("1") {
            return (StatusCode::FORBIDDEN, "forbidden").into_response();
        }
    }

    next.run(req).await
}

async fn handle_index() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "text/html; charset=utf-8".parse().unwrap());
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    (headers, Html(DASHBOARD_HTML))
}

async fn handle_state(
    Query(q): Query<StateQuery>,
    State(app): State<Arc<AppState>>,
) -> impl IntoResponse {
    let eng_status = app.engine.get_status().await;
    let running = app.listener_handle.lock().await.is_some();
    let settings = app.settings.read().await.clone();
    let listen_err = app.listen_err.read().await.clone();
    let started_at = *app.started_at.read().await;

    let clients = app.scan_server.get_clients().await;
    let (events, seq) = app.events.since(q.since);

    let srv = &app.scan_server;
    let queued = srv.scheduler.queued();
    let inflight_mb = srv.budget.in_use_bytes() as f64 / (1024.0 * 1024.0);
    let ld = |a: &std::sync::atomic::AtomicI64| a.load(std::sync::atomic::Ordering::Relaxed);
    let checked = ld(&srv.stats.checked);
    let uploads = ld(&srv.stats.uploads);

    let state = serde_json::json!({
        "engine": {
            "status": eng_status.status,
            "error": eng_status.error,
            "loadMs": eng_status.load_ms,
            "name": eng_status.name,
        },
        "server": {
            "running": running,
            "host": settings.host,
            "port": settings.port,
            "path": settings.path,
            "error": listen_err,
            "startedAt": started_at,
        },
        "limits": {
            "workers": app.cfg.workers,
            "pipeline": app.cfg.pipeline,
            "maxConns": app.cfg.max_conns,
            "maxPerIp": app.cfg.max_per_ip,
            "token": !app.cfg.token.is_empty(),
            "hashWhitelist": app.engine.whitelist_active(),
            "hashSignatures": app.engine.malicious_hash_count(),
            "maxMB": app.cfg.max_mb,
            "maxInflightMB": app.cfg.max_inflight_mb,
            "cache": app.cfg.cache(),
            "signatureCheck": !app.cfg.memory_only,
        },
        "lanAddresses": lan_addresses(),
        "stats": {
            "connections": clients.len(),
            "totalConnections": app.scan_server.total_connections.load(std::sync::atomic::Ordering::Relaxed),
            "scanned": app.scan_server.total_scanned.load(std::sync::atomic::Ordering::Relaxed),
            "threats": app.scan_server.total_threats.load(std::sync::atomic::Ordering::Relaxed),
            "errors": app.scan_server.total_errors.load(std::sync::atomic::Ordering::Relaxed),
            "queued": queued,
            "busy": srv.scheduler.busy(),
            "inflightMB": inflight_mb,
            "inflightFiles": srv.inflight_files(),
            "checked": checked,
            "uploads": uploads,
            "gbUploaded": ld(&srv.stats.bytes_uploaded) as f64 / (1024.0 * 1024.0 * 1024.0),
            "cacheHits": ld(&srv.stats.cache_hits),
            "whitelistHits": ld(&srv.stats.whitelist_hits),
            "hashSigHits": ld(&srv.stats.hash_sig_hits),
            "sharedHits": ld(&srv.stats.shared_hits),
            "engineScans": ld(&srv.stats.engine_scans),
            "engineCrashes": ld(&srv.stats.engine_crashes),
            "rejectedAuth": ld(&srv.stats.rejected_auth),
            "cacheSize": srv.cache.len(),
            "keptUnknown": ld(&app.engine.kept_files),
            "uploadSavedPct": if checked > 0 { 100.0 * (checked - uploads).max(0) as f64 / checked as f64 } else { 0.0 },
        },
        "clients": clients,
        "events": events,
        "seq": seq,
    });

    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    (headers, Json(state))
}

async fn handle_start(
    State(app): State<Arc<AppState>>,
    Json(settings): Json<SavedSettings>,
) -> impl IntoResponse {
    match app.start_listener(settings).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": err})),
        )
            .into_response(),
    }
}

async fn handle_stop(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    app.stop_listener(true).await;
    Json(serde_json::json!({"ok": true}))
}

fn lan_addresses() -> Vec<String> {
    let mut addrs = Vec::new();
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = socket.local_addr() {
                let ip = local.ip();
                if !ip.is_loopback() {
                    addrs.push(ip.to_string());
                }
            }
        }
    }
    if addrs.is_empty() {
        addrs.push("127.0.0.1".to_string());
    }
    addrs
}
