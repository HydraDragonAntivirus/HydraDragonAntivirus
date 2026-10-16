use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
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
use crate::limits::LimitSettings;
use crate::scan_server::ScanServer;
use crate::threat_intel::ThreatIntelStore;

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
    pub threat_intel: Arc<ThreatIntelStore>,
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
        threat_intel: Arc<ThreatIntelStore>,
    ) -> Arc<Self> {
        let mut settings = SavedSettings::default();
        let settings_path = app_dir().join("multron_server.json");
        if let Ok(data) = std::fs::read(&settings_path) {
            if let Ok(saved) = serde_json::from_slice::<SavedSettings>(&data) {
                settings = saved;
            }
        }

        // CLI --port, --listen, or --path overrides saved address
        if let Some(port) = cfg.port {
            settings.port = port;
            settings.autostart = true;
        }
        if !cfg.listen.is_empty() {
            if let Ok(addr) = cfg.listen.parse::<SocketAddr>() {
                settings.host = addr.ip().to_string();
                settings.port = addr.port();
                settings.autostart = true;
            }
        }
        if !cfg.path.is_empty() {
            let mut p = cfg.path.clone();
            if !p.starts_with('/') {
                p = format!("/{}", p);
            }
            settings.path = p;
        }

        // Keeping possible_clean files: saved dashboard choice, unless the command line
        // turns it off.
        if cfg.no_keep_possible_clean {
            settings.keep_possible_clean = false;
        }
        engine.keep_possible_clean.store(settings.keep_possible_clean, std::sync::atomic::Ordering::Relaxed);
        // Keeping every unique file / collecting XOR-filter hits: saved dashboard choice
        // (both on by default), unless the command line turns them off.
        if cfg.no_keep_all_unique {
            settings.keep_all_unique = false;
        }
        engine.keep_all_unique.store(settings.keep_all_unique, std::sync::atomic::Ordering::Relaxed);
        if cfg.no_collect_xorfilter {
            settings.collect_xorfilter = false;
        }
        engine.collect_xorfilter.store(settings.collect_xorfilter, std::sync::atomic::Ordering::Relaxed);
        // Keeping clean PE / APK files: saved dashboard choice; `--keep-clean` turns it on.
        if cfg.keep_clean {
            settings.keep_clean = true;
        }
        engine.keep_clean.store(settings.keep_clean, std::sync::atomic::Ordering::Relaxed);
        // Low-disk LZMA2 compression: saved dashboard choice (off by default); the
        // command line (--compress-low-disk / --no-compress-low-disk) wins.
        if let Some(on) = cfg.compress_low_disk_flag() {
            settings.lzma_low_disk = on;
        }
        engine.compress_low_disk.store(settings.lzma_low_disk, std::sync::atomic::Ordering::Relaxed);
        scan_server.rescan.after_reload.store(settings.rescan_after_reload, std::sync::atomic::Ordering::Relaxed);
        if !cfg.offload_dir.trim().is_empty() {
            settings.offload_target = cfg.offload_dir.trim().to_string();
        }
        *scan_server.offload.target.write().unwrap() = settings.offload_target.clone();
        if !cfg.archive_mirror.trim().is_empty() {
            settings.archive_mirror = cfg.archive_mirror.trim().to_string();
        }
        if crate::config::is_archive() {
            // Nothing is ever written here: no mirror out, no rescans after reloads.
            settings.archive_mirror.clear();
            settings.rescan_after_reload = false;
            scan_server.rescan.after_reload.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        scan_server.mirror.set_target(&settings.archive_mirror);
        if settings.maintenance {
            scan_server.set_maintenance("maintenance");
            eprintln!("[maintenance] still on from before the restart (turn it off in the dashboard)");
        }
        scan_server.offload.auto.store(settings.offload_auto, std::sync::atomic::Ordering::Relaxed);

        // Limits saved from the dashboard win over the command-line defaults.
        if let Some(saved) = settings.limits.take() {
            let applied = scan_server.apply_limits(saved);
            eprintln!("[limits] loaded from multron_server.json");
            settings.limits = Some(applied);
        }

        Arc::new(Self {
            cfg,
            engine,
            events,
            scan_server,
            threat_intel,
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
            return Err("path must be /ws".to_string());
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
                    origin_type: None,
                });
            }
        });

        *handle_guard = Some(ListenerControl { shutdown_tx });
        *self.listen_err.write().await = String::new();
        *self.started_at.write().await = Some(Utc::now());

        s.autostart = true;
        {
            let mut g = self.settings.write().await;
            s.limits = g.limits.take();
            // Not part of the listener form: keep the current choice.
            s.keep_possible_clean = g.keep_possible_clean;
            s.keep_all_unique = g.keep_all_unique;
            s.collect_xorfilter = g.collect_xorfilter;
            s.keep_clean = g.keep_clean;
            s.lzma_low_disk = g.lzma_low_disk;
            s.rescan_after_reload = g.rescan_after_reload;
            s.offload_target = g.offload_target.clone();
            s.offload_auto = g.offload_auto;
            s.archive_mirror = g.archive_mirror.clone();
            s.maintenance = g.maintenance;
            s.archive = g.archive;
            *g = s.clone();
        }
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
            origin_type: None,
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
                origin_type: None,
            });
        }
    }
}

pub fn dashboard_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(handle_index))
        .route("/api/state", get(handle_state))
        .route("/api/scan-queue", get(handle_scan_queue))
        .route("/api/alyzer/open", post(crate::alyzer::handle_open))
        .route("/api/alyzer/list", get(crate::alyzer::handle_list))
        .route("/api/alyzer/bytes", get(crate::alyzer::handle_bytes))
        .route("/api/alyzer/search", get(crate::alyzer::handle_search))
        .route("/api/alyzer/strings", get(crate::alyzer::handle_strings))
        .route("/api/alyzer/disasm", get(crate::alyzer::handle_disasm))
        .route("/api/alyzer/archive", get(crate::alyzer::handle_archive))
        .route("/api/alyzer/archive/open", post(crate::alyzer::handle_archive_open))
        .route("/api/alyzer/decompile", get(crate::alyzer::handle_decompile))
        .route("/api/alyzer/unpack", post(crate::alyzer::handle_unpack))
        .route("/api/alyzer/scan", post(crate::alyzer::handle_scan))
        .route("/api/alyzer/save", post(crate::alyzer::handle_save).route_layer(DefaultBodyLimit::max(64 * 1024 * 1024)))
        .route("/api/events/ecs", get(handle_events_ecs))
        .route("/api/start", post(handle_start))
        .route("/api/stop", post(handle_stop))
        .route("/api/maintenance", get(handle_maintenance_status).post(handle_maintenance))
        .route("/api/handoff/begin", post(handle_handoff_begin))
        .route("/api/handoff/cancel", post(handle_handoff_cancel))
        .route("/api/handoff/release", post(handle_handoff_release))
        .route("/api/keep-possible-clean", post(handle_keep_possible_clean))
        .route("/api/keep-clean", post(handle_keep_clean))
        .route("/api/keep-all-unique", post(handle_keep_all_unique))
        .route("/api/collect-xorfilter", post(handle_collect_xorfilter))
        .route("/api/dataset/conflicts", get(handle_dataset_conflicts))
        .route("/api/dataset/remove-incoming-duplicates", post(handle_remove_incoming_duplicates))
        .route("/api/kept/sort-by-type", post(handle_sort_kept_by_type))
        .route("/api/kept/unpack-xz", post(handle_unpack_kept_xz))
        .route("/api/compress-low-disk", post(handle_compress_low_disk))
        .route("/api/rescan", post(handle_rescan_one))
        .route("/api/rescan/bulk", get(handle_rescan_status).post(handle_rescan_bulk))
        .route("/api/rescan/stop", post(handle_rescan_stop))
        .route("/api/rescan/audit", get(handle_rescan_audit).post(handle_rescan_audit_bulk))
        .route("/api/rescan/log", get(handle_rescan_log))
        .route("/api/kept/info/:sha256", get(handle_kept_info))
        .route("/api/reviews/requeue", post(handle_reviews_requeue))
        .route("/api/kept/reveal", post(handle_kept_reveal))
        .route("/api/kept/dedupe", post(handle_kept_dedupe))
        .route("/api/rescan/after-reload", post(handle_rescan_after_reload))
        .route("/api/mirror/config", post(handle_mirror_config))
        .route("/api/mirror/run", post(handle_mirror_run))
        .route("/api/mirror/stop", post(handle_mirror_stop))
        .route("/api/mirror/dedupe", post(handle_mirror_dedupe))
        .route("/api/offload/config", post(handle_offload_config))
        .route("/api/offload/start", post(handle_offload_start))
        .route("/api/offload/stop", post(handle_offload_stop))
        .route("/api/limits", post(handle_limits))
        .route("/api/limits/reset", post(handle_limits_reset))
        .route("/api/unban", post(handle_unban))
        .route("/api/insights/stats", get(handle_dashboard_insights_stats))
        .route("/api/insights/:sha256", get(handle_dashboard_insights_hash))
        .route("/api/rules", post(handle_rules_reload).route_layer(DefaultBodyLimit::disable()))
        .route("/api/engine/reload", post(handle_engine_reload))
        .route("/api/reviews", get(handle_reviews_list))
        .route("/api/review", post(handle_review_save))
        .route("/api/review/delete", post(handle_review_delete))
        .route("/api/review/start", post(handle_review_start))
        .route("/api/review/release", post(handle_review_release))
        .route("/api/reviews/similar/:sha256", get(handle_review_similar))
        .route("/api/fs/list", get(handle_fs_list))
        .route("/api/folder-wl/types", post(handle_folder_types))
        .route("/api/folder-wl/start", post(handle_folder_start))
        .route("/api/folder-wl/status", get(handle_folder_status))
        .route("/api/folder-wl/stop", post(handle_folder_stop))
        .route(
            "/api/reviews/bulk",
            post(handle_reviews_bulk).route_layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/api/signatures", get(handle_signatures_list).post(handle_signature_save))
        .route("/api/signatures/delete", post(handle_signature_delete))
        .route("/api/fp/detections/:sha256", get(handle_fp_detections))
        .route("/api/fp/lists", get(handle_fp_lists))
        .route("/api/fp/ignore", post(handle_fp_ignore))
        .route("/api/fp/unignore", post(handle_fp_unignore))
        .route("/api/sources", get(handle_sources))
        .route("/api/sources/files", get(handle_source_files))
        .route("/api/bans", get(handle_bans_list))
        .route("/api/bans/add", post(handle_ban_add))
        .route("/api/bans/remove", post(handle_ban_remove))
        .route("/api/retrohunt", get(handle_retrohunt_status))
        .route("/api/retrohunt/stop", post(handle_retrohunt_stop))
        .route("/api/retrohunt/archive", post(handle_retrohunt_archive))
        .route("/api/naming", get(handle_naming_check))
        .route("/api/companies", get(handle_companies_get).post(handle_companies_save))
        .layer(middleware::from_fn(guard_middleware))
        .with_state(state)
}

/// Dashboard calls that change nothing in the mirrored data (archive mode).
const ARCHIVE_ALLOWED: [&str; 19] = [
    "/api/start", "/api/stop", "/api/maintenance", "/api/limits", "/api/limits/reset", "/api/unban",
    "/api/handoff/begin", "/api/handoff/cancel", "/api/handoff/release",
    "/api/alyzer/open", "/api/alyzer/bytes", "/api/alyzer/search", "/api/alyzer/strings", "/api/alyzer/list", "/api/fs/list",
    "/api/alyzer/archive/open", "/api/alyzer/unpack", "/api/retrohunt/archive", "/api/retrohunt/stop",
];

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

    // Archive server: read-only. Only running the listener and viewing files are allowed.
    if crate::config::is_archive() && req.method() != Method::GET && !ARCHIVE_ALLOWED.contains(&req.uri().path()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"ok": false, "error": "archive server: read-only (make changes on the main server; they are mirrored here)"})),
        )
            .into_response();
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

/// Kept-file counts walk multron_incoming; refreshed at most every 30 s.
static KEPT_CACHE: std::sync::Mutex<Option<(std::time::Instant, serde_json::Value)>> = std::sync::Mutex::new(None);

async fn kept_counts_cached(engine: &Arc<EngineAdapter>) -> serde_json::Value {
    if let Some((t, v)) = KEPT_CACHE.lock().unwrap().as_ref() {
        if t.elapsed() < std::time::Duration::from_secs(30) {
            return v.clone();
        }
    }
    let eng = Arc::clone(engine);
    let counts = tokio::task::spawn_blocking(move || eng.kept_counts()).await.unwrap_or_default();
    let mut v = serde_json::Map::new();
    for (cat, files, bytes) in counts {
        v.insert(cat.to_string(), serde_json::json!({ "files": files, "gb": bytes as f64 / (1024.0 * 1024.0 * 1024.0) }));
    }
    let v = serde_json::Value::Object(v);
    *KEPT_CACHE.lock().unwrap() = Some((std::time::Instant::now(), v.clone()));
    v
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
    // Whole database, not only this run of the server.
    let tstats = app.threat_intel.stats();
    let rstats = app.threat_intel.reviews.stats();
    let all_time = serde_json::json!({
        "hashes": tstats.total_unique_hashes,
        "sightings": tstats.total_sightings,
        "malicious": tstats.malicious_count,
        "suspicious": tstats.suspicious_count,
        "clean": tstats.clean_count,
        "possibleClean": tstats.possible_clean_count,
        "unknown": tstats.unknown_count,
        "humanVerdicts": rstats.completed,
        "humanQueue": rstats.pending,
        "kept": kept_counts_cached(&app.engine).await,
    });

    let srv = &app.scan_server;
    let queued = srv.scheduler.queued();
    let inflight_mb = srv.budget.in_use_bytes() as f64 / (1024.0 * 1024.0);
    let ld = |a: &std::sync::atomic::AtomicI64| a.load(std::sync::atomic::Ordering::Relaxed);
    let checked = ld(&srv.stats.checked);
    let uploads = ld(&srv.stats.uploads);
    let saved_pct = if checked > 0 {
        100.0 * (checked - uploads).max(0) as f64 / checked as f64
    } else {
        0.0
    };

    let state = serde_json::json!({
        "engine": {
            "status": eng_status.status,
            "error": eng_status.error,
            "loadMs": eng_status.load_ms,
            "reloading": eng_status.reloading,
            "reloadMsg": eng_status.reload_msg,
            "name": eng_status.name,
        },
        "server": {
            "running": running,
            "maintenance": app.scan_server.maintenance(),
            "maintenanceMode": app.scan_server.maintenance_mode(),
            "uptimeSecs": app.scan_server.uptime_secs(),
            "host": settings.host,
            "port": settings.port,
            "path": settings.path,
            "error": listen_err,
            "startedAt": started_at,
        },
        "limits": {
            "workers": app.cfg.workers,
            "token": !app.cfg.token.is_empty(),
            "hashWhitelist": app.engine.whitelist_active(),
            "hashSignatures": app.engine.malicious_hash_count(),
            "cache": app.cfg.cache(),
            "signatureCheck": !app.cfg.memory_only,
            "maxFileMBCeiling": crate::config::MAX_FILE_MB,
            "keepThreats": app.engine.keep_threats,
            "keepClean": app.engine.keep_clean.load(std::sync::atomic::Ordering::Relaxed),
            "keepCleanGB": app.engine.keep_clean_limit_bytes / (1024 * 1024 * 1024),
            "keptCleanGB": app.engine.kept_clean_bytes.load(std::sync::atomic::Ordering::Relaxed) as f64 / (1024.0 * 1024.0 * 1024.0),
            "keepPossibleClean": app.engine.keep_possible_clean.load(std::sync::atomic::Ordering::Relaxed),
            "keepAllUnique": app.engine.keep_all_unique.load(std::sync::atomic::Ordering::Relaxed),
            "collectXorfilter": app.engine.collect_xorfilter.load(std::sync::atomic::Ordering::Relaxed),
            "dataset": app.engine.dataset.get().map(|d| d.status()),
            "compressLowDisk": app.engine.compress_low_disk.load(std::sync::atomic::Ordering::Relaxed),
            "lowDiskThresholdGB": app.engine.low_disk_threshold_bytes / (1024 * 1024 * 1024),
        },
        "editableLimits": srv.limits.get(),
        "rescan": srv.rescan.status(),
        "offload": srv.offload.status(),
        "mirror": srv.mirror.status(),
        "uptimeTotal": crate::uptime::json(),
        "archive": if crate::config::is_archive() { crate::archive::info_json() } else { serde_json::Value::Null },
        "bannedIps": srv.limiter.banned_now(),
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
            "gbSavedByCompression": ld(&srv.stats.bytes_saved_compression) as f64 / (1024.0 * 1024.0 * 1024.0),
            "cacheHits": ld(&srv.stats.cache_hits),
            "whitelistHits": ld(&srv.stats.whitelist_hits),
            "hashSigHits": ld(&srv.stats.hash_sig_hits),
            "sharedHits": ld(&srv.stats.shared_hits),
            "engineScans": ld(&srv.stats.engine_scans),
            "engineCrashes": ld(&srv.stats.engine_crashes),
            "rejectedAuth": ld(&srv.stats.rejected_auth),
            "blocked": ld(&srv.limiter.blocked),
            "bansTotal": ld(&srv.limiter.bans),
            "bannedNow": srv.limiter.banned_now().len(),
            "cacheSize": srv.cache.len(),
            "keptUnknown": ld(&app.engine.kept_files),
            "uploadSavedPct": saved_pct,
        },
        "allTime": all_time,
        "clients": clients,
        "events": events,
        "seq": seq,
    });

    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    (headers, Json(state))
}

#[derive(Deserialize)]
struct EcsQuery {
    #[serde(default)]
    since: i64,
}

async fn handle_events_ecs(
    State(app): State<Arc<AppState>>,
    Query(query): Query<EcsQuery>,
) -> impl IntoResponse {
    let (ecs_events, seq) = app.events.since_ecs(query.since);
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    (headers, Json(serde_json::json!({
        "events": ecs_events,
        "seq": seq,
    })))
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

/// An analyst verdict is a reliable label: files with this content already in the ML
/// dataset folders under the other label move to the verdict's folder (nothing is
/// lost, see `Dataset::apply_human_verdict`), then the kept file is copied there if
/// the dataset does not have it yet.
fn export_human_label(engine: &crate::engine_adapter::EngineAdapter, sha: &str, verdict: &str) {
    let (Some(ds), Some(label)) = (engine.dataset.get(), crate::dataset::human_label(verdict)) else { return };
    ds.apply_human_verdict(sha, label);
    let Some(k) = engine.find_kept(&sha.to_ascii_uppercase()) else { return };
    if let Some(bytes) = k.read() {
        ds.export(sha, &bytes, &k.name, label);
    }
}

#[derive(Deserialize)]
struct KeepToggle {
    #[serde(default)]
    enabled: bool,
}

/// Whether `possible_clean` files (TLSH smart whitelist) are kept in the work folder.
/// Applies at once and is saved to multron_server.json.
async fn handle_keep_possible_clean(State(app): State<Arc<AppState>>, Json(t): Json<KeepToggle>) -> impl IntoResponse {
    app.engine.keep_possible_clean.store(t.enabled, std::sync::atomic::Ordering::Relaxed);
    app.settings.write().await.keep_possible_clean = t.enabled;
    app.save_settings().await;
    info_event(&app, format!("keep possible_clean files: {}", if t.enabled { "on" } else { "off" }));
    Json(serde_json::json!({ "ok": true, "enabled": t.enabled }))
}

/// Unpacks every `.xz` file in multron_incoming and deletes the `.xz` once the
/// unpacked SHA-256 is verified.
async fn handle_unpack_kept_xz(State(app): State<Arc<AppState>>) -> Response {
    let eng = Arc::clone(&app.engine);
    match tokio::task::spawn_blocking(move || eng.unpack_kept_xz()).await {
        Ok(r) => {
            info_event(&app, format!(
                "multron_incoming: {} .xz files unpacked ({:.1} MB more on disk), {} failed{}",
                r.unpacked,
                r.bytes_added as f64 / 1048576.0,
                r.failed,
                if r.stopped_low_disk { "; stopped: low disk space" } else { "" }
            ));
            Json(serde_json::json!({ "ok": true, "result": r })).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "ok": false, "error": "failed" }))).into_response(),
    }
}

/// Sorts multron_incoming by ClamAV file type: `<category>/<type>/`.
async fn handle_sort_kept_by_type(State(app): State<Arc<AppState>>) -> Response {
    let eng = Arc::clone(&app.engine);
    match tokio::task::spawn_blocking(move || eng.sort_kept_by_type()).await {
        Ok(Ok(counts)) => {
            let moved: Vec<String> = counts
                .iter()
                .filter(|(k, _)| k.as_str() != "unchanged")
                .map(|(k, n)| format!("{n} {k}"))
                .collect();
            info_event(&app, format!("multron_incoming sorted by file type (HydraDragonSig / ClamAV): {} moved", if moved.is_empty() { "nothing".to_string() } else { moved.join(", ") }));
            Json(serde_json::json!({ "ok": true, "moved": counts })).into_response()
        }
        Ok(Err(e)) => (StatusCode::CONFLICT, Json(serde_json::json!({ "ok": false, "error": e }))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "ok": false, "error": "failed" }))).into_response(),
    }
}

#[derive(Deserialize)]
struct DryRun {
    #[serde(default)]
    dry_run: bool,
}

/// ML dataset copies of files in multron_incoming (server-written `<SHA256>.<ext>`):
/// `dry_run` counts them, otherwise they are moved to the backup folders.
/// multron_incoming stays. Copies of samples with an analyst verdict (clean /
/// malicious) always stay: they are the human labels the models train on.
async fn handle_remove_incoming_duplicates(State(app): State<Arc<AppState>>, Json(b): Json<DryRun>) -> Response {
    let eng = Arc::clone(&app.engine);
    let dry = b.dry_run;
    let human: std::collections::HashSet<String> = app
        .threat_intel
        .reviews
        .completed_verdicts()
        .into_iter()
        .filter(|(_, v)| crate::dataset::human_label(v).is_some())
        .map(|(s, _)| s.to_ascii_uppercase())
        .collect();
    match tokio::task::spawn_blocking(move || eng.remove_dataset_copies_of_kept(dry, &human)).await {
        Ok(Ok((files, bytes))) => {
            if !dry && files > 0 {
                info_event(&app, format!("moved {files} ML dataset copies of multron_incoming files to the deleted_from_* backup folders ({:.1} MB)", bytes as f64 / 1048576.0));
            }
            Json(serde_json::json!({ "ok": true, "dry_run": dry, "files": files, "bytes": bytes })).into_response()
        }
        Ok(Err(e)) => (StatusCode::CONFLICT, Json(serde_json::json!({ "ok": false, "error": e }))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "ok": false, "error": "failed" }))).into_response(),
    }
}

/// ML dataset label conflicts (same content already in the other label folder in a
/// file the server did not write), newest first.
async fn handle_dataset_conflicts(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    match app.engine.dataset.get() {
        Some(ds) => {
            let ds = Arc::clone(ds);
            let list = tokio::task::spawn_blocking(move || ds.recent_conflicts(500)).await.unwrap_or_default();
            Json(serde_json::json!({ "ok": true, "enabled": true, "conflicts": list }))
        }
        None => Json(serde_json::json!({ "ok": true, "enabled": false, "conflicts": [] })),
    }
}

/// Keep every unique file (any category, any type; quotas still apply).
async fn handle_keep_all_unique(State(app): State<Arc<AppState>>, Json(t): Json<KeepToggle>) -> impl IntoResponse {
    app.engine.keep_all_unique.store(t.enabled, std::sync::atomic::Ordering::Relaxed);
    app.settings.write().await.keep_all_unique = t.enabled;
    app.save_settings().await;
    info_event(&app, format!("keep every unique file: {}", if t.enabled { "on" } else { "off" }));
    Json(serde_json::json!({ "ok": true, "enabled": t.enabled }))
}

/// Collect XOR-filter hash hits (benign whitelist / malicious hash filter) for checking.
async fn handle_collect_xorfilter(State(app): State<Arc<AppState>>, Json(t): Json<KeepToggle>) -> impl IntoResponse {
    app.engine.collect_xorfilter.store(t.enabled, std::sync::atomic::Ordering::Relaxed);
    app.settings.write().await.collect_xorfilter = t.enabled;
    app.save_settings().await;
    info_event(&app, format!("collect XOR-filter hits: {}", if t.enabled { "on" } else { "off" }));
    Json(serde_json::json!({ "ok": true, "enabled": t.enabled }))
}

async fn handle_keep_clean(State(app): State<Arc<AppState>>, Json(t): Json<KeepToggle>) -> impl IntoResponse {
    app.engine.keep_clean.store(t.enabled, std::sync::atomic::Ordering::Relaxed);
    app.settings.write().await.keep_clean = t.enabled;
    app.save_settings().await;
    info_event(&app, format!("keep clean PE/APK files: {}", if t.enabled { "on" } else { "off" }));
    Json(serde_json::json!({ "ok": true, "enabled": t.enabled }))
}

async fn handle_compress_low_disk(State(app): State<Arc<AppState>>, Json(t): Json<KeepToggle>) -> impl IntoResponse {
    app.engine.compress_low_disk.store(t.enabled, std::sync::atomic::Ordering::Relaxed);
    app.settings.write().await.lzma_low_disk = t.enabled;
    app.save_settings().await;
    info_event(&app, format!("LZMA2 compression of kept files when space runs low: {}", if t.enabled { "on" } else { "off" }));
    Json(serde_json::json!({ "ok": true, "enabled": t.enabled }))
}

#[derive(Deserialize)]
struct RescanBody {
    sha256: String,
}

/// Rescans one file kept in multron_incoming with the current engine, analyst
/// signatures and smart whitelist; updates cache, telemetry and the website.
async fn handle_rescan_one(State(app): State<Arc<AppState>>, Json(b): Json<RescanBody>) -> Response {
    let srv = Arc::clone(&app.scan_server);
    let sha = b.sha256.clone();
    match tokio::task::spawn_blocking(move || crate::rescan::rescan_logged(&srv, &sha, "single", 0)).await {
        Ok(Ok(c)) => Json(serde_json::json!({ "ok": true, "change": c })).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct BulkRescanBody {
    /// "unknown", "possible_clean", "suspicious", "malicious", "clean" ("threat" = both);
    /// empty = unknown + possible_clean for a rescan, every category for a move.
    #[serde(default)]
    categories: Vec<String>,
}

async fn handle_rescan_bulk(State(app): State<Arc<AppState>>, Json(b): Json<BulkRescanBody>) -> Response {
    match crate::rescan::start_bulk(&app.scan_server, &b.categories) {
        Ok(n) => Json(serde_json::json!({ "ok": true, "queued": n })).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

/// Duplicate / not-listed kept files per category. Walks the work folder.
async fn handle_rescan_audit(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let srv = Arc::clone(&app.scan_server);
    let v = tokio::task::spawn_blocking(move || crate::rescan::kept_audit(&srv))
        .await
        .unwrap_or_else(|e| serde_json::json!({ "ok": false, "error": e.to_string() }));
    Json(v)
}

#[derive(Deserialize, Default)]
struct AuditBulkBody {
    #[serde(default)]
    categories: Vec<String>,
    /// "duplicate", "not_listed" (empty = both).
    #[serde(default)]
    kinds: Vec<String>,
}

async fn handle_rescan_audit_bulk(State(app): State<Arc<AppState>>, Json(b): Json<AuditBulkBody>) -> Response {
    let srv = Arc::clone(&app.scan_server);
    match tokio::task::spawn_blocking(move || crate::rescan::start_bulk_problems(&srv, &b.categories, &b.kinds)).await {
        Ok(Ok(n)) => Json(serde_json::json!({ "ok": true, "queued": n })).into_response(),
        Ok(Err(e)) => (StatusCode::CONFLICT, Json(serde_json::json!({ "error": e }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

#[derive(Deserialize)]
struct RequeueBody {
    verdict: String,
    #[serde(default)]
    include_removed: bool,
}

/// Queues again the files with this engine verdict that have no human review
/// ("missing" in the coverage line), plus the removed ones when asked.
async fn handle_reviews_requeue(State(app): State<Arc<AppState>>, Json(b): Json<RequeueBody>) -> Response {
    let v = b.verdict.trim().to_ascii_lowercase();
    if !crate::human_review::AUTO_QUEUE_VERDICTS.contains(&v.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "unknown verdict" }))).into_response();
    }
    let ti = Arc::clone(&app.threat_intel);
    match tokio::task::spawn_blocking(move || ti.requeue(&v, b.include_removed)).await {
        Ok(Ok(n)) => Json(serde_json::json!({ "ok": true, "queued": n })).into_response(),
        Ok(Err(e)) => (StatusCode::CONFLICT, Json(serde_json::json!({ "error": e }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

/// Where a kept upload is on this server (multron_incoming/<category>/...).
async fn handle_kept_info(State(app): State<Arc<AppState>>, Path(sha256): Path<String>) -> impl IntoResponse {
    let sha = sha256.trim().to_ascii_uppercase();
    let eng = Arc::clone(&app.engine);
    let kept = tokio::task::spawn_blocking(move || eng.find_kept(&sha)).await.ok().flatten();
    match kept {
        Some(k) => Json(serde_json::json!({
            "ok": true, "kept": true,
            "path": k.path.display().to_string(),
            "folder": k.path.parent().map(|p| p.display().to_string()),
            "category": k.category, "name": k.name, "compressed": k.xz,
        })),
        None => Json(serde_json::json!({ "ok": true, "kept": false })),
    }
}

/// Opens Explorer on this server with the kept file selected. The dashboard only
/// answers on localhost, so this is the machine the analyst is sitting at (or the
/// remote desktop of the VDS).
async fn handle_kept_reveal(State(app): State<Arc<AppState>>, Json(b): Json<RescanBody>) -> Response {
    let sha = b.sha256.trim().to_ascii_uppercase();
    let eng = Arc::clone(&app.engine);
    let Some(k) = tokio::task::spawn_blocking(move || eng.find_kept(&sha)).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "this file is not kept on the server (not uploaded, deleted, or moved by offload)" }))).into_response();
    };
    let path = k.path.clone();
    let res = reveal_in_file_manager(&path);
    match res {
        Ok(()) => Json(serde_json::json!({ "ok": true, "path": path.display().to_string() })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e, "path": path.display().to_string() }))).into_response(),
    }
}

#[cfg(windows)]
fn reveal_in_file_manager(path: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    // explorer.exe wants `/select,"C:\path"` as one raw argument (Rust's quoting would
    // wrap the whole thing in quotes, which explorer does not understand).
    std::process::Command::new("explorer.exe")
        .raw_arg(format!("/select,\"{}\"", path.display()))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("cannot start explorer.exe: {e}"))
}

#[cfg(not(windows))]
fn reveal_in_file_manager(path: &std::path::Path) -> Result<(), String> {
    let dir = path.parent().ok_or("no parent folder")?;
    std::process::Command::new("xdg-open")
        .arg(dir)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("cannot open the folder: {e}"))
}

/// Every rescanned file (newest first, across runs) with old/new verdict and engines.
async fn handle_rescan_log(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "status": app.scan_server.rescan.status(), "log": app.scan_server.rescan.log() }))
}

async fn handle_rescan_status(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    Json(app.scan_server.rescan.status())
}

async fn handle_rescan_stop(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    app.scan_server.rescan.request_stop();
    Json(serde_json::json!({ "ok": true }))
}

async fn handle_rescan_after_reload(State(app): State<Arc<AppState>>, Json(t): Json<KeepToggle>) -> impl IntoResponse {
    app.scan_server.rescan.after_reload.store(t.enabled, std::sync::atomic::Ordering::Relaxed);
    app.settings.write().await.rescan_after_reload = t.enabled;
    app.save_settings().await;
    Json(serde_json::json!({ "ok": true, "enabled": t.enabled }))
}

// ---------------- Folder whitelist on the server's own disk ----------------

#[derive(Deserialize)]
struct FsListQuery {
    #[serde(default)]
    path: String,
}

async fn handle_fs_list(Query(q): Query<FsListQuery>) -> Response {
    match tokio::task::spawn_blocking(move || crate::folder_wl::list_dir(&q.path)).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct FolderBody {
    path: String,
    #[serde(default)]
    exts: Vec<String>,
    /// Skip files larger than this (0 = no limit).
    #[serde(default)]
    max_mb: u64,
}

/// Work folder and move target: never walked (client uploads, malware included).
fn folder_exclusions(app: &AppState) -> Vec<Option<PathBuf>> {
    let target = app.scan_server.offload.target();
    vec![
        app.engine.work_dir().map(|p| p.to_path_buf()),
        if target.trim().is_empty() { None } else { Some(PathBuf::from(target.trim())) },
    ]
}

async fn handle_folder_types(State(app): State<Arc<AppState>>, Json(b): Json<FolderBody>) -> Response {
    let ex = folder_exclusions(&app);
    let res = tokio::task::spawn_blocking(move || {
        let refs: Vec<Option<&std::path::Path>> = ex.iter().map(|p| p.as_deref()).collect();
        crate::folder_wl::scan_types(&b.path, b.max_mb * 1024 * 1024, &refs)
    })
    .await;
    match res {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn handle_folder_start(State(app): State<Arc<AppState>>, Json(b): Json<FolderBody>) -> Response {
    let ex = folder_exclusions(&app);
    let refs: Vec<Option<&std::path::Path>> = ex.iter().map(|p| p.as_deref()).collect();
    let srv = Arc::clone(&app.scan_server);
    match crate::folder_wl::start(&b.path, &b.exts, b.max_mb * 1024 * 1024, &refs, move |m| srv.log_info(m)) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

async fn handle_folder_status() -> impl IntoResponse {
    Json(crate::folder_wl::JOB.status())
}

async fn handle_folder_stop() -> impl IntoResponse {
    crate::folder_wl::JOB.request_stop();
    Json(serde_json::json!({"ok": true}))
}

// ---------------- Backup archive mirror ----------------

#[derive(Deserialize)]
struct MirrorConfigBody {
    #[serde(default)]
    target: String,
}

async fn handle_mirror_config(State(app): State<Arc<AppState>>, Json(b): Json<MirrorConfigBody>) -> Response {
    let target = b.target.trim().to_string();
    if !target.is_empty() && !std::path::Path::new(&target).is_absolute() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "use an absolute path, e.g. \\\\ARCHIVEPC\\viruskov_archive or Z:\\viruskov_archive" }))).into_response();
    }
    app.scan_server.mirror.set_target(&target);
    app.settings.write().await.archive_mirror = target.clone();
    app.save_settings().await;
    info_event(&app, format!("archive mirror: {}", if target.is_empty() { "off" } else { &target }));
    if !target.is_empty() {
        app.scan_server.mirror.run_now();
    }
    Json(serde_json::json!({ "ok": true, "mirror": app.scan_server.mirror.status() })).into_response()
}

async fn handle_mirror_run(State(app): State<Arc<AppState>>) -> Response {
    if app.scan_server.mirror.target().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "set the archive folder first" }))).into_response();
    }
    app.scan_server.mirror.run_now();
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// Removes extra copies of the same sample from this server's work folder.
async fn handle_kept_dedupe(State(app): State<Arc<AppState>>) -> Response {
    let engine = Arc::clone(&app.engine);
    let ti = Arc::clone(&app.threat_intel);
    let r = tokio::task::spawn_blocking(move || {
        engine.dedupe_kept(|sha| {
            let (verdict, source, _) = ti.effective(&sha.to_ascii_lowercase());
            (source != "unseen").then_some(verdict)
        })
    })
    .await;
    match r {
        Ok((n, bytes)) => {
            *KEPT_CACHE.lock().unwrap() = None;
            info_event(&app, format!("{n} duplicate kept file(s) removed, {:.1} MB freed", bytes as f64 / 1048576.0));
            Json(serde_json::json!({ "ok": true, "removed": n, "bytes": bytes })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn handle_mirror_dedupe(State(app): State<Arc<AppState>>) -> Response {
    let m = Arc::clone(&app.scan_server.mirror);
    match tokio::task::spawn_blocking(move || m.dedupe_now()).await {
        Ok(Ok((n, bytes))) => {
            info_event(&app, format!("archive: {n} duplicate sample(s) removed, {:.1} MB freed", bytes as f64 / 1048576.0));
            Json(serde_json::json!({ "ok": true, "removed": n, "bytes": bytes })).into_response()
        }
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn handle_mirror_stop(State(app): State<Arc<AppState>>) -> Response {
    app.scan_server.mirror.request_stop();
    Json(serde_json::json!({ "ok": true })).into_response()
}

// ---------------- Moving kept files to another disk / network share ----------------

#[derive(Deserialize)]
struct OffloadConfigBody {
    #[serde(default)]
    target: String,
    #[serde(default)]
    auto: bool,
}

async fn handle_offload_config(State(app): State<Arc<AppState>>, Json(b): Json<OffloadConfigBody>) -> Response {
    let target = b.target.trim().to_string();
    if !target.is_empty() {
        let engine = Arc::clone(&app.engine);
        let t = target.clone();
        match tokio::task::spawn_blocking(move || crate::offload::check_target(&engine, &t)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
        }
    }
    let off = &app.scan_server.offload;
    *off.target.write().unwrap() = target.clone();
    off.auto.store(b.auto && !target.is_empty(), std::sync::atomic::Ordering::Relaxed);
    {
        let mut g = app.settings.write().await;
        g.offload_target = target.clone();
        g.offload_auto = b.auto && !target.is_empty();
    }
    app.save_settings().await;
    info_event(&app, format!("move target: {} (automatic: {})", if target.is_empty() { "off" } else { &target }, if b.auto { "on" } else { "off" }));
    Json(serde_json::json!({ "ok": true, "offload": off.status() })).into_response()
}

async fn handle_offload_start(State(app): State<Arc<AppState>>, body: Option<Json<BulkRescanBody>>) -> Response {
    let cats = body.map(|Json(b)| b.categories).unwrap_or_default();
    let srv = Arc::clone(&app.scan_server);
    let engine = Arc::clone(&app.engine);
    let res = tokio::task::spawn_blocking(move || {
        let log_srv = Arc::clone(&srv);
        crate::offload::start(&engine, &srv.offload, crate::offload::Mode::Categories(cats), move |m| log_srv.log_info(m))
    })
    .await;
    match res {
        Ok(Ok(n)) => Json(serde_json::json!({ "ok": true, "files": n })).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn handle_offload_stop(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    app.scan_server.offload.request_stop();
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct MaintenanceToggle {
    #[serde(default)]
    enabled: bool,
    /// "maintenance" (default) or "updating" (Multron Updater, before it replaces the exe).
    #[serde(default)]
    mode: String,
}

/// Files being uploaded or scanned right now (the updater waits for 0 before closing).
fn active_work(app: &AppState) -> usize {
    let srv = &app.scan_server;
    srv.inflight_files() + srv.scheduler.busy() + srv.scheduler.queued()
}

fn maintenance_json(app: &AppState) -> serde_json::Value {
    let srv = &app.scan_server;
    serde_json::json!({
        "ok": true,
        "maintenance": srv.maintenance(),
        "mode": srv.maintenance_mode(),
        "message": if srv.maintenance_mode() != "off" { srv.maintenance_message() } else { "" },
        "activeWork": active_work(app),
        // Seamless update: the updater sees the switch by the pid changing.
        "pid": std::process::id(),
        "handoff": srv.handoff.status_json(),
        "seamlessUpdate": true,
    })
}

async fn handle_maintenance_status(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    Json(maintenance_json(&app))
}

/// Maintenance mode: the listener stays up (health answers) but new file and
/// URL scans are refused with a message while in-flight work finishes.
/// "maintenance" is the normal mode (kept across restarts); "updating" is set by
/// Multron Updater right before it closes and replaces the server, so the updated
/// server starts with scans open again.
async fn handle_maintenance(
    State(app): State<Arc<AppState>>,
    Json(toggle): Json<MaintenanceToggle>,
) -> impl IntoResponse {
    let mode = if !toggle.enabled { "off" } else if toggle.mode.eq_ignore_ascii_case("updating") { "updating" } else { "maintenance" };
    app.scan_server.set_maintenance(mode);
    // "updating" is not saved and leaves the saved choice alone: a server that was in
    // normal maintenance before the update comes back in normal maintenance.
    if mode != "updating" {
        app.settings.write().await.maintenance = mode == "maintenance";
        app.save_settings().await;
    }
    info_event(
        &app,
        match mode {
            "updating" => "maintenance mode ON (updating server): new scans refused, in-flight work finishes".into(),
            "maintenance" => "maintenance mode ON: new scans refused, in-flight work finishes".into(),
            _ => "maintenance mode OFF: scans accepted again".into(),
        },
    );
    Json(maintenance_json(&app))
}

#[derive(Deserialize)]
struct HandoffReq {
    #[serde(default)]
    pid: u32,
    #[serde(default, rename = "drainSeconds")]
    drain_seconds: Option<u64>,
}

/// Seamless update: the new version started next to this one and loads its engine.
/// Scans go on ("getting updated"); called again every few seconds as a heartbeat.
async fn handle_handoff_begin(State(app): State<Arc<AppState>>, Json(req): Json<HandoffReq>) -> impl IntoResponse {
    if app.scan_server.handoff.begin(&app.scan_server, req.pid) {
        info_event(&app, format!("getting updated: the new version (pid {}) is loading next to this one; scans continue", req.pid));
    }
    let listening = app.listener_handle.lock().await.is_some();
    Json(serde_json::json!({ "ok": true, "pid": std::process::id(), "listening": listening, "mode": app.scan_server.maintenance_mode() }))
}

/// Seamless update abandoned by the new version (it could not load).
async fn handle_handoff_cancel(State(app): State<Arc<AppState>>, Json(req): Json<HandoffReq>) -> impl IntoResponse {
    if app.scan_server.handoff.standby_pid() == Some(req.pid) {
        app.scan_server.handoff.abandon(&app.scan_server, false);
        info_event(&app, format!("seamless update cancelled by the new version (pid {}); back to normal", req.pid));
    }
    Json(maintenance_json(&app))
}

/// Seamless update, last step: refuse new scans for a moment, let the ones in progress
/// finish, close the sessions, let the writers flush, answer and exit, so the new
/// version can bind the ports.
async fn handle_handoff_release(State(app): State<Arc<AppState>>, Json(req): Json<HandoffReq>) -> Response {
    let standby = app.scan_server.handoff.standby_pid();
    if standby != Some(req.pid) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "ok": false, "error": format!("no seamless update from pid {} (standby: {:?})", req.pid, standby) })),
        )
            .into_response();
    }
    let started = std::time::Instant::now();
    let listening = app.listener_handle.lock().await.is_some();
    if app.scan_server.maintenance_mode() != "maintenance" {
        app.scan_server.set_maintenance("switching");
    }
    info_event(&app, format!("seamless update: handing over to pid {}; finishing the scans in progress", req.pid));
    let limit = std::time::Duration::from_secs(req.drain_seconds.unwrap_or(30).min(300));
    while active_work(&app) > 0 && started.elapsed() < limit {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let left = active_work(&app);
    app.stop_listener(false).await;
    // Background jobs stop here (start them again on the new version if needed), then
    // everything buffered goes to disk before the new version reads the last lines.
    let srv = Arc::clone(&app.scan_server);
    srv.rescan.request_stop();
    srv.retrohunt.stop_all();
    srv.offload.request_stop();
    srv.mirror.request_stop();
    let flushed = tokio::task::spawn_blocking(move || {
        let t = std::time::Duration::from_secs(10);
        srv.threat_intel.flush(t) & srv.cache.flush(t)
    })
    .await
    .unwrap_or(false);
    if !flushed {
        // A writer did not answer: fall back to its own 2 s flush.
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    }
    crate::uptime::save_now();
    eprintln!(
        "[handoff] handed over to pid {} after {} ms ({left} scan(s) cut off); exiting",
        req.pid,
        started.elapsed().as_millis()
    );
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        std::process::exit(0);
    });
    Json(serde_json::json!({ "ok": true, "released": true, "listening": listening, "pid": std::process::id(), "cutOff": left })).into_response()
}

/// Leaves "getting updated" when the new version stopped calling (it crashed).
pub fn spawn_handoff_watchdog(app: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(crate::handoff::BEAT_EVERY).await;
            if let Some(pid) = app.scan_server.handoff.abandon(&app.scan_server, true) {
                info_event(&app, format!("seamless update abandoned: the new version (pid {pid}) stopped answering; back to normal"));
            }
        }
    });
}

fn info_event(app: &AppState, message: String) {
    app.events.add(crate::events::Event {
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
        message: Some(message),
        origin_type: None,
    });
}

/// Saves new limits from the dashboard. They apply at once and survive a restart.
async fn handle_limits(
    State(app): State<Arc<AppState>>,
    Json(new): Json<LimitSettings>,
) -> impl IntoResponse {
    let applied = app.scan_server.apply_limits(new);
    app.settings.write().await.limits = Some(applied.clone());
    app.save_settings().await;
    info_event(
        &app,
        format!(
            "limits changed: max file {} MB, {} conn/IP, {} connects/min, {} MB upload/h, {} msg/s, {} checks/s, ban after {} strikes for {} min",
            applied.max_mb, applied.max_per_ip, applied.connects_per_min, applied.upload_mb_per_hour,
            applied.msgs_per_sec, applied.checks_per_sec, applied.ban_strikes, applied.ban_minutes
        ),
    );
    Json(serde_json::json!({"ok": true, "limits": applied}))
}

/// Back to the command-line values; the saved limits are removed.
async fn handle_limits_reset(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let applied = app.scan_server.apply_limits(LimitSettings::from_args(&app.cfg));
    app.settings.write().await.limits = None;
    app.save_settings().await;
    info_event(&app, "limits reset to the command-line values".into());
    Json(serde_json::json!({"ok": true, "limits": applied}))
}

async fn handle_unban(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let n = app.scan_server.limiter.unban_all();
    info_event(&app, format!("{n} blocked IP(s) unblocked"));
    Json(serde_json::json!({"ok": true, "unbanned": n}))
}

#[derive(Deserialize)]
struct EngineReloadQuery {
    /// Keep cached verdicts (default: invalidate them so files are rescanned).
    #[serde(default)]
    keep_cache: bool,
}

/// Hot reload of the whole engine in this process; the listener and sessions stay up.
async fn handle_engine_reload(
    State(app): State<Arc<AppState>>,
    Query(q): Query<EngineReloadQuery>,
) -> impl IntoResponse {
    let app2 = Arc::clone(&app);
    let keep_cache = q.keep_cache;
    let tl = app.threat_intel.similarity.reload_known_malware();
    let refs = app.threat_intel.similarity.reload_corpus_refs();
    info_event(&app, format!("TLSH blacklist: {tl} digests, smart-whitelist corpus: {refs} references"));
    let started = app.engine.reload_all(move |res| match res {
        Ok(ms) => {
            if !keep_cache {
                app2.scan_server.cache.invalidate_all();
            }
            info_event(
                &app2,
                format!(
                    "engine hot-reloaded in {ms} ms{}",
                    if keep_cache { "" } else { ", verdict cache invalidated" }
                ),
            );
            // New rules may settle kept unknown / possible_clean files.
            if app2.scan_server.rescan.after_reload.load(std::sync::atomic::Ordering::Relaxed) {
                if let Err(e) = crate::rescan::start_bulk_from(&app2.scan_server, &[], "reload") {
                    info_event(&app2, format!("rescan after reload not started: {e}"));
                }
            }
        }
        Err(e) => info_event(&app2, format!("engine reload failed, old engine kept: {e}")),
    });
    match started {
        Ok(()) => {
            info_event(&app, "engine hot reload started".to_string());
            (StatusCode::ACCEPTED, Json(serde_json::json!({"ok": true, "detail": "reload started"}))).into_response()
        }
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct RulesReloadQuery {
    #[serde(default)]
    kind: String,
}

/// General runtime rule reload without restart or rebuild.
///
/// POST /api/rules?kind=url|strings|registry|yara_src with the raw rule text
/// as the body (64 MB cap). Replaces the live rule set of that kind; binary
/// bundles (ML models, compiled .yrc) stay restart-only.
async fn handle_rules_reload(
    State(app): State<Arc<AppState>>,
    Query(q): Query<RulesReloadQuery>,
    body: String,
) -> impl IntoResponse {
    const MAX_RULES_BODY: usize = 64 * 1024 * 1024;
    if body.len() > MAX_RULES_BODY {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "rule body over 64 MB, refusing"})),
        )
            .into_response();
    }
    if body.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "empty rule body"})),
        )
            .into_response();
    }
    match app.engine.reload_rules(&q.kind, &body) {
        Ok(detail) => {
            info_event(&app, format!("rules reloaded ({kind}): {detail}", kind = q.kind));
            (StatusCode::OK, Json(serde_json::json!({"ok": true, "detail": detail}))).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": err})),
        )
            .into_response(),
    }
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

async fn handle_dashboard_insights_stats(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = app.threat_intel.stats();
    let srv = Arc::clone(&app.scan_server);
    let types = tokio::task::spawn_blocking(move || crate::scan_server::cached_type_stats(&srv)).await.unwrap_or_default();
    Json(serde_json::json!({
        "ok": true,
        "types": types,
        "telemetry": {
            "total_unique_hashes": stats.total_unique_hashes,
            "total_sightings": stats.total_sightings,
            "verdicts": {
                "malicious": stats.malicious_count,
                "suspicious": stats.suspicious_count,
                "clean": stats.clean_count,
                "possible_clean": stats.possible_clean_count,
                "unknown": stats.unknown_count,
            }
        }
    }))
}

async fn handle_dashboard_insights_hash(
    State(app): State<Arc<AppState>>,
    Path(sha256): Path<String>,
) -> impl IntoResponse {
    let clean = sha256.trim().to_lowercase();
    if let Some(insight) = app.threat_intel.get(&clean) {
        Json(serde_json::json!({
            "ok": true,
            "found": true,
            "prevalence": insight.prevalence(),
            "insight": insight,
            "review": app.threat_intel.reviews.get(&clean).map(|r| r.to_dashboard_json()),
            "virustotal": crate::human_review::virustotal_url(&clean),
        }))
    } else {
        Json(serde_json::json!({
            "ok": true,
            "found": false,
            "sha256": clean,
            "review": app.threat_intel.reviews.get(&clean).map(|r| r.to_dashboard_json()),
            "virustotal": crate::human_review::virustotal_url(&clean),
            "message": "Hash has not been observed in VirusKov telemetry",
        }))
    }
}

// ---------------- Human analysis (Valkyrie-style queue) ----------------

/// Lower-case extension of a file name ("" when it has none).
fn file_ext(name: &str) -> String {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    match base.rfind('.') {
        Some(i) if i > 0 && i + 1 < base.len() && base.len() - i <= 12 => base[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Pending queue (up to 5000, oldest first) with telemetry for grouping by extension
/// and folder. Similar files are loaded per item (`/api/reviews/similar/:sha256`).
/// Files waiting for the engine and files being scanned right now (oldest first).
#[derive(Deserialize)]
struct AllQuery {
    #[serde(default)]
    all: Option<String>,
}

impl AllQuery {
    fn all(&self) -> bool {
        self.all.as_deref().is_some_and(|v| v == "1" || v == "true")
    }
}

async fn handle_scan_queue(State(app): State<Arc<AppState>>, Query(q): Query<AllQuery>) -> impl IntoResponse {
    let (scanning, waiting, ns, nw) = app.scan_server.scan_queue.snapshot(if q.all() { usize::MAX } else { 500 });
    Json(serde_json::json!({
        "ok": true,
        "scanning": scanning,
        "waiting": waiting,
        "scanningTotal": ns,
        "waitingTotal": nw,
        "now": Utc::now(),
    }))
}

async fn handle_reviews_list(State(app): State<Arc<AppState>>, Query(q): Query<AllQuery>) -> impl IntoResponse {
    // Open files that are not queued yet (e.g. removed by hand, or seen before
    // auto-queueing) are added before listing.
    let ti = Arc::clone(&app.threat_intel);
    let _ = tokio::task::spawn_blocking(move || ti.sync_review_queue()).await;
    let r = &app.threat_intel.reviews;
    let pending: Vec<serde_json::Value> = r
        .pending(if q.all() { usize::MAX } else { 5000 })
        .iter()
        .map(|rv| {
            let mut v = rv.to_dashboard_json();
            let ins = app.threat_intel.get(&rv.sha256);
            let name = rv
                .file_name
                .clone()
                .or_else(|| ins.as_ref().and_then(|i| i.file_names.first().cloned()))
                .unwrap_or_default();
            v["ext"] = serde_json::json!(file_ext(&name));
            if let Some(ins) = ins {
                v["seen_count"] = serde_json::json!(ins.seen_count);
                v["file_names"] = serde_json::json!(ins.file_names);
                v["file_size"] = serde_json::json!(ins.file_size);
                v["folders"] = serde_json::json!(ins.folders);
                v["full_folders"] = serde_json::json!(ins.full_folders);
                v["sightings"] = serde_json::json!(ins.sightings);
                v["current_verdict"] = serde_json::json!(ins.verdict);
                v["current_threat"] = serde_json::json!(ins.threat_name);
                v["detections"] = serde_json::json!(ins.detections);
                if let Some(sg) = &ins.signer {
                    v["signer"] = serde_json::json!(sg);
                }
            }
            add_engine_detail(&app, &mut v, &rv.sha256);
            v["classification"] = crate::scan_server::classification_json(
                v["current_verdict"].as_str().unwrap_or(""),
                v["current_threat"].as_str(),
            );
            v
        })
        .collect();
    let recent: Vec<serde_json::Value> = r
        .recent_completed(200)
        .iter()
        .map(|rv| {
            let mut v = rv.to_dashboard_json();
            add_engine_detail(&app, &mut v, &rv.sha256);
            v["classification"] = crate::scan_server::classification_json(rv.verdict.as_deref().unwrap_or(""), rv.threat_name.as_deref());
            v
        })
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "stats": r.stats(),
        "coverage": app.threat_intel.queue_coverage(),
        "pending": pending,
        "recent": recent,
    }))
}

/// Which engines flagged the file ("jpeg (YARA), MalwareNet.PE (PE_ML)"), from the
/// last engine verdict in the scan cache. Missing when the cache entry expired.
fn add_engine_detail(app: &AppState, v: &mut serde_json::Value, sha256: &str) {
    if v.get("signer").map_or(true, |s| s.is_null()) || v.get("detections").is_none() {
        if let Some(ins) = app.threat_intel.get(sha256) {
            if v.get("signer").map_or(true, |s| s.is_null()) {
                if let Some(sg) = ins.signer {
                    v["signer"] = serde_json::json!(sg);
                }
            }
            if v.get("detections").is_none() {
                v["detections"] = serde_json::json!(ins.detections);
            }
        }
    }
    if let Some(sha) = crate::cache::parse_sha(sha256) {
        if let Some(c) = app.scan_server.cache.get(&sha) {
            if let Some(d) = c.detail.filter(|d| !d.is_empty()) {
                v["engine_detail"] = serde_json::json!(d);
            }
            if v.get("current_threat").map_or(true, |t| t.is_null()) {
                if let Some(t) = c.threat {
                    v["current_threat"] = serde_json::json!(t);
                }
            }
        }
    }
}

async fn handle_review_similar(State(app): State<Arc<AppState>>, Path(sha256): Path<String>) -> impl IntoResponse {
    let sha = sha256.trim().to_lowercase();
    let ti = Arc::clone(&app.threat_intel);
    let list = tokio::task::spawn_blocking(move || crate::scan_server::similar_files(&ti, &sha, 5)).await.unwrap_or_default();
    Json(serde_json::json!({"ok": true, "similar": list}))
}

/// Bulk human verdicts: a whitelist from a folder hashed in the browser, or the queue
/// entries of one extension. `dry_run` only reports what would happen, so the dashboard
/// can warn before anything is written.
#[derive(Deserialize)]
struct ReviewBulkBody {
    #[serde(default)]
    sha256s: Vec<String>,
    /// Use the hashes of the last finished server-side folder hashing (`folder_wl`).
    #[serde(default)]
    folder_job: bool,
    /// malicious | suspicious | clean, or "dismiss" (remove pending entries from the queue).
    verdict: String,
    #[serde(default)]
    threat_name: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    internal_note: String,
    #[serde(default)]
    analyst: String,
    #[serde(default)]
    dry_run: bool,
    /// Also write hashes that conflict (engine flagged them, or an analyst gave another verdict).
    #[serde(default)]
    override_conflicts: bool,
    /// Skip hashes VirusKov has never seen (a folder whitelist may hold many of them).
    #[serde(default)]
    only_seen: bool,
}

const BULK_MAX: usize = 100_000;

async fn handle_reviews_bulk(State(app): State<Arc<AppState>>, Json(mut b): Json<ReviewBulkBody>) -> Response {
    if b.folder_job {
        if crate::folder_wl::JOB.is_running() {
            return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "the folder is still being hashed"}))).into_response();
        }
        b.sha256s = crate::folder_wl::JOB.hashes();
    }
    let bad = |e: String| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response();
    let verdict = b.verdict.trim().to_ascii_lowercase();
    let dismiss = verdict == "dismiss";
    if !dismiss && !crate::human_review::VERDICTS.contains(&verdict.as_str()) {
        return bad("verdict must be malicious, suspicious, clean or dismiss".into());
    }
    if b.sha256s.len() > BULK_MAX {
        return bad(format!("at most {BULK_MAX} hashes per request"));
    }
    // A dry run only counts, so the dashboard can warn before the threat name is typed.
    if verdict == "malicious" && !b.dry_run && b.threat_name.trim().is_empty() {
        return bad("a malicious verdict needs a threat name, e.g. Trojan.Win32.Remcos.A".into());
    }
    if !dismiss && !b.threat_name.trim().is_empty() {
        if let Err(e) = crate::naming::normalize_threat_name(&b.threat_name) {
            return bad(e);
        }
    }
    let ti = Arc::clone(&app.threat_intel);
    let engine = Arc::clone(&app.engine);
    let result = tokio::task::spawn_blocking(move || {
        let adapter = Arc::clone(&engine);
        let mut relabel: Vec<(String, String)> = Vec::new();
        let mut seen_set = std::collections::HashSet::new();
        let (mut invalid, mut duplicates, mut unseen, mut pending, mut same, mut written, mut skipped, mut failed) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        let mut engine_flagged = 0usize;
        let mut human_conflicts = 0usize;
        let mut conflicts: Vec<serde_json::Value> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        for raw in &b.sha256s {
            let sha = raw.trim().to_ascii_lowercase();
            if sha.len() != 64 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
                invalid += 1;
                continue;
            }
            if !seen_set.insert(sha.clone()) {
                duplicates += 1;
                continue;
            }
            let ins = ti.get(&sha);
            let review = ti.reviews.get(&sha);
            let is_pending = review.as_ref().is_some_and(|r| !r.is_completed());
            if is_pending {
                pending += 1;
            }
            if ins.is_none() {
                unseen += 1;
            }
            if dismiss {
                if !is_pending {
                    skipped += 1;
                } else if !b.dry_run {
                    if ti.reviews.remove(&sha) { written += 1 } else { failed += 1 }
                }
                continue;
            }
            let human = review.as_ref().filter(|r| r.is_completed()).and_then(|r| r.verdict.clone());
            if human.as_deref() == Some(verdict.as_str()) {
                same += 1;
                continue;
            }
            let engine = ins.as_ref().map(|i| i.verdict.as_str()).unwrap_or("unknown");
            let engine_conflict = match verdict.as_str() {
                "clean" => matches!(engine, "malicious" | "suspicious"),
                _ => matches!(engine, "clean"),
            };
            let human_conflict = human.is_some();
            if engine_conflict {
                engine_flagged += 1;
            }
            if human_conflict {
                human_conflicts += 1;
            }
            if engine_conflict || human_conflict {
                if conflicts.len() < 200 {
                    conflicts.push(serde_json::json!({
                        "sha256": sha,
                        "name": ins.as_ref().and_then(|i| i.file_names.first().cloned())
                            .or_else(|| review.as_ref().and_then(|r| r.file_name.clone())),
                        "engine": engine,
                        "threat": ins.as_ref().and_then(|i| i.threat_name.clone()),
                        "human": human,
                    }));
                }
                if !b.override_conflicts {
                    skipped += 1;
                    continue;
                }
            }
            if ins.is_none() && b.only_seen {
                skipped += 1;
                continue;
            }
            if b.dry_run {
                written += 1;
                continue;
            }
            let threat = if b.threat_name.trim().is_empty() { None } else { Some(b.threat_name.as_str()) };
            match ti.reviews.complete(&sha, &verdict, threat, &b.note, &b.internal_note, &b.analyst) {
                Ok(r) => {
                    written += 1;
                    relabel.push((sha.clone(), verdict.clone()));
                    sync_analyst_tlsh(&adapter, &ti, &sha, &verdict, r.threat_name.as_deref(), &b.analyst);
                }
                Err(e) => {
                    failed += 1;
                    if errors.len() < 5 {
                        errors.push(e);
                    }
                }
            }
        }
        let moved = engine.relabel_many(&relabel);
        for (sha, v) in &relabel {
            export_human_label(&engine, sha, v);
        }
        serde_json::json!({
            "ok": true,
            "moved_kept": moved,
            "dry_run": b.dry_run,
            "verdict": verdict,
            "received": b.sha256s.len(),
            "valid": seen_set.len(),
            "invalid": invalid,
            "duplicates": duplicates,
            "unseen": unseen,
            "pending": pending,
            "already_same": same,
            "engine_flagged": engine_flagged,
            "human_conflicts": human_conflicts,
            "conflicts": conflicts,
            "written": written,
            "skipped": skipped,
            "failed": failed,
            "errors": errors,
        })
    })
    .await;
    match result {
        Ok(v) => {
            if !v["dry_run"].as_bool().unwrap_or(true) {
                info_event(
                    &app,
                    format!(
                        "human analysis bulk {}: {} written, {} skipped, {} failed",
                        v["verdict"].as_str().unwrap_or("?"),
                        v["written"],
                        v["skipped"],
                        v["failed"]
                    ),
                );
            }
            (StatusCode::OK, Json(v)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ReviewSaveBody {
    sha256: String,
    verdict: String,
    #[serde(default)]
    threat_name: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    internal_note: String,
    #[serde(default)]
    analyst: String,
}

/// Keeps the analyst TLSH signature of `sha` in step with its human verdict: created
/// for malicious (from the kept file, padding stripped; else the indexed TLSH of the
/// whole file), dropped for any other verdict. Blocking (reads the kept file).
fn sync_analyst_tlsh(
    engine: &crate::engine_adapter::EngineAdapter,
    ti: &crate::threat_intel::ThreatIntelStore,
    sha: &str,
    verdict: &str,
    threat: Option<&str>,
    analyst: &str,
) {
    let sha = sha.trim().to_ascii_lowercase();
    if verdict != "malicious" {
        ti.similarity.remove_analyst_sig(&sha);
        return;
    }
    let (tlsh, size) = match engine.read_kept_sample(&sha.to_ascii_uppercase()) {
        Some(data) => {
            let body = crate::similarity::trim_trailing_padding(&data);
            (crate::analyzer::tlsh_digest(body), body.len() as u64)
        }
        None => (ti.similarity.tlsh_of(&sha), 0),
    };
    let Some(tlsh) = tlsh else { return };
    ti.similarity.add_analyst_sig(crate::similarity::AnalystTlsh {
        sha256: sha,
        tlsh,
        threat: threat.filter(|t| !t.is_empty()).unwrap_or("Generic.Multi.Malware").to_string(),
        analyst: analyst.to_string(),
        size,
        added: chrono::Utc::now().to_rfc3339(),
    });
}

async fn handle_review_save(
    State(app): State<Arc<AppState>>,
    Json(b): Json<ReviewSaveBody>,
) -> Response {
    let threat = if b.threat_name.trim().is_empty() { None } else { Some(b.threat_name.as_str()) };
    match app.threat_intel.reviews.complete(b.sha256.trim(), &b.verdict, threat, &b.note, &b.internal_note, &b.analyst) {
        Ok(r) => {
            if let Some(v) = r.verdict.clone() {
                let (eng, ti, sha) = (Arc::clone(&app.engine), Arc::clone(&app.threat_intel), r.sha256.clone());
                let (threat, analyst) = (r.threat_name.clone(), r.analyst.clone());
                tokio::task::spawn_blocking(move || {
                    eng.relabel_kept(&sha.to_ascii_uppercase(), &v);
                    sync_analyst_tlsh(&eng, &ti, &sha, &v, threat.as_deref(), &analyst);
                    export_human_label(&eng, &sha, &v);
                });
            }
            info_event(
                &app,
                format!(
                    "human analysis: {} -> {} by {} ({} s)",
                    r.sha256,
                    r.verdict.as_deref().unwrap_or("?"),
                    if r.analyst.is_empty() { "analyst" } else { r.analyst.as_str() },
                    r.response_secs.unwrap_or(0)
                ),
            );
            (StatusCode::OK, Json(serde_json::json!({"ok": true, "review": r.to_dashboard_json()}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ReviewStartBody {
    sha256: String,
    #[serde(default)]
    analyst: String,
    #[serde(default)]
    take_over: bool,
}

/// "Start analysis" (Valkyrie-style start date): marks the hash as being analysed.
async fn handle_review_start(State(app): State<Arc<AppState>>, Json(b): Json<ReviewStartBody>) -> Response {
    match app.threat_intel.reviews.start(b.sha256.trim(), &b.analyst, b.take_over) {
        Ok(r) => {
            info_event(&app, format!("human analysis started: {} by {}", r.sha256, if r.started_by.is_empty() { "analyst" } else { &r.started_by }));
            (StatusCode::OK, Json(serde_json::json!({"ok": true, "review": r.to_dashboard_json()}))).into_response()
        }
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

async fn handle_review_release(State(app): State<Arc<AppState>>, Json(b): Json<ReviewDeleteBody>) -> Response {
    match app.threat_intel.reviews.release(b.sha256.trim()) {
        Ok(r) => (StatusCode::OK, Json(serde_json::json!({"ok": true, "review": r.to_dashboard_json()}))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ReviewDeleteBody {
    sha256: String,
}

async fn handle_review_delete(
    State(app): State<Arc<AppState>>,
    Json(b): Json<ReviewDeleteBody>,
) -> Response {
    if app.threat_intel.reviews.remove(b.sha256.trim()) {
        app.threat_intel.similarity.remove_analyst_sig(b.sha256.trim());
        info_event(&app, format!("human analysis removed: {}", b.sha256.trim().to_lowercase()));
        (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no review for this hash"}))).into_response()
    }
}

// ---------------- Signature room (analyst YARA rules, stored apart) ----------------

#[derive(Deserialize)]
struct NamingQuery {
    #[serde(default)]
    name: String,
}

async fn handle_naming_check(Query(q): Query<NamingQuery>) -> impl IntoResponse {
    match crate::naming::normalize_threat_name(&q.name) {
        Ok(n) => Json(serde_json::json!({"ok": true, "name": n, "yara_id": crate::naming::yara_identifier(&n)})),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

async fn handle_signatures_list() -> impl IntoResponse {
    use crate::analyst_engine::SigKind;
    let mut items = Vec::new();
    for kind in SigKind::ALL {
        let dir = crate::human_review::analyst_dir().join(kind.folder());
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some(kind.ext()) {
                continue;
            }
            let name = p.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let modified = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339());
            items.push(serde_json::json!({
                "kind": kind.id(),
                "name": name,
                "source": std::fs::read_to_string(&p).unwrap_or_default(),
                "modified": modified,
            }));
        }
    }
    items.sort_by(|a, b| (a["name"].as_str(), a["kind"].as_str()).cmp(&(b["name"].as_str(), b["kind"].as_str())));
    Json(serde_json::json!({
        "ok": true,
        "folder": crate::human_review::analyst_dir().display().to_string(),
        "categories": crate::naming::CATEGORIES,
        "platforms": crate::naming::PLATFORMS,
        "items": items,
    }))
}

fn default_kind() -> String {
    "yara".into()
}

#[derive(Deserialize)]
struct SignatureSaveBody {
    #[serde(default = "default_kind")]
    kind: String,
    name: String,
    source: String,
}

/// Validates the name and the source for its engine, then writes
/// `analyst_signatures/<engine>/<Name>.<ext>`. YARA is compiled into the live engine
/// (append-only); ClamAV and HydraDragonSig sets are rebuilt from disk at once.
async fn handle_signature_save(
    State(app): State<Arc<AppState>>,
    Json(b): Json<SignatureSaveBody>,
) -> Response {
    use crate::analyst_engine::{validate_clamav, validate_hydrasig, SigKind};
    let bad = |e: String| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response();
    let Some(kind) = SigKind::parse(&b.kind) else {
        return bad("unknown kind (yara | hydradragonsig | clamav_ndb | clamav_ldb)".into());
    };
    let name = match crate::naming::normalize_threat_name(&b.name) {
        Ok(n) => n,
        Err(e) => return bad(e),
    };
    if b.source.len() > 1024 * 1024 {
        return bad("rule source over 1 MB".into());
    }
    let path = kind.path(&name);
    let existed = path.exists();
    let checked = match kind {
        SigKind::Yara => {
            if !b.source.contains("rule ") {
                return bad("the source does not contain a YARA rule".into());
            }
            app.engine.reload_rules("yara_src", &b.source).map(|_| 1)
        }
        SigKind::HydraSig => validate_hydrasig(&b.source),
        SigKind::ClamNdb | SigKind::ClamLdb => validate_clamav(kind, &b.source),
    };
    let count = match checked {
        Ok(n) => n,
        Err(e) => return bad(e),
    };
    if let Err(e) = std::fs::write(&path, &b.source) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }
    let note = if kind == SigKind::Yara {
        if existed {
            "Saved. The previous version stays loaded too until the next engine reload.".to_string()
        } else {
            "Saved and active.".to_string()
        }
    } else {
        let engine = Arc::clone(&app.engine);
        let summary = tokio::task::spawn_blocking(move || engine.analyst.reload()).await.unwrap_or_default();
        format!("Saved and active ({count} signature(s)). {summary}")
    };
    info_event(&app, format!("signature room: {} {name} {}", kind.id(), if existed { "updated" } else { "added" }));
    // Retrohunt: this signature over every kept file, matches rescanned with the full engine.
    let hunt = crate::retrohunt::start(&app.scan_server, kind, &name, &b.source);
    let note = format!("{note} Retrohunt #{hunt} queued over all kept files.");
    Json(serde_json::json!({ "ok": true, "kind": kind.id(), "name": name, "file": path.display().to_string(), "note": note, "retrohunt": hunt })).into_response()
}

async fn handle_retrohunt_status(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    Json(app.scan_server.retrohunt.status())
}

/// Archive server: matches a rule (saved or only in the editor) against every file of
/// the mirrored work folder. Match only: no engine, nothing written.
async fn handle_retrohunt_archive(State(app): State<Arc<AppState>>, Json(b): Json<SignatureSaveBody>) -> Response {
    use crate::analyst_engine::SigKind;
    let bad = |e: &str| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response();
    if !crate::config::is_archive() {
        return bad("on the main server, saving the signature starts its retrohunt");
    }
    let Some(kind) = SigKind::parse(&b.kind) else {
        return bad("unknown kind (yara | hydradragonsig | clamav_ndb | clamav_ldb)");
    };
    if b.source.trim().is_empty() {
        return bad("the rule is empty");
    }
    if b.source.len() > 1024 * 1024 {
        return bad("rule source over 1 MB");
    }
    let name: String = b.name.trim().chars().take(200).collect();
    let name = if name.is_empty() { "(unsaved rule)".to_string() } else { name };
    let hunt = crate::retrohunt::start_match_only(&app.scan_server, kind, &name, &b.source);
    Json(serde_json::json!({ "ok": true, "retrohunt": hunt })).into_response()
}

async fn handle_retrohunt_stop(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    app.scan_server.retrohunt.stop_all();
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct SignatureDeleteBody {
    #[serde(default = "default_kind")]
    kind: String,
    name: String,
}

async fn handle_signature_delete(
    State(app): State<Arc<AppState>>,
    Json(b): Json<SignatureDeleteBody>,
) -> Response {
    use crate::analyst_engine::SigKind;
    let (Some(kind), Ok(name)) = (SigKind::parse(&b.kind), crate::naming::normalize_threat_name(&b.name)) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid kind or name"}))).into_response();
    };
    if let Err(e) = std::fs::remove_file(kind.path(&name)) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }
    let note = if kind == SigKind::Yara {
        "Deleted. It stays loaded until the next engine reload.".to_string()
    } else {
        let engine = Arc::clone(&app.engine);
        tokio::task::spawn_blocking(move || engine.analyst.reload()).await.unwrap_or_default();
        "Deleted and unloaded.".to_string()
    };
    info_event(&app, format!("signature room: {} {name} deleted", kind.id()));
    Json(serde_json::json!({"ok": true, "note": note})).into_response()
}

// ---------------- Company (signer) allow / block lists ----------------

async fn handle_companies_get(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "lists": app.engine.analyst.company_lists() }))
}

#[derive(Deserialize)]
struct CompaniesBody {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    block: Vec<String>,
}

async fn handle_companies_save(
    State(app): State<Arc<AppState>>,
    Json(b): Json<CompaniesBody>,
) -> Response {
    if b.allow.len() + b.block.len() > 10_000 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "too many entries"}))).into_response();
    }
    if let Some(both) = b.allow.iter().find(|a| b.block.iter().any(|x| x.trim().eq_ignore_ascii_case(a.trim()))) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("\"{}\" is in both lists", both.trim())}))).into_response();
    }
    if let Err(e) = crate::analyst_engine::save_company_lists(&b.allow, &b.block) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }
    let engine = Arc::clone(&app.engine);
    let summary = tokio::task::spawn_blocking(move || engine.analyst.reload()).await.unwrap_or_default();
    // Cached verdicts were made with the old lists.
    app.scan_server.cache.invalidate_all();
    info_event(&app, format!("company lists saved: {summary}"));
    Json(serde_json::json!({ "ok": true, "lists": app.engine.analyst.company_lists(), "note": "Saved and active; cached verdicts cleared." })).into_response()
}


// ---------------- False-positive signature lists ----------------

fn fp_rules_dir(app: &AppState) -> Result<std::path::PathBuf, Response> {
    app.engine.rules_dir().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "the engine has not started loading yet"}))).into_response()
    })
}

/// Signatures named in the last result for this file (verdict cache, else the
/// rescan log), with the engine each belongs to.
async fn handle_fp_detections(State(app): State<Arc<AppState>>, Path(sha256): Path<String>) -> impl IntoResponse {
    let sha = sha256.trim().to_ascii_lowercase();
    let detail = crate::cache::parse_sha(&sha.to_ascii_uppercase())
        .and_then(|s| app.scan_server.cache.get(&s))
        .and_then(|c| c.detail.clone())
        .or_else(|| app.scan_server.rescan.log().into_iter().find(|e| e.sha256 == sha && e.error.is_none()).and_then(|e| e.detail));
    let threat = app.threat_intel.get(&sha).and_then(|i| i.threat_name);
    match detail {
        Some(d) => Json(serde_json::json!({"ok": true, "detail": d, "threat": threat, "detections": crate::fp_ignore::parse_detail(&d)})),
        None => Json(serde_json::json!({"ok": true, "detail": null, "threat": threat, "detections": [],
            "note": "No engine detail for this file in memory: rescan it first."})),
    }
}

#[derive(Deserialize)]
struct SourcesQuery {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    limit: Option<usize>,
}

/// Client IPs that sent files, with file / path counts (bot and abuse hunting).
async fn handle_sources(State(app): State<Arc<AppState>>, Query(q): Query<SourcesQuery>) -> Response {
    let ti = Arc::clone(&app.threat_intel);
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let mut list = tokio::task::spawn_blocking(move || ti.sources(&q.ip, &q.path, limit)).await.unwrap_or_default();
    for v in &mut list {
        let banned = v["ip"].as_str().is_some_and(|ip| app.scan_server.ip_bans.is_banned(ip));
        v["banned"] = serde_json::json!(banned);
    }
    Json(serde_json::json!({"ok": true, "sources": list})).into_response()
}

/// Files one client IP sent, with the full paths it sent them from.
async fn handle_source_files(State(app): State<Arc<AppState>>, Query(q): Query<SourcesQuery>) -> Response {
    if q.ip.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false, "error": "ip required"}))).into_response();
    }
    let ti = Arc::clone(&app.threat_intel);
    let limit = q.limit.unwrap_or(500).clamp(1, 5000);
    let ip = q.ip.clone();
    let (total, files) = tokio::task::spawn_blocking(move || ti.files_from_ip(&q.ip, &q.path, limit)).await.unwrap_or_default();
    let banned = app.scan_server.ip_bans.is_banned(&ip);
    Json(serde_json::json!({"ok": true, "ip": ip.trim(), "banned": banned, "total": total, "files": files})).into_response()
}

/// Analyst IP bans plus the automatic (rate limit) bans active now.
async fn handle_bans_list(State(app): State<Arc<AppState>>) -> Response {
    Json(serde_json::json!({
        "ok": true,
        "bans": app.scan_server.ip_bans.list(),
        "auto": app.scan_server.limiter.banned_now(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct BanBody {
    ip: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    analyst: String,
    /// 0 = until removed.
    #[serde(default)]
    minutes: u64,
}

/// Bans an IP or CIDR range on every public route and closes its open sessions.
async fn handle_ban_add(State(app): State<Arc<AppState>>, Json(b): Json<BanBody>) -> Response {
    match app.scan_server.ip_bans.add(&b.ip, &b.reason, &b.analyst, b.minutes) {
        Ok(ban) => {
            let closed = app.scan_server.close_banned_sessions().await;
            let span = if b.minutes == 0 { "until removed".to_string() } else { format!("for {} min", b.minutes) };
            info_event(&app, format!("IP ban {} {span} by {}: {} ({closed} session(s) closed)", ban.rule,
                if ban.analyst.is_empty() { "analyst" } else { &ban.analyst }, ban.reason));
            Json(serde_json::json!({"ok": true, "ban": ban, "closed": closed})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false, "error": e}))).into_response(),
    }
}

async fn handle_ban_remove(State(app): State<Arc<AppState>>, Json(b): Json<BanBody>) -> Response {
    match app.scan_server.ip_bans.remove(&b.ip) {
        Ok(removed) => {
            if removed {
                info_event(&app, format!("IP ban {} removed", b.ip.trim()));
            }
            Json(serde_json::json!({"ok": true, "removed": removed})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false, "error": e}))).into_response(),
    }
}

async fn handle_fp_lists(State(app): State<Arc<AppState>>) -> Response {
    let rules = match fp_rules_dir(&app) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let lists: Vec<_> = crate::fp_ignore::Kind::ALL.iter().map(|k| crate::fp_ignore::list(&rules, *k)).collect();
    Json(serde_json::json!({"ok": true, "lists": lists})).into_response()
}

#[derive(Deserialize)]
struct FpIgnoreBody {
    kind: String,
    name: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    analyst: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    file_name: String,
}

async fn handle_fp_ignore(State(app): State<Arc<AppState>>, Json(b): Json<FpIgnoreBody>) -> Response {
    let bad = |e: String| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response();
    let Some(kind) = crate::fp_ignore::Kind::parse(&b.kind) else {
        return bad("kind must be clamav, hydrasig or yara".into());
    };
    let rules = match fp_rules_dir(&app) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let req = crate::fp_ignore::AddRequest {
        kind,
        name: b.name.trim(),
        file: &b.file,
        reason: &b.reason,
        analyst: &b.analyst,
        sha256: &b.sha256,
        file_name: &b.file_name,
    };
    match crate::fp_ignore::add(&rules, &req) {
        Ok(path) => {
            info_event(&app, format!("FP list: {} {} added to {} ({})", kind.id(), b.name.trim(), path.display(), b.reason.trim()));
            Json(serde_json::json!({"ok": true, "file": path.display().to_string(), "note": kind.note()})).into_response()
        }
        Err(e) => bad(e),
    }
}

#[derive(Deserialize)]
struct FpUnignoreBody {
    kind: String,
    file: String,
    name: String,
}

async fn handle_fp_unignore(State(app): State<Arc<AppState>>, Json(b): Json<FpUnignoreBody>) -> Response {
    let Some(kind) = crate::fp_ignore::Kind::parse(&b.kind) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unknown kind"}))).into_response();
    };
    let rules = match fp_rules_dir(&app) {
        Ok(r) => r,
        Err(e) => return e,
    };
    match crate::fp_ignore::remove(&rules, kind, &b.file, b.name.trim()) {
        Ok(()) => {
            info_event(&app, format!("FP list: {} {} removed from {}", kind.id(), b.name.trim(), b.file));
            Json(serde_json::json!({"ok": true, "note": "Removed. Active after the next engine reload."})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}
