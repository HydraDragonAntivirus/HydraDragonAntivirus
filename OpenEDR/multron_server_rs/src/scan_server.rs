use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};

use crate::budget::ByteBudget;
use crate::config::CliArgs;
use crate::engine_adapter::{EngineAdapter, ResultMessage, ENGINE_NAME};
use crate::events::{Event, EventLog};
use crate::scheduler::FairScheduler;

pub const PROTOCOL_VERSION: i32 = 2;

#[derive(Debug, Deserialize)]
struct ClientMessage {
    pub r#type: String,
    #[serde(default)]
    pub version: i32,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub sha256: String,
}

#[derive(Debug, Serialize)]
struct ErrorMessage {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub message: String,
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
}

pub struct ScanServer {
    pub cfg: CliArgs,
    pub engine: Arc<EngineAdapter>,
    pub scheduler: Arc<FairScheduler>,
    pub budget: Arc<ByteBudget>,
    pub events: Arc<EventLog>,

    pub cache: Mutex<HashMap<String, ResultMessage>>,
    pub sessions: RwLock<HashMap<i64, Arc<SessionHandle>>>,

    pub next_session_id: AtomicI64,
    pub total_connections: AtomicI64,
    pub total_scanned: AtomicI64,
    pub total_threats: AtomicI64,
    pub total_errors: AtomicI64,
    pub active_connections: AtomicUsize,
}

pub struct SessionHandle {
    pub id: i64,
    pub address: String,
    pub app: RwLock<String>,
    pub connected_at: chrono::DateTime<Utc>,
    pub scanned: AtomicI64,
    pub threats: AtomicI64,
    pub in_flight: AtomicUsize,
    pub abort_tx: mpsc::Sender<()>,
}

impl ScanServer {
    pub fn new(
        cfg: CliArgs,
        engine: Arc<EngineAdapter>,
        events: Arc<EventLog>,
    ) -> Arc<Self> {
        let workers = cfg.workers;
        let scheduler = FairScheduler::new(workers);
        let budget = ByteBudget::new(cfg.max_inflight_mb * 1024 * 1024);

        Arc::new(Self {
            cfg,
            engine,
            scheduler,
            budget,
            events,
            cache: Mutex::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicI64::new(0),
            total_connections: AtomicI64::new(0),
            total_scanned: AtomicI64::new(0),
            total_threats: AtomicI64::new(0),
            total_errors: AtomicI64::new(0),
            active_connections: AtomicUsize::new(0),
        })
    }

    pub fn router(self: &Arc<Self>, path: &str) -> Router {
        let normalized_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };

        Router::new()
            .route(&normalized_path, get(ws_handler))
            .route(
                "/health",
                get(|| async {
                    axum::Json(serde_json::json!({
                        "status": "ok",
                        "engine": ENGINE_NAME,
                        "protocol": PROTOCOL_VERSION,
                    }))
                }),
            )
            .with_state(Arc::clone(self))
    }

    pub async fn get_clients(&self) -> Vec<ClientInfo> {
        let guard = self.sessions.read().await;
        let mut list = Vec::new();
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
            });
        }
        list.sort_by_key(|c| c.id);
        list
    }

    pub async fn close_all_sessions(&self) {
        let guard = self.sessions.read().await;
        for sess in guard.values() {
            let _ = sess.abort_tx.send(()).await;
        }
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(server): State<Arc<ScanServer>>,
) -> Response {
    let current_conns = server.active_connections.fetch_add(1, Ordering::SeqCst);
    if current_conns >= server.cfg.max_conns {
        server.active_connections.fetch_sub(1, Ordering::SeqCst);
        return (StatusCode::SERVICE_UNAVAILABLE, "server busy").into_response();
    }

    let client_ip = addr.ip().to_string();
    ws.on_upgrade(move |socket| handle_socket(socket, server, client_ip))
}

async fn handle_socket(socket: WebSocket, server: Arc<ScanServer>, client_ip: String) {
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
        in_flight: AtomicUsize::new(0),
        abort_tx,
    });

    {
        let mut guard = server.sessions.write().await;
        guard.insert(session_id, Arc::clone(&session_handle));
    }

    server.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "connect".to_string(),
        session: Some(session_id),
        client: Some(client_ip.clone()),
        verdict: None,
        file: None,
        size: None,
        ms: None,
        threat: None,
        detail: None,
        sha256: None,
        message: None,
    });

    let run_res = tokio::select! {
        res = run_session(socket, Arc::clone(&server), Arc::clone(&session_handle)) => res,
        _ = abort_rx.recv() => Ok(()),
    };

    server.active_connections.fetch_sub(1, Ordering::SeqCst);
    {
        let mut guard = server.sessions.write().await;
        guard.remove(&session_id);
    }

    let scanned_count = session_handle.scanned.load(Ordering::Relaxed);
    let mut disconnect_msg = format!("{} file(s) scanned", scanned_count);
    if let Err(e) = run_res {
        disconnect_msg.push_str(&format!(", {}", e));
    }

    server.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "disconnect".to_string(),
        session: Some(session_id),
        client: Some(client_ip),
        verdict: None,
        file: None,
        size: None,
        ms: None,
        threat: None,
        detail: None,
        sha256: None,
        message: Some(disconnect_msg),
    });
}

async fn run_session(
    socket: WebSocket,
    server: Arc<ScanServer>,
    session: Arc<SessionHandle>,
) -> Result<(), String> {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Message>(server.cfg.pipeline * 2);

    // Dedicated writer task
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = outgoing_rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // 1. Handshake: wait for `hello`
    let hello_msg = match tokio::time::timeout(Duration::from_secs(30), ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str::<ClientMessage>(&t)
            .map_err(|e| format!("invalid hello JSON: {}", e))?,
        _ => return Err("handshake timeout or invalid initial message".to_string()),
    };

    if hello_msg.r#type != "hello" {
        send_error_msg(&outgoing_tx, None, "expected hello").await;
        return Err(format!("unexpected first message: {}", hello_msg.r#type));
    }

    if hello_msg.version != PROTOCOL_VERSION {
        let err = format!(
            "unsupported protocol version {} (server speaks {}), please update Multron Win Cleaner",
            hello_msg.version, PROTOCOL_VERSION
        );
        send_error_msg(&outgoing_tx, None, &err).await;
        return Err(err);
    }

    *session.app.write().await = hello_msg.client;

    let hello_ok = serde_json::json!({
        "type": "hello_ok",
        "version": PROTOCOL_VERSION,
        "engine": ENGINE_NAME,
        "pipeline": server.cfg.pipeline,
    });
    let _ = outgoing_tx
        .send(Message::Text(serde_json::to_string(&hello_ok).unwrap()))
        .await;

    // Pipeline slots semaphore
    let slots = Arc::new(Semaphore::new(server.cfg.pipeline));

    // 2. Main Scan Loop
    loop {
        let next_msg = match tokio::time::timeout(Duration::from_secs(1800), ws_rx.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str::<ClientMessage>(&t)
                .map_err(|e| format!("invalid JSON message: {}", e))?,
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
            Ok(Some(Ok(Message::Ping(_)))) => continue,
            _ => break,
        };

        if next_msg.r#type != "scan" {
            send_error_msg(&outgoing_tx, None, "expected scan").await;
            return Err(format!("unexpected message: {}", next_msg.r#type));
        }

        if next_msg.id <= 0 {
            send_error_msg(&outgoing_tx, None, "scan request without id").await;
            return Err("scan request without id".to_string());
        }

        let sha = next_msg.sha256.trim().to_uppercase();
        if sha.len() != 64 || hex::decode(&sha).is_err() {
            send_error_msg(&outgoing_tx, Some(next_msg.id), "invalid sha256").await;
            continue;
        }

        let max_bytes = server.cfg.max_mb * 1024 * 1024;
        if next_msg.size < 0 || next_msg.size > max_bytes {
            let reason = format!("file too large (limit {} MB)", server.cfg.max_mb);
            server.events.add(Event {
                seq: 0,
                time: Utc::now(),
                kind: "rejected".to_string(),
                session: Some(session.id),
                client: Some(session.address.clone()),
                verdict: None,
                file: Some(next_msg.name.clone()),
                size: Some(next_msg.size),
                ms: None,
                threat: None,
                detail: None,
                sha256: Some(sha.clone()),
                message: Some(reason.clone()),
            });
            send_error_msg(&outgoing_tx, Some(next_msg.id), &reason).await;
            continue;
        }

        // Cache Check
        if server.cfg.cache {
            let cache_guard = server.cache.lock().await;
            if let Some(cached) = cache_guard.get(&sha) {
                let mut res = cached.clone();
                res.id = next_msg.id;
                record_result(&server, &session, &res, &next_msg.name, next_msg.size, "cached");
                let _ = outgoing_tx
                    .send(Message::Text(serde_json::to_string(&res).unwrap()))
                    .await;
                continue;
            }
        }

        // Acquire slot & budget
        let slot_permit = slots.clone().acquire_owned().await.map_err(|e| e.to_string())?;
        server.budget.acquire(next_msg.size).await;
        session.in_flight.fetch_add(1, Ordering::SeqCst);

        // Tell client to send file bytes
        let send_file_msg = serde_json::json!({
            "type": "send_file",
            "id": next_msg.id,
        });
        if outgoing_tx
            .send(Message::Text(serde_json::to_string(&send_file_msg).unwrap()))
            .await
            .is_err()
        {
            server.budget.release(next_msg.size).await;
            session.in_flight.fetch_sub(1, Ordering::SeqCst);
            break;
        }

        // Receive binary upload
        let mut upload_data = Vec::with_capacity(next_msg.size as usize);
        let mut upload_err = None;

        while (upload_data.len() as i64) < next_msg.size {
            match tokio::time::timeout(Duration::from_secs(120), ws_rx.next()).await {
                Ok(Some(Ok(Message::Binary(bin)))) => {
                    upload_data.extend_from_slice(&bin);
                }
                Ok(Some(Ok(Message::Ping(_)))) => continue,
                _ => {
                    upload_err = Some("upload timeout or connection dropped");
                    break;
                }
            }
        }

        if let Some(err) = upload_err {
            server.budget.release(next_msg.size).await;
            session.in_flight.fetch_sub(1, Ordering::SeqCst);
            return Err(err.to_string());
        }

        // Verify SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&upload_data);
        let calculated_sha: String = hasher.finalize().encode_hex_upper();

        if calculated_sha != sha {
            server.budget.release(next_msg.size).await;
            session.in_flight.fetch_sub(1, Ordering::SeqCst);
            let reason = "sha256 of the uploaded bytes does not match".to_string();
            server.events.add(Event {
                seq: 0,
                time: Utc::now(),
                kind: "rejected".to_string(),
                session: Some(session.id),
                client: Some(session.address.clone()),
                verdict: None,
                file: Some(next_msg.name.clone()),
                size: Some(next_msg.size),
                ms: None,
                threat: None,
                detail: None,
                sha256: Some(sha),
                message: Some(reason.clone()),
            });
            send_error_msg(&outgoing_tx, Some(next_msg.id), &reason).await;
            continue;
        }

        // Submit to FairScheduler
        let srv = Arc::clone(&server);
        let sess = Arc::clone(&session);
        let out_tx = outgoing_tx.clone();
        let file_size = next_msg.size;
        let file_id = next_msg.id;
        let file_name = next_msg.name.clone();

        server
            .scheduler
            .submit(
                session.id,
                Box::new(move || {
                    let rt = tokio::runtime::Handle::current();
                    rt.block_on(async move {
                        let scan_res = srv.engine.scan(&upload_data, &file_name, &sha).await;
                        srv.budget.release(file_size).await;
                        sess.in_flight.fetch_sub(1, Ordering::SeqCst);
                        drop(slot_permit);

                        match scan_res {
                            Ok(mut res) => {
                                res.id = file_id;
                                record_result(&srv, &sess, &res, &file_name, file_size, "");
                                if srv.cfg.cache {
                                    srv.cache.lock().await.insert(sha, res.clone());
                                }
                                let _ = out_tx
                                    .send(Message::Text(serde_json::to_string(&res).unwrap()))
                                    .await;
                            }
                            Err(e) => {
                                sess.scanned.fetch_add(1, Ordering::Relaxed);
                                srv.total_scanned.fetch_add(1, Ordering::Relaxed);
                                srv.total_errors.fetch_add(1, Ordering::Relaxed);
                                srv.events.add(Event {
                                    seq: 0,
                                    time: Utc::now(),
                                    kind: "error".to_string(),
                                    session: Some(sess.id),
                                    client: Some(sess.address.clone()),
                                    verdict: None,
                                    file: Some(file_name),
                                    size: Some(file_size),
                                    ms: None,
                                    threat: None,
                                    detail: None,
                                    sha256: Some(sha),
                                    message: Some(e.clone()),
                                });
                                send_error_msg(&out_tx, Some(file_id), &format!("scan failed: {}", e)).await;
                            }
                        }
                    });
                }),
            )
            .await;
    }

    drop(outgoing_tx);
    let _ = writer_task.await;
    Ok(())
}

fn record_result(
    server: &ScanServer,
    session: &SessionHandle,
    res: &ResultMessage,
    file_name: &str,
    size: i64,
    note: &str,
) {
    session.scanned.fetch_add(1, Ordering::Relaxed);
    server.total_scanned.fetch_add(1, Ordering::Relaxed);

    if res.verdict == "malicious" || res.verdict == "suspicious" {
        session.threats.fetch_add(1, Ordering::Relaxed);
        server.total_threats.fetch_add(1, Ordering::Relaxed);
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
        message: if note.is_empty() {
            None
        } else {
            Some(note.to_string())
        },
    });
}

async fn send_error_msg(tx: &mpsc::Sender<Message>, id: Option<i64>, msg: &str) {
    let err = ErrorMessage {
        r#type: "error".to_string(),
        id,
        message: msg.to_string(),
    };
    let _ = tx
        .send(Message::Text(serde_json::to_string(&err).unwrap()))
        .await;
}
