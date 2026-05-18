use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use http_mitm_proxy::hyper::header::{HeaderMap, HeaderValue};
use http_mitm_proxy::{
    DefaultClient, MitmProxy,
    hyper::{
        StatusCode,
        http::{request::Parts as HttpRequestParts, response::Parts as HttpResponseParts},
        service::service_fn,
    },
    moka::sync::Cache,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::oneshot;

use crate::engine::{FirewallSettings, LogEntry, LogLevel, PacketInfo, Protocol, emit_log_event};
use crate::sdk::{PacketContext, RuleAction, SdkRegistry};

// ── Rich HTTP event emitted by the Transparent TLS Proxy ───────────────────

/// Full HTTP-level detail for every intercepted request/response.
/// Emitted as a `"proxy_http"` Tauri event so the UI can show decrypted traffic.
#[derive(Clone, Debug, Serialize)]
pub struct ProxyHttpEvent {
    pub id: String,
    pub timestamp: u64,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub full_url: String,
    pub status: u16,
    pub request_headers: HashMap<String, String>,
    pub response_headers: HashMap<String, String>,
    /// Selected well-known request fields for quick display
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub referer: Option<String>,
    /// Response content-type
    pub response_content_type: Option<String>,
    /// Response content-length (if advertised)
    pub response_content_length: Option<String>,
    /// Raw request body — UTF-8 text if decodable, hex otherwise. Capped at 64 KB.
    pub request_body: Option<String>,
    /// True if the request body was truncated to the 64 KB cap.
    pub request_body_truncated: bool,
    /// Raw response body — UTF-8 text if decodable, hex otherwise. Capped at 64 KB.
    pub response_body: Option<String>,
    /// True if the response body was truncated to the 64 KB cap.
    pub response_body_truncated: bool,
}

// ── CA persistence paths ───────────────────────────────────────────────────────

/// Directory-relative filenames used to persist the CA across restarts.
const CA_KEY_FILE: &str = "hydradragon_ca.key.der";
const CA_CERT_FILE: &str = "hydradragon_ca.der";

fn ca_dir() -> PathBuf {
    // Store next to the running executable so the same cert is reused.
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

// ── CA generation ──────────────────────────────────────────────────────────────

/// A self-signed root CA bundle: the `Issuer` for signing child certs, plus the
/// DER-encoded certificate to install into trust stores.
pub struct CaBundle {
    pub issuer: rcgen::Issuer<'static, KeyPair>,
    pub cert_der: Vec<u8>,
}

// ── Generic header rewriting helpers ───────────────────────────────────────────

/// Rewrite any response/request body: **always update Content-Length, clear Transfer-Encoding**.
/// This is the generic fix: all body rewrites go through here.
fn safe_rewrite_headers(headers: &mut HeaderMap, new_body_len: usize) {
    headers.remove(http_mitm_proxy::hyper::header::TRANSFER_ENCODING);
    let content_len = new_body_len.to_string();
    if let Ok(hval) = HeaderValue::from_str(&content_len) {
        headers.insert(http_mitm_proxy::hyper::header::CONTENT_LENGTH, hval);
    }
}

/// Updates the Content-Length header in response parts when body size changes.
fn update_content_length_header(parts: &mut HttpResponseParts, new_body_len: usize) {
    safe_rewrite_headers(&mut parts.headers, new_body_len);
}

/// Updates the Content-Length header in request parts when body size changes.
fn update_request_content_length_header(parts: &mut HttpRequestParts, new_body_len: usize) {
    safe_rewrite_headers(&mut parts.headers, new_body_len);
}

// ── Generic error response builders ────────────────────────────────────────────

/// Build a 502 Bad Gateway response when upstream fails.
fn error_response_502() -> http_mitm_proxy::hyper::Response<Full<Bytes>> {
    let body = Full::new(Bytes::from_static(b"Bad Gateway"));
    http_mitm_proxy::hyper::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(body)
        .unwrap_or_else(|_| {
            http_mitm_proxy::hyper::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::new()))
                .unwrap()
        })
}

/// Validates that the request has a valid URI and method before forwarding.
fn validate_request(
    req: &http_mitm_proxy::hyper::Request<http_mitm_proxy::hyper::body::Incoming>,
) -> Result<(), String> {
    let uri = req.uri();

    // Check that URI has a host
    if uri.host().is_none() {
        return Err("Request missing host in URI".to_string());
    }

    // Check that method is valid
    let method = req.method().as_str();
    if method.is_empty() {
        return Err("Request has empty method".to_string());
    }

    Ok(())
}

// ── Helper: build the CA `CertificateParams` with a fixed DN.
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("HydraDragon Firewall CA".to_string()),
    );
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
}

/// Load a previously persisted CA from disk, or generate a new one and save it.
///
/// By reusing the same CA across restarts the user only needs to install the
/// certificate into the trust store **once**.
pub fn generate_ca() -> CaBundle {
    let dir = ca_dir();
    let key_path = dir.join(CA_KEY_FILE);
    let cert_path = dir.join(CA_CERT_FILE);

    // ── Try to load an existing CA ─────────────────────────────────────────
    if let (Ok(key_der_bytes), Ok(cert_der)) = (std::fs::read(&key_path), std::fs::read(&cert_path))
    {
        if let Ok(key) = KeyPair::try_from(key_der_bytes.as_slice()) {
            let params = ca_params();
            let issuer = rcgen::Issuer::new(params, key);
            return CaBundle { issuer, cert_der };
        }
    }

    // ── Generate a fresh CA ────────────────────────────────────────────────
    let params = ca_params();
    let key = KeyPair::generate().unwrap();
    let cert: Certificate = params.self_signed(&key).unwrap();
    let cert_der = cert.der().to_vec();

    // Serialize the private key to PKCS#8 DER bytes for persistence.
    let key_der_bytes = key.serialize_der();
    let _ = std::fs::write(&key_path, &key_der_bytes);
    let _ = std::fs::write(&cert_path, &cert_der);

    let params = ca_params();
    let issuer = rcgen::Issuer::new(params, key);

    CaBundle { issuer, cert_der }
}

// ── Proxy runner ───────────────────────────────────────────────────────────────

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Start the Transparent TLS Proxy on `addr`, drive it until `stop_rx` fires.
pub async fn run_proxy<R: Runtime>(
    addr: SocketAddr,
    ca: rcgen::Issuer<'static, KeyPair>,
    app_handle: AppHandle<R>,
    sdk: Arc<RwLock<SdkRegistry>>,
    settings: Arc<RwLock<FirewallSettings>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let handshake_timeout = {
        let s = settings.read().unwrap();
        std::time::Duration::from_millis(s.tls_proxy.handshake_timeout_ms)
    };
    let proxy = MitmProxy::new(Some(ca), Some(Cache::new(512)))
        .with_handshake_timeout(handshake_timeout);

    let client = DefaultClient::new();
    let app_handle_cloned = app_handle.clone();

    let bind_result =
        proxy
            .bind_transparent_or_proxy(
                addr,
                service_fn(
                    move |req: http_mitm_proxy::hyper::Request<
                        http_mitm_proxy::hyper::body::Incoming,
                    >| {
                        let client = client.clone();
                        let app = app_handle_cloned.clone();
                        let sdk = sdk.clone();
                        let settings = settings.clone();

                        async move {
                            // Wrap in generic error handler: all errors return 502
                            match handle_proxy_request(client, app.clone(), sdk, settings, req)
                                .await
                            {
                                Ok(res) => Ok::<_, http_mitm_proxy::default_client::Error>(res),
                                Err(e) => {
                                    let ts = now_ts();
                                    emit_log_event(
                                        &app,
                                        LogEntry {
                                            id: format!("{}-proxy-err", ts),
                                            timestamp: ts,
                                            level: LogLevel::Error,
                                            message: format!("Proxy error: {}", e),
                                        },
                                    );
                                    Ok::<_, http_mitm_proxy::default_client::Error>(
                                        error_response_502(),
                                    )
                                }
                            }
                        }
                    },
                ),
            )
            .await;

    match bind_result {
        Ok(server) => {
            let ts = now_ts();
            emit_log_event(
                &app_handle,
                LogEntry {
                    id: format!("{}-proxy-ready", ts),
                    timestamp: ts,
                    level: LogLevel::Success,
                    message: format!("Transparent TLS Proxy active on {}", addr),
                },
            );

            tokio::select! {
                _ = server => {
                    let ts = now_ts();
                    emit_log_event(&app_handle, LogEntry {
                        id: format!("{}-proxy-exit", ts),
                        timestamp: ts,
                        level: LogLevel::Warning,
                        message: "Embedded proxy exited unexpectedly".to_string(),
                    });
                }
                _ = &mut stop_rx => {
                    let ts = now_ts();
                    emit_log_event(&app_handle, LogEntry {
                        id: format!("{}-proxy-shutdown", ts),
                        timestamp: ts,
                        level: LogLevel::Info,
                        message: "Embedded proxy shutting down".to_string(),
                    });
                }
            }
        }
        Err(e) => {
            let ts = now_ts();
            emit_log_event(
                &app_handle,
                LogEntry {
                    id: format!("{}-proxy-bind-err", ts),
                    timestamp: ts,
                    level: LogLevel::Error,
                    message: format!("Proxy bind failed on {}: {}", addr, e),
                },
            );
        }
    }
}

// ── Generic request handler ────────────────────────────────────────────────────

/// All request/response streams go through this single generic handler.
/// Centralizes error handling, timeout management, and protocol safety.
async fn handle_proxy_request<R: Runtime>(
    client: DefaultClient,
    app: AppHandle<R>,
    sdk: Arc<RwLock<SdkRegistry>>,
    settings: Arc<RwLock<FirewallSettings>>,
    req: http_mitm_proxy::hyper::Request<http_mitm_proxy::hyper::body::Incoming>,
) -> Result<http_mitm_proxy::hyper::Response<Full<Bytes>>, String> {
    // ── Validate request ────────────────────────────────────────────────────
    validate_request(&req)?;

    // Determine MAX_BODY and timeouts based on settings
    let (max_body, request_timeout, response_timeout) = {
        let settings_guard = settings.read().unwrap();
        let max = if settings_guard.log_full_bodies {
            usize::MAX
        } else {
            64 * 1024
        };
        let req_t = settings_guard.tls_proxy.request_timeout_secs;
        let res_t = settings_guard.tls_proxy.response_timeout_secs;
        (max, req_t, res_t)
    };

    let method = req.method().to_string();
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("unknown").to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path = format!(
        "{}{}",
        uri.path(),
        uri.query().map(|q| format!("?{}", q)).unwrap_or_default()
    );
    let full_url = format!(
        "{}://{}:{}{}",
        uri.scheme_str().unwrap_or("https"),
        host,
        port,
        path
    );

    let mut request_headers: HashMap<String, String> = HashMap::new();
    for (name, value) in req.headers().iter() {
        request_headers.insert(
            name.to_string(),
            value.to_str().unwrap_or("<binary>").to_string(),
        );
    }
    let user_agent = request_headers.get("user-agent").cloned();
    let content_type = request_headers.get("content-type").cloned();
    let referer = request_headers.get("referer").cloned();

    // ── Collect request body with timeout ───────────────────────────────────
    let (parts, body) = req.into_parts();
    let raw_body: Bytes =
        tokio::time::timeout(std::time::Duration::from_secs(request_timeout), body.collect())
            .await
            .map_err(|_| "Request body timeout".to_string())?
            .map_err(|e| e.to_string())?
            .to_bytes();
    let raw_request_body_len = raw_body.len();

    let body_truncated = raw_body.len() > max_body;
    let body_bytes = if body_truncated {
        raw_body.slice(..max_body)
    } else {
        raw_body.clone()
    };

    let request_body = if body_bytes.is_empty() {
        None
    } else {
        Some(match String::from_utf8(body_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => body_bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" "),
        })
    };

    // Get client's port to lookup PID
    let client_port = parts
        .extensions
        .get::<http_mitm_proxy::RemoteAddr>()
        .map(|r| r.0.port())
        .unwrap_or(0);

    let mut resolved_pid = 0;
    let mut app_name = "hydradragonfirewall_proxy".to_string();
    let mut app_path = String::new();

    if client_port != 0 {
        if let Some(engine) = app.try_state::<Arc<crate::engine::FirewallEngine>>() {
            if let Some(pid) = engine.app_manager.get_pid_for_port(client_port) {
                resolved_pid = pid;
                let info = engine.app_manager.info_cache.get_info(pid);
                app_name = info.name;
                app_path = info.path;
            }
        }
    }

    // ── Create mock packet for SDK evaluation ────────────────────────────────
    let mock_packet = PacketInfo {
        timestamp: now_ts(),
        protocol: Protocol::TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        src_port: client_port,
        dst_port: port,
        size: 0,
        outbound: true,
        process_id: resolved_pid,
        dns_query: None,
        hostname: Some(host.clone()),
        full_url: Some(full_url.clone()),
        tls_handshake: false,
        http_method: Some(method.clone()),
        http_path: Some(path.clone()),
        http_user_agent: user_agent.clone(),
        http_content_type: content_type.clone(),
        http_referer: referer.clone(),
        payload_entropy: None,
        payload_sample: None,
        payload_urls: vec![],
        payload_domains: vec![],
        image_path: app_path.clone(),
        detected_file_type: None,
        http_request_body: request_body.clone(),
        http_response_body: None,
    };

    let _mock_context = PacketContext {
        process_id: resolved_pid,
        process_name: app_name,
        process_path: app_path,
    };

    // ── SDK Rule Evaluation (request) ───────────────────────────────────────
    let (blocked, req_body_override) = {
        let sdk_guard = sdk.read().unwrap();
        let first_match = sdk_guard.evaluate_first_match(&mock_packet, &[], false);
        let mut b = false;
        let mut override_body: Option<String> = None;

        if let Some(finding) = first_match {
            match finding.action {
                RuleAction::Block => {
                    b = true;
                }
                RuleAction::ChangeRequestBody => {
                    if let Some(new_body) = finding.change_request_body {
                        override_body = Some(new_body);
                    }
                }
                _ => {}
            }
        }
        (b, override_body)
    };

    if blocked {
        let ts = now_ts();
        let _ = app.emit(
            "proxy_http",
            ProxyHttpEvent {
                id: format!("{}-http-{}-{}", ts, host, port),
                timestamp: ts,
                method: method.clone(),
                host: host.clone(),
                port,
                path: path.clone(),
                full_url: full_url.clone(),
                status: 403,
                request_headers: request_headers.clone(),
                response_headers: HashMap::new(),
                user_agent: user_agent.clone(),
                content_type: content_type.clone(),
                referer: referer.clone(),
                response_content_type: None,
                response_content_length: None,
                request_body: request_body.clone(),
                request_body_truncated: body_truncated,
                response_body: None,
                response_body_truncated: false,
            },
        );
        return Err("Blocked by SDK rule (request)".to_string());
    }

    // ── Apply request body override + ALWAYS rewrite headers ────────────────
    let mut req_parts = parts;
    let req_body_obj = if let Some(new_body) = req_body_override {
        let new_bytes = Bytes::from(new_body.into_bytes());
        update_request_content_length_header(&mut req_parts, new_bytes.len());
        Full::new(new_bytes)
    } else {
        // Use the FULL original body, not the truncated display version
        update_request_content_length_header(&mut req_parts, raw_body.len());
        Full::new(raw_body)
    };
    let req = http_mitm_proxy::hyper::Request::from_parts(req_parts, req_body_obj);

    // ── Forward upstream ────────────────────────────────────────────────────
    let (res, _) = client
        .send_request(req)
        .await
        .map_err(|e| format!("Upstream failed: {}", e))?;

    // ── Capture response ────────────────────────────────────────────────────
    let status = res.status().as_u16();
    let mut response_headers: HashMap<String, String> = HashMap::new();
    for (name, value) in res.headers().iter() {
        response_headers.insert(
            name.to_string(),
            value.to_str().unwrap_or("<binary>").to_string(),
        );
    }
    let response_content_type = response_headers.get("content-type").cloned();
    let response_content_length = response_headers.get("content-length").cloned();

    // ── Collect response body with timeout ──────────────────────────────────
    let (mut res_parts, res_body) = res.into_parts();
    let raw_res_body: Bytes = tokio::time::timeout(
        std::time::Duration::from_secs(response_timeout),
        res_body.collect(),
    )
    .await
    .map_err(|_| "Response body timeout".to_string())?
    .map_err(|e| e.to_string())?
    .to_bytes();
    let raw_response_body_len = raw_res_body.len();

    let res_body_truncated = raw_res_body.len() > max_body;
    let res_body_bytes = if res_body_truncated {
        raw_res_body.slice(..max_body)
    } else {
        raw_res_body.clone()
    };

    let response_body = if res_body_bytes.is_empty() {
        None
    } else {
        Some(match String::from_utf8(res_body_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => res_body_bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" "),
        })
    };

    // ── SDK Rule Evaluation (response) ──────────────────────────────────────
    let (resp_blocked, resp_body_override) = if response_body.is_some() {
        let mut resp_packet = mock_packet.clone();
        resp_packet.http_response_body = response_body.clone();
        let sdk_guard = sdk.read().unwrap();
        let first_match = sdk_guard.evaluate_first_match(&resp_packet, &[], false);
        let mut b = false;
        let mut override_body: Option<String> = None;

        if let Some(finding) = first_match {
            match finding.action {
                RuleAction::Block => b = true,
                RuleAction::ChangeResponseBody => {
                    if let Some(new_body) = finding.change_response_body {
                        override_body = Some(new_body);
                    }
                }
                _ => {}
            }
        }
        (b, override_body)
    } else {
        (false, None)
    };

    if resp_blocked {
        let ts = now_ts();
        let _ = app.emit(
            "proxy_http",
            ProxyHttpEvent {
                id: format!("{}-http-{}-{}", ts, host, port),
                timestamp: ts,
                method: method.clone(),
                host: host.clone(),
                port,
                path: path.clone(),
                full_url: full_url.clone(),
                status: 403,
                request_headers: request_headers.clone(),
                response_headers: response_headers.clone(),
                user_agent: user_agent.clone(),
                content_type: content_type.clone(),
                referer: referer.clone(),
                response_content_type: response_content_type.clone(),
                response_content_length: response_content_length.clone(),
                request_body: request_body.clone(),
                request_body_truncated: body_truncated,
                response_body: response_body.clone(),
                response_body_truncated: res_body_truncated,
            },
        );
        return Err("Blocked by SDK rule (response)".to_string());
    }

    // ── Apply response body override + ALWAYS rewrite headers ────────────────
    let res_body_obj = if let Some(new_body) = resp_body_override {
        let new_bytes = Bytes::from(new_body.into_bytes());
        update_content_length_header(&mut res_parts, new_bytes.len());
        Full::new(new_bytes)
    } else {
        // Use the FULL original body, not the truncated display version
        update_content_length_header(&mut res_parts, raw_res_body.len());
        Full::new(raw_res_body)
    };

    // ── Emit events ─────────────────────────────────────────────────────────
    let ts = now_ts();
    let show_blocked_http_only = settings.read().unwrap().tls_proxy.show_blocked_only;
    if !show_blocked_http_only {
        emit_log_event(
            &app,
            LogEntry {
                id: format!("{}-intercept-{}-{}", ts, host, port),
                timestamp: ts,
                level: LogLevel::Info,
                message: format!("Proxy: {} {}:{}{} → {}", method, host, port, path, status),
            },
        );
    }

    if let Some(engine) = app.try_state::<Arc<crate::engine::FirewallEngine>>() {
        let mut telemetry_packet = mock_packet.clone();
        telemetry_packet.size = raw_request_body_len + raw_response_body_len;
        telemetry_packet.http_response_body = response_body.clone();
        if let Ok(json) = serde_json::to_string(&telemetry_packet) {
            engine.send_hydranet_message(format!("FULL_PACKET:{}\n", json));
        }

        if request_body.is_some() || response_body.is_some() {
            let req_b = request_body.as_deref().unwrap_or("").replace('|', " ");
            let resp_b = response_body.as_deref().unwrap_or("").replace('|', " ");
            let msg = format!(
                "HTTP_BODY:{}|{}|{}|{}|{}\n",
                resolved_pid,
                method.replace('|', " "),
                full_url.replace('|', " "),
                req_b,
                resp_b
            );
            engine.send_hydranet_message(msg);
        }
    }

    if !show_blocked_http_only {
        let _ = app.emit(
            "proxy_http",
            ProxyHttpEvent {
                id: format!("{}-http-{}-{}", ts, host, port),
                timestamp: ts,
                method,
                host,
                port,
                path,
                full_url,
                status,
                request_headers,
                response_headers,
                user_agent,
                content_type,
                referer,
                response_content_type,
                response_content_length,
                request_body,
                request_body_truncated: body_truncated,
                response_body,
                response_body_truncated: res_body_truncated,
            },
        );
    }

    Ok(http_mitm_proxy::hyper::Response::from_parts(
        res_parts,
        res_body_obj,
    ))
}
