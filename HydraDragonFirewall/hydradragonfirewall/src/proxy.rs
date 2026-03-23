use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use http_mitm_proxy::{DefaultClient, MitmProxy, hyper::service::service_fn, moka::sync::Cache};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::oneshot;

use crate::engine::{emit_log_event, FirewallSettings, LogEntry, LogLevel, PacketInfo, Protocol};
use crate::sdk::{PacketContext, RuleAction, SdkRegistry};

// ── Rich HTTP event emitted by the MITM proxy ─────────────────────────────────

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

/// Helper: build the CA `CertificateParams` with a fixed DN.
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
    if let (Ok(key_der_bytes), Ok(cert_der)) = (
        std::fs::read(&key_path),
        std::fs::read(&cert_path),
    ) {
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

/// Start the embedded MITM proxy on `addr`, drive it until `stop_rx` fires.
///
/// Every intercepted HTTP/HTTPS flow emits a `"log"` Tauri event so the UI
/// shows intercept activity attributed to the originating application.
pub async fn run_proxy(
    addr: SocketAddr,
    ca: rcgen::Issuer<'static, KeyPair>,
    app_handle: AppHandle,
    sdk: Arc<RwLock<SdkRegistry>>,
    _settings: Arc<RwLock<FirewallSettings>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let proxy = MitmProxy::new(
        Some(ca),
        // Per-host cert cache — avoids regenerating certs on every connection.
        Some(Cache::new(512)),
    );

    let client = DefaultClient::new();
    let app_handle_cloned = app_handle.clone(); // Clone app_handle before the service_fn closure

    let bind_result = proxy
        .bind(
            addr,
            service_fn(move |req: http_mitm_proxy::hyper::Request<http_mitm_proxy::hyper::body::Incoming>| {
                let client = client.clone();
                let app = app_handle_cloned.clone();
                let sdk = sdk.clone();

                async move {
                    // ── Capture request metadata before consuming ──────────
                    let method = req.method().to_string();
                    let uri = req.uri().clone();
                    let host = uri.host().unwrap_or("unknown").to_string();
                    let port = uri.port_u16().unwrap_or(443);
                    let path = uri.path().to_string();
                    let full_url = format!(
                        "{}://{}:{}{}",
                        uri.scheme_str().unwrap_or("https"),
                        host,
                        port,
                        path
                    );

                    // Collect request headers into a HashMap for the event.
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

                    // ── Collect request body (cap at 64 KB) ───────────────
                    const MAX_BODY: usize = 64 * 1024;
                    let (parts, body) = req.into_parts();
                    let raw_body: Bytes = body
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    let body_truncated = raw_body.len() > MAX_BODY;
                    let body_bytes = if body_truncated {
                        raw_body.slice(..MAX_BODY)
                    } else {
                        raw_body
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
                    // Reconstruct request with collected body so it can be forwarded.
                    let req = http_mitm_proxy::hyper::Request::from_parts(
                        parts,
                        Full::new(body_bytes),
                    );

                    // ── SDK Rule Evaluation ────────────────────────────────
                    // We mock a PacketInfo to evaluate against HTTP-specific SDK rules.
                    let mock_packet = PacketInfo {
                        timestamp: now_ts(),
                        protocol: Protocol::TCP,
                        src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        src_port: 0,
                        dst_port: port,
                        size: 0,
                        outbound: true,
                        process_id: 0, // In proxy context, we don't know the PID here
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
                        image_path: String::new(),
                        detected_file_type: None,
                        http_request_body: request_body.clone(),
                        http_response_body: None, // filled after response is received
                    };

                    let mock_context = PacketContext {
                        process_id: 0,
                        process_name: "hydradragonfirewall_proxy".to_string(),
                        process_path: String::new(),
                    };

                    // ── SDK Rule Evaluation (request) ─────────────────────
                    let (blocked, block_reason, req_body_override) = {
                        let sdk_guard = sdk.read().unwrap();
                        let first_match = sdk_guard.evaluate_first_match(&mock_packet, &[], false);
                        let mut b = false;
                        let mut reason = String::new();
                        let mut override_body: Option<String> = None;

                        if let Some(finding) = first_match {
                            match finding.action {
                                RuleAction::Block => {
                                    b = true;
                                    reason = format!("Blocked by SDK Rule [{}]: {}", finding.rule_name, finding.description);
                                }
                                RuleAction::ChangeRequestBody => {
                                    if let Some(new_body) = finding.change_request_body {
                                        override_body = Some(new_body);
                                    }
                                }
                                _ => {}
                            }
                        }
                        (b, reason, override_body)
                    };

                    // Apply request body override before forwarding.
                    let (req, request_body) = if let Some(new_body) = req_body_override {
                        let new_bytes = Bytes::from(new_body.clone().into_bytes());
                        let (req_parts, _) = req.into_parts();
                        let new_req = http_mitm_proxy::hyper::Request::from_parts(
                            req_parts,
                            Full::new(new_bytes),
                        );
                        (new_req, Some(new_body))
                    } else {
                        (req, request_body)
                    };

                    let ts = now_ts();

                    if blocked {
                        let ts = now_ts();
                        
                        // Increment global stats if the engine is available
                        if let Some(engine) = app.try_state::<Arc<crate::engine::FirewallEngine>>() {
                            engine.stats.packets_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            engine.stats.packets_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }

                        // Emit log for the console/log view
                        emit_log_event(
                            &app,
                            LogEntry {
                                id: format!("{}-intercept-block-{}-{}", ts, host, port),
                                timestamp: ts,
                                level: LogLevel::Warning,
                                message: format!("Proxy Intercept Blocked: HTTP {} {} -> {}", method, full_url, block_reason),
                            },
                        );

                        // Emit raw_packet for the Blocked list and traffic view
                        let raw_packet = crate::sdk::RawPacket::from_parts(
                            format!("{}-proxy-block", ts),
                            &[], // No decrypted payload passed here yet
                            &mock_packet,
                            &mock_context,
                            "Block",
                            block_reason.clone(),
                        );
                        let _ = app.emit("raw_packet", raw_packet);

                        // We drop the connection by returning an IO error, which is supported by http_mitm_proxy.
                        return Err(http_mitm_proxy::default_client::Error::IoError(
                            std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                block_reason, // Use the block_reason string from the evaluation loop
                            )
                        ));
                    }

                    // ── Forward to upstream ────────────────────────────────
                    let (res, _upgrade): (
                        http_mitm_proxy::hyper::Response<http_mitm_proxy::hyper::body::Incoming>,
                        _,
                    ) = client.send_request(req).await?;

                    // ── Capture response metadata ─────────────────────────
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

                    // ── Collect response body (cap at 64 KB) ──────────────
                    let (res_parts, res_body) = res.into_parts();
                    let raw_res_body: Bytes = res_body
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    let res_body_truncated = raw_res_body.len() > MAX_BODY;
                    let res_body_bytes = if res_body_truncated {
                        raw_res_body.slice(..MAX_BODY)
                    } else {
                        raw_res_body
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
                    // Reconstruct the response so it can be forwarded.
                    let res = http_mitm_proxy::hyper::Response::from_parts(
                        res_parts,
                        Full::new(res_body_bytes),
                    );

                    // ── SDK Rule Evaluation (response body) ───────────────
                    // Re-evaluate rules now that we have the response body.
                    let (resp_blocked, resp_block_reason, resp_body_override, res) =
                    if response_body.is_some() {
                        let mut resp_packet = mock_packet.clone();
                        resp_packet.http_response_body = response_body.clone();
                        let sdk_guard = sdk.read().unwrap();
                        let first_match = sdk_guard.evaluate_first_match(&resp_packet, &[], false);
                        let mut b = false;
                        let mut reason = String::new();
                        let mut override_body: Option<String> = None;
                        if let Some(finding) = first_match {
                            match finding.action {
                                RuleAction::Block => {
                                    b = true;
                                    reason = format!("Blocked by SDK Rule [{}]: {}", finding.rule_name, finding.description);
                                }
                                RuleAction::ChangeResponseBody => {
                                    if let Some(new_body) = finding.change_response_body {
                                        override_body = Some(new_body);
                                    }
                                }
                                _ => {}
                            }
                        }
                        (b, reason, override_body, res)
                    } else {
                        (false, String::new(), None, res)
                    };

                    // Apply response body override.
                    let (res, response_body) = if let Some(new_body) = resp_body_override {
                        let new_bytes = Bytes::from(new_body.clone().into_bytes());
                        let (r_parts, _) = res.into_parts();
                        let new_res = http_mitm_proxy::hyper::Response::from_parts(
                            r_parts,
                            Full::new(new_bytes),
                        );
                        (new_res, Some(new_body))
                    } else {
                        (res, response_body)
                    };

                    if resp_blocked {
                        if let Some(engine) = app.try_state::<Arc<crate::engine::FirewallEngine>>() {
                            engine.stats.packets_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            engine.stats.packets_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        emit_log_event(
                            &app,
                            LogEntry {
                                id: format!("{}-intercept-resp-block-{}-{}", ts, host, port),
                                timestamp: ts,
                                level: LogLevel::Warning,
                                message: format!("Proxy Response Blocked: HTTP {} {} -> {}", method, full_url, resp_block_reason),
                            },
                        );
                        let mut resp_packet = mock_packet.clone();
                        resp_packet.http_response_body = response_body.clone();
                        let raw_packet = crate::sdk::RawPacket::from_parts(
                            format!("{}-proxy-resp-block", ts),
                            &[],
                            &resp_packet,
                            &mock_context,
                            "Block",
                            resp_block_reason.clone(),
                        );
                        let _ = app.emit("raw_packet", raw_packet);
                        return Err(http_mitm_proxy::default_client::Error::IoError(
                            std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                resp_block_reason,
                            )
                        ));
                    }

                    // ── Emit events ───────────────────────────────────────
                    // 1. Legacy one-line log (keeps existing UI working)
                    emit_log_event(
                        &app,
                        LogEntry {
                            id: format!("{}-intercept-{}-{}", ts, host, port),
                            timestamp: ts,
                            level: LogLevel::Info,
                            message: format!(
                                "Proxy Intercept: {} {}:{}{} → {} | UA={} | CT={}",
                                method,
                                host,
                                port,
                                path,
                                status,
                                user_agent.as_deref().unwrap_or("-"),
                                response_content_type.as_deref().unwrap_or("-"),
                            ),
                        },
                    );

                    // ── Send HTTP_BODY to Owlyshield behavior engine ──────
                    // Only send if there is at least one body so we don't flood the pipe.
                    if request_body.is_some() || response_body.is_some() {
                        if let Some(engine) = app.try_state::<Arc<crate::engine::FirewallEngine>>() {
                            let req_b = request_body.as_deref().unwrap_or("").replace('|', " ");
                            let resp_b = response_body.as_deref().unwrap_or("").replace('|', " ");
                            // HTTP_BODY:<pid>|<method>|<url>|<request_body>|<response_body>
                            // PID is 0 in proxy context — behavior engine maps by PID,
                            // bodies contribute when the process is identified later.
                            let msg = format!(
                                "HTTP_BODY:0|{}|{}|{}|{}\n",
                                method.replace('|', " "),
                                full_url.replace('|', " "),
                                req_b,
                                resp_b,
                            );
                            engine.send_hydranet_message(msg);
                        }
                    }

                    // 2. Rich HTTP event with full headers + body
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

                    Ok::<_, http_mitm_proxy::default_client::Error>(res)
                }
            }),
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
                    message: format!(
                        "Embedded MITM proxy active on {} — system proxy configured",
                        addr
                    ),
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
                    // Clean shutdown via stop() — no log spam needed.
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
                    message: format!(
                        "Embedded proxy failed to bind on {}: {}",
                        addr, e
                    ),
                },
            );
        }
    }
}
