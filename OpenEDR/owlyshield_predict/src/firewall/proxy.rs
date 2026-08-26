use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use http_mitm_proxy::hyper::body::{Body as HttpBody, Frame, SizeHint};
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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::Poll;
use tokio::sync::oneshot;

use super::engine::{FirewallSettings, LogEntry, LogLevel, PacketInfo, Protocol, emit_log_event};
use super::sdk::{PacketContext, RuleAction, SdkRegistry};

// ── CA persistence paths ───────────────────────────────────────────────────────

/// Directory-relative filenames used to persist the CA across restarts.
const CA_KEY_FILE: &str = "hydradragon_ca.key.der";
const CA_CERT_FILE: &str = "hydradragon_ca.der";

fn ca_dir() -> PathBuf {
    // Store under ProgramData so the CA persists across reinstalls/upgrades and
    // is not tied to the (read-mostly, self-protected) Program Files install dir.
    let dir = PathBuf::from(r"C:\ProgramData\edrsvc\ca");
    let _ = std::fs::create_dir_all(&dir);
    dir
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

/// Check if a HTTP status code should NOT have a body (1xx, 204, 304)
fn is_bodiless_status(status: u16) -> bool {
    (status >= 100 && status < 200) || status == 204 || status == 304
}

/// Computes a body-collection timeout that scales with the declared Content-Length.
/// Fixed 30s caps fail large downloads (>64 KB) on slower links, so larger bodies
/// are given proportionally more time while still bounding runaway transfers.
fn adaptive_body_timeout(
    base_secs: u64,
    content_length_header: Option<&str>,
) -> std::time::Duration {
    let base = std::time::Duration::from_secs(base_secs.max(1));
    let Some(len) = content_length_header.and_then(|v| v.trim().parse::<u64>().ok()) else {
        return base;
    };
    // Allow roughly 1 second of extra time per 64 KB of declared payload.
    let extra_secs = len.saturating_div(64 * 1024);
    // Bound the extra time so a bogus/huge Content-Length cannot hang forever.
    let bounded = std::time::Duration::from_secs(extra_secs.min(300));
    base + bounded
}

/// Boxed body error used by the proxy response stream.
type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Boxes a fully-buffered body into the proxy's response body type.
fn boxed_full(body: Bytes) -> BoxBody<Bytes, DynErr> {
    Full::new(body)
        .map_err(|never| -> DynErr { match never {} })
        .boxed()
}

/// Streams a response body: yields the already-buffered head bytes first,
/// then polls the remaining upstream `Incoming` body. This lets large bodies
/// (> `max_body`) pass through without ever being fully buffered in memory.
struct HeadThenStream {
    head: Bytes,
    head_pos: usize,
    rest: Option<http_mitm_proxy::hyper::body::Incoming>,
}

impl HttpBody for HeadThenStream {
    type Data = Bytes;
    type Error = DynErr;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.head_pos < self.head.len() {
            let end = (self.head_pos + 8192).min(self.head.len());
            let chunk = self.head.slice(self.head_pos..end);
            self.head_pos = end;
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        if let Some(rest) = self.rest.as_mut() {
            match Pin::new(rest).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
                Poll::Ready(None) => {
                    self.rest = None;
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn is_end_stream(&self) -> bool {
        self.head_pos >= self.head.len() && self.rest.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

// ── Generic error response builders ────────────────────────────────────────────

/// Build a 502 Bad Gateway response when upstream fails.
fn error_response_502() -> http_mitm_proxy::hyper::Response<BoxBody<Bytes, DynErr>> {
    let body = boxed_full(Bytes::from_static(b"Bad Gateway"));
    http_mitm_proxy::hyper::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(body)
        .unwrap_or_else(|_| {
            http_mitm_proxy::hyper::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(boxed_full(Bytes::new()))
                .unwrap()
        })
}

/// Validates that the request has a valid URI and method before forwarding.
fn validate_request(
    req: &http_mitm_proxy::hyper::Request<http_mitm_proxy::hyper::body::Incoming>,
) -> Result<(), String> {
    let uri = req.uri();

    // Check that URI has a host, or the request has a Host header
    if uri.host().is_none()
        && !req
            .headers()
            .contains_key(http_mitm_proxy::hyper::header::HOST)
    {
        return Err("Request missing host in URI and missing Host header".to_string());
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
///
/// Returns an error (rather than panicking) if the persisted CA is unusable and
/// a fresh key/certificate cannot be produced, so callers such as the installer
/// can abort setup instead of crashing across the FFI boundary.
pub fn generate_ca() -> Result<CaBundle, String> {
    let dir = ca_dir();
    let key_path = dir.join(CA_KEY_FILE);
    let cert_path = dir.join(CA_CERT_FILE);

    // ── Try to load an existing CA ─────────────────────────────────────────
    if let (Ok(key_der_bytes), Ok(cert_der)) = (std::fs::read(&key_path), std::fs::read(&cert_path))
    {
        if let Ok(key) = KeyPair::try_from(key_der_bytes.as_slice()) {
            let params = ca_params();
            let issuer = rcgen::Issuer::new(params, key);
            return Ok(CaBundle { issuer, cert_der });
        }
    }

    // ── Generate a fresh CA ────────────────────────────────────────────────
    let params = ca_params();
    let key = KeyPair::generate().map_err(|e| format!("failed to generate CA key: {e}"))?;
    let cert: Certificate = params
        .self_signed(&key)
        .map_err(|e| format!("failed to self-sign CA certificate: {e}"))?;
    let cert_der = cert.der().to_vec();

    // Serialize the private key to PKCS#8 DER bytes for persistence.
    let key_der_bytes = key.serialize_der();
    let _ = std::fs::write(&key_path, &key_der_bytes);
    let _ = std::fs::write(&cert_path, &cert_der);

    let params = ca_params();
    let issuer = rcgen::Issuer::new(params, key);

    Ok(CaBundle { issuer, cert_der })
}

// ── Proxy runner ───────────────────────────────────────────────────────────────

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Start the Transparent TLS Proxy on `addr`, drive it until `stop_rx` fires.
pub async fn run_proxy(
    addr: SocketAddr,
    ca: rcgen::Issuer<'static, KeyPair>,
    sdk: Arc<RwLock<SdkRegistry>>,
    settings: Arc<RwLock<FirewallSettings>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let handshake_timeout = {
        let s = settings.read().unwrap();
        std::time::Duration::from_millis(s.tls_proxy.handshake_timeout_ms)
    };
    let proxy =
        MitmProxy::new(Some(ca), Some(Cache::new(512))).with_handshake_timeout(handshake_timeout);

    let client = DefaultClient::new();

    let bind_result =
        proxy
            .bind_transparent_or_proxy(
                addr,
                service_fn(
                    move |req: http_mitm_proxy::hyper::Request<
                        http_mitm_proxy::hyper::body::Incoming,
                    >| {
                        let client = client.clone();
                        let sdk = sdk.clone();
                        let settings = settings.clone();

                        async move {
                            // Wrap in generic error handler: all errors return 502
                            match handle_proxy_request(client, sdk, settings, req).await {
                                Ok(res) => Ok::<_, http_mitm_proxy::default_client::Error>(res),
                                Err(e) => {
                                    let ts = now_ts();
                                    emit_log_event(LogEntry {
                                        id: format!("{}-proxy-err", ts),
                                        timestamp: ts,
                                        level: LogLevel::Error,
                                        message: format!("Proxy error: {}", e),
                                    });
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
            emit_log_event(LogEntry {
                id: format!("{}-proxy-ready", ts),
                timestamp: ts,
                level: LogLevel::Success,
                message: format!("Transparent TLS Proxy active on {}", addr),
            });

            tokio::select! {
                _ = server => {
                    let ts = now_ts();
                    emit_log_event(LogEntry {
                        id: format!("{}-proxy-exit", ts),
                        timestamp: ts,
                        level: LogLevel::Warning,
                        message: "Embedded proxy exited unexpectedly".to_string(),
                    });
                }
                _ = &mut stop_rx => {
                    let ts = now_ts();
                    emit_log_event(LogEntry {
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
            emit_log_event(LogEntry {
                id: format!("{}-proxy-bind-err", ts),
                timestamp: ts,
                level: LogLevel::Error,
                message: format!("Proxy bind failed on {}: {}", addr, e),
            });
        }
    }
}

// ── Host:port parsing helper ───────────────────────────────────────────────────

/// Extract an explicit port from a host string, handling bracketed IPv6 correctly.
/// Returns `None` when no explicit port is present (caller should fall back to scheme default).
fn extract_port_from_host(host: &str) -> Option<u16> {
    // Handle bracketed IPv6 `[::1]:443`
    if host.starts_with('[') {
        if let Some(idx) = host.rfind("]:") {
            return host[idx + 2..].parse().ok();
        }
        return None;
    }

    // Non-bracketed host: allow at most one `:` separating host and port
    if let Some(idx) = host.rfind(':') {
        let (host_part, port_part_with_colon) = host.split_at(idx);
        // If the host part itself contains another `:`, this is likely bare IPv6;
        // treat it as "no port".
        if host_part.contains(':') {
            return None;
        }
        let port_str = &port_part_with_colon[1..];
        if port_str.is_empty() {
            return None;
        }
        return port_str.parse().ok();
    }

    None
}

// ── Generic request handler ────────────────────────────────────────────────────

/// All request/response streams go through this single generic handler.
/// Centralizes error handling, timeout management, and protocol safety.
async fn handle_proxy_request(
    client: DefaultClient,
    sdk: Arc<RwLock<SdkRegistry>>,
    settings: Arc<RwLock<FirewallSettings>>,
    req: http_mitm_proxy::hyper::Request<http_mitm_proxy::hyper::body::Incoming>,
) -> Result<http_mitm_proxy::hyper::Response<BoxBody<Bytes, DynErr>>, String> {
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

    let host = if let Some(h) = uri.host() {
        h.to_string()
    } else {
        let host_header = req
            .headers()
            .get(http_mitm_proxy::hyper::header::HOST)
            .ok_or_else(|| "Request missing host in URI and missing Host header".to_string())?;

        let host_str = host_header
            .to_str()
            .map_err(|_| "Malformed Host header (invalid UTF-8)".to_string())?;

        let host_str = host_str.trim();
        if host_str.is_empty() {
            return Err("Empty Host header".to_string());
        }

        host_str.to_string()
    };

    let scheme = uri.scheme_str().unwrap_or("https").to_string();

    let port = uri.port_u16().unwrap_or_else(|| {
        if let Some(p) = extract_port_from_host(&host) {
            p
        } else if scheme == "http" {
            80
        } else {
            443
        }
    });

    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let path = path_and_query.to_string();
    let full_url = format!("{}://{}{}", scheme, host, path);

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
    let req_content_length = request_headers.get("content-length").map(|s| s.as_str());
    let raw_body: Bytes = match tokio::time::timeout(
        adaptive_body_timeout(request_timeout, req_content_length),
        body.collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) => {
            return Err(format!("Request body read failed: {}", e));
        }
        Err(_) => {
            return Err("Request body timeout".to_string());
        }
    };
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
        if let Some(engine) = super::headless::engine() {
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
        ip_proto: 6,
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
        return Err("Blocked by SDK rule (request)".to_string());
    }

    // ── Apply request body override + ALWAYS rewrite headers ────────────────
    let mut req_parts = parts;

    // Rewrite URI to be absolute for hyper client
    let absolute_uri_str = format!("{}://{}{}", scheme, host, path);
    if let Ok(new_uri) = http_mitm_proxy::hyper::Uri::try_from(&absolute_uri_str) {
        req_parts.uri = new_uri;
    }

    // Strip Accept-Encoding so the upstream server sends plain text. This allows
    // our proxy to read/modify the body safely without breaking compression.
    req_parts
        .headers
        .remove(http_mitm_proxy::hyper::header::ACCEPT_ENCODING);

    let req_body_obj = if let Some(new_body) = req_body_override {
        let new_bytes = Bytes::from(new_body.into_bytes());
        update_request_content_length_header(&mut req_parts, new_bytes.len());
        Full::new(new_bytes)
    } else {
        // Use the FULL original body, not the truncated display version.
        // Don't inject Content-Length: 0 for bodiless GET/HEAD requests, as it can cause 400 Bad Request.
        if raw_body.len() > 0
            || req_parts.method != http_mitm_proxy::hyper::Method::GET
                && req_parts.method != http_mitm_proxy::hyper::Method::HEAD
        {
            update_request_content_length_header(&mut req_parts, raw_body.len());
        } else {
            req_parts
                .headers
                .remove(http_mitm_proxy::hyper::header::TRANSFER_ENCODING);
        }
        Full::new(raw_body)
    };
    let req = http_mitm_proxy::hyper::Request::from_parts(req_parts, req_body_obj);

    // ── Forward upstream ────────────────────────────────────────────────────
    let (res, _) = match client.send_request(req).await {
        Ok(response) => response,
        Err(e) => {
            return Err(format!("Upstream failed: {}", e));
        }
    };

    // ── Capture response ────────────────────────────────────────────────────
    let status = res.status().as_u16();
    let mut response_headers: HashMap<String, String> = HashMap::new();
    for (name, value) in res.headers().iter() {
        response_headers.insert(
            name.to_string(),
            value.to_str().unwrap_or("<binary>").to_string(),
        );
    }

    // ── Collect response head + stream the rest ─────────────────────────────
    // Large bodies are never fully buffered: we read only the first `max_body`
    // bytes (head) for SDK inspection/display, then forward head + the remaining
    // upstream stream. This avoids response-body timeouts on big downloads.
    let (mut res_parts, mut res_body) = res.into_parts();
    let res_content_length = response_headers.get("content-length").map(|s| s.as_str());
    let head_timeout = adaptive_body_timeout(response_timeout, res_content_length);

    let mut raw_res_body: Vec<u8> = Vec::with_capacity(max_body.min(64 * 1024));
    let mut body_eof = false;
    let mut head_error: Option<String> = None;
    while raw_res_body.len() < max_body {
        match tokio::time::timeout(head_timeout, res_body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    raw_res_body.extend_from_slice(&data);
                }
            }
            Ok(Some(Err(e))) => {
                head_error = Some(format!("Response body read failed: {}", e));
                break;
            }
            Ok(None) => {
                body_eof = true;
                break;
            }
            Err(_) => {
                head_error = Some("Response body timeout".to_string());
                break;
            }
        }
    }

    if let Some(err) = head_error {
        return Err(err);
    }

    let raw_res_body = Bytes::from(raw_res_body);
    let res_body_truncated = !body_eof || raw_res_body.len() > max_body;
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
        return Err("Blocked by SDK rule (response)".to_string());
    }

    // ── Apply response body override + ALWAYS rewrite headers ────────────────
    let res_body_obj: BoxBody<Bytes, DynErr> = if let Some(new_body) = resp_body_override {
        let new_bytes = Bytes::from(new_body.into_bytes());
        res_parts
            .headers
            .remove(http_mitm_proxy::hyper::header::CONTENT_ENCODING);
        if !is_bodiless_status(status) {
            update_content_length_header(&mut res_parts, new_bytes.len());
        } else {
            res_parts
                .headers
                .remove(http_mitm_proxy::hyper::header::CONTENT_LENGTH);
            res_parts
                .headers
                .remove(http_mitm_proxy::hyper::header::TRANSFER_ENCODING);
        }
        boxed_full(new_bytes)
    } else if !body_eof {
        // Large body: keep the upstream Content-Length (head + remaining stream
        // still total the original body length); remove Transfer-Encoding so hyper
        // recomputes framing for the streamed body.
        res_parts
            .headers
            .remove(http_mitm_proxy::hyper::header::TRANSFER_ENCODING);
        if is_bodiless_status(status) {
            res_parts
                .headers
                .remove(http_mitm_proxy::hyper::header::CONTENT_LENGTH);
        }
        HeadThenStream {
            head: raw_res_body.clone(),
            head_pos: 0,
            rest: Some(res_body),
        }
        .boxed()
    } else {
        // Use the FULL original body, not the truncated display version
        if !is_bodiless_status(status) {
            update_content_length_header(&mut res_parts, raw_res_body.len());
        } else {
            res_parts
                .headers
                .remove(http_mitm_proxy::hyper::header::CONTENT_LENGTH);
            res_parts
                .headers
                .remove(http_mitm_proxy::hyper::header::TRANSFER_ENCODING);
        }
        boxed_full(raw_res_body)
    };

    // ── Emit activity log ────────────────────────────────────────────────────
    let ts = now_ts();
    let show_blocked_http_only = settings.read().unwrap().show_blocked_http_inspector_only;
    if !show_blocked_http_only {
        emit_log_event(LogEntry {
            id: format!("{}-intercept-{}-{}", ts, host, port),
            timestamp: ts,
            level: LogLevel::Info,
            message: format!("Proxy: {} {}:{}{} → {}", method, host, port, path, status),
        });
    }

    Ok(http_mitm_proxy::hyper::Response::from_parts(
        res_parts,
        res_body_obj,
    ))
}
