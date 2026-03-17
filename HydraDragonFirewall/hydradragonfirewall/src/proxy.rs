use http_mitm_proxy::{DefaultClient, MitmProxy, hyper::service::service_fn, moka::sync::Cache};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::net::SocketAddr;
use tauri::{AppHandle, Emitter};
use tokio::sync::oneshot;

use crate::engine::{LogEntry, LogLevel};

// ── CA generation ──────────────────────────────────────────────────────────────

/// A self-signed root CA bundle: the `Issuer` for signing child certs, plus the
/// DER-encoded certificate to install into trust stores.
pub struct CaBundle {
    pub issuer: rcgen::Issuer<'static, KeyPair>,
    pub cert_der: Vec<u8>,
}

/// Generate a self-signed root CA used by the embedded proxy to impersonate
/// upstream TLS certificates.
pub fn generate_ca() -> CaBundle {
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("HydraDragon Firewall CA".to_string()),
    );
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let key = KeyPair::generate().unwrap();
    let cert: Certificate = params.self_signed(&key).unwrap();
    let cert_der = cert.der().to_vec();

    // Issuer::new consumes `params` — the self-signed cert has already been
    // generated above so its DER bytes are captured separately.
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
    mut stop_rx: oneshot::Receiver<()>,
) {
    let proxy = MitmProxy::new(
        Some(ca),
        // Per-host cert cache — avoids regenerating certs on every connection.
        Some(Cache::new(512)),
    );

    let client = DefaultClient::new();

    let app = app_handle.clone();

    let bind_result = proxy
        .bind(
            addr,
            service_fn(move |req: http_mitm_proxy::hyper::Request<http_mitm_proxy::hyper::body::Incoming>| {
                let client = client.clone();
                let app = app.clone();
                async move {
                    // Capture what we can before consuming the request.
                    let method = req.method().to_string();
                    let host = req
                        .uri()
                        .host()
                        .unwrap_or("unknown")
                        .to_string();
                    let port = req.uri().port_u16().unwrap_or(443);
                    let path = req.uri().path().to_string();

                    let (res, _upgrade): (
                        http_mitm_proxy::hyper::Response<http_mitm_proxy::hyper::body::Incoming>,
                        _,
                    ) = client.send_request(req).await?;

                    let ts = now_ts();
                    let _ = app.emit(
                        "log",
                        LogEntry {
                            id: format!("{}-intercept-{}-{}", ts, host, port),
                            timestamp: ts,
                            level: LogLevel::Info,
                            message: format!(
                                "Proxy Intercept: {} {}:{}{} → {}",
                                method,
                                host,
                                port,
                                path,
                                res.status().as_u16()
                            ),
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
            let _ = app_handle.emit(
                "log",
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
                    let _ = app_handle.emit("log", LogEntry {
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
            let _ = app_handle.emit(
                "log",
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
