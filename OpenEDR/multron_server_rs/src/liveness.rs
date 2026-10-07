//! PyFunceble-style Asynchronous Liveness Checker for URLs & Domains.
//! Evaluates whether a domain is alive (resolves via DNS) or inactive/dead (NXDOMAIN).

use std::net::IpAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use url::Url;

/// Liveness result codes matching OpenEDR URL Threat Engine convention:
/// - 0 = Unknown (timeout or ambiguous resolution)
/// - 1 = Active (domain resolves to one or more valid IP addresses)
/// - 2 = Inactive / Dead (NXDOMAIN or DNS host resolution failure)
pub const LIVENESS_UNKNOWN: i32 = 0;
pub const LIVENESS_ACTIVE: i32 = 1;
pub const LIVENESS_INACTIVE: i32 = 2;

/// Inspects host liveness asynchronously.
///
/// If target is an IP, verifies its format.
/// If target is a domain name, resolves A/AAAA records via async DNS with a 1.5s timeout.
pub async fn check_liveness(raw_url: &str) -> (i32, String) {
    let parsed = Url::parse(raw_url).or_else(|_| Url::parse(&format!("https://{}", raw_url)));

    let (host, port) = match parsed {
        Ok(u) => {
            let h = u.host_str().unwrap_or("").trim().to_lowercase();
            let p = u.port().unwrap_or(if u.scheme() == "https" { 443 } else { 80 });
            (h, p)
        }
        Err(_) => {
            let h = raw_url
                .split('/')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            (h, 80)
        }
    };

    let clean_host = host
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(&host)
        .to_string();

    if clean_host.is_empty() {
        return (LIVENESS_UNKNOWN, "UNKNOWN".to_string());
    }

    // Direct IP Address check
    if clean_host.parse::<IpAddr>().is_ok() {
        return (LIVENESS_ACTIVE, "ACTIVE".to_string());
    }

    // Domain DNS lookup with timeout (PyFunceble emulation)
    let addr_str = format!("{}:{}", clean_host, port);
    let resolution_timeout = Duration::from_millis(1500);

    match tokio::time::timeout(resolution_timeout, lookup_host(&addr_str)).await {
        Ok(Ok(mut addrs)) => {
            if addrs.next().is_some() {
                (LIVENESS_ACTIVE, "ACTIVE".to_string())
            } else {
                (LIVENESS_INACTIVE, "INACTIVE".to_string())
            }
        }
        Ok(Err(err)) => {
            // DNS resolution failure (NXDOMAIN / Host not found)
            tracing::debug!(
                host = %clean_host,
                error = %err,
                "Liveness check: host resolution failed (NXDOMAIN / inactive)"
            );
            (LIVENESS_INACTIVE, "INACTIVE".to_string())
        }
        Err(_) => {
            // Timeout - consider status ambiguous
            tracing::debug!(
                host = %clean_host,
                "Liveness check: DNS resolution timed out"
            );
            (LIVENESS_UNKNOWN, "UNKNOWN".to_string())
        }
    }
}

/// Attempts to safely fetch page content over HTTP (512 KiB cap, 2s timeout)
/// for deep HTML, script ML and YARA-X threat analysis.
pub async fn fetch_page_content_safe(raw_url: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let parsed = Url::parse(raw_url).or_else(|_| Url::parse(&format!("https://{}", raw_url))).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }

    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(80);
    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{}", parsed.path(), q),
        None => parsed.path().to_string(),
    };
    let path = if path_and_query.is_empty() { "/" } else { &path_and_query };

    let addr = format!("{}:{}", host, port);
    let mut stream = tokio::time::timeout(
        Duration::from_millis(2000),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .ok()?
    .ok()?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) VirusKov/1.0\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n",
        path, host
    );

    stream.write_all(req.as_bytes()).await.ok()?;

    let mut buf = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 8192];
    let max_bytes = 512 * 1024; // 512 KiB safety limit

    while buf.len() < max_bytes {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }

    String::from_utf8(buf).ok()
}
