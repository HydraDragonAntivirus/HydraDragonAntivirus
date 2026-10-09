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
/// - 3 = Potentially Up (resolves, but HTTP answers evasively: 3xx, 403, 5xx)
/// - 4 = Potentially Down (resolves, but HTTP says client error: 400/404/410...)
///
/// Codes 0/1/2 keep their historical meaning: the engine treats 3/4 like
/// ACTIVE for ML gating (only 2 skips ML / earns the dead-domain Clean verdict).
pub const LIVENESS_UNKNOWN: i32 = 0;
pub const LIVENESS_ACTIVE: i32 = 1;
pub const LIVENESS_INACTIVE: i32 = 2;
pub const LIVENESS_POTENTIALLY_UP: i32 = 3;
pub const LIVENESS_POTENTIALLY_DOWN: i32 = 4;

/// PyFunceble `active_http_codes`: the server clearly answers.
pub const ACTIVE_HTTP_CODES: &[u16] = &[100, 101, 200, 201, 202, 203, 204, 205, 206];
/// PyFunceble `potentially_up_codes`: redirects, bot-blocks, server errors.
/// The host answers, but we cannot be sure it is really serving the page.
pub const POTENTIALLY_UP_HTTP_CODES: &[u16] = &[
    0, 300, 301, 302, 303, 304, 305, 307, 403, 405, 406, 407, 408, 411, 413, 417,
    500, 501, 502, 503, 504, 505,
];
/// PyFunceble `down_potentially_codes`: client errors. Checked before the
/// potentially-up list (403 lives in both): we cannot be sure a 400/404
/// means the domain is dead, so it is potentially down, not down.
pub const POTENTIALLY_DOWN_HTTP_CODES: &[u16] =
    &[400, 402, 403, 404, 409, 410, 412, 414, 415, 416];

pub fn liveness_label(code: i32) -> &'static str {
    match code {
        LIVENESS_ACTIVE => "ACTIVE",
        LIVENESS_INACTIVE => "INACTIVE",
        LIVENESS_POTENTIALLY_UP => "POTENTIALLY_UP",
        LIVENESS_POTENTIALLY_DOWN => "POTENTIALLY_DOWN",
        _ => "UNKNOWN",
    }
}

/// Refine a DNS-based liveness result with the HTTP status, PyFunceble-style.
/// Non-ACTIVE DNS results are returned untouched (without DNS there is nothing
/// to refine); DNS-ACTIVE with no HTTP answer stays ACTIVE.
pub fn classify_with_http(dns_code: i32, http_status: Option<u16>) -> (i32, String) {
    if dns_code != LIVENESS_ACTIVE {
        return (dns_code, liveness_label(dns_code).to_string());
    }
    let refined = match http_status {
        None => LIVENESS_ACTIVE,
        Some(s) if ACTIVE_HTTP_CODES.contains(&s) => LIVENESS_ACTIVE,
        Some(s) if POTENTIALLY_DOWN_HTTP_CODES.contains(&s) => LIVENESS_POTENTIALLY_DOWN,
        Some(s) if POTENTIALLY_UP_HTTP_CODES.contains(&s) => LIVENESS_POTENTIALLY_UP,
        Some(_) => LIVENESS_ACTIVE,
    };
    (refined, liveness_label(refined).to_string())
}

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
/// Returns the response status code with the raw bytes (headers included,
/// same as before) so callers can gate comparisons on equal statuses.
pub async fn fetch_page_content_safe(raw_url: &str) -> Option<(u16, String)> {
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

    let text = String::from_utf8(buf).ok()?;
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    Some((status, text))
}
