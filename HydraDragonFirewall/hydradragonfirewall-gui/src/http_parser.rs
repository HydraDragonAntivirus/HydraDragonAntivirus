//! HTTP Parser Module - Extracts full URLs from HTTP requests
//!
//! This module parses HTTP request packets to extract the hostname (from Host header)
//! and the full URL path, enabling the firewall to filter HTTP traffic by URL.

/// Result of parsing an HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path (e.g., "/path/to/resource")
    pub path: String,
    /// Parsed scheme hint (http/https) when it can be inferred
    pub scheme: Option<String>,
    /// Server port derived from the Host header or transport metadata
    pub port: Option<u16>,
    /// Host from the Host header
    pub host: Option<String>,
    /// User-Agent header for richer telemetry/alerting
    pub user_agent: Option<String>,
    /// Content-Type header for payload awareness
    pub content_type: Option<String>,
    /// Referer header for tracing navigation chains
    pub referer: Option<String>,
    /// Full reconstructed URL
    pub full_url: Option<String>,
}

/// HTTP methods we recognize
const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Extracts HTTP request information from a packet payload.
///
/// # Arguments
/// * `data` - Raw packet payload (TCP payload)
///
/// # Returns
/// * `Some(HttpRequestInfo)` - If this is a valid HTTP request
/// * `None` - If the packet is not an HTTP request
pub fn extract_http_info(data: &[u8], port_hint: Option<u16>) -> Option<HttpRequestInfo> {
    // Convert to string for parsing
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // Try to parse just the ASCII portion
            let ascii_end = data.iter().position(|&b| b > 127).unwrap_or(data.len());
            if ascii_end < 16 {
                return None;
            }
            std::str::from_utf8(&data[..ascii_end]).ok()?
        }
    };

    // Find the request line (first line)
    let first_line = text.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        return None;
    }

    let method = parts[0];
    let path = parts[1];
    let version = parts[2];

    // Validate HTTP method
    if !HTTP_METHODS.contains(&method) {
        return None;
    }

    // Validate HTTP version
    if !version.starts_with("HTTP/") {
        return None;
    }

    // Extract key headers
    let host_header = extract_header(text, "host");
    let (host, host_port) = host_header
        .as_ref()
        .map(|h| {
            let mut parts = h.splitn(2, ':');
            let hostname = parts.next().unwrap_or("").to_string();
            let port = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .or(port_hint);
            (Some(hostname), port)
        })
        .unwrap_or((None, port_hint));
    let user_agent = extract_header(text, "user-agent");
    let content_type = extract_header(text, "content-type");
    let referer = extract_header(text, "referer");

    // Reconstruct full URL with best-effort scheme detection
    let scheme = if path.starts_with("https://") {
        Some("https".to_string())
    } else if path.starts_with("http://") {
        Some("http".to_string())
    } else if let Some(port) = host_port {
        Some(if port == 443 { "https" } else { "http" }.to_string())
    } else {
        None
    };

    let full_url = host.as_ref().map(|h| {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            let scheme_prefix = scheme.clone().unwrap_or_else(|| "http".to_string());
            let port_suffix = if let Some(port) = host_port {
                if (scheme_prefix == "http" && port != 80)
                    || (scheme_prefix == "https" && port != 443)
                {
                    format!(":{}", port)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            format!("{}://{}{}{}", scheme_prefix, h, port_suffix, path)
        }
    });

    Some(HttpRequestInfo {
        method: method.to_string(),
        path: path.to_string(),
        scheme,
        port: host_port,
        host,
        user_agent,
        content_type,
        referer,
        full_url,
    })
}

/// Extracts the value of a case-insensitive HTTP header name
fn extract_header(text: &str, name: &str) -> Option<String> {
    for line in text.lines().skip(1) {
        // Empty line marks end of headers
        if line.is_empty() || line == "\r" {
            break;
        }

        // Parse header
        if let Some(colon_pos) = line.find(':') {
            let header_name = line[..colon_pos].trim().to_lowercase();
            let header_value = line[colon_pos + 1..].trim();

            if header_name == name {
                return Some(header_value.to_string());
            }
        }
    }
    None
}

/// Quick check if the packet looks like an HTTP request
pub fn is_http_request(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check for common HTTP methods
    let prefix = &data[..4.min(data.len())];
    matches!(
        prefix,
        b"GET " | b"POST" | b"PUT " | b"HEAD" | b"DELE" | b"OPTI" | b"PATC" | b"CONN" | b"TRAC"
    )
}

/// Extracts just the hostname from HTTP data (convenience function)
pub fn extract_hostname(data: &[u8]) -> Option<String> {
    extract_http_info(data, None).and_then(|info| info.host)
}

/// Extracts the full URL from HTTP data (convenience function)
pub fn extract_full_url(data: &[u8]) -> Option<String> {
    extract_http_info(data, None).and_then(|info| info.full_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_get() {
        let request = b"GET /test/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let info = extract_http_info(request, Some(80)).unwrap();
        assert_eq!(info.method, "GET");
        assert_eq!(info.path, "/test/path");
        assert_eq!(info.scheme, Some("http".to_string()));
        assert_eq!(info.port, Some(80));
        assert_eq!(info.host, Some("example.com".to_string()));
        assert_eq!(info.user_agent, None);
        assert_eq!(
            info.full_url,
            Some("http://example.com/test/path".to_string())
        );
    }

    #[test]
    fn test_headers_are_captured() {
        let request = b"POST /submit HTTP/1.1\r\nHost: api.test.local:8080\r\nUser-Agent: curl/8.6.0\r\nContent-Type: application/json\r\nReferer: https://portal.test.local/dashboard\r\n\r\n{}";
        let info = extract_http_info(request, Some(8080)).unwrap();
        assert_eq!(info.method, "POST");
        assert_eq!(info.path, "/submit");
        assert_eq!(info.scheme, Some("http".to_string()));
        assert_eq!(info.port, Some(8080));
        assert_eq!(info.host, Some("api.test.local".to_string()));
        assert_eq!(info.user_agent, Some("curl/8.6.0".to_string()));
        assert_eq!(info.content_type, Some("application/json".to_string()));
        assert_eq!(
            info.referer,
            Some("https://portal.test.local/dashboard".to_string())
        );
    }

    #[test]
    fn test_is_http_request() {
        assert!(is_http_request(b"GET /"));
        assert!(is_http_request(b"POST /"));
        assert!(!is_http_request(b"\x16\x03\x01"));
    }
}
