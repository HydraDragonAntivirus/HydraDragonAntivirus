//! EDR threat feedback loop to VirusKov Cloud.
//!
//! When OpenEDR's behavioral, ransomware, heuristic, ML or quarantine engines
//! detect a threat locally (which may be Clean or Unknown on VirusKov), this module:
//! 1. Telemetry Step: Sends threat metadata (SHA-256, path, detection name, source, details)
//!    via `POST /api/v1/edr/report` to VirusKov.
//! 2. Sample Ingestion Step: If VirusKov responds with `need_sample: true`, compresses
//!    the binary payload using Brotli (if <= 100 MB) and uploads it to
//!    `POST /api/v1/edr/upload/{sha256}` with `Content-Encoding: br`.
//! 3. Runs completely asynchronously in a background thread so system remediation
//!    and driver kills are NEVER delayed.

use crate::logging::Logging;
use serde::{Deserialize, Serialize};
use std::io::Write;

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    INTERNET_DEFAULT_HTTPS_PORT, INTERNET_DEFAULT_HTTP_PORT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_FLAG_SECURE, WINHTTP_OPEN_REQUEST_FLAGS, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE,
};

pub const MAX_SAMPLE_BYTES: usize = 100 * 1024 * 1024; // 100 MB limit

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub sha256: String,
    pub file_name: String,
    pub original_path: String,
    pub detection: String,
    pub source: String, // "quarantine", "behavioral", "ml", "ransomware", "fls"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ReportResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    need_sample: bool,
    #[serde(default)]
    message: String,
}

/// Compress arbitrary payload using Brotli (quality 6, lgwin 22).
pub fn compress_brotli(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 6, 22);
        writer.write_all(data)?;
    }
    Ok(out)
}

struct ServerTarget {
    host: String,
    port: u16,
    is_https: bool,
    path_prefix: String,
}

fn resolve_server_target() -> ServerTarget {
    if let Ok(url_str) = std::env::var("VIRUSKOV_API_URL") {
        if let Ok(u) = url::Url::parse(&url_str) {
            let is_https = u.scheme() == "https";
            let default_port = if is_https {
                INTERNET_DEFAULT_HTTPS_PORT as u16
            } else {
                INTERNET_DEFAULT_HTTP_PORT as u16
            };
            let port = u.port().unwrap_or(default_port);
            let host = u.host_str().unwrap_or("viruskov.com").to_string();
            let path_prefix = u.path().trim_end_matches('/').to_string();
            return ServerTarget {
                host,
                port,
                is_https,
                path_prefix,
            };
        }
    }

    // Default primary target
    ServerTarget {
        host: "viruskov.com".to_string(),
        port: 443,
        is_https: true,
        path_prefix: String::new(),
    }
}

#[cfg(target_os = "windows")]
fn winhttp_post(
    host: &str,
    port: u16,
    is_https: bool,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u32, Vec<u8>), String> {
    unsafe {
        let user_agent: Vec<u16> = "VirusKov-EDR-Feedback/1.0\0".encode_utf16().collect();
        let h_session = WinHttpOpen(
            PCWSTR(user_agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if h_session.is_null() {
            return Err("WinHttpOpen returned null session handle".into());
        }

        let wide_host: Vec<u16> = host.encode_utf16().chain(std::iter::once(0)).collect();
        let h_connect = WinHttpConnect(h_session, PCWSTR(wide_host.as_ptr()), port, 0);
        if h_connect.is_null() {
            let _ = WinHttpCloseHandle(h_session);
            return Err(format!("WinHttpConnect failed for {}:{}", host, port));
        }

        let verb: Vec<u16> = "POST\0".encode_utf16().collect();
        let wide_path: Vec<u16> = path_and_query.encode_utf16().chain(std::iter::once(0)).collect();
        let open_flags = if is_https {
            WINHTTP_FLAG_SECURE
        } else {
            WINHTTP_OPEN_REQUEST_FLAGS(0)
        };

        let h_request = WinHttpOpenRequest(
            h_connect,
            PCWSTR(verb.as_ptr()),
            PCWSTR(wide_path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            open_flags,
        );
        if h_request.is_null() {
            let _ = WinHttpCloseHandle(h_connect);
            let _ = WinHttpCloseHandle(h_session);
            return Err("WinHttpOpenRequest failed".into());
        }

        // Combine headers into RFC standard format
        let mut headers_str = String::new();
        for (k, v) in headers {
            headers_str.push_str(k);
            headers_str.push_str(": ");
            headers_str.push_str(v);
            headers_str.push_str("\r\n");
        }
        let wide_headers: Vec<u16> = headers_str.encode_utf16().collect();

        let send_res = WinHttpSendRequest(
            h_request,
            if wide_headers.is_empty() {
                None
            } else {
                Some(&wide_headers[..])
            },
            if body.is_empty() {
                None
            } else {
                Some(body.as_ptr() as *const _)
            },
            body.len() as u32,
            body.len() as u32,
            0,
        );
        if !send_res.as_bool() {
            let _ = WinHttpCloseHandle(h_request);
            let _ = WinHttpCloseHandle(h_connect);
            let _ = WinHttpCloseHandle(h_session);
            return Err("WinHttpSendRequest failed".into());
        }

        if !WinHttpReceiveResponse(h_request, std::ptr::null_mut()).as_bool() {
            let _ = WinHttpCloseHandle(h_request);
            let _ = WinHttpCloseHandle(h_connect);
            let _ = WinHttpCloseHandle(h_session);
            return Err("WinHttpReceiveResponse failed".into());
        }

        let mut status_code: u32 = 0;
        let mut status_size = std::mem::size_of::<u32>() as u32;
        let _ = WinHttpQueryHeaders(
            h_request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status_code as *mut _ as *mut _),
            &mut status_size,
            std::ptr::null_mut(),
        );

        let mut resp_body = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let mut read_bytes: u32 = 0;
            let read_ok = WinHttpReadData(
                h_request,
                chunk.as_mut_ptr() as *mut _,
                chunk.len() as u32,
                &mut read_bytes,
            );
            if !read_ok.as_bool() || read_bytes == 0 {
                break;
            }
            resp_body.extend_from_slice(&chunk[..read_bytes as usize]);
        }

        let _ = WinHttpCloseHandle(h_request);
        let _ = WinHttpCloseHandle(h_connect);
        let _ = WinHttpCloseHandle(h_session);

        Ok((status_code, resp_body))
    }
}

#[cfg(not(target_os = "windows"))]
fn winhttp_post(
    _host: &str,
    _port: u16,
    _is_https: bool,
    _path_and_query: &str,
    _headers: &[(&str, &str)],
    _body: &[u8],
) -> Result<(u32, Vec<u8>), String> {
    Err("winhttp is only available on Windows".into())
}

/// Dispatches threat telemetry and sample upload to VirusKov asynchronously.
pub fn report_threat_async(report: ThreatReport, file_bytes: Option<Vec<u8>>) {
    let _ = std::thread::Builder::new()
        .name("edr-feedback".into())
        .spawn(move || {
            let target = resolve_server_target();
            let report_path = format!("{}/api/v1/edr/report", target.path_prefix);

            let json_body = match serde_json::to_vec(&report) {
                Ok(b) => b,
                Err(e) => {
                    Logging::error(&format!("[EDR Feedback] Failed to serialize report: {e}"));
                    return;
                }
            };

            let headers = [
                ("Content-Type", "application/json"),
                ("User-Agent", "VirusKov-EDR-Feedback/1.0"),
            ];

            Logging::info(&format!(
                "[EDR Feedback] Reporting threat to {}:{}{} for {} [{}] ({})",
                target.host, target.port, report_path, report.sha256, report.detection, report.source
            ));

            let (status, resp_bytes) = match winhttp_post(
                &target.host,
                target.port,
                target.is_https,
                &report_path,
                &headers,
                &json_body,
            ) {
                Ok(res) => res,
                Err(e) => {
                    Logging::warning(&format!(
                        "[EDR Feedback] Failed to reach VirusKov endpoint: {e}"
                    ));
                    return;
                }
            };

            if status != 200 {
                let err_text = String::from_utf8_lossy(&resp_bytes);
                Logging::warning(&format!(
                    "[EDR Feedback] VirusKov returned HTTP {status}: {err_text}"
                ));
                return;
            }

            let report_resp: ReportResponse = match serde_json::from_slice(&resp_bytes) {
                Ok(r) => r,
                Err(_) => {
                    Logging::warning("[EDR Feedback] Received non-JSON response from VirusKov");
                    return;
                }
            };

            Logging::info(&format!(
                "[EDR Feedback] VirusKov report acknowledged: status={} need_sample={} msg={}",
                report_resp.status, report_resp.need_sample, report_resp.message
            ));

            // Step 2: Upload sample if requested
            if report_resp.need_sample {
                if let Some(bytes) = file_bytes {
                    if bytes.is_empty() {
                        Logging::warning("[EDR Feedback] Cannot upload sample: empty payload");
                        return;
                    }
                    if bytes.len() > MAX_SAMPLE_BYTES {
                        Logging::warning(&format!(
                            "[EDR Feedback] Sample size {} exceeds limit {} MB; skipping upload",
                            bytes.len(),
                            MAX_SAMPLE_BYTES / (1024 * 1024)
                        ));
                        return;
                    }

                    // Brotli compression
                    let (upload_body, is_compressed) = match compress_brotli(&bytes) {
                        Ok(compressed) if compressed.len() < bytes.len() => (compressed, true),
                        _ => (bytes, false),
                    };

                    let enc_name = urlencoding::encode(&report.file_name);
                    let enc_det = urlencoding::encode(&report.detection);
                    let enc_src = urlencoding::encode(&report.source);
                    let upload_path = format!(
                        "{}/api/v1/edr/upload/{}?name={}&detection={}&source={}",
                        target.path_prefix, report.sha256, enc_name, enc_det, enc_src
                    );

                    let mut upload_headers = vec![
                        ("User-Agent", "VirusKov-EDR-Feedback/1.0"),
                        ("Content-Type", "application/octet-stream"),
                    ];
                    if is_compressed {
                        upload_headers.push(("Content-Encoding", "br"));
                    }

                    Logging::info(&format!(
                        "[EDR Feedback] Uploading sample for {} (upload: {} bytes, br={})",
                        report.sha256, upload_body.len(), is_compressed
                    ));

                    match winhttp_post(
                        &target.host,
                        target.port,
                        target.is_https,
                        &upload_path,
                        &upload_headers,
                        &upload_body,
                    ) {
                        Ok((200, _)) => {
                            Logging::info(&format!(
                                "[EDR Feedback] Successfully uploaded malware sample {} to VirusKov queue",
                                report.sha256
                            ));
                        }
                        Ok((st, err_b)) => {
                            let text = String::from_utf8_lossy(&err_b);
                            Logging::warning(&format!(
                                "[EDR Feedback] Upload failed with HTTP {st}: {text}"
                            ));
                        }
                        Err(e) => {
                            Logging::warning(&format!(
                                "[EDR Feedback] Sample upload network error: {e}"
                            ));
                        }
                    }
                }
            }
        });
}

// Minimal percent-encoder to avoid extra crate dependency
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{:02X}", b));
            }
        }
        out
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brotli_compression() {
        let original = b"VirusKov OpenEDR Threat Feedback Test Sample Payload 1234567890".repeat(20);
        let compressed = compress_brotli(&original).expect("compression should succeed");
        assert!(!compressed.is_empty());
        assert!(compressed.len() < original.len());

        let mut decompressed = Vec::new();
        let mut decompressor = brotli::Decompressor::new(&compressed[..], 4096);
        std::io::copy(&mut decompressor, &mut decompressed).expect("decompression should succeed");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_threat_report_json() {
        let report = ThreatReport {
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            file_name: "ransom.exe".to_string(),
            original_path: r"C:\Windows\Temp\ransom.exe".to_string(),
            detection: "Ransom.Behavioral.OpenEDR".to_string(),
            source: "quarantine".to_string(),
            pid: Some(1234),
            details: serde_json::json!({ "score": 1.0, "ransom_indicators": ["vssadmin_delete"] }),
        };

        let json = serde_json::to_string(&report).expect("serialization should succeed");
        assert!(json.contains("ransom.exe"));
        assert!(json.contains("Ransom.Behavioral.OpenEDR"));

        let deserialized: ThreatReport = serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(deserialized.sha256, report.sha256);
        assert_eq!(deserialized.pid, Some(1234));
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(urlencoding::encode("test file.exe"), "test%20file.exe");
        assert_eq!(urlencoding::encode("abc-123_xyz.bin"), "abc-123_xyz.bin");
        assert_eq!(urlencoding::encode("Trojan:Win32/Wacatac.B!ml"), "Trojan%3AWin32%2FWacatac.B%21ml");
    }
}
