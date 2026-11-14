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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

/// Read Windows MachineGuid from HKLM\SOFTWARE\Microsoft\Cryptography as default endpoint identifier (Zero API Key requirement).
#[cfg(target_os = "windows")]
pub fn get_machine_guid() -> String {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(crypto) = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
        if let Ok(guid) = crypto.get_value::<String, _>("MachineGuid") {
            let clean = guid.trim().to_string();
            if !clean.is_empty() {
                return clean;
            }
        }
    }
    hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|_| "hydra-endpoint-anonymous".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn get_machine_guid() -> String {
    hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|_| "hydra-endpoint-anonymous".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlowRecord {
    pub timestamp: u64,
    pub pid: u32,
    pub process_name: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlowBatch {
    pub machine_id: String,
    pub flows: Vec<NetworkFlowRecord>,
}

/// Last outcome of the flow / system telemetry posts (HTTP status, 0 = network
/// error). Flows go out every few seconds, so only a change is logged.
static LAST_FLOWS_STATUS: AtomicU32 = AtomicU32::new(200);
static LAST_SYSTEM_STATUS: AtomicU32 = AtomicU32::new(200);

/// Logs a telemetry post's failure (or its recovery) when the outcome differs
/// from the previous post's, instead of dropping it silently or on every post.
fn log_telemetry_outcome(kind: &str, last: &AtomicU32, res: &Result<(u32, Vec<u8>), String>) {
    let status = match res {
        Ok((st, _)) => *st,
        Err(_) => 0,
    };
    if last.swap(status, Ordering::Relaxed) == status {
        return;
    }
    match res {
        Ok((200, _)) => Logging::info(&format!("[EDR Feedback] {kind} telemetry delivered again (HTTP 200)")),
        Ok((st, body)) => {
            let text = String::from_utf8_lossy(&body[..body.len().min(256)]);
            Logging::warning(&format!("[EDR Feedback] {kind} telemetry endpoint returned HTTP {st}: {text}"));
        }
        Err(e) => Logging::warning(&format!("[EDR Feedback] Failed to stream {kind} telemetry: {e}")),
    }
}

/// Number of flows left out of the telemetry because they are the product's own
/// loopback traffic (see `is_own_loopback_flow`).
static SUPPRESSED_OWN_LOOPBACK_FLOWS: AtomicU64 = AtomicU64::new(0);

/// Install root of the product: the directory of the running service executable
/// (edrsvc.exe loads this DLL; edrgui.exe and the other components live in the
/// same directory tree). The same notion as `utils::is_own_companion_process`.
fn own_install_root() -> Option<&'static std::path::Path> {
    static ROOT: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    })
    .as_deref()
}

/// A loopback address, including an IPv4-mapped one (`::ffff:127.0.0.1`).
fn is_loopback_ip(ip: &std::net::IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// Both ends of the flow are loopback and the image of the process is inside
/// `install_root`. The image is matched by its full path, not by its file name:
/// any process can be called `edrsvc.exe`. Windows paths compare case-insensitively.
pub fn is_loopback_flow_of_image_under(
    src_ip: &std::net::IpAddr,
    dst_ip: &std::net::IpAddr,
    image_path: &str,
    install_root: &std::path::Path,
) -> bool {
    if !is_loopback_ip(src_ip) || !is_loopback_ip(dst_ip) {
        return false;
    }
    if image_path.is_empty() || install_root.as_os_str().is_empty() {
        return false;
    }
    let image = std::path::PathBuf::from(image_path.to_lowercase());
    let root = std::path::PathBuf::from(install_root.to_string_lossy().to_lowercase());
    // Component-wise: "...\OpenEDR-evil\x.exe" is not under "...\OpenEDR".
    image.starts_with(&root)
}

/// The product's own loopback traffic (edrsvc.exe <-> edrgui.exe and the other
/// components of the install directory talking over 127.0.0.1 / ::1). It carries
/// no detection value, the server never judges loopback addresses, and it is the
/// bulk of the flow telemetry, so it is left out. Everything else stays: loopback
/// traffic of any other process (local proxies, tunnels) and the product's own
/// connections to remote addresses.
pub fn is_own_loopback_flow(src_ip: &std::net::IpAddr, dst_ip: &std::net::IpAddr, image_path: &str) -> bool {
    let Some(root) = own_install_root() else {
        return false;
    };
    if !is_loopback_flow_of_image_under(src_ip, dst_ip, image_path, root) {
        return false;
    }
    let n = SUPPRESSED_OWN_LOOPBACK_FLOWS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n % 1000 == 0 {
        Logging::info(&format!(
            "[EDR Feedback] Own loopback flows left out of the network telemetry so far: {n}"
        ));
    }
    true
}

/// How many own loopback flows were left out of the telemetry since the start.
pub fn suppressed_own_loopback_flows() -> u64 {
    SUPPRESSED_OWN_LOOPBACK_FLOWS.load(Ordering::Relaxed)
}

/// Stream process network telemetry to VirusKov cloud for ML model training.
pub fn stream_network_flows_async(flows: Vec<NetworkFlowRecord>) {
    if flows.is_empty() {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("edr-network-telemetry".into())
        .spawn(move || {
            let target = resolve_server_target();
            let telemetry_path = format!("{}/api/v1/edr/telemetry/network-flows", target.path_prefix);
            let machine_id = get_machine_guid();
            let batch = NetworkFlowBatch {
                machine_id: machine_id.clone(),
                flows,
            };
            let json_body = match serde_json::to_vec(&batch) {
                Ok(b) => b,
                Err(_) => return,
            };
            let mut headers = vec![
                ("Content-Type", "application/json"),
                ("User-Agent", "VirusKov-EDR-Telemetry/1.0"),
                ("X-Machine-ID", machine_id.as_str()),
                ("X-Endpoint-ID", machine_id.as_str()),
            ];
            let api_key_opt = std::env::var("VIRUSKOV_API_KEY").ok();
            if let Some(ref key) = api_key_opt {
                headers.push(("X-API-Key", key.as_str()));
            }

            let res = winhttp_post(
                &target.host,
                target.port,
                target.is_https,
                &telemetry_path,
                &headers,
                &json_body,
            );
            log_telemetry_outcome("network flow", &LAST_FLOWS_STATUS, &res);
        });
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsSummary {
    pub ops_read: u64,
    pub ops_written: u64,
    pub ops_open: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub entropy_read: f64,
    pub entropy_written: f64,
    pub files_renamed_count: usize,
    pub files_read_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorTelemetryPayload {
    pub machine_id: String,
    pub timestamp: u64,
    pub pid: u32,
    pub gid: u64,
    pub process_name: String,
    pub exe_path: String,
    pub command_line: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    pub detection: String,
    pub source: String,
    pub risk_score: f32,
    pub indicators: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops_summary: Option<OpsSummary>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VirusKovBehaviorResponse {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub threat_name: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub need_sample: bool,
}

/// Send a raw formatted newline-terminated string to the Pascal HIPS event pipe \\.\pipe\HydraHipEvent.
pub fn send_hips_pipe_raw(message: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
            FlushFileBuffers, OPEN_EXISTING, WriteFile,
        };
        use windows::Win32::System::Pipes::WaitNamedPipeW;
        use windows::core::PCWSTR;

        const PIPE: &str = r"\\.\pipe\HydraHipEvent";
        let mut pipe_name_wide: Vec<u16> = PIPE.encode_utf16().collect();
        pipe_name_wide.push(0);
        let pcwstr = PCWSTR(pipe_name_wide.as_ptr());
        let message_bytes = message.as_bytes();

        let wait_ok = unsafe { WaitNamedPipeW(pcwstr, 150) };
        if wait_ok.as_bool() {
            if let Ok(handle) = unsafe {
                CreateFileW(
                    pcwstr,
                    FILE_GENERIC_WRITE.0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    HANDLE::default(),
                )
            } {
                if !handle.is_invalid() {
                    let mut written: u32 = 0;
                    let write_res = unsafe {
                        let _ = WriteFile(
                            handle,
                            Some(message_bytes),
                            Some(&mut written as *mut u32),
                            None,
                        );
                        let _ = FlushFileBuffers(handle);
                        CloseHandle(handle)
                    };
                    return write_res.as_bool();
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = message;
    }
    false
}

/// Send interactive HIPS decision request to Pascal GUI (TAlertForm.ShowInteractivePrompt).
pub fn send_hips_ask(
    req_id: &str,
    pid: u32,
    app_name: &str,
    exe_path: &str,
    target: &str,
    verdict: &str,
    sig_status: &str,
    reason: &str,
    dll_chain: &str,
) -> bool {
    let msg = format!(
        "HIPS_ASK:{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
        req_id, pid, app_name, exe_path, target, verdict, sig_status, reason, dll_chain
    );
    send_hips_pipe_raw(&msg)
}

/// Send threat alert notification to Pascal GUI.
pub fn send_threat_alert(threat_name: &str, file_path: &str, reboot_required: bool) -> bool {
    let reboot_flag = if reboot_required { "1" } else { "0" };
    let msg = format!("THREAT_ALERT:{}|{}|{}\n", threat_name, file_path, reboot_flag);
    send_hips_pipe_raw(&msg)
}

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
    let url_str = std::env::var("VIRUSKOV_API_URL").ok();

    if let Some(ref raw) = url_str {
        if let Ok(u) = url::Url::parse(raw) {
            let is_https = u.scheme() == "https";
            let default_port = if is_https {
                INTERNET_DEFAULT_HTTPS_PORT as u16
            } else {
                INTERNET_DEFAULT_HTTP_PORT as u16
            };
            let port = u.port().unwrap_or(default_port);
            let host = u.host_str().unwrap_or("127.0.0.1").to_string();
            let path_prefix = u.path().trim_end_matches('/').to_string();
            return ServerTarget {
                host,
                port,
                is_https,
                path_prefix,
            };
        }
    }

    // Default primary target: official VirusKov cloud (api.viruskov.com)
    ServerTarget {
        host: "api.viruskov.com".to_string(),
        port: 443,
        is_https: true,
        path_prefix: String::new(),
    }
}

/// "<what> failed for host:port: WinHTTP error N (meaning)" from the thread's last error.
#[cfg(target_os = "windows")]
fn winhttp_error(what: &str, host: &str, port: u16) -> String {
    let code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
    let meaning = match code {
        12002 => "timed out",
        12007 => "host name not resolved (DNS)",
        12029 => "cannot connect (blocked, or nothing listening)",
        12030 => "connection aborted",
        12031 => "connection reset",
        12152 => "invalid server response",
        12157 | 12175 => "TLS / secure channel error",
        12038 | 12044 | 12045 | 12169 => "server certificate rejected",
        12180 => "proxy auto-detection failed",
        _ => "see WinHTTP error codes",
    };
    format!("{what} failed for {host}:{port}: WinHTTP error {code} ({meaning})")
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
            let e = winhttp_error("WinHttpConnect", host, port);
            let _ = WinHttpCloseHandle(h_session);
            return Err(e);
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
            let e = winhttp_error("WinHttpOpenRequest", host, port);
            let _ = WinHttpCloseHandle(h_connect);
            let _ = WinHttpCloseHandle(h_session);
            return Err(e);
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
            let e = winhttp_error("WinHttpSendRequest", host, port);
            let _ = WinHttpCloseHandle(h_request);
            let _ = WinHttpCloseHandle(h_connect);
            let _ = WinHttpCloseHandle(h_session);
            return Err(e);
        }

        if !WinHttpReceiveResponse(h_request, std::ptr::null_mut()).as_bool() {
            let e = winhttp_error("WinHttpReceiveResponse", host, port);
            let _ = WinHttpCloseHandle(h_request);
            let _ = WinHttpCloseHandle(h_connect);
            let _ = WinHttpCloseHandle(h_session);
            return Err(e);
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

/// POSTs `body` to `path` (under the configured server's prefix) with the endpoint's
/// identity headers (and the API key when one is set); blocking, for a caller that is
/// already on its own thread. Returns (HTTP status, response body).
pub(crate) fn post_to_server(path: &str, content_type: &str, content_encoding: Option<&str>, body: &[u8]) -> Result<(u32, Vec<u8>), String> {
    let target = resolve_server_target();
    let full_path = format!("{}{}", target.path_prefix, path);
    let machine_id = get_machine_guid();
    let mut headers = vec![
        ("Content-Type", content_type),
        ("User-Agent", "VirusKov-EDR-Feedback/1.0"),
        ("X-Machine-ID", machine_id.as_str()),
        ("X-Endpoint-ID", machine_id.as_str()),
    ];
    if let Some(enc) = content_encoding {
        headers.push(("Content-Encoding", enc));
    }
    let api_key_opt = std::env::var("VIRUSKOV_API_KEY").ok();
    if let Some(ref key) = api_key_opt {
        headers.push(("X-API-Key", key.as_str()));
    }
    winhttp_post(&target.host, target.port, target.is_https, &full_path, &headers, body)
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

            let machine_id = get_machine_guid();
            let mut headers = vec![
                ("Content-Type", "application/json"),
                ("User-Agent", "VirusKov-EDR-Feedback/1.0"),
                ("X-Machine-ID", machine_id.as_str()),
                ("X-Endpoint-ID", machine_id.as_str()),
            ];
            let api_key_opt = std::env::var("VIRUSKOV_API_KEY").ok();
            if let Some(ref key) = api_key_opt {
                headers.push(("X-API-Key", key.as_str()));
            }

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
                        ("X-Machine-ID", machine_id.as_str()),
                        ("X-Endpoint-ID", machine_id.as_str()),
                    ];
                    if let Some(ref key) = api_key_opt {
                        upload_headers.push(("X-API-Key", key.as_str()));
                    }
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


/// Stream rich behavioral telemetry to VirusKov cloud and process verdicts to prompt user via Pascal HIPS pipe.
pub fn stream_behavior_telemetry_async(
    payload: BehaviorTelemetryPayload,
    file_bytes: Option<Vec<u8>>,
) {
    stream_behavior_telemetry_inner(payload, file_bytes, true);
}

/// `prompt_user`: forward the server's verdict to the Pascal HIPS prompt. Off for
/// records of detections OpenEDR already acted on (killed / quarantined), so the user
/// is not asked a second time about the same process.
fn stream_behavior_telemetry_inner(
    payload: BehaviorTelemetryPayload,
    file_bytes: Option<Vec<u8>>,
    prompt_user: bool,
) {
    let _ = std::thread::Builder::new()
        .name("edr-behavior-telemetry".into())
        .spawn(move || {
            let target = resolve_server_target();
            let behavior_path = format!("{}/api/v1/edr/telemetry/behavior", target.path_prefix);
            let machine_id = get_machine_guid();

            let json_body = match serde_json::to_vec(&payload) {
                Ok(b) => b,
                Err(e) => {
                    Logging::error(&format!("[EDR Feedback] Failed to serialize behavior telemetry: {e}"));
                    return;
                }
            };

            let mut headers = vec![
                ("Content-Type", "application/json"),
                ("User-Agent", "VirusKov-EDR-Feedback/1.0"),
                ("X-Machine-ID", machine_id.as_str()),
                ("X-Endpoint-ID", machine_id.as_str()),
            ];
            let api_key_opt = std::env::var("VIRUSKOV_API_KEY").ok();
            if let Some(ref key) = api_key_opt {
                headers.push(("X-API-Key", key.as_str()));
            }

            Logging::info(&format!(
                "[EDR Feedback] Streaming behavior telemetry for PID {} ({}) [{}] to {}:{}{}",
                payload.pid, payload.process_name, payload.detection, target.host, target.port, behavior_path
            ));

            let (status, resp_bytes) = match winhttp_post(
                &target.host,
                target.port,
                target.is_https,
                &behavior_path,
                &headers,
                &json_body,
            ) {
                Ok(res) => res,
                Err(e) => {
                    Logging::warning(&format!(
                        "[EDR Feedback] Failed to stream behavior to VirusKov: {e}"
                    ));
                    return;
                }
            };

            if status != 200 {
                let err_text = String::from_utf8_lossy(&resp_bytes);
                Logging::warning(&format!(
                    "[EDR Feedback] VirusKov behavior endpoint returned HTTP {status}: {err_text}"
                ));
                return;
            }

            let resp: VirusKovBehaviorResponse = match serde_json::from_slice(&resp_bytes) {
                Ok(r) => r,
                Err(_) => {
                    Logging::warning("[EDR Feedback] Non-JSON response from VirusKov behavior endpoint");
                    return;
                }
            };

            Logging::info(&format!(
                "[EDR Feedback] VirusKov behavior response: status={} verdict={:?} action={:?} threat={:?}",
                resp.status, resp.verdict, resp.action, resp.threat_name
            ));

            // Forward to Pascal HIPS alert prompt if action is ask or threat detected
            let is_ask = resp.action.as_deref() == Some("ask");
            let is_alert = resp.action.as_deref() == Some("alert") || resp.action.as_deref() == Some("block");
            let is_threat_verdict = resp.verdict.as_deref().map_or(false, |v| {
                v.eq_ignore_ascii_case("malicious") || v.eq_ignore_ascii_case("suspicious")
            });

            if !prompt_user {
                // OpenEDR already handled this detection; the record is for the server.
            } else if is_ask || (is_threat_verdict && resp.action.as_deref() != Some("ignore")) {
                let req_id = format!("ask_{}_{}", payload.pid, payload.timestamp);
                let first_ind = payload.indicators.first().cloned().unwrap_or_else(|| "VirusKov Cloud Behavioral Threat".to_string());
                let verdict_label = format!(
                    "{} ({:.2})",
                    resp.verdict.as_deref().unwrap_or("Threat Detected"),
                    resp.confidence.unwrap_or(0.95)
                );
                let sig_status = if payload.sha256.is_empty() {
                    "Behavioral Anomaly"
                } else {
                    "Cloud AI Analyzed"
                };
                let reason_str = format!(
                    "VirusKov Cloud: {} - {}",
                    resp.threat_name.as_deref().unwrap_or("Behavioral Indicator"),
                    resp.reason.as_deref().unwrap_or("Suspicious Telemetry Pattern")
                );
                let dll_chain = if payload.indicators.is_empty() {
                    String::new()
                } else {
                    payload.indicators.join(" -> ")
                };

                let popped = send_hips_ask(
                    &req_id,
                    payload.pid,
                    &payload.process_name,
                    &payload.exe_path,
                    &first_ind,
                    &verdict_label,
                    sig_status,
                    &reason_str,
                    &dll_chain,
                );

                if popped {
                    Logging::alert(&format!(
                        "[EDR Feedback] Interactive Pascal HIPS prompt popped for PID {} ({}) from VirusKov verdict",
                        payload.pid, payload.process_name
                    ));
                }
            } else if is_alert {
                let threat_title = resp.threat_name.as_deref().unwrap_or("VirusKov.Cloud.Threat");
                send_threat_alert(threat_title, &payload.exe_path, false);
            }

            // Upload sample if requested
            if resp.need_sample {
                if let Some(bytes) = file_bytes {
                    if !bytes.is_empty() && bytes.len() <= MAX_SAMPLE_BYTES && !payload.sha256.is_empty() {
                        let (upload_body, is_compressed) = match compress_brotli(&bytes) {
                            Ok(c) if c.len() < bytes.len() => (c, true),
                            _ => (bytes, false),
                        };

                        let enc_name = urlencoding::encode(&payload.process_name);
                        let enc_det = urlencoding::encode(resp.threat_name.as_deref().unwrap_or(&payload.detection));
                        let enc_src = urlencoding::encode(&payload.source);
                        let upload_path = format!(
                            "{}/api/v1/edr/upload/{}?name={}&detection={}&source={}",
                            target.path_prefix, payload.sha256, enc_name, enc_det, enc_src
                        );

                        let mut upload_headers = vec![
                            ("User-Agent", "VirusKov-EDR-Feedback/1.0"),
                            ("Content-Type", "application/octet-stream"),
                            ("X-Machine-ID", machine_id.as_str()),
                            ("X-Endpoint-ID", machine_id.as_str()),
                        ];
                        if let Some(ref key) = api_key_opt {
                            upload_headers.push(("X-API-Key", key.as_str()));
                        }
                        if is_compressed {
                            upload_headers.push(("Content-Encoding", "br"));
                        }

                        let _ = winhttp_post(
                            &target.host,
                            target.port,
                            target.is_https,
                            &upload_path,
                            &upload_headers,
                            &upload_body,
                        );
                    }
                }
            }
        });
}

/// The raw detection event goes along in `details` only below this size (an event
/// carries the whole `processes` chain; the server takes 256 KB per record).
const MAX_DETECTION_DETAILS_BYTES: usize = 64 * 1024;

/// First non-empty string among `paths` ("process.imageFile.path" style) in `event`.
fn event_str(event: &serde_json::Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|p| {
        let mut v = event;
        for key in p.split('.') {
            v = v.get(key)?;
        }
        match v {
            serde_json::Value::String(s) if !s.is_empty() && s != "<undefined>" && s != "null" => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    })
}

/// OpenEDR detections waiting for the worker thread. The worker owns the process
/// records (file operations, written extensions, ML features), so it is the one
/// that can attach the kill chain of the detected process to the report.
static PENDING_DETECTIONS: std::sync::Mutex<Vec<serde_json::Value>> = std::sync::Mutex::new(Vec::new());

/// The worker loop is running and drains `PENDING_DETECTIONS` every few
/// milliseconds. When it is not, detections are sent at once without a kill chain
/// so that none is lost.
static DETECTION_WORKER_ALIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// More detections than this waiting for the worker means it is stuck: send the
/// new ones directly instead of growing the queue.
const MAX_PENDING_DETECTIONS: usize = 256;

/// Called by the worker loop when it starts (`true`) and when it ends (`false`).
pub fn set_detection_worker_alive(alive: bool) {
    DETECTION_WORKER_ALIVE.store(alive, Ordering::SeqCst);
}

/// Detections queued since the last call, oldest first. Called by the worker loop.
pub fn take_pending_detections() -> Vec<serde_json::Value> {
    match PENDING_DETECTIONS.lock() {
        Ok(mut q) => std::mem::take(&mut *q),
        Err(_) => Vec::new(),
    }
}

/// PID of the process an OpenEDR detection event is about (0 when it names none).
pub fn openedr_detection_pid(event: &serde_json::Value) -> u32 {
    event_str(event, &["process.pid", "process.id", "childProcess.pid", "childProcess.id"])
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Attaches the kill chain of the detected process to its behavior report: the
/// forensic trace (`details.killchain_trace`), the file-operation counters and the
/// process group id.
fn attach_process_killchain(payload: &mut BehaviorTelemetryPayload, proc: &crate::process::ProcessRecord) {
    payload.gid = proc.gid;
    payload.ops_summary = Some(crate::actions_on_kill::process_ops_summary(proc));
    let trace = crate::actions_on_kill::process_killchain_trace(proc);
    if let Some(details) = payload.details.as_object_mut() {
        details.insert("killchain_trace".to_string(), serde_json::Value::Object(trace));
    }
}

/// Sends an OpenEDR detection as a behavior report, with the kill chain of the
/// detected process when the worker has its record. Called by the worker loop.
pub fn stream_openedr_detection_with_process(
    event: &serde_json::Value,
    proc: Option<&crate::process::ProcessRecord>,
) {
    let mut payload = behavior_from_openedr_detection(event);
    if let Some(proc) = proc {
        attach_process_killchain(&mut payload, proc);
    }
    stream_behavior_telemetry_inner(payload, None, false);
}

/// Stream an OpenEDR policy detection (detnotif, e.g. MLE_GODMODE_ACTIVITY) to the
/// VirusKov behavior endpoint. OpenEDR already killed / quarantined, so the user is
/// not prompted again.
pub fn stream_openedr_detection_async(event: &serde_json::Value) {
    // Hand the detection to the worker: it attaches the kill chain of the
    // detected process (see `stream_openedr_detection_with_process`).
    if DETECTION_WORKER_ALIVE.load(Ordering::SeqCst)
        && let Ok(mut pending) = PENDING_DETECTIONS.lock()
        && pending.len() < MAX_PENDING_DETECTIONS
    {
        pending.push(event.clone());
        return;
    }
    // No worker (or it is stuck): the report still goes out, without a kill chain.
    stream_behavior_telemetry_inner(behavior_from_openedr_detection(event), None, false);
}

/// The behavior record of an OpenEDR detection event (field paths as the ptm
/// policies write them: process.pid / process.id, process.imageFile.*, cmdLine).
fn behavior_from_openedr_detection(event: &serde_json::Value) -> BehaviorTelemetryPayload {
    let detection = event_str(event, &["type", "eventType", "title"]).unwrap_or_else(|| "OpenEDR.Detection".to_string());
    let pid = openedr_detection_pid(event);
    let exe_path = event_str(
        event,
        &[
            "process.imageFile.path",
            "process.imageFile.rawPath",
            "process.imageFile.abstractPath",
            "process.imagePath",
            "quarantineTarget",
        ],
    )
    .unwrap_or_default();
    let process_name = exe_path
        .rsplit(['\\', '/'])
        .next()
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .or_else(|| event_str(event, &["process.name"]))
        .unwrap_or_else(|| "unknown".to_string());
    let command_line = event_str(event, &["process.cmdLine", "childProcess.cmdLine"]).unwrap_or_default();
    let sha256 = event_str(event, &["process.imageFile.rawHash", "process.imageFile.hash", "process.imageHash"])
        .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|h| h.to_ascii_lowercase())
        .unwrap_or_default();

    let mut indicators = vec![format!("OpenEDR policy: {detection}")];
    if let Some(base) = event_str(event, &["baseType"]) {
        indicators.push(format!("baseType: {base}"));
    }
    if let Some(target) = event_str(event, &["quarantineTarget"]) {
        indicators.push(format!("target: {target}"));
    }
    let child_cmd = event_str(event, &["childProcess.cmdLine"]);

    let raw_len = serde_json::to_vec(event).map(|b| b.len()).unwrap_or(usize::MAX);
    let details = if raw_len <= MAX_DETECTION_DETAILS_BYTES {
        serde_json::json!({ "openedr_event": event, "child_cmdline": child_cmd })
    } else {
        serde_json::json!({ "openedr_event_omitted_bytes": raw_len, "child_cmdline": child_cmd })
    };

    BehaviorTelemetryPayload {
        machine_id: get_machine_guid(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        pid,
        gid: 0,
        process_name,
        exe_path,
        command_line,
        sha256,
        parent_pid: None,
        parent_name: None,
        detection,
        source: "openedr_detnotif".to_string(),
        // A policy detection is a verdict, not a score: OpenEDR acted on it.
        risk_score: 1.0,
        indicators,
        ops_summary: None,
        details,
    }
}

#[cfg(test)]
mod openedr_detection_tests {
    use super::*;

    #[test]
    fn godmode_detection_becomes_a_behavior_record() {
        // Shape of MLE_GODMODE_ACTIVITY as ptm.local.src builds it.
        let event = serde_json::json!({
            "type": "MLE_GODMODE_ACTIVITY",
            "baseType": 1000016,
            "process": {
                "id": 4242,
                "cmdLine": "cmd.exe /c start shell:::{ED7BA470-8E54-465E-825C-99712043E01C}",
                "imageFile": { "path": "C:\\Windows\\System32\\cmd.exe",
                               "rawHash": "AB".repeat(32) }
            },
            "childProcess": { "cmdLine": "explorer.exe GodMode" },
            "quarantineTarget": ""
        });
        let p = behavior_from_openedr_detection(&event);
        assert_eq!(p.detection, "MLE_GODMODE_ACTIVITY");
        assert_eq!(p.pid, 4242);
        assert_eq!(p.process_name, "cmd.exe");
        assert_eq!(p.exe_path, "C:\\Windows\\System32\\cmd.exe");
        assert!(p.command_line.starts_with("cmd.exe /c"));
        assert_eq!(p.sha256, "ab".repeat(32));
        assert_eq!(p.source, "openedr_detnotif");
        assert!(p.risk_score >= 0.75, "server must count it as malicious");
        assert!(p.indicators.iter().any(|i| i == "baseType: 1000016"));
        assert!(!p.indicators.iter().any(|i| i.starts_with("target:")), "empty target is skipped");
        assert_eq!(p.details["child_cmdline"], "explorer.exe GodMode");
        assert!(p.details.get("openedr_event").is_some());
    }

    #[test]
    fn empty_event_still_yields_a_record() {
        let p = behavior_from_openedr_detection(&serde_json::json!({}));
        assert_eq!(p.detection, "OpenEDR.Detection");
        assert_eq!(p.pid, 0);
        assert_eq!(p.process_name, "unknown");
    }

    #[test]
    fn huge_event_is_not_attached() {
        let big = "x".repeat(MAX_DETECTION_DETAILS_BYTES + 1);
        let p = behavior_from_openedr_detection(&serde_json::json!({ "type": "T", "processes": [big] }));
        assert!(p.details.get("openedr_event").is_none());
        assert!(p.details.get("openedr_event_omitted_bytes").is_some());
    }

    #[test]
    fn detection_carries_the_kill_chain_of_its_process_record() {
        let event = serde_json::json!({ "type": "MLE_RANSOM_BEHAVIOR", "process": { "pid": 4242 } });
        assert_eq!(openedr_detection_pid(&event), 4242);
        assert_eq!(openedr_detection_pid(&serde_json::json!({})), 0);

        let mut proc = crate::process::ProcessRecord::new(77, "evil.exe".to_string(), std::path::PathBuf::new());
        proc.pids.insert(4242);
        proc.ops_written = 9;
        proc.fpaths_created.insert(r"C:\Users\x\doc.txt.locked".to_string());
        proc.driver_msg_count = 12;

        let mut p = behavior_from_openedr_detection(&event);
        assert_eq!(p.gid, 0);
        assert!(p.ops_summary.is_none());
        attach_process_killchain(&mut p, &proc);

        assert_eq!(p.gid, 77);
        assert_eq!(p.ops_summary.as_ref().map(|o| o.ops_written), Some(9));
        let trace = &p.details["killchain_trace"];
        assert_eq!(trace["files_created"][0], r"C:\Users\x\doc.txt.locked");
        assert_eq!(trace["driver_msg_count"], 12);
        // The original event stays in the report.
        assert!(p.details.get("openedr_event").is_some());
    }

    #[test]
    fn detections_are_queued_only_while_the_worker_is_alive() {
        // One test owns the global queue: both states are checked in sequence.
        let _ = take_pending_detections();
        set_detection_worker_alive(true);
        stream_openedr_detection_async(&serde_json::json!({ "type": "QUEUED_ONE" }));
        let pending = take_pending_detections();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["type"], "QUEUED_ONE");
        assert!(take_pending_detections().is_empty(), "the queue is drained by a take");
        set_detection_worker_alive(false);
    }
}

/// Stream Sigma/Hayabusa event log threat detection to VirusKov cloud.
pub fn stream_sigma_detection_async(
    rule_title: &str,
    level: &str,
    details: serde_json::Value,
) {
    let machine_id = get_machine_guid();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let risk_score = match level.to_ascii_lowercase().as_str() {
        "critical" => 1.0,
        "high" => 0.85,
        "medium" => 0.6,
        _ => 0.3,
    };

    let payload = BehaviorTelemetryPayload {
        machine_id,
        timestamp: now_ts,
        pid: 0,
        gid: 0,
        process_name: "winevt/hayabusa".to_string(),
        exe_path: r"C:\Windows\System32\winevt\Logs".to_string(),
        command_line: format!("Sigma Rule: {}", rule_title),
        sha256: String::new(),
        parent_pid: None,
        parent_name: None,
        detection: format!("Sigma.{}", rule_title.replace(' ', ".")),
        source: "sigma_event_log".to_string(),
        risk_score,
        indicators: vec![
            format!("Sigma Level: {}", level),
            format!("Rule Title: {}", rule_title),
        ],
        ops_summary: None,
        details: serde_json::json!({
            "engine": "hayabusa_sigma",
            "rule_title": rule_title,
            "level": level,
            "event_details": details,
        }),
    };

    // If level is critical or high, notify the Pascal GUI via HIPS pipe too
    if level.eq_ignore_ascii_case("critical") || level.eq_ignore_ascii_case("high") {
        send_threat_alert(
            &format!("Sigma: {}", rule_title),
            r"C:\Windows\System32\winevt\Logs",
            false,
        );
    }

    stream_behavior_telemetry_async(payload, None);
}

/// Best-effort on-alert thread stack capture for forensic telemetry.
/// 1. Tries host export `OwlyCaptureThreadStacks` if running inside edrsvc.
/// 2. Falls back to ToolHelp thread snapshot and context register inspection (RIP/RSP).
#[cfg(target_os = "windows")]
pub fn capture_process_thread_stacks(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }

    // 1. Try host C++ function if exported
    unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        if let Ok(h_mod) = GetModuleHandleW(None) {
            if !h_mod.is_invalid() {
                let sym = std::ffi::CString::new("OwlyCaptureThreadStacks").ok();
                if let Some(s) = sym {
                    let proc_addr = GetProcAddress(h_mod, windows::core::PCSTR(s.as_ptr() as *const u8));
                    if let Some(f) = proc_addr {
                        let func: extern "C" fn(u32, *mut u8, u32) -> u32 = std::mem::transmute(f);
                        let mut buf = vec![0u8; 8192];
                        let n = func(pid, buf.as_mut_ptr(), buf.len() as u32);
                        if n > 0 {
                            buf.truncate(n as usize);
                            if let Ok(st) = String::from_utf8(buf) {
                                if !st.trim().is_empty() {
                                    return Some(st);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Native ToolHelp thread capture fallback
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Diagnostics::Debug::GetThreadContext;
        use windows::Win32::System::Threading::{
            GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread,
            SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
        };

        let self_pid = GetCurrentProcessId();
        let self_tid = GetCurrentThreadId();
        if pid == self_pid {
            return None;
        }

        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let mut tids = Vec::with_capacity(8);
        let mut te = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(snap, &mut te).as_bool() {
            loop {
                if te.th32OwnerProcessID == pid && te.th32ThreadID != self_tid {
                    tids.push(te.th32ThreadID);
                    if tids.len() >= 8 {
                        break;
                    }
                }
                if !Thread32Next(snap, &mut te).as_bool() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);

        if tids.is_empty() {
            return None;
        }

        let mut out = String::with_capacity(1024);
        for tid in tids {
            if let Ok(h_thread) = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, false, tid) {
                if !h_thread.is_invalid() {
                    let prev_suspend = SuspendThread(h_thread);
                    if prev_suspend != u32::MAX {
                        #[cfg(target_arch = "x86_64")]
                        {
                            use windows::Win32::System::Diagnostics::Debug::CONTEXT;
                            let mut ctx = std::mem::zeroed::<CONTEXT>();
                            ctx.ContextFlags = 0x00100000 | 0x00000001 | 0x00000002; // CONTEXT_CONTROL
                            if GetThreadContext(h_thread, &mut ctx).as_bool() {
                                if !out.is_empty() {
                                    out.push(';');
                                }
                                out.push_str(&format!("tid={}:rip=0x{:x},rsp=0x{:x}", tid, ctx.Rip, ctx.Rsp));
                            }
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        {
                            if !out.is_empty() {
                                out.push(';');
                            }
                            out.push_str(&format!("tid={}", tid));
                        }
                        let _ = ResumeThread(h_thread);
                    }
                    let _ = CloseHandle(h_thread);
                }
            }
        }

        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn capture_process_thread_stacks(_pid: u32) -> Option<String> {
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDiagnosticTelemetry {
    pub machine_id: String,
    pub timestamp: String,
    pub hostname: String,
    pub os_version: String,
    pub monitored_processes_count: usize,
    pub rootkit_findings_count: usize,
    pub processes: Vec<serde_json::Value>,
}

/// Stream system diagnostic report telemetry to VirusKov cloud.
pub fn stream_system_report_async(report: &crate::report::SystemReport) {
    let machine_id = get_machine_guid();
    let procs: Vec<serde_json::Value> = report
        .monitored_processes
        .iter()
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "gid": p.gid,
                "name": p.name,
                "path": p.path,
                "cmdline": p.command_line,
                "state": p.process_state,
                "ops_read": p.ops_read,
                "ops_written": p.ops_written,
                "is_malicious": p.is_malicious,
                "detections": p.detections,
            })
        })
        .collect();

    let diag = SystemDiagnosticTelemetry {
        machine_id: machine_id.clone(),
        timestamp: report.timestamp.clone(),
        hostname: report.hostname.clone(),
        os_version: report.os_version.clone(),
        monitored_processes_count: report.monitored_processes.len(),
        rootkit_findings_count: report.rootkit_findings.len(),
        processes: procs,
    };

    let _ = std::thread::Builder::new()
        .name("edr-system-telemetry".into())
        .spawn(move || {
            let target = resolve_server_target();
            let path = format!("{}/api/v1/edr/telemetry/system", target.path_prefix);
            let json_body = match serde_json::to_vec(&diag) {
                Ok(b) => b,
                Err(_) => return,
            };
            let mut headers = vec![
                ("Content-Type", "application/json"),
                ("User-Agent", "VirusKov-EDR-Feedback/1.0"),
                ("X-Machine-ID", machine_id.as_str()),
                ("X-Endpoint-ID", machine_id.as_str()),
            ];
            let api_key_opt = std::env::var("VIRUSKOV_API_KEY").ok();
            if let Some(ref key) = api_key_opt {
                headers.push(("X-API-Key", key.as_str()));
            }
            let res = winhttp_post(
                &target.host,
                target.port,
                target.is_https,
                &path,
                &headers,
                &json_body,
            );
            log_telemetry_outcome("system report", &LAST_SYSTEM_STATUS, &res);
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

    #[test]
    fn own_loopback_flow_needs_loopback_ends_and_image_under_install_root() {
        use std::net::IpAddr;
        let root = std::path::Path::new(r"C:\Program Files\HydraDragonAntivirus\OpenEDR");
        let lo4: IpAddr = "127.0.0.1".parse().unwrap();
        let lo6: IpAddr = "::1".parse().unwrap();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let lan: IpAddr = "192.168.1.5".parse().unwrap();
        let svc = r"C:\Program Files\HydraDragonAntivirus\OpenEDR\edrsvc.exe";
        let gui = r"c:\program files\hydradragonantivirus\openedr\EDRGUI.EXE";
        let sub = r"C:\Program Files\HydraDragonAntivirus\OpenEDR\Sanctum\um_engine.exe";

        // Own components talking over loopback: left out.
        assert!(is_loopback_flow_of_image_under(&lo4, &lo4, svc, root));
        assert!(is_loopback_flow_of_image_under(&lo6, &lo6, gui, root));
        assert!(is_loopback_flow_of_image_under(&lo4, &mapped, sub, root));

        // Own component talking to a remote address: kept.
        assert!(!is_loopback_flow_of_image_under(&lo4, &lan, svc, root));
        assert!(!is_loopback_flow_of_image_under(&lan, &lo4, svc, root));

        // Another process on loopback, even one that borrows the name: kept.
        assert!(!is_loopback_flow_of_image_under(&lo4, &lo4, r"C:\Users\x\AppData\Local\Temp\edrsvc.exe", root));
        assert!(!is_loopback_flow_of_image_under(&lo4, &lo4, r"C:\Program Files\HydraDragonAntivirus\OpenEDR-evil\edrsvc.exe", root));
        assert!(!is_loopback_flow_of_image_under(&lo4, &lo4, r"C:\Windows\System32\svchost.exe", root));

        // Unknown image or root: kept.
        assert!(!is_loopback_flow_of_image_under(&lo4, &lo4, "", root));
        assert!(!is_loopback_flow_of_image_under(&lo4, &lo4, svc, std::path::Path::new("")));
    }
}
