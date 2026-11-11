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

            let _ = winhttp_post(
                &target.host,
                target.port,
                target.is_https,
                &telemetry_path,
                &headers,
                &json_body,
            );
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
    let mut url_str = std::env::var("VIRUSKOV_API_URL").ok();
    if url_str.is_none() {
        if let Ok(cur_exe) = std::env::current_exe() {
            let dir = cur_exe.parent().unwrap_or(std::path::Path::new("."));
            if let Ok(s) = std::fs::read_to_string(dir.join("viruskov_server.txt")) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    url_str = Some(trimmed.to_string());
                }
            }
        }
    }

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

            if is_ask || (is_threat_verdict && resp.action.as_deref() != Some("ignore")) {
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
            let _ = winhttp_post(
                &target.host,
                target.port,
                target.is_https,
                &path,
                &headers,
                &json_body,
            );
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
