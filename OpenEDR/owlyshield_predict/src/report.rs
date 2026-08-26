use crate::config::Config;
use crate::globals;

use crate::utils::resolve_process_path;
use chrono::Local;
use std::fs;
use std::path::{Path, PathBuf};

use winreg::RegKey;

use winreg::enums::*;

#[derive(Debug, Clone, Default)]
pub struct SystemReport {
    pub timestamp: String,
    pub hostname: String,
    pub os_version: String,
    pub startups: Vec<StartupEntry>,
    pub hosts_entries: Vec<String>,
    pub monitored_processes: Vec<ProcessSnapshot>,
    pub av_status: AVIntegrationStatus,
    pub network_listeners: Vec<NetworkListener>,
    pub kernel_drivers: Vec<DriverEntry>,
    pub browser_extensions: Vec<ExtensionEntry>,
    pub rootkit_findings: Vec<RootkitEntry>,
}

#[derive(Debug, Clone)]
pub struct StartupEntry {
    pub location: String,
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub gid: u32,
    pub name: String,
    pub path: String,
    pub command_line: Option<String>,
    pub process_state: String,
    pub total_ops: u64,
    pub high_entropy_files: usize,
    pub driver_message_count: usize,
    pub ops_read: u64,
    pub ops_written: u64,
    pub ops_open: u64,
    pub ops_setinfo: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub files_created: usize,
    pub files_updated: usize,
    pub files_deleted: usize,
    pub directories_touched: usize,
    pub is_malicious: bool,
    pub detections: Vec<String>,
    pub detection_details: Option<String>,
    pub named_conditions: Vec<String>,
    pub detected_apis: Vec<String>,
    pub network_targets: Vec<String>,
    pub rootkit_implicated: bool,
    pub rootkit_findings: Vec<String>,
    pub remediation_target: Option<String>,
    pub signature_summary: String,
    pub sample_created_paths: Vec<String>,
    pub sample_updated_paths: Vec<String>,
    pub restart_cleanup_requested: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AVIntegrationStatus {
    pub is_enabled: bool,
    pub service_running: bool,
    pub config_exists: bool,
    pub signatures_count: usize,
}

#[derive(Debug, Clone)]
pub struct NetworkListener {
    pub protocol: String,
    pub local_addr: String,
    pub process_name: String,
    pub pid: u32,
    pub process_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DriverEntry {
    pub name: String,
    pub display_name: String,
    pub path: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct ExtensionEntry {
    pub browser: String,
    pub name: String,
    pub id: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct RootkitEntry {
    pub label: String,
    pub description: String,
    pub address: u64,
    pub pid: u32,
    pub severity: u8,
}

impl SystemReport {
    fn sort_sections(&mut self) {
        self.startups.sort_by(|a, b| {
            a.location
                .cmp(&b.location)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.command.cmp(&b.command))
        });
        self.hosts_entries.sort();
        self.network_listeners.sort_by(|a, b| {
            a.process_name
                .cmp(&b.process_name)
                .then_with(|| a.pid.cmp(&b.pid))
                .then_with(|| a.local_addr.cmp(&b.local_addr))
        });
        self.kernel_drivers
            .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));
        self.browser_extensions.sort_by(|a, b| {
            a.browser
                .cmp(&b.browser)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.id.cmp(&b.id))
        });
        self.monitored_processes.sort_by(|a, b| {
            b.is_malicious
                .cmp(&a.is_malicious)
                .then_with(|| b.detections.len().cmp(&a.detections.len()))
                .then_with(|| b.total_ops.cmp(&a.total_ops))
                .then_with(|| b.high_entropy_files.cmp(&a.high_entropy_files))
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        self.rootkit_findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.label.cmp(&b.label))
                .then_with(|| a.pid.cmp(&b.pid))
        });
    }

    fn format_bytes(bytes: u64) -> String {
        const KB: f64 = 1024.0;
        const MB: f64 = KB * 1024.0;
        const GB: f64 = MB * 1024.0;

        let value = bytes as f64;
        if value >= GB {
            format!("{:.2} GB", value / GB)
        } else if value >= MB {
            format!("{:.2} MB", value / MB)
        } else if value >= KB {
            format!("{:.2} KB", value / KB)
        } else {
            format!("{} B", bytes)
        }
    }

    fn push_sample_lines(s: &mut String, label: &str, values: &[String]) {
        if values.is_empty() {
            return;
        }

        s.push_str(&format!("    {}:\n", label));
        for value in values {
            s.push_str(&format!("      - {}\n", value));
        }
    }

    pub fn collect(_config: &Config) -> Self {
        let mut report = SystemReport::default();
        report.av_status.signatures_count = 0;
        report.timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        report.hostname = hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "Unknown".into());

        {
            report.os_version = "Windows".to_string();
            report.collect_windows_startups();
            report.collect_hosts_file();
            report.collect_network_listeners(None);
            report.collect_kernel_drivers();
            report.collect_browser_extensions();
        }

        report.sort_sections();
        report
    }

    fn collect_windows_startups(&mut self) {
        let registry_paths = [
            (
                HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Run",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\RunOnce",
            ),
            (
                HKEY_CURRENT_USER,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Run",
            ),
            (
                HKEY_CURRENT_USER,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\RunOnce",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Run (x64)",
            ),
        ];

        for (hive, path, label) in registry_paths {
            let hk = RegKey::predef(hive);
            if let Ok(key) = hk.open_subkey(path) {
                for i in key.enum_values().flatten() {
                    let (name, value) = i;
                    self.startups.push(StartupEntry {
                        location: label.to_string(),
                        name,
                        command: value.to_string(),
                    });
                }
            }
        }

        // Folders
        if let Ok(appdata) = std::env::var("APPDATA") {
            let user_startup =
                Path::new(&appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            self.collect_folder_startups(&user_startup, "User Startup Folder");
        }
        if let Ok(programdata) = std::env::var("PROGRAMDATA") {
            let common_startup =
                Path::new(&programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            self.collect_folder_startups(&common_startup, "Common Startup Folder");
        }
    }

    fn collect_folder_startups(&mut self, path: &Path, label: &str) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_file() {
                        self.startups.push(StartupEntry {
                            location: label.to_string(),
                            name: entry.file_name().to_string_lossy().into_owned(),
                            command: entry.path().to_string_lossy().into_owned(),
                        });
                    }
                }
            }
        }
    }

    fn collect_hosts_file(&mut self) {
        let path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    self.hosts_entries.push(trimmed.to_string());
                }
            }
        }
    }

    fn collect_network_listeners(
        &mut self,
        firewall_pids: Option<&std::collections::HashSet<u32>>,
    ) {
        if let Some(pids) = firewall_pids {
            for &pid in pids {
                let process_path = resolve_process_path(pid)
                    .map(|path: std::path::PathBuf| path.to_string_lossy().into_owned());
                let process_name = process_path
                    .as_ref()
                    .and_then(|path| {
                        Path::new(path)
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                    })
                    .unwrap_or_else(|| "Firewall-Observed Process".to_string());
                self.network_listeners.push(NetworkListener {
                    protocol: "TCP/UDP (Firewall)".to_string(),
                    local_addr: "0.0.0.0:*".to_string(),
                    process_name,
                    pid: pid,
                    process_path,
                });
            }
        }

        // Use firewall-observed PIDs for the report
    }

    fn collect_kernel_drivers(&mut self) {
        let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(services) = hk.open_subkey("SYSTEM\\CurrentControlSet\\Services") {
            for name in services.enum_keys().flatten() {
                if let Ok(svc) = services.open_subkey(&name) {
                    let svc_type: u32 = svc.get_value("Type").unwrap_or(0);
                    if svc_type == 1 || svc_type == 2 {
                        // Kernel Driver or File System Driver
                        let display_name: String = svc
                            .get_value("DisplayName")
                            .unwrap_or_else(|_| name.clone());
                        let image_path: String = svc.get_value("ImagePath").unwrap_or_default();
                        self.kernel_drivers.push(DriverEntry {
                            name: name.clone(),
                            display_name,
                            path: image_path,
                            state: "Loaded/Registered".to_string(),
                        });
                    }
                }
            }
        }
    }

    fn collect_browser_extensions(&mut self) {
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let chrome_ext =
                Path::new(&local_appdata).join("Google\\Chrome\\User Data\\Default\\Extensions");
            self.scan_extension_dir(&chrome_ext, "Google Chrome");

            let edge_ext =
                Path::new(&local_appdata).join("Microsoft\\Edge\\User Data\\Default\\Extensions");
            self.scan_extension_dir(&edge_ext, "Microsoft Edge");
        }
    }

    fn scan_extension_dir(&mut self, path: &Path, browser: &str) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let id = entry.file_name().to_string_lossy().into_owned();
                self.browser_extensions.push(ExtensionEntry {
                    browser: browser.to_string(),
                    name: "Unknown Extension".to_string(), // Would need manifest.json parsing for real name
                    id,
                    path: entry.path().to_string_lossy().into_owned(),
                });
            }
        }
    }

    pub fn to_hijackthis_string(&self) -> String {
        let mut s = String::new();
        let malicious_processes = self
            .monitored_processes
            .iter()
            .filter(|p| p.is_malicious)
            .count();
        let processes_with_detections = self
            .monitored_processes
            .iter()
            .filter(|p| !p.detections.is_empty())
            .count();
        let active_processes = self
            .monitored_processes
            .iter()
            .filter(|p| p.total_ops > 0 || p.high_entropy_files > 0)
            .count();

        s.push_str(&format!(
            "HydraDragon Owlyshield Advanced System Report - {}\n",
            self.timestamp
        ));
        s.push_str("------------------------------------------------------------------\n");
        s.push_str(&format!("Hostname: {}\n", self.hostname));
        s.push_str(&format!("OS: {}\n\n", self.os_version));

        s.push_str("-- Summary --\n");
        s.push_str(&format!(
            "Tracked Processes: {} (Malicious: {}, With Detections: {}, Active: {})\n",
            self.monitored_processes.len(),
            malicious_processes,
            processes_with_detections,
            active_processes
        ));
        s.push_str(&format!("Startup Entries: {}\n", self.startups.len()));
        s.push_str(&format!("Hosts Entries: {}\n", self.hosts_entries.len()));
        s.push_str(&format!(
            "Firewall Listener PIDs: {}\n",
            self.network_listeners.len()
        ));
        s.push_str(&format!("Kernel Drivers: {}\n", self.kernel_drivers.len()));
        s.push_str(&format!(
            "Browser Extensions: {}\n",
            self.browser_extensions.len()
        ));
        s.push_str(&format!(
            "Rootkit Findings: {}\n\n",
            self.rootkit_findings.len()
        ));

        s.push_str("-- HydraDragon Integration (O24) --\n");
        s.push_str(&format!("O24 - Firewall Status: Enabled\n"));
        s.push_str(&format!(
            "O24 - AV Integration: {}\n",
            if self.av_status.is_enabled {
                "ACTIVE"
            } else {
                "NOT_ENABLED"
            }
        ));
        s.push_str(&format!(
            "O24 - AV Service Running: {}\n",
            self.av_status.service_running
        ));
        s.push_str(&format!(
            "O24 - AV Config Found: {}\n",
            self.av_status.config_exists
        ));
        s.push_str(&format!(
            "O24 - AV Signatures Loaded: {}\n\n",
            self.av_status.signatures_count
        ));

        s.push_str(&format!(
            "-- Hosts File (O1, {} entries) --\n",
            self.hosts_entries.len()
        ));
        if self.hosts_entries.is_empty() {
            s.push_str("O1 - No non-comment hosts entries found.\n");
        } else {
            for entry in &self.hosts_entries {
                s.push_str(&format!("O1 - {}\n", entry));
            }
        }
        s.push_str("\n");

        s.push_str(&format!(
            "-- Registry/Startup (O4, {} entries) --\n",
            self.startups.len()
        ));
        if self.startups.is_empty() {
            s.push_str("O4 - No startup entries found.\n");
        } else {
            for entry in &self.startups {
                s.push_str(&format!(
                    "O4 - {}: [{}] {}\n",
                    entry.location, entry.name, entry.command
                ));
            }
        }
        s.push_str("\n");

        s.push_str(&format!(
            "-- Network Listeners (O17, {} entries) --\n",
            self.network_listeners.len()
        ));
        if self.network_listeners.is_empty() {
            s.push_str("O17 - No firewall-observed listeners found.\n");
        } else {
            for l in &self.network_listeners {
                if let Some(path) = &l.process_path {
                    s.push_str(&format!(
                        "O17 - {} - {} (PID: {}) [{}] ({})\n",
                        l.protocol, l.local_addr, l.pid, l.process_name, path
                    ));
                } else {
                    s.push_str(&format!(
                        "O17 - {} - {} (PID: {}) [{}]\n",
                        l.protocol, l.local_addr, l.pid, l.process_name
                    ));
                }
            }
        }
        s.push_str("\n");

        s.push_str(&format!(
            "-- Kernel Drivers (O18, {} entries) --\n",
            self.kernel_drivers.len()
        ));
        if self.kernel_drivers.is_empty() {
            s.push_str("O18 - No kernel drivers found.\n");
        } else {
            for d in &self.kernel_drivers {
                s.push_str(&format!(
                    "O18 - {}: {} [{}] ({})\n",
                    d.name, d.display_name, d.path, d.state
                ));
            }
        }
        s.push_str("\n");

        s.push_str(&format!(
            "-- Browser Extensions (O23, {} entries) --\n",
            self.browser_extensions.len()
        ));
        if self.browser_extensions.is_empty() {
            s.push_str("O23 - No browser extensions found.\n");
        } else {
            for e in &self.browser_extensions {
                s.push_str(&format!(
                    "O23 - {}: {} [ID: {}] ({})\n",
                    e.browser, e.name, e.id, e.path
                ));
            }
        }
        s.push_str("\n");

        s.push_str(&format!(
            "-- Monitored Processes behavioral snapshot ({} tracked, {} malicious, {} with detections, {} active) --\n",
            self.monitored_processes.len(),
            malicious_processes,
            processes_with_detections,
            active_processes,
        ));
        if self.monitored_processes.is_empty() {
            s.push_str("P - No tracked processes in snapshot.\n");
        }
        for m in &self.monitored_processes {
            let status = if m.is_malicious {
                "!!! MALICIOUS !!!"
            } else {
                "Clean"
            };
            s.push_str(&format!(
                "P {} - G {} - {} [{}]\n",
                m.pid, m.gid, m.name, status
            ));
            s.push_str(&format!("    Path: {}\n", m.path));
            s.push_str(&format!(
                "    State: {} | Signature: {}\n",
                m.process_state, m.signature_summary
            ));
            s.push_str(&format!(
                "    Activity: total_ops={} driver_msgs={} high_entropy={}\n",
                m.total_ops, m.driver_message_count, m.high_entropy_files
            ));
            s.push_str(&format!(
                "    IRP Counters: read={} write={} open={} setinfo={}\n",
                m.ops_read, m.ops_written, m.ops_open, m.ops_setinfo
            ));
            s.push_str(&format!(
                "    Bytes: read={} written={}\n",
                Self::format_bytes(m.bytes_read),
                Self::format_bytes(m.bytes_written)
            ));
            s.push_str(&format!(
                "    Files: created={} updated={} deleted={} dirs_touched={}\n",
                m.files_created, m.files_updated, m.files_deleted, m.directories_touched
            ));
            if let Some(cmdline) = &m.command_line
                && !cmdline.trim().is_empty()
            {
                s.push_str(&format!("    Command Line: {}\n", cmdline));
            }
            if let Some(remediation_target) = &m.remediation_target {
                s.push_str(&format!("    Remediation Target: {}\n", remediation_target));
            }
            if m.restart_cleanup_requested {
                s.push_str("    Restart Cleanup: QUEUED\n");
            }
            if !m.network_targets.is_empty() {
                s.push_str(&format!(
                    "    Network Targets: {}\n",
                    m.network_targets.join(", ")
                ));
            }
            if !m.detected_apis.is_empty() {
                s.push_str(&format!(
                    "    Detected APIs: {}\n",
                    m.detected_apis.join(", ")
                ));
            }
            if !m.named_conditions.is_empty() {
                s.push_str(&format!(
                    "    Named Conditions: {}\n",
                    m.named_conditions.join(", ")
                ));
            }
            for det in &m.detections {
                s.push_str(&format!("    - [DETECTION]: {}\n", det));
            }
            if let Some(details) = &m.detection_details
                && !details.trim().is_empty()
            {
                s.push_str(&format!("    Detection Details: {}\n", details));
            }
            if m.rootkit_implicated {
                s.push_str("    Rootkit Implicated: YES\n");
            }
            if !m.rootkit_findings.is_empty() {
                for finding in &m.rootkit_findings {
                    s.push_str(&format!("    - [ROOTKIT]: {}\n", finding));
                }
            }
            Self::push_sample_lines(&mut s, "Sample Created Paths", &m.sample_created_paths);
            Self::push_sample_lines(&mut s, "Sample Updated Paths", &m.sample_updated_paths);
            s.push('\n');
        }
        s.push_str("\n");

        s.push_str(&format!(
            "-- Rootkit Detection Findings (O25, {} entries) --\n",
            self.rootkit_findings.len()
        ));
        if self.rootkit_findings.is_empty() {
            s.push_str("O25 - No rootkit activity detected.\n");
        } else {
            for f in &self.rootkit_findings {
                let sev_str = match f.severity {
                    3 => "CRITICAL",
                    2 => "HIGH",
                    1 => "MEDIUM",
                    _ => "LOW",
                };
                s.push_str(&format!(
                    "O25 - [{}] {}: {} (Addr: 0x{:X}, PID: {})\n",
                    sev_str, f.label, f.description, f.address, f.pid
                ));
            }
        }

        s
    }

    pub fn save_to_file(&self) -> Result<PathBuf, std::io::Error> {
        let report_dir = globals::report_dir();
        fs::create_dir_all(report_dir)?;

        let filename = format!(
            "HydraDragon_Advanced_Report_{}.log",
            Local::now().format("%Y%m%d_%H%M%S")
        );
        let path = report_dir.join(filename);

        fs::write(&path, self.to_hijackthis_string())?;
        Ok(path)
    }
}
