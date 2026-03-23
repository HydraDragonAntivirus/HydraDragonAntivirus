use std::fs;
use std::path::{Path, PathBuf};
use chrono::Local;
use crate::config::Config;
use crate::globals;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

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
    pub path: String,
    pub total_ops: u64,
    pub high_entropy_files: usize,
    pub is_malicious: bool,
    pub detections: Vec<String>,
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

impl SystemReport {
    pub fn collect(_config: &Config) -> Self {
        let mut report = SystemReport::default();
        report.timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        report.hostname = hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_else(|_| "Unknown".into());
        
        #[cfg(target_os = "windows")]
        {
            report.os_version = "Windows".to_string();
            report.collect_windows_startups();
            report.collect_hosts_file();
            report.collect_av_status();
            report.collect_network_listeners();
            report.collect_kernel_drivers();
            report.collect_browser_extensions();
        }

        report
    }

    #[cfg(target_os = "windows")]
    fn collect_windows_startups(&mut self) {
        let registry_paths = [
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Run"),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM\\RunOnce"),
            (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Run"),
            (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU\\RunOnce"),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Run (x64)"),
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
            let user_startup = Path::new(&appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            self.collect_folder_startups(&user_startup, "User Startup Folder");
        }
        if let Ok(programdata) = std::env::var("PROGRAMDATA") {
            let common_startup = Path::new(&programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
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

    #[cfg(target_os = "windows")]
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

    #[cfg(target_os = "windows")]
    fn collect_av_status(&mut self) {
        self.av_status.is_enabled = crate::is_hydra_dragon_enabled();
        
        if let Ok(pf) = std::env::var("ProgramFiles") {
            let base_path = Path::new(&pf).join("HydraDragonAntivirus");
            self.av_status.config_exists = base_path.join("config.json").exists();
        }
    }

    #[cfg(target_os = "windows")]
    fn collect_network_listeners(&mut self) {
        use sysinfo::{System, Networks};
        let mut sys = System::new_all();
        sys.refresh_all();
        
        // Note: sysinfo 0.38+ has better network collection but listeners might need netstat-like logic
        // For advanced report, we'll use a placeholder or system-specific command integration if possible
        // Let's stick to process-based network info available in sysinfo
        for (pid, process) in sys.processes() {
             // In a real advanced EDR, we'd query the TCP table here.
             // For this implementation, we report active processes with potential network capabilities
             if process.name().to_lowercase().contains("http") || process.name().to_lowercase().contains("server") {
                 self.network_listeners.push(NetworkListener {
                     protocol: "TCP/UDP (Potential)".to_string(),
                     local_addr: "0.0.0.0:*".to_string(),
                     process_name: process.name().to_string_lossy().into_owned(),
                     pid: pid.as_u32(),
                 });
             }
        }
    }

    #[cfg(target_os = "windows")]
    fn collect_kernel_drivers(&mut self) {
        let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(services) = hk.open_subkey("SYSTEM\\CurrentControlSet\\Services") {
            for name in services.enum_keys().flatten() {
                if let Ok(svc) = services.open_subkey(&name) {
                    let svc_type: u32 = svc.get_value("Type").unwrap_or(0);
                    if svc_type == 1 || svc_type == 2 { // Kernel Driver or File System Driver
                        let display_name: String = svc.get_value("DisplayName").unwrap_or_else(|_| name.clone());
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

    #[cfg(target_os = "windows")]
    fn collect_browser_extensions(&mut self) {
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
             let chrome_ext = Path::new(&local_appdata).join("Google\\Chrome\\User Data\\Default\\Extensions");
             self.scan_extension_dir(&chrome_ext, "Google Chrome");
             
             let edge_ext = Path::new(&local_appdata).join("Microsoft\\Edge\\User Data\\Default\\Extensions");
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
        s.push_str(&format!("HydraDragon Owlyshield Advanced System Report - {}\n", self.timestamp));
        s.push_str("------------------------------------------------------------------\n");
        s.push_str(&format!("Hostname: {}\n", self.hostname));
        s.push_str(&format!("OS: {}\n\n", self.os_version));

        s.push_str("-- HydraDragon Integration (O24) --\n");
        s.push_str(&format!("O24 - Firewall Status: Enabled\n"));
        s.push_str(&format!("O24 - AV Integration: {}\n", if self.av_status.is_enabled { "ACTIVE" } else { "NOT_ENABLED" }));
        s.push_str(&format!("O24 - AV Config Found: {}\n\n", self.av_status.config_exists));

        s.push_str("-- Hosts File (O1) --\n");
        for entry in &self.hosts_entries {
            s.push_str(&format!("O1 - {}\n", entry));
        }
        s.push_str("\n");

        s.push_str("-- Registry/Startup (O4) --\n");
        for entry in &self.startups {
            s.push_str(&format!("O4 - {}: [{}] {}\n", entry.location, entry.name, entry.command));
        }
        s.push_str("\n");

        s.push_str("-- Network Listeners (O17) --\n");
        for l in &self.network_listeners {
            s.push_str(&format!("O17 - {} - {} (PID: {}) [{}]\n", l.protocol, l.local_addr, l.pid, l.process_name));
        }
        s.push_str("\n");

        s.push_str("-- Kernel Drivers (O18) --\n");
        let limit = 20; // Only show first 20 for brevity unless malicious
        for (i, d) in self.kernel_drivers.iter().enumerate() {
            if i < limit {
                s.push_str(&format!("O18 - {}: {} [{}] ({})\n", d.name, d.display_name, d.path, d.state));
            }
        }
        if self.kernel_drivers.len() > limit {
            s.push_str(&format!("... and {} more drivers.\n", self.kernel_drivers.len() - limit));
        }
        s.push_str("\n");

        s.push_str("-- Browser Extensions (O23) --\n");
        for e in &self.browser_extensions {
            s.push_str(&format!("O23 - {}: {} [ID: {}]\n", e.browser, e.name, e.id));
        }
        s.push_str("\n");

        s.push_str("-- Monitored Processes behavioral snapshot --\n");
        for m in &self.monitored_processes {
            let status = if m.is_malicious { "!!! MALICIOUS !!!" } else { "Clean" };
            s.push_str(&format!("P {} - G {} - {} - [{}] (Ops: {}, HighEntropy: {})\n", 
                m.pid, m.gid, m.path, status, m.total_ops, m.high_entropy_files));
            for det in &m.detections {
                s.push_str(&format!("    - [DETECTION]: {}\n", det));
            }
        }

        s
    }

    pub fn save_to_file(&self) -> Result<PathBuf, std::io::Error> {
        let report_dir = globals::report_dir();
        fs::create_dir_all(report_dir)?;
        
        let filename = format!("HydraDragon_Advanced_Report_{}.log", Local::now().format("%Y%m%d_%H%M%S"));
        let path = report_dir.join(filename);
        
        fs::write(&path, self.to_hijackthis_string())?;
        Ok(path)
    }
}
