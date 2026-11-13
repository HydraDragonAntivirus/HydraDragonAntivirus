use std::path::{Path, PathBuf};
use std::time::Instant;
use serde::{Deserialize, Serialize};

pub const DEFAULT_WINDOWS_HOSTS_TEMPLATE: &str = r#"# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostsEntry {
    pub ip: String,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostsCheckReport {
    pub hosts_path: String,
    pub exists: bool,
    pub is_modified: bool,
    pub total_entries: usize,
    pub entries: Vec<HostsEntry>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostsRestoreReport {
    pub hosts_path: String,
    pub success: bool,
    pub backup_path: Option<String>,
    pub message: String,
}

pub fn get_default_hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            return PathBuf::from(sysroot).join(r"System32\drivers\etc\hosts");
        }
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Check if the hosts file has any modifications compared to default Windows hosts.
pub fn check_hosts_file(custom_path: Option<&Path>) -> HostsCheckReport {
    let t0 = Instant::now();
    let path = custom_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(get_default_hosts_path);
    let path_str = path.display().to_string();

    if !path.exists() {
        return HostsCheckReport {
            hosts_path: path_str,
            exists: false,
            is_modified: false,
            total_entries: 0,
            entries: Vec::new(),
            scan_time_ms: t0.elapsed().as_millis() as u64,
        };
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            return HostsCheckReport {
                hosts_path: path_str,
                exists: true,
                is_modified: false,
                total_entries: 0,
                entries: Vec::new(),
                scan_time_ms: t0.elapsed().as_millis() as u64,
            };
        }
    };

    let mut entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Remove inline comments
        let line_no_comment = if let Some(idx) = trimmed.find('#') {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        let parts: Vec<&str> = line_no_comment.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ip = parts[0].trim().to_lowercase();
        let is_loopback = ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip.starts_with("127.");

        for &domain_raw in &parts[1..] {
            let domain = domain_raw.trim().to_lowercase();
            if domain.is_empty() {
                continue;
            }

            // Standard default localhost mapping is not considered a modification
            if (domain == "localhost" || domain == "localhost.localdomain") && is_loopback {
                continue;
            }

            entries.push(HostsEntry {
                ip: ip.clone(),
                domain,
            });
        }
    }

    let total_entries = entries.len();
    let is_modified = total_entries > 0;

    HostsCheckReport {
        hosts_path: path_str,
        exists: true,
        is_modified,
        total_entries,
        entries,
        scan_time_ms: t0.elapsed().as_millis() as u64,
    }
}

/// Restore the hosts file back to the clean default Microsoft Windows template.
/// Optionally creates a timestamped backup before replacing.
pub fn restore_hosts_file(custom_path: Option<&Path>, create_backup: bool) -> HostsRestoreReport {
    let path = custom_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(get_default_hosts_path);
    let path_str = path.display().to_string();

    let mut backup_path_str = None;

    if path.exists() && create_backup {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bak_path = path.with_extension(format!("backup_{}", ts));
        if std::fs::copy(&path, &bak_path).is_ok() {
            backup_path_str = Some(bak_path.display().to_string());
        }
    }

    // Ensure write permissions
    if path.exists() {
        if let Ok(metadata) = std::fs::metadata(&path) {
            let mut perms = metadata.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(&path, perms);
        }
    }

    match std::fs::write(&path, DEFAULT_WINDOWS_HOSTS_TEMPLATE) {
        Ok(_) => {
            // Flush DNS cache on Windows
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("ipconfig")
                    .arg("/flushdns")
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .output();
            }

            HostsRestoreReport {
                hosts_path: path_str,
                success: true,
                backup_path: backup_path_str,
                message: "Hosts file successfully restored to clean Microsoft Windows default.".to_string(),
            }
        }
        Err(e) => HostsRestoreReport {
            hosts_path: path_str,
            success: false,
            backup_path: backup_path_str,
            message: format!("Failed to restore hosts file (Administrator privileges required): {}", e),
        },
    }
}
