//! Process Utilities module
//!
//! Provides process manipulation utilities for testing malware behaviour.
//! This module is available when the `processutils` feature is enabled.

#![cfg(feature = "processutils")]

use crate::{Result, SignatureMonsterError};
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Process utilities for testing
pub struct ProcessUtils {
    _private: (),
}

impl ProcessUtils {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Check if the current process is running as administrator
    pub fn is_admin(&self) -> bool {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ])
            .output();

        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_lowercase() == "true",
            Err(_) => false,
        }
    }

    /// Get the current process integrity level
    pub fn get_integrity_level(&self) -> Result<String> {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                r#"
                $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = New-Object Security.Principal.WindowsPrincipal($identity)
                if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    'High'
                } elseif ($identity.IsSystem) {
                    'System'
                } else {
                    'Medium'
                }
                "#,
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get the PC uptime in seconds
    pub fn get_uptime_seconds(&self) -> Result<u64> {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime | ForEach-Object { [int]((Get-Date) - $_).TotalSeconds }",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
        result.parse().map_err(|e| SignatureMonsterError::ParseError(format!("Failed to parse uptime: {}", e)))
    }

    /// Check if uptime is suspiciously short (potential sandbox/VM)
    pub fn is_uptime_suspicious(&self, min_minutes: u64) -> Result<bool> {
        let uptime = self.get_uptime_seconds()?;
        Ok(uptime < min_minutes * 60)
    }

    /// Get the count of running processes
    pub fn get_process_count(&self) -> Result<usize> {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-Process).Count",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
        result.parse().map_err(|e| SignatureMonsterError::ParseError(format!("Failed to parse count: {}", e)))
    }

    /// Check if process count is suspiciously low (potential sandbox)
    pub fn is_process_count_suspicious(&self, min_count: usize) -> Result<bool> {
        let count = self.get_process_count()?;
        Ok(count < min_count)
    }

    /// Get all enabled privileges for the current process
    pub fn get_privileges(&self) -> Result<Vec<String>> {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'State' -eq 'Enabled' } | Select-Object -ExpandProperty 'Privilege Name'",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout);
        Ok(result.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }

    /// Check if a specific privilege is enabled
    pub fn has_privilege(&self, privilege: &str) -> Result<bool> {
        let privs = self.get_privileges()?;
        Ok(privs.iter().any(|p| p.to_lowercase() == privilege.to_lowercase()))
    }

    /// Check if SeDebugPrivilege is available (useful for advanced operations)
    pub fn has_debug_privilege(&self) -> Result<bool> {
        self.has_privilege("SeDebugPrivilege")
    }

    /// Get the parent process name
    pub fn get_parent_process_name(&self) -> Result<String> {
        let pid = std::process::id();
        let cmd = format!(
            "(Get-CimInstance Win32_Process -Filter \"ProcessId={}\" | Select-Object -ExpandProperty ParentProcessId) | ForEach-Object {{ (Get-Process -Id $_ -ErrorAction SilentlyContinue).Name }}",
            pid
        );

        let mut cmd_obj = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd_obj.creation_flags(0x08000000);
        }
        let output = cmd_obj
            .args(["-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-Command", &cmd])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Check if parent process is suspicious (e.g., cmd.exe, powershell.exe from unusual parent)
    pub fn is_parent_suspicious(&self) -> Result<bool> {
        let parent = self.get_parent_process_name()?;
        let suspicious_parents = ["python", "pythonw", "wscript", "cscript", "mshta", "regsvr32"];
        Ok(suspicious_parents.iter().any(|&s| parent.to_lowercase().contains(s)))
    }

    /// Check internet connectivity
    pub fn has_internet(&self) -> bool {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet",
            ])
            .output();

        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_lowercase() == "true",
            Err(_) => false,
        }
    }

    /// Get monitor resolution (low resolution might indicate VM)
    pub fn get_screen_resolution(&self) -> Result<(u32, u32)> {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen.Bounds | ForEach-Object { \"$($_.Width)x$($_.Height)\" }",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let parts: Vec<&str> = result.split('x').collect();
        if parts.len() == 2 {
            let width = parts[0].parse().unwrap_or(0);
            let height = parts[1].parse().unwrap_or(0);
            Ok((width, height))
        } else {
            Err(SignatureMonsterError::ParseError("Failed to parse resolution".to_string()))
        }
    }

    /// Check if resolution is suspiciously low (common in VMs)
    pub fn is_resolution_suspicious(&self) -> Result<bool> {
        let (width, height) = self.get_screen_resolution()?;
        // Common VM resolutions are often 800x600 or 1024x768
        Ok(width < 1280 || height < 720)
    }

    /// Get USB device count
    pub fn get_usb_device_count(&self) -> Result<usize> {
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance -ClassName Win32_USBHub).Count",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if result.is_empty() {
            Ok(0)
        } else {
            result.parse().map_err(|e| SignatureMonsterError::ParseError(format!("Failed to parse: {}", e)))
        }
    }

    /// Check if no USB devices are connected (suspicious for analysis VM)
    pub fn is_usb_suspicious(&self) -> Result<bool> {
        let count = self.get_usb_device_count()?;
        Ok(count == 0)
    }
}

impl Default for ProcessUtils {
    fn default() -> Self {
        Self::new()
    }
}
