//! Disk drive checking module
//!
//! Provides functions to enumerate and check disk drive models.

use crate::{Result, SignatureMonsterError};
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Disk checker
pub struct DiskChecker {
    _private: (),
}

impl DiskChecker {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn run_powershell(&self, cmd: &str) -> Result<String> {
        let mut cmd_obj = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd_obj.creation_flags(0x08000000);
        }
        let output = cmd_obj
            .args(["-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-Command", cmd])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        if !output.status.success() {
            return Err(SignatureMonsterError::PowerShellError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    /// List all disk drives
    pub fn list_drives(&self) -> Result<Vec<DiskInfo>> {
        let output = self.run_powershell(
            "Get-CimInstance -ClassName Win32_DiskDrive | Select-Object Model, SerialNumber, Size, MediaType, InterfaceType | ConvertTo-Json -Compress"
        )?;

        if output.is_empty() || output == "null" {
            return Ok(Vec::new());
        }

        let disks: Vec<DiskInfo> = serde_json::from_str(&output)
            .or_else(|_| {
                let single: DiskInfo = serde_json::from_str(&output)?;
                Ok::<_, serde_json::Error>(vec![single])
            })
            .unwrap_or_default();

        Ok(disks)
    }

    /// List disk models only
    pub fn list_models(&self) -> Result<Vec<String>> {
        let disks = self.list_drives()?;
        Ok(disks.into_iter().filter_map(|d| d.model).collect())
    }

    /// Check if any disk model contains the pattern
    pub fn model_contains(&self, pattern: &str) -> Result<bool> {
        let models = self.list_models()?;
        let p = pattern.to_lowercase();
        Ok(models.iter().any(|m| m.to_lowercase().contains(&p)))
    }

    /// Check if any disk model matches regex
    pub fn model_matches_regex(&self, pattern: &str) -> Result<bool> {
        let re = regex::Regex::new(pattern)
            .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
        let models = self.list_models()?;
        Ok(models.iter().any(|m| re.is_match(m)))
    }

    /// Check for virtual disk indicators (VM detection)
    pub fn is_virtual(&self) -> Result<bool> {
        let models = self.list_models()?;
        let vm_indicators = ["vbox", "vmware", "virtual", "qemu", "xen", "hyper-v"];
        for model in &models {
            let m = model.to_lowercase();
            for ind in &vm_indicators {
                if m.contains(ind) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Get disk serial numbers
    pub fn list_serials(&self) -> Result<Vec<String>> {
        let disks = self.list_drives()?;
        Ok(disks.into_iter().filter_map(|d| d.serial_number).collect())
    }

    /// Check if serial contains pattern
    pub fn serial_contains(&self, pattern: &str) -> Result<bool> {
        let serials = self.list_serials()?;
        let p = pattern.to_lowercase();
        Ok(serials.iter().any(|s| s.to_lowercase().contains(&p)))
    }
}

impl Default for DiskChecker { fn default() -> Self { Self::new() } }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiskInfo {
    #[serde(rename = "Model")]
    pub model: Option<String>,
    #[serde(rename = "SerialNumber")]
    pub serial_number: Option<String>,
    #[serde(rename = "Size")]
    pub size: Option<u64>,
    #[serde(rename = "MediaType")]
    pub media_type: Option<String>,
    #[serde(rename = "InterfaceType")]
    pub interface_type: Option<String>,
}
