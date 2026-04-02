//! Hardware ID (HWID) checking module
//!
//! Retrieves various hardware identifiers using PowerShell commands.
//! This approach avoids WMIC (deprecated) and works purely in usermode.

use crate::{CheckResult, HwidField, Result, SignatureMonsterError};
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Hardware ID checker
pub struct HwidChecker {
    _private: (),
}

impl HwidChecker {
    /// Create a new HWID checker
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Get a specific HWID field value
    pub fn get_field(&self, field: HwidField) -> Result<String> {
        match field {
            HwidField::ProcessorId => self.get_processor_id(),
            HwidField::MotherboardSerial => self.get_motherboard_serial(),
            HwidField::BiosSerial => self.get_bios_serial(),
            HwidField::SystemUuid => self.get_system_uuid(),
            HwidField::MachineGuid => self.get_machine_guid(),
            HwidField::ProductId => self.get_product_id(),
            HwidField::ComputerName => self.get_computer_name(),
            HwidField::MacAddress => self.get_mac_addresses(),
            HwidField::DiskSerial => self.get_disk_serials(),
            HwidField::SystemModel => self.get_system_model(),
        }
    }

    /// Check if a field matches a pattern
    pub fn field_matches(&self, field: HwidField, pattern: &str) -> Result<CheckResult> {
        let value = self.get_field(field)?;
        if value.to_lowercase().contains(&pattern.to_lowercase()) {
            Ok(CheckResult::matched(&value))
        } else {
            Ok(CheckResult::not_matched())
        }
    }

    /// Check if a field matches a regex pattern
    pub fn field_matches_regex(&self, field: HwidField, pattern: &str) -> Result<CheckResult> {
        let value = self.get_field(field)?;
        let re = regex::Regex::new(pattern)
            .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
        if re.is_match(&value) {
            Ok(CheckResult::matched(&value))
        } else {
            Ok(CheckResult::not_matched())
        }
    }

    /// Execute a PowerShell command and return the output
    fn run_powershell(&self, command: &str) -> Result<String> {
        let mut cmd = Command::new("powershell");
        
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SignatureMonsterError::PowerShellError(stderr.to_string()));
        }

        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    /// Get CPU Processor ID
    pub fn get_processor_id(&self) -> Result<String> {
        self.run_powershell("(Get-CimInstance -ClassName Win32_Processor).ProcessorId")
    }

    /// Get motherboard serial number
    pub fn get_motherboard_serial(&self) -> Result<String> {
        self.run_powershell("(Get-CimInstance -ClassName Win32_BaseBoard).SerialNumber")
    }

    /// Get BIOS serial number
    pub fn get_bios_serial(&self) -> Result<String> {
        self.run_powershell("(Get-CimInstance -ClassName Win32_BIOS).SerialNumber")
    }

    /// Get System UUID
    pub fn get_system_uuid(&self) -> Result<String> {
        self.run_powershell("(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID")
    }

    /// Get Machine GUID from registry
    pub fn get_machine_guid(&self) -> Result<String> {
        self.run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name 'MachineGuid').MachineGuid"
        )
    }

    /// Get Windows Product ID
    pub fn get_product_id(&self) -> Result<String> {
        self.run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name 'ProductId').ProductId"
        )
    }

    /// Get Computer Name
    pub fn get_computer_name(&self) -> Result<String> {
        self.run_powershell("$env:COMPUTERNAME")
    }

    /// Get all MAC addresses (comma-separated)
    pub fn get_mac_addresses(&self) -> Result<String> {
        self.run_powershell(
            "(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -ne $null } | Select-Object -ExpandProperty MACAddress) -join ','"
        )
    }

    /// Get all disk serial numbers (comma-separated)
    pub fn get_disk_serials(&self) -> Result<String> {
        self.run_powershell(
            "(Get-CimInstance -ClassName Win32_DiskDrive | Select-Object -ExpandProperty SerialNumber) -join ','"
        )
    }

    /// Get system model from SMBIOS
    pub fn get_system_model(&self) -> Result<String> {
        self.run_powershell("(Get-CimInstance -ClassName Win32_ComputerSystem).Model")
    }

    /// Get Windows product name (e.g., "Windows 11 Pro")
    pub fn get_windows_name(&self) -> Result<String> {
        self.run_powershell(
            "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"
        )
    }

    /// Get Windows version (e.g., "10.0.22631")
    pub fn get_windows_version(&self) -> Result<String> {
        self.run_powershell(
            "(Get-CimInstance -ClassName Win32_OperatingSystem).Version"
        )
    }

    /// Get Windows build number (e.g., "22631")
    pub fn get_windows_build(&self) -> Result<String> {
        self.run_powershell(
            "(Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber"
        )
    }

    /// Get Windows display version (e.g., "23H2")
    pub fn get_windows_display_version(&self) -> Result<String> {
        self.run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name 'DisplayVersion').DisplayVersion"
        )
    }

    /// Get Windows edition ID (e.g., "Professional")
    pub fn get_windows_edition(&self) -> Result<String> {
        self.run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name 'EditionID').EditionID"
        )
    }

    /// Get full Windows info
    pub fn get_windows_info(&self) -> Result<WindowsInfo> {
        Ok(WindowsInfo {
            name: self.get_windows_name().ok(),
            version: self.get_windows_version().ok(),
            build: self.get_windows_build().ok(),
            display_version: self.get_windows_display_version().ok(),
            edition: self.get_windows_edition().ok(),
            product_id: self.get_product_id().ok(),
        })
    }

    /// Get all HWID information as a struct
    pub fn get_all(&self) -> Result<HwidInfo> {
        Ok(HwidInfo {
            processor_id: self.get_processor_id().ok(),
            motherboard_serial: self.get_motherboard_serial().ok(),
            bios_serial: self.get_bios_serial().ok(),
            system_uuid: self.get_system_uuid().ok(),
            machine_guid: self.get_machine_guid().ok(),
            product_id: self.get_product_id().ok(),
            computer_name: self.get_computer_name().ok(),
            mac_addresses: self.get_mac_addresses()
                .ok()
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default(),
            disk_serials: self.get_disk_serials()
                .ok()
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default(),
        })
    }

    /// Generate a composite HWID hash
    pub fn generate_hwid_hash(&self) -> Result<String> {
        let info = self.get_all()?;
        let composite = format!(
            "{}|{}|{}|{}",
            info.processor_id.as_deref().unwrap_or(""),
            info.motherboard_serial.as_deref().unwrap_or(""),
            info.system_uuid.as_deref().unwrap_or(""),
            info.machine_guid.as_deref().unwrap_or(""),
        );
        
        // Simple hash using the uuid crate to generate a deterministic UUID v5
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        composite.hash(&mut hasher);
        let hash = hasher.finish();
        
        Ok(format!("{:016X}", hash))
    }
}

impl Default for HwidChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete HWID information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HwidInfo {
    pub processor_id: Option<String>,
    pub motherboard_serial: Option<String>,
    pub bios_serial: Option<String>,
    pub system_uuid: Option<String>,
    pub machine_guid: Option<String>,
    pub product_id: Option<String>,
    pub computer_name: Option<String>,
    pub mac_addresses: Vec<String>,
    pub disk_serials: Vec<String>,
}

/// Windows OS information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowsInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub build: Option<String>,
    pub display_version: Option<String>,
    pub edition: Option<String>,
    pub product_id: Option<String>,
}
