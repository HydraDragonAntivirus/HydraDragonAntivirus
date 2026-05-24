//! MITRE ATT&CK Technique Mapping
//!
//! Maps observed behaviors to MITRE ATT&CK techniques

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MITRE ATT&CK Technique representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub severity: u8, // 1-10 scale
}

/// Maps behaviors to MITRE ATT&CK techniques
pub struct TechniqueMapper {
    techniques: HashMap<String, MitreTechnique>,
}

impl TechniqueMapper {
    pub fn new() -> Self {
        let mut mapper = TechniqueMapper {
            techniques: HashMap::new(),
        };
        mapper.initialize_techniques();
        mapper
    }

    /// Create a new TechniqueMapper with ALL 200+ techniques loaded from JSON
    pub fn new_from_json() -> Self {
        let techniques = crate::mitre_attack::json_loader::load_all_techniques_from_json();
        TechniqueMapper { techniques }
    }

    fn initialize_techniques(&mut self) {
        // Defense Evasion
        self.add_technique(MitreTechnique {
            id: "T1562.001".to_string(),
            name: "Impair Defenses: Disable or Modify Tools".to_string(),
            tactic: "Defense Evasion".to_string(),
            description: "Adversaries may disable security tools to avoid detection".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1070.001".to_string(),
            name: "Indicator Removal: Clear Windows Event Logs".to_string(),
            tactic: "Defense Evasion".to_string(),
            description: "Adversaries may clear Windows Event Logs to hide activity".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1027".to_string(),
            name: "Obfuscated Files or Information".to_string(),
            tactic: "Defense Evasion".to_string(),
            description: "Adversaries may obfuscate files or information to evade detection".to_string(),
            severity: 6,
        });

        self.add_technique(MitreTechnique {
            id: "T1055".to_string(),
            name: "Process Injection".to_string(),
            tactic: "Defense Evasion".to_string(),
            description: "Adversaries may inject code into processes to evade detection".to_string(),
            severity: 9,
        });

        // Persistence
        self.add_technique(MitreTechnique {
            id: "T1547.001".to_string(),
            name: "Boot or Logon Autostart Execution: Registry Run Keys".to_string(),
            tactic: "Persistence".to_string(),
            description: "Adversaries may achieve persistence by adding programs to startup".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1053.005".to_string(),
            name: "Scheduled Task/Job: Scheduled Task".to_string(),
            tactic: "Persistence".to_string(),
            description: "Adversaries may abuse task scheduling to execute programs".to_string(),
            severity: 7,
        });

        // Credential Access
        self.add_technique(MitreTechnique {
            id: "T1003.001".to_string(),
            name: "OS Credential Dumping: LSASS Memory".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may attempt to access credential material stored in LSASS".to_string(),
            severity: 10,
        });

        self.add_technique(MitreTechnique {
            id: "T1555".to_string(),
            name: "Credentials from Password Stores".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may search for credentials in password stores".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1056.001".to_string(),
            name: "Input Capture: Keylogging".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may log user keystrokes to intercept credentials".to_string(),
            severity: 9,
        });

        // Discovery
        self.add_technique(MitreTechnique {
            id: "T1082".to_string(),
            name: "System Information Discovery".to_string(),
            tactic: "Discovery".to_string(),
            description: "Adversaries may gather system information".to_string(),
            severity: 4,
        });

        self.add_technique(MitreTechnique {
            id: "T1083".to_string(),
            name: "File and Directory Discovery".to_string(),
            tactic: "Discovery".to_string(),
            description: "Adversaries may enumerate files and directories".to_string(),
            severity: 3,
        });

        self.add_technique(MitreTechnique {
            id: "T1057".to_string(),
            name: "Process Discovery".to_string(),
            tactic: "Discovery".to_string(),
            description: "Adversaries may enumerate running processes".to_string(),
            severity: 3,
        });

        // Collection
        self.add_technique(MitreTechnique {
            id: "T1005".to_string(),
            name: "Data from Local System".to_string(),
            tactic: "Collection".to_string(),
            description: "Adversaries may search local system sources for data".to_string(),
            severity: 6,
        });

        self.add_technique(MitreTechnique {
            id: "T1113".to_string(),
            name: "Screen Capture".to_string(),
            tactic: "Collection".to_string(),
            description: "Adversaries may capture screen content".to_string(),
            severity: 7,
        });

        // Command and Control
        self.add_technique(MitreTechnique {
            id: "T1071.001".to_string(),
            name: "Application Layer Protocol: Web Protocols".to_string(),
            tactic: "Command and Control".to_string(),
            description: "Adversaries may communicate using HTTP/HTTPS".to_string(),
            severity: 6,
        });

        self.add_technique(MitreTechnique {
            id: "T1095".to_string(),
            name: "Non-Application Layer Protocol".to_string(),
            tactic: "Command and Control".to_string(),
            description: "Adversaries may use non-application layer protocols".to_string(),
            severity: 7,
        });

        // Exfiltration
        self.add_technique(MitreTechnique {
            id: "T1041".to_string(),
            name: "Exfiltration Over C2 Channel".to_string(),
            tactic: "Exfiltration".to_string(),
            description: "Adversaries may steal data over their C2 channel".to_string(),
            severity: 8,
        });

        // Impact
        self.add_technique(MitreTechnique {
            id: "T1486".to_string(),
            name: "Data Encrypted for Impact".to_string(),
            tactic: "Impact".to_string(),
            description: "Adversaries may encrypt data to disrupt availability (Ransomware)".to_string(),
            severity: 10,
        });

        self.add_technique(MitreTechnique {
            id: "T1490".to_string(),
            name: "Inhibit System Recovery".to_string(),
            tactic: "Impact".to_string(),
            description: "Adversaries may delete or remove backup data".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1489".to_string(),
            name: "Service Stop".to_string(),
            tactic: "Impact".to_string(),
            description: "Adversaries may stop or disable services".to_string(),
            severity: 7,
        });

        // Execution - EXPANDED
        self.add_technique(MitreTechnique {
            id: "T1059.001".to_string(),
            name: "Command and Scripting Interpreter: PowerShell".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse PowerShell for execution".to_string(),
            severity: 6,
        });

        self.add_technique(MitreTechnique {
            id: "T1059.003".to_string(),
            name: "Command and Scripting Interpreter: Windows Command Shell".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse cmd.exe for execution".to_string(),
            severity: 5,
        });

        self.add_technique(MitreTechnique {
            id: "T1059.005".to_string(),
            name: "Command and Scripting Interpreter: Visual Basic".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse Visual Basic for execution".to_string(),
            severity: 6,
        });

        self.add_technique(MitreTechnique {
            id: "T1059.006".to_string(),
            name: "Command and Scripting Interpreter: Python".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse Python for execution".to_string(),
            severity: 5,
        });

        self.add_technique(MitreTechnique {
            id: "T1059.007".to_string(),
            name: "Command and Scripting Interpreter: JavaScript".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse JavaScript for execution".to_string(),
            severity: 6,
        });

        self.add_technique(MitreTechnique {
            id: "T1106".to_string(),
            name: "Native API".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may interact with Windows API to execute behaviors".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1129".to_string(),
            name: "Shared Modules".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may execute malicious payloads via loading shared modules".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1203".to_string(),
            name: "Exploitation for Client Execution".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may exploit software vulnerabilities in client applications".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1204.001".to_string(),
            name: "User Execution: Malicious Link".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may rely on users clicking malicious links".to_string(),
            severity: 5,
        });

        self.add_technique(MitreTechnique {
            id: "T1204.002".to_string(),
            name: "User Execution: Malicious File".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may rely on users opening malicious files".to_string(),
            severity: 6,
        });

        self.add_technique(MitreTechnique {
            id: "T1559.001".to_string(),
            name: "Inter-Process Communication: Component Object Model".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may use COM for local code execution".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1559.002".to_string(),
            name: "Inter-Process Communication: Dynamic Data Exchange".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may use DDE to execute arbitrary commands".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1569.002".to_string(),
            name: "System Services: Service Execution".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse Windows services to execute commands".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1047".to_string(),
            name: "Windows Management Instrumentation".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse WMI to execute malicious commands".to_string(),
            severity: 7,
        });

        // Privilege Escalation - EXPANDED
        self.add_technique(MitreTechnique {
            id: "T1134".to_string(),
            name: "Access Token Manipulation".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may modify access tokens to escalate privileges".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1134.001".to_string(),
            name: "Access Token Manipulation: Token Impersonation/Theft".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may duplicate then impersonate another user's token".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1134.002".to_string(),
            name: "Access Token Manipulation: Create Process with Token".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may create a new process with a duplicated token".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1134.003".to_string(),
            name: "Access Token Manipulation: Make and Impersonate Token".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may make and impersonate tokens to escalate privileges".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1134.004".to_string(),
            name: "Access Token Manipulation: Parent PID Spoofing".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may spoof the parent process identifier (PPID)".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1134.005".to_string(),
            name: "Access Token Manipulation: SID-History Injection".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may use SID-History Injection to escalate privileges".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1548.002".to_string(),
            name: "Abuse Elevation Control Mechanism: Bypass User Account Control".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may bypass UAC mechanisms to elevate privileges".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1068".to_string(),
            name: "Exploitation for Privilege Escalation".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may exploit software vulnerabilities to elevate privileges".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1574.001".to_string(),
            name: "Hijack Execution Flow: DLL Search Order Hijacking".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may execute their own malicious payloads by hijacking DLL search order".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1574.002".to_string(),
            name: "Hijack Execution Flow: DLL Side-Loading".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may execute their own malicious payloads by side-loading DLLs".to_string(),
            severity: 7,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.001".to_string(),
            name: "Process Injection: Dynamic-link Library Injection".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject DLLs into processes".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.002".to_string(),
            name: "Process Injection: Portable Executable Injection".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject portable executables into processes".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.003".to_string(),
            name: "Process Injection: Thread Execution Hijacking".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject code into hijacked processes via thread execution".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.004".to_string(),
            name: "Process Injection: Asynchronous Procedure Call".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject code via asynchronous procedure calls".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.011".to_string(),
            name: "Process Injection: Extra Window Memory Injection".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject code into process via extra window memory".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.012".to_string(),
            name: "Process Injection: Process Hollowing".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject code into suspended and hollowed processes".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.013".to_string(),
            name: "Process Injection: Process Doppelgänging".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject code using process doppelgänging".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1055.014".to_string(),
            name: "Process Injection: VDSO Hijacking".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may inject code by hijacking VDSO".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1543.003".to_string(),
            name: "Create or Modify System Process: Windows Service".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may create or modify Windows services".to_string(),
            severity: 8,
        });

        self.add_technique(MitreTechnique {
            id: "T1484.001".to_string(),
            name: "Domain Policy Modification: Group Policy Modification".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may modify Group Policy Objects".to_string(),
            severity: 9,
        });

        self.add_technique(MitreTechnique {
            id: "T1611".to_string(),
            name: "Escape to Host".to_string(),
            tactic: "Privilege Escalation".to_string(),
            description: "Adversaries may break out of a container to gain access to the host".to_string(),
            severity: 9,
        });
    }

    fn add_technique(&mut self, technique: MitreTechnique) {
        self.techniques.insert(technique.id.clone(), technique);
    }

    pub fn get_technique(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.get(id)
    }

    /// Map behavior indicators to MITRE techniques
    pub fn map_behavior_to_techniques(&self, behavior: &str) -> Vec<MitreTechnique> {
        let mut techniques = Vec::new();
        let behavior_lower = behavior.to_lowercase();

        // Process injection indicators
        if behavior_lower.contains("virtualalloc")
            || behavior_lower.contains("writeprocessmemory")
            || behavior_lower.contains("createremotethread")
        {
            if let Some(tech) = self.get_technique("T1055") {
                techniques.push(tech.clone());
            }
        }

        // Credential dumping
        if behavior_lower.contains("lsass") || behavior_lower.contains("credential") {
            if let Some(tech) = self.get_technique("T1003.001") {
                techniques.push(tech.clone());
            }
        }

        // Ransomware indicators
        if behavior_lower.contains("encrypt") || behavior_lower.contains("ransom") {
            if let Some(tech) = self.get_technique("T1486") {
                techniques.push(tech.clone());
            }
        }

        // Event log tampering
        if behavior_lower.contains("event") && behavior_lower.contains("log") {
            if let Some(tech) = self.get_technique("T1070.001") {
                techniques.push(tech.clone());
            }
        }

        // Registry persistence
        if behavior_lower.contains("registry") && behavior_lower.contains("run") {
            if let Some(tech) = self.get_technique("T1547.001") {
                techniques.push(tech.clone());
            }
        }

        // Password store access
        if behavior_lower.contains("password") || behavior_lower.contains("vault") {
            if let Some(tech) = self.get_technique("T1555") {
                techniques.push(tech.clone());
            }
        }

        // Network communication
        if behavior_lower.contains("http") || behavior_lower.contains("network") {
            if let Some(tech) = self.get_technique("T1071.001") {
                techniques.push(tech.clone());
            }
        }

        // Backup deletion
        if behavior_lower.contains("backup") && behavior_lower.contains("delete") {
            if let Some(tech) = self.get_technique("T1490") {
                techniques.push(tech.clone());
            }
        }

        // PowerShell execution
        if behavior_lower.contains("powershell") {
            if let Some(tech) = self.get_technique("T1059.001") {
                techniques.push(tech.clone());
            }
        }

        techniques
    }

    pub fn all_techniques(&self) -> Vec<&MitreTechnique> {
        self.techniques.values().collect()
    }
}

impl Default for TechniqueMapper {
    fn default() -> Self {
        Self::new()
    }
}
