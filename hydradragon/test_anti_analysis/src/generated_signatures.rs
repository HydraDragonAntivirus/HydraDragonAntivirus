//! Auto-generated signatures - embedded at compile time
use crate::{SignatureRule, SignatureCondition, MatchType, HwidField, Action, CpuidHypervisorType};

pub fn get_embedded_signatures() -> Vec<SignatureRule> { vec![
SignatureRule {
id: "antidebug_blacklisted_windows".to_string(), name: "Blacklisted Window Titles Detected".to_string(), description: "Detects analysis and debugging tools by their window titles".to_string(),
conditions: vec![
SignatureCondition::Process { name: "x64dbg.exe".to_string(), regex: false },
SignatureCondition::Process { name: "x32dbg.exe".to_string(), regex: false },
SignatureCondition::Process { name: "ollydbg.exe".to_string(), regex: false },
SignatureCondition::Process { name: "ida64.exe".to_string(), regex: false },
SignatureCondition::Process { name: "ida.exe".to_string(), regex: false },
SignatureCondition::Process { name: "windbg.exe".to_string(), regex: false },
SignatureCondition::Process { name: "dnspy.exe".to_string(), regex: false },
SignatureCondition::Process { name: "ilspy.exe".to_string(), regex: false },
SignatureCondition::Process { name: "ghidra.exe".to_string(), regex: false },
SignatureCondition::Process { name: "pestudio.exe".to_string(), regex: false },
SignatureCondition::Process { name: "wireshark.exe".to_string(), regex: false },
SignatureCondition::Process { name: "fiddler.exe".to_string(), regex: false },
SignatureCondition::Process { name: "httpdebuggerui.exe".to_string(), regex: false },
SignatureCondition::Process { name: "HTTP Toolkit.exe".to_string(), regex: false },
SignatureCondition::Process { name: "procmon.exe".to_string(), regex: false },
SignatureCondition::Process { name: "procmon64.exe".to_string(), regex: false },
SignatureCondition::Process { name: "processhacker.exe".to_string(), regex: false },
SignatureCondition::Process { name: "megadumper.exe".to_string(), regex: false },
SignatureCondition::Process { name: "extremedumper.exe".to_string(), regex: false },
SignatureCondition::Process { name: "ksdumper.exe".to_string(), regex: false },
SignatureCondition::Process { name: "ksdumperclient.exe".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "programmatic_analysis_check".to_string(), name: "Programmatic Analysis Detection".to_string(), description: "Detects analysis environments using programmatic checks like IsDebuggerPresent".to_string(),
conditions: vec![
SignatureCondition::AnalysisDetected,
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "antidebug_banned_processes".to_string(), name: "Banned Analysis Processes Running".to_string(), description: "Detects processes commonly used for malware analysis".to_string(),
conditions: vec![
SignatureCondition::Process { name: "df5serv.exe".to_string(), regex: false },
SignatureCondition::Process { name: "joeboxcontrol.exe".to_string(), regex: false },
SignatureCondition::Process { name: "joeboxserver.exe".to_string(), regex: false },
SignatureCondition::Process { name: "petools.exe".to_string(), regex: false },
SignatureCondition::Process { name: "hxd.exe".to_string(), regex: false },
SignatureCondition::Process { name: "protection_id.exe".to_string(), regex: false },
SignatureCondition::Process { name: "scyllahide.exe".to_string(), regex: false },
SignatureCondition::Process { name: "de4dot.exe".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_vmware".to_string(), name: "VMware Virtual Machine".to_string(), description: "Detects VMware virtualization environment".to_string(),
conditions: vec![
SignatureCondition::CpuidHypervisor { hypervisor: CpuidHypervisorType::VMware },
SignatureCondition::CpuidVendor { pattern: "VMware".to_string(), regex: false },
SignatureCondition::DiskModel { pattern: "vmware".to_string(), regex: false },
SignatureCondition::Process { name: "vmtoolsd.exe".to_string(), regex: false },
SignatureCondition::Process { name: "vmacthlp.exe".to_string(), regex: false },
SignatureCondition::Process { name: "vgauthservice.exe".to_string(), regex: false },
SignatureCondition::Registry { path: "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools".to_string(), value_name: None, expected_data: None },
SignatureCondition::Service { name: "VMTools".to_string(), must_be_running: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_virtualbox".to_string(), name: "VirtualBox Virtual Machine".to_string(), description: "Detects VirtualBox virtualization environment".to_string(),
conditions: vec![
SignatureCondition::CpuidHypervisor { hypervisor: CpuidHypervisorType::VirtualBox },
SignatureCondition::CpuidVendor { pattern: "VBox".to_string(), regex: false },
SignatureCondition::DiskModel { pattern: "vbox".to_string(), regex: false },
SignatureCondition::Process { name: "VBoxService.exe".to_string(), regex: false },
SignatureCondition::Process { name: "VBoxTray.exe".to_string(), regex: false },
SignatureCondition::Registry { path: "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions".to_string(), value_name: None, expected_data: None },
SignatureCondition::Service { name: "VBoxService".to_string(), must_be_running: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_hyperv".to_string(), name: "Hyper-V Virtual Machine (Minimal)".to_string(), description: "Detects Microsoft Hyper-V using CPUID, SMBIOS, and motherboard vendor".to_string(),
conditions: vec![
SignatureCondition::CpuidHypervisor { hypervisor: CpuidHypervisorType::HyperV },
SignatureCondition::CpuidVendor { pattern: "Microsoft Hv".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemModel, pattern: "virtual machine".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::MotherboardSerial, pattern: "Microsoft Corporation".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_hyperv_event_logs".to_string(), name: "Hyper-V Event Logs".to_string(), description: "Detects Microsoft Hyper-V by the presence of its event log providers.".to_string(),
conditions: vec![
SignatureCondition::EventLogProvider { provider: "Microsoft-Windows-Hyper-V-VMMS".to_string() },
SignatureCondition::EventLogProvider { provider: "Microsoft-Windows-Hyper-V-Worker".to_string() },
SignatureCondition::EventLogProvider { provider: "Microsoft-Windows-Hyper-V-Hypervisor".to_string() },
SignatureCondition::EventLogProvider { provider: "Microsoft-Windows-Hyper-V-Config".to_string() },
SignatureCondition::EventLogProvider { provider: "Microsoft-Windows-Hyper-V-VMSwitch".to_string() },
SignatureCondition::EventLogProvider { provider: "Microsoft-Windows-Hyper-V-StorageVSP".to_string() },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_smbios_model".to_string(), name: "VM Detection via SMBIOS Model".to_string(), description: "Detects virtual machines by checking the SMBIOS system model for common VM identifiers.".to_string(),
conditions: vec![
SignatureCondition::Hwid { field: HwidField::SystemModel, pattern: "Virtual".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemModel, pattern: "VMware".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemModel, pattern: "KVM".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemModel, pattern: "QEMU".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemModel, pattern: "HVM domU".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_qemu".to_string(), name: "QEMU Virtual Machine".to_string(), description: "Detects QEMU virtualization environment".to_string(),
conditions: vec![
SignatureCondition::CpuidVendor { pattern: "QEMU".to_string(), regex: false },
SignatureCondition::DiskModel { pattern: "qemu".to_string(), regex: false },
SignatureCondition::Process { name: "qemu-ga.exe".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_kvm".to_string(), name: "KVM Virtual Machine".to_string(), description: "Detects KVM virtualization environment".to_string(),
conditions: vec![
SignatureCondition::CpuidHypervisor { hypervisor: CpuidHypervisorType::KVM },
SignatureCondition::CpuidVendor { pattern: "KVM".to_string(), regex: false },
SignatureCondition::DiskModel { pattern: "virtio".to_string(), regex: false },
SignatureCondition::Registry { path: "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS".to_string(), value_name: Some("SystemManufacturer".to_string()), expected_data: Some("QEMU".to_string()) },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_parallels".to_string(), name: "Parallels Virtual Machine".to_string(), description: "Detects Parallels Desktop virtualization environment".to_string(),
conditions: vec![
SignatureCondition::CpuidHypervisor { hypervisor: CpuidHypervisorType::Parallels },
SignatureCondition::CpuidVendor { pattern: "Parallels".to_string(), regex: false },
SignatureCondition::Process { name: "prl_cc.exe".to_string(), regex: false },
SignatureCondition::Process { name: "prl_tools.exe".to_string(), regex: false },
SignatureCondition::DiskModel { pattern: "parallels".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "vm_xen".to_string(), name: "Xen Virtual Machine".to_string(), description: "Detects Xen virtualization environment".to_string(),
conditions: vec![
SignatureCondition::CpuidHypervisor { hypervisor: CpuidHypervisorType::Xen },
SignatureCondition::CpuidVendor { pattern: "Xen".to_string(), regex: false },
SignatureCondition::Process { name: "xenservice.exe".to_string(), regex: false },
SignatureCondition::DiskModel { pattern: "xen".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_sandboxie".to_string(), name: "Sandboxie Environment".to_string(), description: "Detects Sandboxie sandbox environment".to_string(),
conditions: vec![
SignatureCondition::File { path: "C:\\Program Files\\Sandboxie\\".to_string(), must_exist: true },
SignatureCondition::File { path: "C:\\Program Files (x86)\\Sandboxie\\".to_string(), must_exist: true },
SignatureCondition::Service { name: "SbieSvc".to_string(), must_be_running: false },
SignatureCondition::Registry { path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie".to_string(), value_name: None, expected_data: None },
SignatureCondition::Registry { path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(), value_name: Some("SandboxiePlus_AutoRun".to_string()), expected_data: None },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_anyrun".to_string(), name: "ANY.RUN Sandbox".to_string(), description: "Detects ANY.RUN online sandbox environment".to_string(),
conditions: vec![
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "ANYRUN".to_string(), regex: false },
SignatureCondition::User { name: "anyrun".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_triage".to_string(), name: "Triage Sandbox".to_string(), description: "Detects Triage/Hatching sandbox environment".to_string(),
conditions: vec![
SignatureCondition::DiskModel { pattern: "DADY HARDDISK".to_string(), regex: false },
SignatureCondition::DiskModel { pattern: "QEMU HARDDISK".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_joesandbox".to_string(), name: "Joe Sandbox".to_string(), description: "Detects Joe Sandbox environment".to_string(),
conditions: vec![
SignatureCondition::Process { name: "joeboxcontrol.exe".to_string(), regex: false },
SignatureCondition::Process { name: "joeboxserver.exe".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_cybercapture".to_string(), name: "Avast CyberCapture".to_string(), description: "Detects Avast CyberCapture sandbox environment".to_string(),
conditions: vec![
SignatureCondition::User { name: "WDAGUtilityAccount".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_deepfreeze".to_string(), name: "Deep Freeze Environment".to_string(), description: "Detects Deep Freeze system protection".to_string(),
conditions: vec![
SignatureCondition::Process { name: "DFServ.exe".to_string(), regex: false },
SignatureCondition::Service { name: "DFServ".to_string(), must_be_running: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_comodo".to_string(), name: "Comodo Container/Sandbox".to_string(), description: "Detects Comodo containment environment".to_string(),
conditions: vec![
SignatureCondition::Registry { path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\cmdGuard".to_string(), value_name: None, expected_data: None },
SignatureCondition::Service { name: "cmdGuard".to_string(), must_be_running: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "sandbox_shadowdefender".to_string(), name: "Shadow Defender".to_string(), description: "Detects Shadow Defender virtualization".to_string(),
conditions: vec![
SignatureCondition::Registry { path: "HKLM\\SOFTWARE\\ShadowDefender".to_string(), value_name: None, expected_data: None },
SignatureCondition::Service { name: "ShadowDefenderService".to_string(), must_be_running: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "blacklist_usernames".to_string(), name: "Blacklisted Username".to_string(), description: "Detects usernames commonly used in analysis environments".to_string(),
conditions: vec![
SignatureCondition::User { name: "Johnson".to_string(), regex: false },
SignatureCondition::User { name: "Miller".to_string(), regex: false },
SignatureCondition::User { name: "malware".to_string(), regex: false },
SignatureCondition::User { name: "maltest".to_string(), regex: false },
SignatureCondition::User { name: "CurrentUser".to_string(), regex: false },
SignatureCondition::User { name: "Sandbox".to_string(), regex: false },
SignatureCondition::User { name: "virus".to_string(), regex: false },
SignatureCondition::User { name: "John Doe".to_string(), regex: false },
SignatureCondition::User { name: "test user".to_string(), regex: false },
SignatureCondition::User { name: "sand box".to_string(), regex: false },
SignatureCondition::User { name: "WDAGUtilityAccount".to_string(), regex: false },
SignatureCondition::User { name: "Bruno".to_string(), regex: false },
SignatureCondition::User { name: "george".to_string(), regex: false },
SignatureCondition::User { name: "Harry Johnson".to_string(), regex: false },
SignatureCondition::User { name: "analyst".to_string(), regex: false },
SignatureCondition::User { name: "admin".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "blacklist_computernames".to_string(), name: "Blacklisted Computer Name".to_string(), description: "Detects computer names commonly used in analysis environments".to_string(),
conditions: vec![
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "SANDBOX".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "ANALYSIS".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "MALWARE".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "VIRUS".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "DESKTOP-NAKFFMT".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "JOHN-PC".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "LISA-PC".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "JULIA-PC".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "WILEYPC".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "SERVER1".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::ComputerName, pattern: "WIN-5E07COS9ALR".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
SignatureRule {
id: "blacklist_uuids".to_string(), name: "Blacklisted System UUID".to_string(), description: "Detects known analysis/sandbox system UUIDs".to_string(),
conditions: vec![
SignatureCondition::Hwid { field: HwidField::SystemUuid, pattern: "7AB5C494-39F5-4941-9163-47F54D6D5016".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemUuid, pattern: "00000000-0000-0000-0000-000000000000".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemUuid, pattern: "11111111-2222-3333-4444-555555555555".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemUuid, pattern: "032E02B4-0499-05C3-0806-3C0700080009".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemUuid, pattern: "49434D53-0200-9065-2500-65902500E439".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemUuid, pattern: "B1112042-52E8-E25B-3655-6A4F54155DBF".to_string(), regex: false },
SignatureCondition::Hwid { field: HwidField::SystemUuid, pattern: "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A".to_string(), regex: false },
],
actions: vec![
Action::Exit { code: 0 },
],
match_type: MatchType::Any,
},
] }
