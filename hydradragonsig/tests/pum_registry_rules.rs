//! The shipped PUM rules (`OpenMalwareScannerPortable/hydradragonsig_rules/
//! pum_registry_rules.yaml`) judged against single registry writes, the way
//! OpenEDR's `check_registry_content` uses them (`ScanReport::registry_event`).

use hydradragonsig::models::{RegistryEvent, ScanReport};
use hydradragonsig::rules::{RuleEvalOptions, RuleSet};
use std::path::PathBuf;

fn load(file: &str) -> RuleSet {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("OpenMalwareScannerPortable")
        .join("hydradragonsig_rules")
        .join(file);
    let rs = RuleSet::from_yaml_file(&path).unwrap_or_else(|e| panic!("{file} loads: {e:#}"));
    assert!(rs.warnings().is_empty(), "{file} warnings: {:?}", rs.warnings());
    rs
}

fn rules() -> RuleSet {
    load("pum_registry_rules.yaml")
}

#[test]
fn file_pum_rules_are_scoped_to_their_file() {
    let rs = load("file_pum_rules.yaml");
    assert!(!rs.rules().is_empty());
    for rule in rs.rules() {
        assert!(rule.required_path.is_some(), "{} must set file_path", rule.id);
    }
}

/// The way the cloud runs it: an endpoint's hosts file uploaded and scanned
/// under its client path. The uploaded bytes are judged, not this machine's
/// hosts file, and the same bytes under any other path never match.
fn hosts_hits(rs: &RuleSet, path: &str, content: &str) -> Vec<String> {
    let mut report = ScanReport { path: PathBuf::from(path), ..ScanReport::default() };
    rs.evaluate_into(
        &mut report,
        content.as_bytes(),
        RuleEvalOptions { profile_rules: false, parallel_rules: false, stop_on_detection: false, min_string_len: 0, decode_strings: false },
    );
    report.findings.iter().map(|f| f.rule_id.clone()).collect()
}

#[test]
fn hosts_file_upload_is_judged_by_its_bytes() {
    let rs = load("file_pum_rules.yaml");
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let hosts = format!("{root}\\System32\\drivers\\etc\\hosts");
    let stock = "# Copyright (c) 1993-2009 Microsoft Corp.\n#\t127.0.0.1       localhost\n127.0.0.1 localhost\n::1 localhost\n";
    let hijacked = format!("{stock}0.0.0.0 update.microsoft.com\n");
    assert_eq!(hosts_hits(&rs, &hosts, &hijacked), vec!["PUM_FILE_0001"]);
    assert!(hosts_hits(&rs, &hosts, stock).is_empty());
    assert!(hosts_hits(&rs, "C:\\Users\\Public\\notes.txt", &hijacked).is_empty());
}

fn hits(rs: &RuleSet, key: &str, value: &str, data: &str) -> Vec<String> {
    let mut report = ScanReport {
        registry_event: Some(RegistryEvent { key: key.into(), value: value.into(), data: data.into() }),
        ..ScanReport::default()
    };
    rs.evaluate_into(
        &mut report,
        &[],
        RuleEvalOptions { profile_rules: false, parallel_rules: false, stop_on_detection: false, min_string_len: 0, decode_strings: false },
    );
    let mut ids: Vec<String> = report.findings.iter().map(|f| f.rule_id.clone()).collect();
    ids.sort();
    ids
}

const USER_SYS: &str = "\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
const MACHINE: &str = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows";

#[test]
fn restriction_flags() {
    let rs = rules();
    assert_eq!(hits(&rs, USER_SYS, "disabletaskmgr", "1"), vec!["PUM_0001"]);
    // Writing the safe value back is not a PUM.
    assert!(hits(&rs, USER_SYS, "DisableTaskMgr", "0").is_empty());
    // Same key, unrelated value.
    assert!(hits(&rs, USER_SYS, "SomethingElse", "1").is_empty());
}

#[test]
fn protections_switched_off() {
    let rs = rules();
    let sys = format!("{MACHINE}\\CurrentVersion\\Policies\\System");
    assert_eq!(hits(&rs, &sys, "EnableLUA", "0"), vec!["PUM_0010"]);
    assert!(hits(&rs, &sys, "EnableLUA", "1").is_empty());
    let fw = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile";
    assert_eq!(hits(&rs, fw, "EnableFirewall", "0"), vec!["PUM_0012"]);
    let tamper = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Features";
    assert_eq!(hits(&rs, tamper, "TamperProtection", "4"), vec!["PUM_0014"]);
    assert!(hits(&rs, tamper, "TamperProtection", "5").is_empty());
}

#[test]
fn hijacked_system_values() {
    let rs = rules();
    let winlogon = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    assert_eq!(hits(&rs, winlogon, "Shell", "explorer.exe, evil.exe"), vec!["PUM_0056"]);
    assert!(hits(&rs, winlogon, "Shell", "explorer.exe").is_empty());
    assert_eq!(hits(&rs, winlogon, "Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\evil.exe"), vec!["PUM_0059"]);
    assert!(hits(&rs, winlogon, "Userinit", "C:\\Windows\\system32\\userinit.exe,").is_empty());
    let ifeo = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe";
    assert_eq!(hits(&rs, ifeo, "Debugger", "C:\\evil.exe"), vec!["PUM_0054"]);
    let tcpip = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters";
    assert_eq!(hits(&rs, tcpip, "DataBasePath", "C:\\Users\\Public\\etc"), vec!["PUM_0057"]);
    assert!(hits(&rs, tcpip, "DataBasePath", "%SystemRoot%\\System32\\drivers\\etc").is_empty());
}
